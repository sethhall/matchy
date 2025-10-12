//! Offset-based Paraglob Pattern Matcher
//!
//! This module implements the complete Paraglob system using a unified
//! offset-based binary format. Everything is stored in a single `Vec<u8>`
//! that can be serialized to disk or memory-mapped for instant loading.
//!
//! # Architecture
//!
//! The buffer contains:
//! 1. ParaglobHeader (72 bytes)
//! 2. AC automaton data (nodes, edges, pattern IDs)
//! 3. Pattern entries (metadata for each pattern)
//! 4. Pattern strings (null-terminated)
//! 5. Glob pattern data (for glob verification)
//!
//! All matching operations work directly on this buffer using offsets.

use crate::ac_offset::{ACAutomaton, MatchMode as ACMatchMode};
use crate::data_section::{DataEncoder, DataValue};
use crate::error::ParaglobError;
use crate::glob::{GlobPattern, MatchMode as GlobMatchMode};
use crate::offset_format::{
    read_cstring, read_str_checked, read_str_unchecked, ACEdge, ParaglobHeader, PatternDataMapping,
    PatternEntry, SingleWildcard,
};
use std::collections::{HashMap, HashSet};
use std::mem;
use zerocopy::Ref;

/// Pattern classification for optimization
#[derive(Debug, Clone)]
enum PatternType {
    /// Pure literal pattern (no wildcards)
    Literal {
        text: String,
        id: u32,
        data: Option<DataValue>,
    },
    /// Glob pattern with extracted literals
    Glob {
        pattern: String,
        literals: Vec<String>,
        id: u32,
        data: Option<DataValue>,
    },
    /// Pure wildcard pattern (no literals to extract)
    PureWildcard {
        pattern: String,
        id: u32,
        data: Option<DataValue>,
    },
}

impl PatternType {
    fn new_with_data(
        pattern: &str,
        id: u32,
        data: Option<DataValue>,
    ) -> Result<Self, ParaglobError> {
        if pattern.is_empty() {
            return Err(ParaglobError::InvalidPattern("Empty pattern".to_string()));
        }

        if Self::is_glob(pattern) {
            let literals = Self::extract_literals(pattern);

            if literals.is_empty() {
                Ok(Self::PureWildcard {
                    pattern: pattern.to_string(),
                    id,
                    data,
                })
            } else {
                Ok(Self::Glob {
                    pattern: pattern.to_string(),
                    literals,
                    id,
                    data,
                })
            }
        } else {
            Ok(Self::Literal {
                text: pattern.to_string(),
                id,
                data,
            })
        }
    }

    fn is_glob(pattern: &str) -> bool {
        let mut escaped = false;
        for ch in pattern.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '*' | '?' | '[' => return true,
                _ => {}
            }
        }
        false
    }

    fn extract_literals(pattern: &str) -> Vec<String> {
        let mut literals = Vec::new();
        let mut current = String::new();
        let mut chars = pattern.chars().peekable();
        let mut escaped = false;

        while let Some(ch) = chars.next() {
            if escaped {
                current.push(ch);
                escaped = false;
                continue;
            }

            match ch {
                '\\' => escaped = true,
                '*' | '?' => {
                    if !current.is_empty() {
                        literals.push(current.clone());
                        current.clear();
                    }
                }
                '[' => {
                    if !current.is_empty() {
                        literals.push(current.clone());
                        current.clear();
                    }
                    // Skip character class
                    let mut depth = 1;
                    while let Some(c) = chars.next() {
                        if c == '\\' {
                            chars.next();
                        } else if c == '[' {
                            depth += 1;
                        } else if c == ']' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                }
                _ => current.push(ch),
            }
        }

        if !current.is_empty() {
            literals.push(current);
        }

        literals
    }

    fn id(&self) -> u32 {
        match self {
            Self::Literal { id, .. } => *id,
            Self::Glob { id, .. } => *id,
            Self::PureWildcard { id, .. } => *id,
        }
    }

    fn pattern(&self) -> &str {
        match self {
            Self::Literal { text, .. } => text,
            Self::Glob { pattern, .. } => pattern,
            Self::PureWildcard { pattern, .. } => pattern,
        }
    }

    fn data(&self) -> Option<&DataValue> {
        match self {
            Self::Literal { data, .. } => data.as_ref(),
            Self::Glob { data, .. } => data.as_ref(),
            Self::PureWildcard { data, .. } => data.as_ref(),
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct Stats {
    /// Number of patterns in the database
    pub pattern_count: usize,
    /// Number of AC automaton nodes
    pub node_count: usize,
    /// Number of AC automaton edges
    pub edge_count: usize,
    /// Size of data section in bytes (0 for v1)
    pub data_section_size: usize,
    /// Number of pattern-data mappings (0 for v1)
    pub mapping_count: usize,
}

/// Incremental builder for constructing Paraglob pattern matchers
///
/// This builder allows you to add patterns one at a time before
/// building the final Paraglob instance.
///
/// # Example
/// ```
/// use matchy::{ParaglobBuilder, data_section::DataValue};
/// use matchy::glob::MatchMode;
/// use std::collections::HashMap;
///
/// let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);
///
/// // Add patterns incrementally
/// builder.add_pattern("*.txt").unwrap();
/// builder.add_pattern("test_*").unwrap();
///
/// // Add pattern with associated data
/// let mut threat_data = HashMap::new();
/// threat_data.insert("level".to_string(), DataValue::String("high".to_string()));
/// builder.add_pattern_with_data("*.evil.com", Some(DataValue::Map(threat_data))).unwrap();
///
/// // Build the final matcher
/// let mut pg = builder.build().unwrap();
/// let matches = pg.find_all("test_file.txt");
/// ```
pub struct ParaglobBuilder {
    patterns: Vec<PatternType>,
    mode: ACMatchMode,
    pattern_set: std::collections::HashSet<String>,
}

impl ParaglobBuilder {
    /// Create a new builder with the specified match mode
    ///
    /// # Arguments
    /// * `mode` - Case sensitivity mode for pattern matching
    pub fn new(mode: GlobMatchMode) -> Self {
        let ac_mode = match mode {
            GlobMatchMode::CaseSensitive => ACMatchMode::CaseSensitive,
            GlobMatchMode::CaseInsensitive => ACMatchMode::CaseInsensitive,
        };
        Self {
            patterns: Vec::new(),
            mode: ac_mode,
            pattern_set: std::collections::HashSet::new(),
        }
    }

    /// Add a pattern without associated data
    ///
    /// Returns the pattern ID that can be used later to retrieve data or identify matches.
    ///
    /// # Arguments
    /// * `pattern` - Glob pattern string (e.g., "*.txt", "test_*")
    ///
    /// # Returns
    /// The assigned pattern ID, or an error if the pattern is invalid
    pub fn add_pattern(&mut self, pattern: &str) -> Result<u32, ParaglobError> {
        self.add_pattern_with_data(pattern, None)
    }

    /// Add a pattern with associated data (v2 format)
    ///
    /// The data will be stored in the v2 format and can be retrieved later
    /// using `Paraglob::get_pattern_data()`.
    ///
    /// # Arguments
    /// * `pattern` - Glob pattern string
    /// * `data` - Optional data to associate with this pattern
    ///
    /// # Returns
    /// The assigned pattern ID
    ///
    /// # Example
    /// ```
    /// use matchy::{ParaglobBuilder, data_section::DataValue};
    /// use matchy::glob::MatchMode;
    /// use std::collections::HashMap;
    ///
    /// let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);
    ///
    /// let mut threat_info = HashMap::new();
    /// threat_info.insert("severity".to_string(), DataValue::String("high".to_string()));
    /// threat_info.insert("score".to_string(), DataValue::Uint32(95));
    ///
    /// let pattern_id = builder.add_pattern_with_data(
    ///     "*.malware.com",
    ///     Some(DataValue::Map(threat_info))
    /// ).unwrap();
    /// ```
    pub fn add_pattern_with_data(
        &mut self,
        pattern: &str,
        data: Option<DataValue>,
    ) -> Result<u32, ParaglobError> {
        // Check for duplicate pattern (match C++ behavior)
        if self.pattern_set.contains(pattern) {
            // Pattern already exists - C++ returns RETURNSTATUS_DUPLICATE_PATTERN
            // We'll just return the existing ID by finding it
            for pat in &self.patterns {
                if pat.pattern() == pattern {
                    return Ok(pat.id());
                }
            }
        }

        let id = self.patterns.len() as u32;
        let pat_type = PatternType::new_with_data(pattern, id, data)?;
        self.pattern_set.insert(pattern.to_string());
        self.patterns.push(pat_type);
        Ok(id)
    }

    /// Get the number of patterns currently in the builder
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Check if a pattern has already been added
    pub fn contains_pattern(&self, pattern: &str) -> bool {
        self.pattern_set.contains(pattern)
    }

    /// Build the final Paraglob matcher
    ///
    /// Consumes the builder and produces a `Paraglob` instance ready for matching.
    /// This operation builds the Aho-Corasick automaton, encodes data (if any),
    /// and serializes everything into the optimized binary format.
    ///
    /// # Returns
    /// A `Paraglob` instance, or an error if building fails
    pub fn build(self) -> Result<Paraglob, ParaglobError> {
        let mode = match self.mode {
            ACMatchMode::CaseSensitive => GlobMatchMode::CaseSensitive,
            ACMatchMode::CaseInsensitive => GlobMatchMode::CaseInsensitive,
        };

        // Build the binary buffer with all serialized data
        let buffer = self.build_internal_v3()?;

        // Extract metadata from the built buffer header
        let (header_ref, _) = Ref::<_, ParaglobHeader>::from_prefix(&buffer[..])
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        let header = *header_ref;

        // Load AC literal hash table from the built buffer
        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_offset = header.ac_literal_map_offset as usize;
            if hash_offset >= buffer.len() {
                return Err(ParaglobError::Validation(format!(
                    "AC literal map offset {} out of bounds (buffer size: {})",
                    hash_offset,
                    buffer.len()
                )));
            }
            let hash_slice = &buffer[hash_offset..];
            // SAFETY: Extending lifetime to 'static is safe because buffer is owned by struct
            let static_slice: &'static [u8] =
                unsafe { std::slice::from_raw_parts(hash_slice.as_ptr(), hash_slice.len()) };
            Some(crate::ac_literal_hash::ACLiteralHash::from_buffer(
                static_slice,
            )?)
        } else {
            None
        };

        let pattern_data_map = if header.has_data_section() && header.mapping_count > 0 {
            Some(PatternDataMetadata {
                offset: header.mapping_table_offset as usize,
                count: header.mapping_count,
            })
        } else {
            None
        };

        Ok(Paraglob {
            buffer: BufferStorage::Owned(buffer),
            mode,
            trusted: true, // Databases we build are trusted
            glob_cache: HashMap::new(),
            ac_literal_hash,
            pattern_data_map,
            candidate_buffer: HashSet::new(),
            ac_literal_buffer: HashSet::new(),
        })
    }

    fn build_internal_v3(self) -> Result<Vec<u8>, ParaglobError> {
        // Collect literals for AC automaton
        // Use HashSet for O(1) deduplication instead of Vec::contains which is O(n)
        let mut ac_literals_set: HashSet<&str> = HashSet::new();
        let mut ac_literals = Vec::new();
        let mut literal_to_patterns: HashMap<String, Vec<u32>> = HashMap::new();

        // Pre-allocate based on pattern count (rough estimate: 2 literals per pattern)
        ac_literals.reserve(self.patterns.len() * 2);
        literal_to_patterns.reserve(self.patterns.len() * 2);

        for pat in &self.patterns {
            match pat {
                PatternType::Literal { text, id, .. } => {
                    // Add to dedup set first
                    let is_new = ac_literals_set.insert(text.as_str());
                    if is_new {
                        ac_literals.push(text.clone());
                    }
                    // HashMap can use the owned string from the set or pattern
                    literal_to_patterns
                        .entry(text.clone())
                        .or_default()
                        .push(*id);
                }
                PatternType::Glob { literals, id, .. } => {
                    for lit in literals {
                        // Filter out very short literals (< 3 chars) to reduce false positives
                        // Short literals like "-", ".", ".com" match too many patterns
                        if lit.len() < 3 {
                            continue;
                        }

                        // O(1) check with HashSet, only clone once for Vec if needed
                        let is_new = ac_literals_set.insert(lit.as_str());
                        if is_new {
                            ac_literals.push(lit.clone());
                        }
                        literal_to_patterns
                            .entry(lit.clone())
                            .or_default()
                            .push(*id);
                    }
                }
                PatternType::PureWildcard { .. } => {
                    // No literals to add
                }
            }
        }

        // Build AC automaton
        let ac_automaton = if !ac_literals.is_empty() {
            let ac_refs: Vec<&str> = ac_literals.iter().map(|s| s.as_str()).collect();
            ACAutomaton::build(&ac_refs, self.mode)?
        } else {
            ACAutomaton::new(self.mode)
        };

        // Build mapping from AC literal ID to pattern IDs
        // AC assigns IDs 0, 1, 2... to literals in the order they were added
        let mut ac_literal_to_patterns = HashMap::new();
        for (literal_id, literal_str) in ac_literals.iter().enumerate() {
            if let Some(pattern_ids) = literal_to_patterns.get(literal_str) {
                ac_literal_to_patterns.insert(literal_id as u32, pattern_ids.clone());
            }
        }

        // Calculate sizes
        let header_size = mem::size_of::<ParaglobHeader>();
        let ac_buffer = ac_automaton.buffer();
        let ac_size = ac_buffer.len();

        // Add padding after AC section to ensure pattern entries are 8-byte aligned
        let unaligned_patterns_start = header_size + ac_size;
        let alignment = 8; // PatternEntry needs 8-byte alignment (16 bytes, 8-byte fields)
        let ac_padding = (alignment - (unaligned_patterns_start % alignment)) % alignment;

        // Pattern entries section
        let patterns_start = unaligned_patterns_start + ac_padding;
        let pattern_entry_size = mem::size_of::<PatternEntry>();
        let pattern_entries_size = self.patterns.len() * pattern_entry_size;

        // Pattern strings section
        let pattern_strings_start = patterns_start + pattern_entries_size;
        let mut pattern_strings_data = Vec::new();
        let mut pattern_string_offsets = Vec::new();

        for pat in &self.patterns {
            pattern_string_offsets.push(pattern_strings_data.len());
            let s = pat.pattern();
            pattern_strings_data.extend_from_slice(s.as_bytes());
            pattern_strings_data.push(0); // Null terminator
        }

        let pattern_strings_size = pattern_strings_data.len();

        // Add padding to ensure wildcards section is 8-byte aligned
        // This allows zerocopy to safely read SingleWildcard structs
        let unaligned_wildcards_start = pattern_strings_start + pattern_strings_size;
        let alignment = 8; // SingleWildcard needs 8-byte alignment
        let padding = (alignment - (unaligned_wildcards_start % alignment)) % alignment;

        // Pure wildcards section (patterns with no literals)
        let pure_wildcards: Vec<&PatternType> = self
            .patterns
            .iter()
            .filter(|p| matches!(p, PatternType::PureWildcard { .. }))
            .collect();

        let wildcards_start = unaligned_wildcards_start + padding;
        let wildcard_entry_size = mem::size_of::<SingleWildcard>();
        let wildcards_size = pure_wildcards.len() * wildcard_entry_size;

        // Data section (v2 feature)
        let data_section_start = wildcards_start + wildcards_size;
        let mut data_encoder = DataEncoder::new();
        let mut pattern_data_mappings = Vec::new();

        // Encode data for each pattern that has it
        for pat in &self.patterns {
            if let Some(data) = pat.data() {
                let data_offset = data_encoder.encode(data);
                pattern_data_mappings.push(PatternDataMapping::new(
                    pat.id(),
                    data_offset,
                    0, // size is implicit in encoded data
                ));
            }
        }

        let data_section_bytes = data_encoder.into_bytes();
        let data_section_size = data_section_bytes.len();

        // Add padding after data section to ensure mapping table is 4-byte aligned
        // PatternDataMapping is 12 bytes with 4-byte alignment requirement
        let unaligned_mappings_start = data_section_start + data_section_size;
        let mapping_alignment = 4; // PatternDataMapping requires 4-byte alignment
        let data_padding = (mapping_alignment - (unaligned_mappings_start % mapping_alignment))
            % mapping_alignment;

        // Pattern data mappings section (v2)
        let mappings_start = unaligned_mappings_start + data_padding;
        let mapping_entry_size = mem::size_of::<PatternDataMapping>();
        let mappings_size = pattern_data_mappings.len() * mapping_entry_size;

        // AC literal mapping section (v3) - use hash table for O(1) lookups
        let ac_literal_map_start = mappings_start + mappings_size;
        let mut ac_hash_builder = crate::ac_literal_hash::ACLiteralHashBuilder::new();
        for (literal_id, pattern_ids) in &ac_literal_to_patterns {
            ac_hash_builder.add_mapping(*literal_id, pattern_ids.clone());
        }
        let ac_hash_bytes = ac_hash_builder.build()?;
        let ac_literal_map_size = ac_hash_bytes.len();

        // Allocate buffer (including padding for alignment)
        let total_size = header_size
            + ac_size
            + ac_padding  // Alignment padding before pattern entries
            + pattern_entries_size
            + pattern_strings_size
            + padding  // Alignment padding before wildcards
            + wildcards_size
            + data_section_size
            + data_padding  // Alignment padding before mapping table
            + mappings_size
            + ac_literal_map_size;
        let mut buffer = vec![0u8; total_size];

        // Write header (v2 if we have data, v1 otherwise)
        let mut header = ParaglobHeader::new();
        header.match_mode = match self.mode {
            ACMatchMode::CaseSensitive => 0,
            ACMatchMode::CaseInsensitive => 1,
        };
        header.ac_node_count = ac_automaton.buffer().len() as u32; // Approximation
        header.ac_nodes_offset = header_size as u32;
        header.ac_edges_size = ac_size as u32;
        header.pattern_count = self.patterns.len() as u32;
        header.patterns_offset = patterns_start as u32;
        header.pattern_strings_offset = pattern_strings_start as u32;
        header.pattern_strings_size = pattern_strings_size as u32;
        header.wildcard_count = pure_wildcards.len() as u32;
        header.total_buffer_size = total_size as u32;
        // header.reserved is already initialized to [0; 3] in new()

        // v2 fields (if we have data)
        if data_section_size > 0 {
            header.data_section_offset = data_section_start as u32;
            header.data_section_size = data_section_size as u32;
            header.mapping_table_offset = mappings_start as u32;
            header.mapping_count = pattern_data_mappings.len() as u32;
            header.data_flags = 0x1; // Inline data flag
        }

        // v3 fields (AC literal mapping - always present)
        header.ac_literal_map_offset = ac_literal_map_start as u32;
        header.ac_literal_map_count = ac_literal_to_patterns.len() as u32;

        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }

        // Write AC automaton data
        buffer[header_size..header_size + ac_size].copy_from_slice(ac_buffer);

        // Padding bytes after AC automaton are already zero-initialized

        // Write pattern entries
        for (i, pat) in self.patterns.iter().enumerate() {
            let entry_offset = patterns_start + i * pattern_entry_size;
            let string_offset = (pattern_strings_start + pattern_string_offsets[i]) as u32;

            let pattern_type = match pat {
                PatternType::Literal { .. } => 0u8,
                PatternType::Glob { .. } | PatternType::PureWildcard { .. } => 1u8,
            };

            let mut entry = PatternEntry::new(pat.id(), pattern_type);
            entry.pattern_string_offset = string_offset;
            entry.pattern_string_length = pat.pattern().len() as u32;

            unsafe {
                let ptr = buffer.as_mut_ptr().add(entry_offset) as *mut PatternEntry;
                ptr.write(entry);
            }
        }

        // Write pattern strings
        buffer[pattern_strings_start..pattern_strings_start + pattern_strings_size]
            .copy_from_slice(&pattern_strings_data);

        // Padding bytes after pattern strings are already zero-initialized

        // Write pure wildcard entries
        for (i, pat) in pure_wildcards.iter().enumerate() {
            let wildcard_offset = wildcards_start + i * wildcard_entry_size;
            let string_offset = pattern_strings_start + pattern_string_offsets[pat.id() as usize];

            let wildcard = SingleWildcard {
                pattern_id: pat.id(),
                pattern_string_offset: string_offset as u32,
            };

            unsafe {
                let ptr = buffer.as_mut_ptr().add(wildcard_offset) as *mut SingleWildcard;
                ptr.write(wildcard);
            }
        }

        // Write data section
        if data_section_size > 0 {
            buffer[data_section_start..data_section_start + data_section_size]
                .copy_from_slice(&data_section_bytes);
        }

        // Write pattern data mappings
        for (i, mapping) in pattern_data_mappings.iter().enumerate() {
            let mapping_offset = mappings_start + i * mapping_entry_size;
            unsafe {
                let ptr = buffer.as_mut_ptr().add(mapping_offset) as *mut PatternDataMapping;
                ptr.write(*mapping);
            }
        }

        // Write AC literal hash table (v3)
        if !ac_hash_bytes.is_empty() {
            buffer[ac_literal_map_start..ac_literal_map_start + ac_literal_map_size]
                .copy_from_slice(&ac_hash_bytes);
        }

        Ok(buffer)
    }
}

/// Buffer storage strategy
enum BufferStorage {
    /// Owned buffer (built from patterns)
    Owned(Vec<u8>),
    /// Borrowed buffer (from mmap)
    Borrowed(&'static [u8]),
}

impl BufferStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            BufferStorage::Owned(vec) => vec.as_slice(),
            BufferStorage::Borrowed(slice) => slice,
        }
    }
}

/// Pattern data mapping metadata for O(1) loading
struct PatternDataMetadata {
    offset: usize,
    count: u32,
}

/// Offset-based Paraglob pattern matcher
///
/// All data stored in a single byte buffer for zero-copy operation.
/// Supports both owned buffers (built from patterns) and borrowed
/// buffers (memory-mapped files).
///
/// Uses memory-mapped hash table for O(1) database loading and O(1) query performance.
///
/// # Security
///
/// By default, pattern strings are validated for UTF-8 correctness on each query.
/// For trusted databases (built by this library), you can use `trusted` mode which
/// skips UTF-8 validation for ~15-20% performance improvement.
///
/// **Only use trusted mode for databases from trusted sources!**
pub struct Paraglob {
    /// Binary buffer containing all data
    buffer: BufferStorage,
    /// Matching mode
    mode: GlobMatchMode,
    /// Whether to trust database and skip UTF-8 validation (faster but unsafe for untrusted DBs)
    trusted: bool,
    /// Compiled glob patterns (cached on first use)
    glob_cache: HashMap<u32, GlobPattern>,
    /// Memory-mapped hash table for AC literal ID to pattern IDs mapping (O(1) lookup)
    ac_literal_hash: Option<crate::ac_literal_hash::ACLiteralHash<'static>>,
    /// Pattern ID to data mapping (lazy-loaded from buffer)
    pattern_data_map: Option<PatternDataMetadata>,
    /// Reusable buffer for candidate patterns (avoids allocation on every query)
    candidate_buffer: HashSet<u32>,
    /// Reusable buffer for AC literal IDs (avoids allocation on every query)
    ac_literal_buffer: HashSet<u32>,
}

impl Paraglob {
    /// Create a new empty Paraglob
    pub fn new() -> Self {
        Self::with_mode(GlobMatchMode::CaseSensitive)
    }

    /// Create with specified match mode
    pub fn with_mode(mode: GlobMatchMode) -> Self {
        Self {
            buffer: BufferStorage::Owned(Vec::new()),
            mode,
            trusted: true, // Databases we build ourselves are trusted
            glob_cache: HashMap::new(),
            ac_literal_hash: None,
            pattern_data_map: None,
            candidate_buffer: HashSet::new(),
            ac_literal_buffer: HashSet::new(),
        }
    }

    /// Build Paraglob from patterns
    pub fn build_from_patterns(
        patterns: &[&str],
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        Self::build_from_patterns_with_data(patterns, None, mode)
    }

    /// Build Paraglob from patterns with associated data (v2 format)
    ///
    /// # Arguments
    /// * `patterns` - Array of pattern strings
    /// * `data` - Optional array of data values (same length as patterns, or None for all)
    /// * `mode` - Match mode (case sensitive/insensitive)
    ///
    /// # Example
    /// ```
    /// use matchy::{Paraglob, data_section::DataValue};
    /// use matchy::glob::MatchMode;
    /// use std::collections::HashMap;
    ///
    /// let patterns = vec!["*.evil.com", "malware.*"];
    /// let mut threat_data = HashMap::new();
    /// threat_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
    ///
    /// let data_values = vec![
    ///     Some(DataValue::Map(threat_data.clone())),
    ///     Some(DataValue::Map(threat_data)),
    /// ];
    ///
    /// let pg = Paraglob::build_from_patterns_with_data(
    ///     &patterns,
    ///     Some(&data_values),
    ///     MatchMode::CaseSensitive
    /// ).unwrap();
    /// ```
    pub fn build_from_patterns_with_data(
        patterns: &[&str],
        data: Option<&[Option<DataValue>]>,
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        let mut builder = ParaglobBuilder::new(mode);

        for (i, pattern) in patterns.iter().enumerate() {
            let pattern_data = data.and_then(|d| d.get(i).and_then(|v| v.clone()));
            builder.add_pattern_with_data(pattern, pattern_data)?;
        }

        builder.build()
    }

    /// Find all matching pattern IDs
    pub fn find_all(&mut self, text: &str) -> Vec<u32> {
        let buffer = self.buffer.as_slice();
        if buffer.is_empty() {
            return Vec::new();
        }

        let (header_ref, _) = match Ref::<_, ParaglobHeader>::from_prefix(buffer) {
            Ok(r) => r,
            Err(_) => return Vec::new(), // Invalid header, return empty
        };
        let header = *header_ref;

        // Phase 1: Use AC automaton to find literal matches and candidate patterns
        let ac_start = header.ac_nodes_offset as usize;
        let ac_size = header.ac_edges_size as usize;

        // Reuse buffers (clear from previous query)
        self.candidate_buffer.clear();
        self.ac_literal_buffer.clear();

        if ac_size > 0 {
            // Extract AC buffer and run AC matching on it
            let ac_buffer = &buffer[ac_start..ac_start + ac_size];

            // Run AC automaton matching directly on text bytes (AC handles case-insensitivity)
            let text_bytes = text.as_bytes();
            let mode = self.mode;
            Self::run_ac_matching_into_static(
                ac_buffer,
                text_bytes,
                mode,
                &mut self.ac_literal_buffer,
            );

            // Map AC literal IDs to pattern IDs using hash table lookup (O(1))
            if !self.ac_literal_buffer.is_empty() {
                if let Some(ref ac_hash) = self.ac_literal_hash {
                    for &literal_id in &self.ac_literal_buffer {
                        let pattern_ids = ac_hash.lookup_slice(literal_id);
                        self.candidate_buffer.extend(pattern_ids);
                    }
                }
            }
        }

        // Phase 2: Verify candidates (or all patterns if no AC)
        let mut matching_ids = Vec::new();

        // CRITICAL: Always check pure wildcards first (patterns with no literals)
        // These must be checked on every query regardless of AC results
        // Wildcards are stored after pattern strings with 8-byte alignment padding
        let unaligned_offset =
            (header.pattern_strings_offset + header.pattern_strings_size) as usize;
        let alignment = 8;
        let padding = (alignment - (unaligned_offset % alignment)) % alignment;
        let wildcards_offset = unaligned_offset + padding;
        let wildcard_count = header.wildcard_count as usize;

        if wildcard_count > 0 {
            for i in 0..wildcard_count {
                let wildcard_offset_val = wildcards_offset + i * mem::size_of::<SingleWildcard>();
                let buffer_slice = match buffer.get(wildcard_offset_val..) {
                    Some(s) => s,
                    None => continue, // Skip corrupted wildcard
                };
                let (wildcard_ref, _) = match Ref::<_, SingleWildcard>::from_prefix(buffer_slice) {
                    Ok(r) => r,
                    Err(_) => continue, // Skip corrupted wildcard
                };
                let wildcard = *wildcard_ref;

                // Look up PatternEntry to get the string length
                let patterns_offset = header.patterns_offset as usize;
                let entry_offset = patterns_offset
                    + (wildcard.pattern_id as usize) * mem::size_of::<PatternEntry>();
                let entry_slice = match buffer.get(entry_offset..) {
                    Some(s) => s,
                    None => continue, // Skip corrupted entry
                };
                let (entry_ref, _) = match Ref::<_, PatternEntry>::from_prefix(entry_slice) {
                    Ok(r) => r,
                    Err(_) => continue, // Skip corrupted entry
                };
                let entry = *entry_ref;

                let pattern_str = if self.trusted {
                    // TRUSTED mode: Skip UTF-8 validation (fast)
                    // SAFETY: We trust the database source to have valid UTF-8
                    unsafe {
                        read_str_unchecked(
                            buffer,
                            entry.pattern_string_offset as usize,
                            entry.pattern_string_length as usize,
                        )
                    }
                } else {
                    // SAFE mode: Validate UTF-8 on untrusted databases
                    match unsafe {
                        read_str_checked(
                            buffer,
                            entry.pattern_string_offset as usize,
                            entry.pattern_string_length as usize,
                        )
                    } {
                        Ok(s) => s,
                        Err(_) => continue, // Skip corrupted pattern
                    }
                };

                // Check glob pattern
                let glob = self
                    .glob_cache
                    .entry(wildcard.pattern_id)
                    .or_insert_with(|| {
                        GlobPattern::new(pattern_str, self.mode).expect("Invalid wildcard pattern")
                    });

                if glob.matches(text) {
                    matching_ids.push(wildcard.pattern_id);
                }
            }
        }

        // Check AC candidates (patterns that have literals that were found)
        for &pattern_id in &self.candidate_buffer {
            let patterns_offset = header.patterns_offset as usize;
            let entry_offset =
                patterns_offset + (pattern_id as usize) * mem::size_of::<PatternEntry>();
            let entry_slice = match buffer.get(entry_offset..) {
                Some(s) => s,
                None => continue, // Skip corrupted pattern
            };
            let entry_ref = match Ref::<_, PatternEntry>::from_prefix(entry_slice) {
                Ok((r, _)) => r,
                Err(_) => continue, // Skip corrupted pattern
            };
            let entry = *entry_ref;

            // Check if pattern matches
            if entry.pattern_type == 0 {
                // Literal pattern - AC automaton already confirmed this matches!
                // No need to read string or verify, just add to results.
                matching_ids.push(entry.pattern_id);
            } else {
                // Glob pattern - need to read pattern string and do glob matching
                let pattern_str = if self.trusted {
                    // TRUSTED mode: Skip UTF-8 validation (fast)
                    // SAFETY: We trust the database source to have valid UTF-8
                    unsafe {
                        read_str_unchecked(
                            buffer,
                            entry.pattern_string_offset as usize,
                            entry.pattern_string_length as usize,
                        )
                    }
                } else {
                    // SAFE mode: Validate UTF-8 on untrusted databases
                    match unsafe {
                        read_str_checked(
                            buffer,
                            entry.pattern_string_offset as usize,
                            entry.pattern_string_length as usize,
                        )
                    } {
                        Ok(s) => s,
                        Err(_) => continue, // Skip corrupted pattern
                    }
                };

                let glob = self.glob_cache.entry(entry.pattern_id).or_insert_with(|| {
                    GlobPattern::new(pattern_str, self.mode).expect("Invalid cached glob pattern")
                });

                if glob.matches(text) {
                    matching_ids.push(entry.pattern_id);
                }
            }
        }

        matching_ids.sort_unstable();
        matching_ids.dedup();
        matching_ids
    }

    /// Run AC automaton matching on the offset-based buffer
    /// Writes AC literal IDs into the provided HashSet (avoids allocation)
    fn run_ac_matching_into_static(
        ac_buffer: &[u8],
        text: &[u8],
        mode: GlobMatchMode,
        matches: &mut HashSet<u32>,
    ) {
        use crate::offset_format::ACNode;

        if ac_buffer.is_empty() || text.is_empty() {
            return;
        }

        let mut current_offset = 0usize; // Start at root node

        for &ch in text.iter() {
            // Normalize character for case-insensitive mode
            let search_ch = match mode {
                GlobMatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
                GlobMatchMode::CaseSensitive => ch,
            };

            // Traverse to next state
            loop {
                // Try to find transition
                if let Some(next_offset) =
                    Self::find_ac_transition(ac_buffer, current_offset, search_ch)
                {
                    current_offset = next_offset;
                    break;
                }

                // Follow failure link
                if current_offset == 0 {
                    break; // At root, stay there
                }

                let node_slice = match ac_buffer.get(current_offset..) {
                    Some(s) => s,
                    None => break,
                };
                let node_ref = match Ref::<_, ACNode>::from_prefix(node_slice) {
                    Ok((r, _)) => r,
                    Err(_) => break,
                };
                let node = *node_ref;
                current_offset = node.failure_offset as usize;

                // Continue loop to try transition from new state
                // Don't break here - we need to retry the transition!
            }

            // Collect pattern IDs at this state
            let node_slice = match ac_buffer.get(current_offset..) {
                Some(s) => s,
                None => continue,
            };
            let node_ref = match Ref::<_, ACNode>::from_prefix(node_slice) {
                Ok((r, _)) => r,
                Err(_) => continue,
            };
            let node = *node_ref;
            if node.pattern_count > 0 {
                // Read pattern IDs with zerocopy (HOT PATH optimization)
                // Pattern IDs are always 4-byte aligned (u32 array follows 8-byte aligned edges section)
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                if patterns_offset + pattern_count * 4 <= ac_buffer.len() {
                    let pattern_slice = &ac_buffer[patterns_offset..];
                    if let Ok((ids_ref, _)) =
                        Ref::<_, [u32]>::from_prefix_with_elems(pattern_slice, pattern_count)
                    {
                        // Zero-copy path - direct slice access (no allocation, no byte parsing)
                        matches.extend(ids_ref.iter().copied());
                    }
                }
            }
        }
    }

    /// Find a transition from a node for a character in AC automaton
    /// Uses state-specific encoding for optimal performance
    fn find_ac_transition(ac_buffer: &[u8], node_offset: usize, ch: u8) -> Option<usize> {
        use crate::offset_format::{ACNode, StateKind};

        let node_slice = ac_buffer.get(node_offset..)?;
        let (node_ref, _) = Ref::<_, ACNode>::from_prefix(node_slice).ok()?;
        let node = *node_ref;

        // Dispatch on state encoding
        let kind = StateKind::from_u8(node.state_kind)?;

        match kind {
            StateKind::Empty => None,

            StateKind::One => {
                // Single inline comparison
                if node.one_char == ch {
                    Some(node.edges_offset as usize)
                } else {
                    None
                }
            }

            StateKind::Sparse => {
                // Linear search through sparse edges
                let edges_offset = node.edges_offset as usize;
                let edge_size = mem::size_of::<ACEdge>();
                let count = node.edge_count as usize;

                for i in 0..count {
                    let edge_offset = edges_offset + i * edge_size;
                    if edge_offset + edge_size > ac_buffer.len() {
                        return None;
                    }

                    let edge_slice = &ac_buffer[edge_offset..];
                    let (edge_ref, _) = Ref::<_, ACEdge>::from_prefix(edge_slice).ok()?;
                    let edge = *edge_ref;

                    if edge.character == ch {
                        return Some(edge.target_offset as usize);
                    }
                    if edge.character > ch {
                        return None;
                    }
                }
                None
            }

            StateKind::Dense => {
                // O(1) lookup in dense table
                let lookup_offset = node.edges_offset as usize;
                let target_offset_offset = lookup_offset + (ch as usize * 4);

                if target_offset_offset + 4 > ac_buffer.len() {
                    return None;
                }

                let target = u32::from_le_bytes([
                    ac_buffer[target_offset_offset],
                    ac_buffer[target_offset_offset + 1],
                    ac_buffer[target_offset_offset + 2],
                    ac_buffer[target_offset_offset + 3],
                ]);

                if target != 0 {
                    Some(target as usize)
                } else {
                    None
                }
            }
        }
    }

    /// Get the buffer (for serialization)
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Load from buffer (for deserialization) - SAFE mode (validates UTF-8)
    ///
    /// Uses ACLiteralHash for O(1) AC literal lookups. Load time is O(1) since
    /// the hash table is already serialized in the buffer.
    ///
    /// Validates UTF-8 on every pattern string read. Use for untrusted databases.
    pub fn from_buffer(buffer: Vec<u8>, mode: GlobMatchMode) -> Result<Self, ParaglobError> {
        Self::from_buffer_with_trust(buffer, mode, false)
    }

    /// Load from buffer (for deserialization) - TRUSTED mode (skips UTF-8 validation)
    ///
    /// **SECURITY WARNING**: Only use for databases from trusted sources!
    /// Skips UTF-8 validation for ~15-20% performance improvement.
    pub fn from_buffer_trusted(
        buffer: Vec<u8>,
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        Self::from_buffer_with_trust(buffer, mode, true)
    }

    /// Load from buffer with explicit trust mode
    fn from_buffer_with_trust(
        buffer: Vec<u8>,
        mode: GlobMatchMode,
        trusted: bool,
    ) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let (header_ref, _) = Ref::<_, ParaglobHeader>::from_prefix(buffer.as_slice())
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        let header = *header_ref;
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;

        // Create AC literal hash table from the buffer
        // This is O(1) - just validates header and stores slice reference
        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_offset = header.ac_literal_map_offset as usize;
            if hash_offset >= buffer.len() {
                return Err(ParaglobError::Validation(format!(
                    "AC literal map offset {} out of bounds (buffer size: {})",
                    hash_offset,
                    buffer.len()
                )));
            }
            let hash_slice = &buffer[hash_offset..];
            // SAFETY: We're extending the lifetime to 'static, which is safe because
            // the buffer is owned by this struct and won't be dropped
            let static_slice: &'static [u8] =
                unsafe { std::slice::from_raw_parts(hash_slice.as_ptr(), hash_slice.len()) };
            Some(crate::ac_literal_hash::ACLiteralHash::from_buffer(
                static_slice,
            )?)
        } else {
            None
        };

        let pattern_data_map = if header.has_data_section() && header.mapping_count > 0 {
            Some(PatternDataMetadata {
                offset: header.mapping_table_offset as usize,
                count: header.mapping_count,
            })
        } else {
            None
        };

        Ok(Self {
            buffer: BufferStorage::Owned(buffer),
            mode,
            trusted,
            glob_cache: HashMap::new(),
            ac_literal_hash,
            pattern_data_map,
            candidate_buffer: HashSet::new(),
            ac_literal_buffer: HashSet::new(),
        })
    }

    /// Load from mmap'd slice (zero-copy) - SAFE mode (validates UTF-8)
    ///
    /// # Safety
    ///
    /// The caller must ensure that the slice remains valid for the lifetime
    /// of this Paraglob instance. Typically used with memory-mapped files.
    ///
    /// This is truly O(1) - only validates header and stores offsets,
    /// no data copying or HashMap building.
    pub unsafe fn from_mmap(
        slice: &'static [u8],
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        Self::from_mmap_with_trust(slice, mode, false)
    }

    /// Load from mmap'd slice (zero-copy) - TRUSTED mode (skips UTF-8 validation)
    ///
    /// **SECURITY WARNING**: Only use for databases from trusted sources!
    /// Skips UTF-8 validation for ~15-20% performance improvement.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the slice remains valid for the lifetime
    /// of this Paraglob instance. Typically used with memory-mapped files.
    pub unsafe fn from_mmap_trusted(
        slice: &'static [u8],
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        Self::from_mmap_with_trust(slice, mode, true)
    }

    /// Load from mmap'd slice with explicit trust mode
    unsafe fn from_mmap_with_trust(
        slice: &'static [u8],
        mode: GlobMatchMode,
        trusted: bool,
    ) -> Result<Self, ParaglobError> {
        if slice.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let (header_ref, _) = Ref::<_, ParaglobHeader>::from_prefix(slice)
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        let header = *header_ref;
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;

        // O(1): Load AC literal hash table from mmap'd buffer
        // This just validates header and stores offsets - no data copying!
        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_offset = header.ac_literal_map_offset as usize;
            if hash_offset >= slice.len() {
                return Err(ParaglobError::Validation(format!(
                    "AC literal map offset {} out of bounds (slice size: {})",
                    hash_offset,
                    slice.len()
                )));
            }
            let hash_slice = &slice[hash_offset..];
            Some(crate::ac_literal_hash::ACLiteralHash::from_buffer(
                hash_slice,
            )?)
        } else {
            None
        };

        // O(1): Just store offset metadata for pattern data
        let pattern_data_map = if header.has_data_section() && header.mapping_count > 0 {
            Some(PatternDataMetadata {
                offset: header.mapping_table_offset as usize,
                count: header.mapping_count,
            })
        } else {
            None
        };

        Ok(Self {
            buffer: BufferStorage::Borrowed(slice),
            mode,
            trusted,
            glob_cache: HashMap::new(),
            ac_literal_hash,
            pattern_data_map,
            candidate_buffer: HashSet::new(),
            ac_literal_buffer: HashSet::new(),
        })
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return 0;
        }

        let (header_ref, _) = match Ref::<_, ParaglobHeader>::from_prefix(buffer) {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let header = *header_ref;
        header.pattern_count as usize
    }

    /// Get data associated with a pattern (v2 feature)
    ///
    /// Returns `None` if the pattern has no associated data or if the file is v1.
    ///
    /// Note: Returns owned DataValue (not reference) for lazy loading from buffer.
    /// Uses binary search through pattern data mapping table.
    pub fn get_pattern_data(&self, pattern_id: u32) -> Option<DataValue> {
        self.find_pattern_data(pattern_id)
    }

    /// Find pattern data by binary search through the mapping table
    ///
    /// Format: [PatternDataMapping { pattern_id: u32, data_offset: u32, size: u32 }]...
    /// Sorted by pattern_id for binary search O(log n).
    fn find_pattern_data(&self, pattern_id: u32) -> Option<DataValue> {
        use crate::data_section::DataDecoder;

        let meta = self.pattern_data_map.as_ref()?;
        let buffer = self.buffer.as_slice();
        let (header_ref, _) = Ref::<_, ParaglobHeader>::from_prefix(buffer).ok()?;
        let header = *header_ref;

        // Get data section bounds
        let data_section_start = header.data_section_offset as usize;
        let data_section_size = header.data_section_size as usize;

        if data_section_start + data_section_size > buffer.len() {
            return None;
        }

        // Binary search through PatternDataMapping array
        let mapping_size = mem::size_of::<PatternDataMapping>();
        let mut left = 0;
        let mut right = meta.count;

        while left < right {
            let mid = left + (right - left) / 2;
            let mapping_offset = meta.offset + (mid as usize * mapping_size);

            if mapping_offset + mapping_size > buffer.len() {
                return None;
            }

            let mapping_slice = buffer.get(mapping_offset..)?;
            let (mapping_ref, _) = Ref::<_, PatternDataMapping>::from_prefix(mapping_slice).ok()?;
            let mapping = *mapping_ref;

            if mapping.pattern_id == pattern_id {
                // Found it! Decode the data
                let data_section =
                    &buffer[data_section_start..data_section_start + data_section_size];
                let decoder = DataDecoder::new(data_section, 0);
                return decoder.decode(mapping.data_offset).ok();
            } else if mapping.pattern_id < pattern_id {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        None
    }

    /// Check if this Paraglob has data section support (v2 format)
    pub fn has_data_section(&self) -> bool {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return false;
        }

        let (header_ref, _) = match Ref::<_, ParaglobHeader>::from_prefix(buffer) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let header = *header_ref;
        header.has_data_section()
    }

    /// Get the version of the Paraglob format
    pub fn version(&self) -> u32 {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return 1;
        }

        let (header_ref, _) = match Ref::<_, ParaglobHeader>::from_prefix(buffer) {
            Ok(r) => r,
            Err(_) => return 1, // Default to v1
        };
        let header = *header_ref;
        header.version
    }

    /// Get pattern string by ID
    pub fn get_pattern(&self, pattern_id: u32) -> Option<String> {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return None;
        }

        let (header_ref, _) = Ref::<_, ParaglobHeader>::from_prefix(buffer).ok()?;
        let header = *header_ref;
        if pattern_id >= header.pattern_count {
            return None;
        }

        let patterns_offset = header.patterns_offset as usize;
        let entry_offset = patterns_offset + (pattern_id as usize) * mem::size_of::<PatternEntry>();
        let entry_slice = buffer.get(entry_offset..)?;
        let (entry_ref, _) = Ref::<_, PatternEntry>::from_prefix(entry_slice).ok()?;
        let entry = *entry_ref;

        unsafe { read_cstring(buffer, entry.pattern_string_offset as usize).ok() }
            .map(|s| s.to_string())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Stats {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return Stats {
                pattern_count: 0,
                node_count: 0,
                edge_count: 0,
                data_section_size: 0,
                mapping_count: 0,
            };
        }

        let (header_ref, _) = match Ref::<_, ParaglobHeader>::from_prefix(buffer) {
            Ok(r) => r,
            Err(_) => {
                // If header read fails, return default stats
                return Stats {
                    pattern_count: 0,
                    node_count: 0,
                    edge_count: 0,
                    data_section_size: 0,
                    mapping_count: 0,
                };
            }
        };
        let header = *header_ref;
        Stats {
            pattern_count: header.pattern_count as usize,
            node_count: header.ac_node_count as usize,
            // AC edges are embedded in nodes, count estimated from size
            edge_count: (header.ac_edges_size as usize) / mem::size_of::<ACEdge>(),
            data_section_size: header.data_section_size as usize,
            mapping_count: header.mapping_count as usize,
        }
    }
}

// Implement Default
impl Default for Paraglob {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple() {
        let patterns = vec!["hello", "world"];
        let pg = Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        assert_eq!(pg.pattern_count(), 2);
        assert!(!pg.buffer().is_empty());
    }

    #[test]
    fn test_literal_matching() {
        let patterns = vec!["hello", "world"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("hello world");
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&0));
        assert!(matches.contains(&1));
    }

    #[test]
    fn test_glob_matching() {
        let patterns = vec!["*.txt", "test_*"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("test_file.txt");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_pure_wildcard() {
        let patterns = vec!["*", "??"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("ab");
        assert_eq!(matches.len(), 2); // Both match
    }

    #[test]
    fn test_case_insensitive() {
        let patterns = vec!["Hello", "*.TXT"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseInsensitive).unwrap();

        let matches = pg.find_all("hello test.txt");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_match() {
        let patterns = vec!["hello", "*.txt"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("goodbye world");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let patterns = vec!["hello", "*.txt", "test_*"];
        let mut pg =
            Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        // Get buffer
        let buffer = pg.buffer().to_vec();

        // Restore from buffer
        let mut pg2 = Paraglob::from_buffer(buffer, GlobMatchMode::CaseSensitive).unwrap();

        // Should produce same results
        let text = "hello test_file.txt";
        assert_eq!(pg.find_all(text), pg2.find_all(text));
    }
}
