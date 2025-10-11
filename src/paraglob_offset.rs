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
    read_cstring, read_struct, ACEdge, ParaglobHeader, PatternDataMapping, PatternEntry,
    SingleWildcard,
};
use std::collections::{HashMap, HashSet};
use std::mem;

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

/// Result type for builder
type BuildResult = (Vec<u8>, HashMap<u32, Vec<u32>>);

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

        // Extract pattern data cache BEFORE consuming self
        let pattern_data_cache: HashMap<u32, DataValue> = self
            .patterns
            .iter()
            .filter_map(|p| p.data().cloned().map(|d| (p.id(), d)))
            .collect();

        let (buffer, ac_literal_to_patterns) = self.build_internal()?;

        Ok(Paraglob {
            buffer: BufferStorage::Owned(buffer),
            mode,
            glob_cache: HashMap::new(),
            ac_literal_to_patterns,
            pattern_data_cache,
        })
    }

    fn build_internal(self) -> Result<BuildResult, ParaglobError> {
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

        // Pattern entries section
        let patterns_start = header_size + ac_size;
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

        // Pure wildcards section (patterns with no literals)
        let pure_wildcards: Vec<&PatternType> = self
            .patterns
            .iter()
            .filter(|p| matches!(p, PatternType::PureWildcard { .. }))
            .collect();

        let wildcards_start = pattern_strings_start + pattern_strings_size;
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

        // Pattern data mappings section (v2)
        let mappings_start = data_section_start + data_section_size;
        let mapping_entry_size = mem::size_of::<PatternDataMapping>();
        let mappings_size = pattern_data_mappings.len() * mapping_entry_size;

        // AC literal mapping section (v3)
        let ac_literal_map_start = mappings_start + mappings_size;
        let ac_literal_map_size = calculate_ac_literal_map_size(&ac_literal_to_patterns);

        // Allocate buffer
        let total_size = header_size
            + ac_size
            + pattern_entries_size
            + pattern_strings_size
            + wildcards_size
            + data_section_size
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
        header.reserved = 0;

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

        // Write AC literal mapping (v3)
        serialize_ac_literal_mapping(&ac_literal_to_patterns, &mut buffer, ac_literal_map_start);

        Ok((buffer, ac_literal_to_patterns))
    }
}

/// Calculate the size needed for AC literal mapping serialization
fn calculate_ac_literal_map_size(ac_literal_to_patterns: &HashMap<u32, Vec<u32>>) -> usize {
    let mut size = 0;
    for pattern_ids in ac_literal_to_patterns.values() {
        size += 4; // literal_id
        size += 4; // pattern_count
        size += pattern_ids.len() * 4; // pattern_ids array
    }
    size
}

/// Calculate AC literal mapping size by reading the buffer
fn calculate_ac_literal_map_size_from_header(
    buffer: &[u8],
    header: &ParaglobHeader,
) -> Result<usize, ParaglobError> {
    let mut size = 0;
    let mut offset = header.ac_literal_map_offset as usize;

    for _ in 0..header.ac_literal_map_count {
        if offset + 8 > buffer.len() {
            return Err(ParaglobError::SerializationError(
                "Truncated AC literal mapping".to_string(),
            ));
        }

        // Skip literal_id
        offset += 4;

        // Read pattern_count
        let pattern_count: u32 = unsafe { read_struct(buffer, offset) };
        offset += 4;

        // Skip pattern_ids
        let patterns_size = pattern_count as usize * 4;
        if offset + patterns_size > buffer.len() {
            return Err(ParaglobError::SerializationError(
                "Truncated AC literal mapping patterns".to_string(),
            ));
        }
        offset += patterns_size;

        size += 4 + 4 + patterns_size; // literal_id + pattern_count + patterns
    }

    Ok(size)
}

/// Serialize AC literal mapping to buffer
fn serialize_ac_literal_mapping(
    ac_literal_to_patterns: &HashMap<u32, Vec<u32>>,
    buffer: &mut [u8],
    start_offset: usize,
) {
    let mut offset = start_offset;

    // Sort keys for deterministic serialization
    let mut sorted_entries: Vec<_> = ac_literal_to_patterns.iter().collect();
    sorted_entries.sort_by_key(|(k, _)| *k);

    for (literal_id, pattern_ids) in sorted_entries {
        // Write literal_id
        unsafe {
            let ptr = buffer.as_mut_ptr().add(offset) as *mut u32;
            ptr.write(*literal_id);
        }
        offset += 4;

        // Write pattern_count
        let pattern_count = pattern_ids.len() as u32;
        unsafe {
            let ptr = buffer.as_mut_ptr().add(offset) as *mut u32;
            ptr.write(pattern_count);
        }
        offset += 4;

        // Write pattern_ids array
        for pattern_id in pattern_ids {
            unsafe {
                let ptr = buffer.as_mut_ptr().add(offset) as *mut u32;
                ptr.write(*pattern_id);
            }
            offset += 4;
        }
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

/// Offset-based Paraglob pattern matcher
///
/// All data stored in a single byte buffer for zero-copy operation.
/// Supports both owned buffers (built from patterns) and borrowed
/// buffers (memory-mapped files).
pub struct Paraglob {
    /// Binary buffer containing all data
    buffer: BufferStorage,
    /// Matching mode
    mode: GlobMatchMode,
    /// Compiled glob patterns (rebuilt from buffer on load)
    glob_cache: HashMap<u32, GlobPattern>,
    /// Mapping from AC literal ID to pattern IDs
    ac_literal_to_patterns: HashMap<u32, Vec<u32>>,
    /// Pattern ID to data mapping (v2 feature)
    pattern_data_cache: HashMap<u32, DataValue>,
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
            glob_cache: HashMap::new(),
            ac_literal_to_patterns: HashMap::new(),
            pattern_data_cache: HashMap::new(),
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

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };

        // Phase 1: Use AC automaton to find literal matches and candidate patterns
        let ac_start = header.ac_nodes_offset as usize;
        let ac_size = header.ac_edges_size as usize;

        let mut candidate_patterns: std::collections::HashSet<u32> =
            std::collections::HashSet::new();

        if ac_size > 0 {
            // Extract AC buffer and run AC matching on it
            let ac_buffer = &buffer[ac_start..ac_start + ac_size];

            // Run AC automaton matching directly on text bytes (AC handles case-insensitivity)
            let text_bytes = text.as_bytes();
            let ac_literal_ids = self.run_ac_matching(ac_buffer, text_bytes);

            // Map AC literal IDs to pattern IDs using our pre-computed mapping
            if !ac_literal_ids.is_empty() {
                for literal_id in ac_literal_ids {
                    if let Some(pattern_ids) = self.ac_literal_to_patterns.get(&literal_id) {
                        candidate_patterns.extend(pattern_ids.iter().copied());
                    }
                }
            }
        }

        // Phase 2: Verify candidates (or all patterns if no AC)
        let mut matching_ids = Vec::new();

        // CRITICAL: Always check pure wildcards first (patterns with no literals)
        // These must be checked on every query regardless of AC results
        // Wildcards are stored right after pattern strings
        let wildcards_offset =
            (header.pattern_strings_offset + header.pattern_strings_size) as usize;
        let wildcard_count = header.wildcard_count as usize;

        if wildcard_count > 0 {
            for i in 0..wildcard_count {
                let wildcard_offset_val = wildcards_offset + i * mem::size_of::<SingleWildcard>();
                let wildcard: SingleWildcard = unsafe { read_struct(buffer, wildcard_offset_val) };

                let pattern_str = unsafe {
                    read_cstring(buffer, wildcard.pattern_string_offset as usize).unwrap_or("")
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
        for &pattern_id in &candidate_patterns {
            let patterns_offset = header.patterns_offset as usize;
            let entry_offset =
                patterns_offset + (pattern_id as usize) * mem::size_of::<PatternEntry>();
            let entry: PatternEntry = unsafe { read_struct(buffer, entry_offset) };

            // Get pattern string
            let pattern_str =
                unsafe { read_cstring(buffer, entry.pattern_string_offset as usize).unwrap_or("") };

            // Check if pattern matches
            if entry.pattern_type == 0 {
                // Literal pattern - simple substring check (avoid allocations)
                let matches = match self.mode {
                    GlobMatchMode::CaseSensitive => text.contains(pattern_str),
                    GlobMatchMode::CaseInsensitive => {
                        // Case-insensitive substring search without allocation
                        text.to_lowercase().contains(&pattern_str.to_lowercase())
                    }
                };

                if matches {
                    matching_ids.push(entry.pattern_id);
                }
            } else {
                // Glob pattern - use glob matching
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
    fn run_ac_matching(&self, ac_buffer: &[u8], text: &[u8]) -> Vec<u32> {
        use crate::offset_format::ACNode;
        use std::collections::HashSet;

        let mut matches = HashSet::new();

        if ac_buffer.is_empty() || text.is_empty() {
            return Vec::new();
        }

        let mut current_offset = 0usize; // Start at root node

        for &ch in text.iter() {
            // Normalize character for case-insensitive mode
            let search_ch = match self.mode {
                GlobMatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
                GlobMatchMode::CaseSensitive => ch,
            };

            // Traverse to next state
            loop {
                // Try to find transition
                if let Some(next_offset) =
                    self.find_ac_transition(ac_buffer, current_offset, search_ch)
                {
                    current_offset = next_offset;
                    break;
                }

                // Follow failure link
                if current_offset == 0 {
                    break; // At root, stay there
                }

                let node: ACNode = unsafe { read_struct(ac_buffer, current_offset) };
                current_offset = node.failure_offset as usize;

                // Continue loop to try transition from new state
                // Don't break here - we need to retry the transition!
            }

            // Collect pattern IDs at this state
            let node: ACNode = unsafe { read_struct(ac_buffer, current_offset) };
            if node.pattern_count > 0 {
                let pattern_ids_slice: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        ac_buffer.as_ptr().add(node.patterns_offset as usize) as *const u32,
                        node.pattern_count as usize,
                    )
                };
                matches.extend(pattern_ids_slice.iter().copied());
            }
        }

        matches.into_iter().collect()
    }

    /// Find a transition from a node for a character in AC automaton
    fn find_ac_transition(&self, ac_buffer: &[u8], node_offset: usize, ch: u8) -> Option<usize> {
        use crate::offset_format::ACNode;

        let node: ACNode = unsafe { read_struct(ac_buffer, node_offset) };

        if node.edge_count == 0 {
            return None;
        }

        let edges: &[ACEdge] = unsafe {
            std::slice::from_raw_parts(
                ac_buffer.as_ptr().add(node.edges_offset as usize) as *const ACEdge,
                node.edge_count as usize,
            )
        };

        // Binary search (edges are sorted by character)
        edges
            .binary_search_by_key(&ch, |edge| edge.character)
            .ok()
            .map(|idx| edges[idx].target_offset as usize)
    }

    /// Get the buffer (for serialization)
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Load from buffer (for deserialization)
    pub fn from_buffer(buffer: Vec<u8>, mode: GlobMatchMode) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let header: ParaglobHeader = unsafe { read_struct(&buffer, 0) };
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;

        // Load ac_literal_to_patterns mapping (O(1) for v3)
        let ac_literal_to_patterns = Self::load_ac_literal_mapping(&buffer, &header)?;

        // Load pattern data cache if has data section
        let pattern_data_cache = if header.has_data_section() {
            Self::load_pattern_data_cache(&buffer, &header)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            buffer: BufferStorage::Owned(buffer),
            mode,
            glob_cache: HashMap::new(),
            ac_literal_to_patterns,
            pattern_data_cache,
        })
    }

    /// Load from mmap'd slice (zero-copy)
    ///
    /// # Safety
    ///
    /// The caller must ensure that the slice remains valid for the lifetime
    /// of this Paraglob instance. Typically used with memory-mapped files.
    pub unsafe fn from_mmap(
        slice: &'static [u8],
        mode: GlobMatchMode,
    ) -> Result<Self, ParaglobError> {
        if slice.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let header: ParaglobHeader = read_struct(slice, 0);
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;

        // Load ac_literal_to_patterns mapping (O(1) for v3)
        let ac_literal_to_patterns = Self::load_ac_literal_mapping(slice, &header)?;

        // Load pattern data cache if has data section
        let pattern_data_cache = if header.has_data_section() {
            Self::load_pattern_data_cache(slice, &header)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            buffer: BufferStorage::Borrowed(slice),
            mode,
            glob_cache: HashMap::new(),
            ac_literal_to_patterns,
            pattern_data_cache,
        })
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return 0;
        }

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };
        header.pattern_count as usize
    }

    /// Get data associated with a pattern (v2 feature)
    ///
    /// Returns `None` if the pattern has no associated data or if the file is v1.
    pub fn get_pattern_data(&self, pattern_id: u32) -> Option<&DataValue> {
        self.pattern_data_cache.get(&pattern_id)
    }

    /// Check if this Paraglob has data section support (v2 format)
    pub fn has_data_section(&self) -> bool {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return false;
        }

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };
        header.has_data_section()
    }

    /// Get the version of the Paraglob format
    pub fn version(&self) -> u32 {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return 1;
        }

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };
        header.version
    }

    /// Get pattern string by ID
    pub fn get_pattern(&self, pattern_id: u32) -> Option<String> {
        let buffer = self.buffer.as_slice();
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return None;
        }

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };
        if pattern_id >= header.pattern_count {
            return None;
        }

        let patterns_offset = header.patterns_offset as usize;
        let entry_offset = patterns_offset + (pattern_id as usize) * mem::size_of::<PatternEntry>();
        let entry: PatternEntry = unsafe { read_struct(buffer, entry_offset) };

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

        let header: ParaglobHeader = unsafe { read_struct(buffer, 0) };
        Stats {
            pattern_count: header.pattern_count as usize,
            node_count: header.ac_node_count as usize,
            // AC edges are embedded in nodes, count estimated from size
            edge_count: (header.ac_edges_size as usize) / mem::size_of::<ACEdge>(),
            data_section_size: header.data_section_size as usize,
            mapping_count: header.mapping_count as usize,
        }
    }

    /// Load AC literal to pattern ID mapping from buffer (v3 format)
    ///
    /// For v3 files, this is a fast O(1) load from the pre-serialized mapping.
    /// The mapping enables instant database loading regardless of pattern count.
    fn load_ac_literal_mapping(
        buffer: &[u8],
        header: &ParaglobHeader,
    ) -> Result<HashMap<u32, Vec<u32>>, ParaglobError> {
        // v3 files must have AC literal mapping
        if !header.has_ac_literal_mapping() {
            return Err(ParaglobError::SerializationError(
                "v3 file missing AC literal mapping".to_string(),
            ));
        }

        let mut map = HashMap::new();
        let mut offset = header.ac_literal_map_offset as usize;
        let end_offset = offset + calculate_ac_literal_map_size_from_header(buffer, header)?;

        if end_offset > buffer.len() {
            return Err(ParaglobError::SerializationError(
                "AC literal mapping extends past buffer end".to_string(),
            ));
        }

        // Read each entry
        for _ in 0..header.ac_literal_map_count {
            if offset + 8 > buffer.len() {
                return Err(ParaglobError::SerializationError(
                    "Truncated AC literal mapping entry".to_string(),
                ));
            }

            // Read literal_id
            let literal_id: u32 = unsafe { read_struct(buffer, offset) };
            offset += 4;

            // Read pattern_count
            let pattern_count: u32 = unsafe { read_struct(buffer, offset) };
            offset += 4;

            // Read pattern_ids array
            if offset + (pattern_count as usize * 4) > buffer.len() {
                return Err(ParaglobError::SerializationError(
                    "Truncated AC literal mapping pattern IDs".to_string(),
                ));
            }

            // Read pattern IDs safely without assuming alignment
            // (offset may not be 4-byte aligned after variable-sized data)
            let mut patterns = Vec::with_capacity(pattern_count as usize);
            for _ in 0..pattern_count {
                let pattern_id: u32 = unsafe { read_struct(buffer, offset) };
                patterns.push(pattern_id);
                offset += 4;
            }

            map.insert(literal_id, patterns);
        }

        Ok(map)
    }

    /// OLD: Reconstruct the AC literal to pattern ID mapping from the buffer
    ///
    /// This is the old O(n) reconstruction method. It's kept here for reference
    /// but should never be called with v3-only support.
    #[allow(dead_code)]
    fn reconstruct_literal_mapping(
        buffer: &[u8],
        header: &ParaglobHeader,
    ) -> Result<HashMap<u32, Vec<u32>>, ParaglobError> {
        let mut mapping: HashMap<u32, Vec<u32>> = HashMap::new();

        // Extract all literals from all patterns, building the mapping as we go
        let mut all_literals = Vec::new();
        let mut literal_to_patterns: HashMap<String, Vec<u32>> = HashMap::new();

        let patterns_offset = header.patterns_offset as usize;
        let pattern_count = header.pattern_count as usize;

        for i in 0..pattern_count {
            let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();
            let entry: PatternEntry = unsafe { read_struct(buffer, entry_offset) };

            let pattern_str = unsafe {
                read_cstring(buffer, entry.pattern_string_offset as usize).map_err(|e| {
                    ParaglobError::SerializationError(format!(
                        "Failed to read pattern string: {}",
                        e
                    ))
                })?
            };

            // Extract literals based on pattern type
            let literals = if entry.pattern_type == 0 {
                // Literal pattern - the whole string is the literal
                vec![pattern_str.to_string()]
            } else {
                // Glob pattern - extract literals from it
                PatternType::extract_literals(pattern_str)
            };

            // Add to mapping
            for lit in literals {
                // Check if this is a new literal
                if !all_literals.contains(&lit) {
                    all_literals.push(lit.clone());
                }

                literal_to_patterns
                    .entry(lit.clone())
                    .or_default()
                    .push(entry.pattern_id);
            }
        }

        // Now build the mapping from AC literal ID (index in all_literals) to pattern IDs
        for (literal_id, literal_str) in all_literals.iter().enumerate() {
            if let Some(pattern_ids) = literal_to_patterns.get(literal_str) {
                mapping.insert(literal_id as u32, pattern_ids.clone());
            }
        }

        Ok(mapping)
    }

    /// Load pattern data cache from buffer (v2 format)
    fn load_pattern_data_cache(
        buffer: &[u8],
        header: &ParaglobHeader,
    ) -> Result<HashMap<u32, DataValue>, ParaglobError> {
        use crate::data_section::DataDecoder;

        let mut cache = HashMap::new();

        if header.mapping_count == 0 {
            return Ok(cache);
        }

        // Get data section and mapping table
        let data_section_start = header.data_section_offset as usize;
        let data_section_size = header.data_section_size as usize;
        let mappings_start = header.mapping_table_offset as usize;
        let mapping_count = header.mapping_count as usize;

        if data_section_start + data_section_size > buffer.len() {
            return Err(ParaglobError::SerializationError(
                "Data section out of bounds".to_string(),
            ));
        }

        // Create decoder
        let data_section = &buffer[data_section_start..data_section_start + data_section_size];
        let decoder = DataDecoder::new(data_section, 0);

        // Load each mapping
        for i in 0..mapping_count {
            let mapping_offset = mappings_start + i * mem::size_of::<PatternDataMapping>();
            if mapping_offset + mem::size_of::<PatternDataMapping>() > buffer.len() {
                return Err(ParaglobError::SerializationError(
                    "Mapping table out of bounds".to_string(),
                ));
            }

            let mapping: PatternDataMapping = unsafe { read_struct(buffer, mapping_offset) };

            // Decode the data
            let data_value = decoder.decode(mapping.data_offset).map_err(|e| {
                ParaglobError::SerializationError(format!("Failed to decode data: {}", e))
            })?;

            cache.insert(mapping.pattern_id, data_value);
        }

        Ok(cache)
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
