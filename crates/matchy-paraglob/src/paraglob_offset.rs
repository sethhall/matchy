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

use crate::error::ParaglobError;
use crate::glob::{CharClassItem, GlobPattern, GlobSegment};
use crate::offset_format::{
    read_cstring, ACEdge, GlobSegmentIndex, ParaglobHeader, PatternDataMapping, PatternEntry,
    SingleWildcard,
};
use matchy_ac::ACAutomaton;
use matchy_data_format::{DataEncoder, DataValue};
use matchy_match_mode::MatchMode;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::mem;
use std::thread_local;
use zerocopy::Ref;

const MIN_GLOB_ANCHOR_LITERAL_LEN: usize = 3;

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
            Self::Literal { id, .. } | Self::Glob { id, .. } | Self::PureWildcard { id, .. } => *id,
        }
    }

    fn pattern(&self) -> &str {
        match self {
            Self::Literal { text, .. } => text,
            Self::Glob { pattern, .. } | Self::PureWildcard { pattern, .. } => pattern,
        }
    }

    fn data(&self) -> Option<&DataValue> {
        match self {
            Self::Literal { data, .. }
            | Self::Glob { data, .. }
            | Self::PureWildcard { data, .. } => data.as_ref(),
        }
    }
}

fn select_glob_anchor_literal(literals: &[String]) -> Option<&String> {
    let mut selected: Option<(usize, &String)> = None;

    for (index, literal) in literals.iter().enumerate() {
        if literal.len() < MIN_GLOB_ANCHOR_LITERAL_LEN {
            continue;
        }

        match selected {
            Some((best_index, best_literal))
                if best_literal.len() > literal.len()
                    || (best_literal.len() == literal.len() && best_index > index) => {}
            _ => selected = Some((index, literal)),
        }
    }

    selected.map(|(_, literal)| literal)
}

/// Incremental builder for constructing Paraglob pattern matchers
///
/// This builder allows you to add patterns one at a time before
/// building the final Paraglob instance.
///
/// # Example
/// ```
/// use matchy_paraglob::ParaglobBuilder;
/// use matchy_data_format::DataValue;
/// use matchy_match_mode::MatchMode;
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
/// let pg = builder.build().unwrap();
/// let matches = pg.find_all("test_file.txt");
/// assert!(!matches.is_empty());
/// ```
pub struct ParaglobBuilder {
    patterns: Vec<PatternType>,
    mode: MatchMode,
    pattern_set: std::collections::HashSet<String>,
}

impl ParaglobBuilder {
    /// Create a new builder with the specified match mode
    ///
    /// # Arguments
    /// * `mode` - Case sensitivity mode for pattern matching
    #[must_use]
    pub fn new(mode: MatchMode) -> Self {
        Self {
            patterns: Vec::new(),
            mode,
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
    /// use matchy_paraglob::ParaglobBuilder;
    /// use matchy_data_format::DataValue;
    /// use matchy_match_mode::MatchMode;
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
    /// assert_eq!(pattern_id, 0);
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

        let id = u32::try_from(self.patterns.len()).map_err(|_| {
            ParaglobError::InvalidPattern("Pattern count exceeds u32::MAX".to_string())
        })?;
        let pat_type = PatternType::new_with_data(pattern, id, data)?;
        self.pattern_set.insert(pattern.to_string());
        self.patterns.push(pat_type);
        Ok(id)
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
        let mode = self.mode;
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
            Some(crate::literal_hash::ACLiteralHash::from_buffer(
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
            ac_literal_hash,
            pattern_data_map,
        })
    }

    /// Serialize glob segments for a single pattern
    fn serialize_glob_segments(
        pattern_str: &str,
        mode: MatchMode,
    ) -> Result<Vec<GlobSegment>, ParaglobError> {
        // Use GlobPattern::new() which calls parse internally
        let pattern = GlobPattern::new(pattern_str, mode)?;
        Ok(pattern.segments().to_vec())
    }

    /// Build serialized glob segment data
    /// Returns (segment_indices, segment_data, total_size, header_count)
    fn build_glob_segment_section(
        patterns: &[PatternType],
        mode: MatchMode,
    ) -> Result<(Vec<GlobSegmentIndex>, Vec<u8>, usize, usize), ParaglobError> {
        use crate::offset_format::{CharClassItemEncoded, GlobSegmentHeader, GlobSegmentIndex};

        let mut indices = Vec::with_capacity(patterns.len());
        let mut segment_headers = Vec::new();
        let mut string_data = Vec::new();
        let mut char_class_data = Vec::new();

        // Process each pattern
        for pat in patterns {
            let pattern_str = pat.pattern();
            let segments = Self::serialize_glob_segments(pattern_str, mode)?;

            let first_segment_offset_placeholder = segment_headers.len();
            let segment_count = u16::try_from(segments.len()).map_err(|_| {
                ParaglobError::InvalidPattern("Segment count exceeds u16::MAX".into())
            })?;

            // Process each segment
            for segment in segments {
                match segment {
                    GlobSegment::Literal(s) => {
                        let data_offset = string_data.len();
                        string_data.extend_from_slice(s.as_bytes());

                        segment_headers.push(GlobSegmentHeader {
                            segment_type: 0,
                            flags: 0,
                            reserved: 0,
                            data_len: u32::try_from(s.len()).unwrap_or(u32::MAX),
                            data_offset: u32::try_from(data_offset).unwrap_or(u32::MAX),
                        });
                    }
                    GlobSegment::Star => {
                        segment_headers.push(GlobSegmentHeader {
                            segment_type: 1,
                            flags: 0,
                            reserved: 0,
                            data_len: 0,
                            data_offset: 0,
                        });
                    }
                    GlobSegment::Question => {
                        segment_headers.push(GlobSegmentHeader {
                            segment_type: 2,
                            flags: 0,
                            reserved: 0,
                            data_len: 0,
                            data_offset: 0,
                        });
                    }
                    GlobSegment::CharClass { chars, negated } => {
                        let data_offset = char_class_data.len();
                        let char_count = chars.len();

                        for item in chars {
                            let encoded = match item {
                                CharClassItem::Char(c) => CharClassItemEncoded {
                                    item_type: 0,
                                    reserved: [0; 3],
                                    char1: c as u32,
                                    char2: 0,
                                },
                                CharClassItem::Range(start, end) => CharClassItemEncoded {
                                    item_type: 1,
                                    reserved: [0; 3],
                                    char1: start as u32,
                                    char2: end as u32,
                                },
                            };
                            // Serialize to bytes
                            char_class_data.push(encoded.item_type);
                            char_class_data.extend_from_slice(&encoded.reserved);
                            char_class_data.extend_from_slice(&encoded.char1.to_le_bytes());
                            char_class_data.extend_from_slice(&encoded.char2.to_le_bytes());
                        }

                        segment_headers.push(GlobSegmentHeader {
                            segment_type: 3,
                            flags: if negated { 1 } else { 0 },
                            reserved: 0,
                            data_len: u32::try_from(
                                char_count * mem::size_of::<CharClassItemEncoded>(),
                            )
                            .unwrap_or(u32::MAX),
                            data_offset: u32::try_from(data_offset).unwrap_or(u32::MAX),
                        });
                    }
                }
            }

            indices.push(GlobSegmentIndex {
                first_segment_offset: u32::try_from(first_segment_offset_placeholder)
                    .unwrap_or(u32::MAX),
                segment_count,
                reserved: 0,
            });
        }

        // Now build the final buffer with proper offsets
        // Layout: [GlobSegmentIndex array] [GlobSegmentHeader array] [string data] [char class data]
        let index_size = indices.len() * mem::size_of::<GlobSegmentIndex>();
        let header_count = segment_headers.len(); // Save before consuming vector
        let headers_size = segment_headers.len() * mem::size_of::<GlobSegmentHeader>();
        let strings_size = string_data.len();
        let char_classes_size = char_class_data.len();

        let total_size = index_size + headers_size + strings_size + char_classes_size;

        let headers_offset = index_size;
        let strings_offset = headers_offset + headers_size;
        let char_classes_offset = strings_offset + strings_size;

        // Adjust offsets in segment headers
        let mut segment_data = Vec::with_capacity(headers_size + strings_size + char_classes_size);

        // Write segment headers with adjusted offsets
        for header in segment_headers {
            let adjusted_header = GlobSegmentHeader {
                segment_type: header.segment_type,
                flags: header.flags,
                reserved: header.reserved,
                data_len: header.data_len,
                data_offset: if header.data_len > 0 {
                    match header.segment_type {
                        0 => u32::try_from(strings_offset).unwrap_or(0) + header.data_offset,
                        3 => u32::try_from(char_classes_offset).unwrap_or(0) + header.data_offset,
                        _ => 0,
                    }
                } else {
                    0
                },
            };

            // Serialize header to bytes (12 bytes per header, no padding)
            segment_data.push(adjusted_header.segment_type);
            segment_data.push(adjusted_header.flags);
            segment_data.extend_from_slice(&adjusted_header.reserved.to_le_bytes());
            segment_data.extend_from_slice(&adjusted_header.data_len.to_le_bytes());
            segment_data.extend_from_slice(&adjusted_header.data_offset.to_le_bytes());
        }

        // Append string data
        segment_data.extend_from_slice(&string_data);

        // Append char class data
        segment_data.extend_from_slice(&char_class_data);

        // Adjust first_segment_offset in indices
        for index in indices.iter_mut() {
            // Calculate actual offset: base + (segment index * sizeof(header))
            let segment_idx = usize::try_from(index.first_segment_offset).unwrap_or(0);
            index.first_segment_offset =
                u32::try_from(headers_offset + segment_idx * mem::size_of::<GlobSegmentHeader>())
                    .unwrap_or(u32::MAX);
        }

        Ok((indices, segment_data, total_size, header_count))
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
                    if let Some(lit) = select_glob_anchor_literal(literals) {
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

        // Build AC automaton and get node count
        let (ac_automaton, ac_node_count) = if ac_literals.is_empty() {
            (ACAutomaton::new(self.mode), 0)
        } else {
            let ac_refs: Vec<&str> = ac_literals
                .iter()
                .map(std::string::String::as_str)
                .collect();
            let automaton = ACAutomaton::build(&ac_refs, self.mode)?;
            let node_count = automaton.node_count();
            (automaton, node_count)
        };

        // Build mapping from AC literal ID to pattern IDs
        // AC assigns IDs 0, 1, 2... to literals in the order they were added
        let mut ac_literal_to_patterns = HashMap::new();
        for (literal_id, literal_str) in ac_literals.iter().enumerate() {
            if let Some(pattern_ids) = literal_to_patterns.get(literal_str) {
                if let Ok(lid) = u32::try_from(literal_id) {
                    ac_literal_to_patterns.insert(lid, pattern_ids.clone());
                }
            }
        }

        // Calculate sizes
        let header_size = mem::size_of::<ParaglobHeader>();
        let ac_buffer = ac_automaton.buffer();
        let ac_size = ac_buffer.len();

        // Add padding after header to align AC buffer to cache-line boundary
        // This ensures dense lookup tables maintain their 64-byte alignment for optimal cache performance
        let ac_alignment = 64; // Cache-line alignment for dense lookups
        let ac_padding = (ac_alignment - (header_size % ac_alignment)) % ac_alignment;
        let ac_start = header_size + ac_padding;

        // Add padding after AC section to ensure pattern entries are 8-byte aligned
        let unaligned_patterns_start = ac_start + ac_size;
        let alignment = 8; // PatternEntry needs 8-byte alignment (16 bytes, 8-byte fields)
        let ac_padding_patterns = (alignment - (unaligned_patterns_start % alignment)) % alignment;

        // Pattern entries section
        let patterns_start = unaligned_patterns_start + ac_padding_patterns;
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
        let mut ac_hash_builder = crate::literal_hash::ACLiteralHashBuilder::new();
        for (literal_id, pattern_ids) in &ac_literal_to_patterns {
            ac_hash_builder.add_mapping(*literal_id, pattern_ids.clone());
        }
        let ac_hash_bytes = ac_hash_builder.build();
        let ac_literal_map_size = ac_hash_bytes.len();

        // Glob segments section (v5) - pre-serialize all glob patterns
        let (glob_indices, glob_segment_data, _glob_segments_total_size, segment_header_count) =
            Self::build_glob_segment_section(&self.patterns, self.mode)?;

        // Add padding after AC literal map to ensure glob segments are 8-byte aligned
        let unaligned_glob_start = ac_literal_map_start + ac_literal_map_size;
        let glob_alignment = 8; // GlobSegmentIndex requires 8-byte alignment
        let glob_padding =
            (glob_alignment - (unaligned_glob_start % glob_alignment)) % glob_alignment;

        let glob_segments_start = unaligned_glob_start + glob_padding;
        let glob_index_size =
            glob_indices.len() * mem::size_of::<crate::offset_format::GlobSegmentIndex>();
        let glob_segments_size = glob_index_size + glob_segment_data.len();

        // Allocate buffer (including padding for alignment)
        let total_size = header_size
            + ac_padding  // Cache-line alignment padding before AC buffer
            + ac_size
            + ac_padding_patterns  // Alignment padding before pattern entries
            + pattern_entries_size
            + pattern_strings_size
            + padding  // Alignment padding before wildcards
            + wildcards_size
            + data_section_size
            + data_padding  // Alignment padding before mapping table
            + mappings_size
            + ac_literal_map_size
            + glob_padding  // Alignment padding before glob segments
            + glob_segments_size;
        let mut buffer = vec![0u8; total_size];

        // Write header (v2 if we have data, v1 otherwise)
        let mut header = ParaglobHeader::new();
        header.match_mode = match self.mode {
            MatchMode::CaseSensitive => 0,
            MatchMode::CaseInsensitive => 1,
        };
        header.ac_node_count = u32::try_from(ac_node_count).unwrap_or(u32::MAX);
        header.ac_nodes_offset = u32::try_from(ac_start).unwrap_or(u32::MAX);
        header.ac_edges_size = u32::try_from(ac_size).unwrap_or(u32::MAX);
        header.pattern_count = u32::try_from(self.patterns.len()).unwrap_or(u32::MAX);
        header.patterns_offset = u32::try_from(patterns_start).unwrap_or(u32::MAX);
        header.pattern_strings_offset = u32::try_from(pattern_strings_start).unwrap_or(u32::MAX);
        header.pattern_strings_size = u32::try_from(pattern_strings_size).unwrap_or(u32::MAX);
        header.wildcard_count = u32::try_from(pure_wildcards.len()).unwrap_or(u32::MAX);
        header.total_buffer_size = u32::try_from(total_size).unwrap_or(u32::MAX);
        // header.reserved is already initialized to [0; 3] in new()

        // v2 fields (if we have data)
        if data_section_size > 0 {
            header.data_section_offset = u32::try_from(data_section_start).unwrap_or(u32::MAX);
            header.data_section_size = u32::try_from(data_section_size).unwrap_or(u32::MAX);
            header.mapping_table_offset = u32::try_from(mappings_start).unwrap_or(u32::MAX);
            header.mapping_count = u32::try_from(pattern_data_mappings.len()).unwrap_or(u32::MAX);
            header.data_flags = 0x1; // Inline data flag
        }

        // v3 fields (AC literal mapping - always present)
        header.ac_literal_map_offset = u32::try_from(ac_literal_map_start).unwrap_or(u32::MAX);
        header.ac_literal_map_count =
            u32::try_from(ac_literal_to_patterns.len()).unwrap_or(u32::MAX);

        // v5 fields (glob segments - always present)
        header.glob_segments_offset = u32::try_from(glob_segments_start).unwrap_or(u32::MAX);
        header.glob_segments_size = u32::try_from(glob_segments_size).unwrap_or(u32::MAX);

        // SAFETY: buffer is freshly allocated with correct size, ptr is aligned for ParaglobHeader
        unsafe {
            let ptr = buffer.as_mut_ptr().cast::<ParaglobHeader>();
            ptr.write(header);
        }

        // Write AC automaton data at aligned offset
        buffer[ac_start..ac_start + ac_size].copy_from_slice(ac_buffer);

        // Padding bytes after AC automaton are already zero-initialized

        // Write pattern entries
        for (i, pat) in self.patterns.iter().enumerate() {
            let entry_offset = patterns_start + i * pattern_entry_size;
            let string_offset = u32::try_from(pattern_strings_start + pattern_string_offsets[i])
                .unwrap_or(u32::MAX);

            let pattern_type = match pat {
                PatternType::Literal { .. } => 0u8,
                PatternType::Glob { .. } | PatternType::PureWildcard { .. } => 1u8,
            };

            let mut entry = PatternEntry::new(pat.id(), pattern_type);
            entry.pattern_string_offset = string_offset;
            entry.pattern_string_length = u32::try_from(pat.pattern().len()).unwrap_or(u32::MAX);

            // SAFETY: entry_offset is within buffer bounds, PatternEntry is repr(C)
            unsafe {
                let ptr = buffer.as_mut_ptr().add(entry_offset).cast::<PatternEntry>();
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
            let pat_id_usize = usize::try_from(pat.id()).unwrap_or(0);
            let string_offset = pattern_strings_start + pattern_string_offsets[pat_id_usize];

            let wildcard = SingleWildcard {
                pattern_id: pat.id(),
                pattern_string_offset: u32::try_from(string_offset).unwrap_or(u32::MAX),
            };

            // SAFETY: wildcard_offset is within buffer bounds, SingleWildcard is repr(C)
            unsafe {
                let ptr = buffer
                    .as_mut_ptr()
                    .add(wildcard_offset)
                    .cast::<SingleWildcard>();
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
            // SAFETY: mapping_offset is within buffer bounds, PatternDataMapping is repr(C)
            unsafe {
                let ptr = buffer
                    .as_mut_ptr()
                    .add(mapping_offset)
                    .cast::<PatternDataMapping>();
                ptr.write(*mapping);
            }
        }

        // Write AC literal hash table (v3)
        if !ac_hash_bytes.is_empty() {
            buffer[ac_literal_map_start..ac_literal_map_start + ac_literal_map_size]
                .copy_from_slice(&ac_hash_bytes);
        }

        // Write glob segments section (v5)
        // First write the GlobSegmentIndex array
        let glob_index_end = glob_segments_start + glob_index_size;
        for (i, index) in glob_indices.iter().enumerate() {
            let index_offset =
                glob_segments_start + i * mem::size_of::<crate::offset_format::GlobSegmentIndex>();
            // Adjust offsets to be relative to buffer start
            let adjusted_index = crate::offset_format::GlobSegmentIndex {
                first_segment_offset: u32::try_from(glob_segments_start).unwrap_or(0)
                    + index.first_segment_offset,
                segment_count: index.segment_count,
                reserved: index.reserved,
            };
            // SAFETY: index_offset is within buffer bounds, GlobSegmentIndex is repr(C)
            unsafe {
                let ptr = buffer
                    .as_mut_ptr()
                    .add(index_offset)
                    .cast::<crate::offset_format::GlobSegmentIndex>();
                ptr.write(adjusted_index);
            }
        }

        // Then write the segment data (headers + strings + char classes)
        // Note: We need to adjust data_offset fields in segment headers to be relative to buffer start
        let mut adjusted_segment_data = glob_segment_data.clone();

        // Iterate through segment headers and adjust their data_offset fields
        for i in 0..segment_header_count {
            let header_offset_in_data =
                i * mem::size_of::<crate::offset_format::GlobSegmentHeader>();
            if header_offset_in_data + mem::size_of::<crate::offset_format::GlobSegmentHeader>()
                <= adjusted_segment_data.len()
            {
                // Read header
                let header_slice = &adjusted_segment_data[header_offset_in_data..];
                if let Ok((header_ref, _)) = zerocopy::Ref::<
                    _,
                    crate::offset_format::GlobSegmentHeader,
                >::from_prefix(header_slice)
                {
                    let mut header = *header_ref;

                    // Adjust data_offset to be relative to buffer start
                    // Note: offsets in segment_data include index_size, but indices are written
                    // separately, so we need to subtract index_size then add glob_index_end
                    if header.data_len > 0 && header.data_offset > 0 {
                        let idx_size = u32::try_from(glob_index_size).unwrap_or(0);
                        let idx_end = u32::try_from(glob_index_end).unwrap_or(0);
                        header.data_offset = header.data_offset - idx_size + idx_end;
                    }

                    // SAFETY: header_offset_in_data is bounds-checked above, GlobSegmentHeader is repr(C)
                    unsafe {
                        let ptr = adjusted_segment_data
                            .as_mut_ptr()
                            .add(header_offset_in_data)
                            .cast::<crate::offset_format::GlobSegmentHeader>();
                        ptr.write(header);
                    }
                }
            }
        }

        buffer[glob_index_end..glob_index_end + adjusted_segment_data.len()]
            .copy_from_slice(&adjusted_segment_data);

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
            Self::Owned(vec) => vec.as_slice(),
            Self::Borrowed(slice) => slice,
        }
    }
}

/// Pattern data mapping metadata for O(1) loading
#[derive(Clone, Copy)]
struct PatternDataMetadata {
    offset: usize,
    count: u32,
}

enum GlobCandidateCheck {
    Simple(bool),
    FullVerification,
    NoMatch,
}

struct FixedWindowShape {
    start_seg_idx: usize,
    end_seg_idx: usize,
    has_leading_star: bool,
    has_trailing_star: bool,
}

/// Lookup counters used by the `bench-diagnostics` feature.
#[cfg(feature = "bench-diagnostics")]
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LookupDiagnostics {
    /// Number of query bytes scanned by the lookup.
    pub query_bytes_scanned: usize,
    /// Number of unique AC literal IDs found in the query.
    pub ac_literal_hits: usize,
    /// Number of candidate pattern IDs emitted before deduplication.
    pub raw_candidate_pattern_ids: usize,
    /// Number of unique pattern IDs selected for candidate checking.
    pub candidate_pattern_ids: usize,
    /// Number of pure wildcard patterns checked for the query.
    pub pure_wildcard_checks: usize,
    /// Number of serialized glob verification attempts.
    pub glob_verification_attempts: usize,
    /// Number of serialized glob verification attempts that matched.
    pub successful_glob_verifications: usize,
    /// Number of literal-order prechecks run before glob verification.
    pub literal_order_precheck_attempts: usize,
    /// Number of serialized glob segment matcher steps.
    pub serialized_glob_segment_steps: usize,
    /// Number of star wildcard backtracking attempts.
    pub star_backtracking_attempts: usize,
}

#[cfg(feature = "bench-diagnostics")]
impl LookupDiagnostics {
    const fn empty() -> Self {
        Self {
            query_bytes_scanned: 0,
            ac_literal_hits: 0,
            raw_candidate_pattern_ids: 0,
            candidate_pattern_ids: 0,
            pure_wildcard_checks: 0,
            glob_verification_attempts: 0,
            successful_glob_verifications: 0,
            literal_order_precheck_attempts: 0,
            serialized_glob_segment_steps: 0,
            star_backtracking_attempts: 0,
        }
    }
}

// Thread-local scratch buffers for zero-allocation queries
// These are reused across queries within each thread
thread_local! {
    static CANDIDATE_BUFFER: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static AC_LITERAL_BUFFER: RefCell<HashSet<u32>> = RefCell::new(HashSet::new());
    static RESULT_BUFFER: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static NORMALIZED_TEXT_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    #[cfg(feature = "bench-diagnostics")]
    static LOOKUP_DIAGNOSTICS: RefCell<LookupDiagnostics> = const { RefCell::new(LookupDiagnostics::empty()) };
    #[cfg(feature = "bench-diagnostics")]
    static LOOKUP_DIAGNOSTICS_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
/// All string operations are validated for UTF-8 correctness.
pub struct Paraglob {
    /// Binary buffer containing all data
    buffer: BufferStorage,
    /// Matching mode (public for Database::mode() access)
    pub(crate) mode: MatchMode,
    /// Memory-mapped hash table for AC literal ID to pattern IDs mapping (O(1) lookup)
    ac_literal_hash: Option<crate::literal_hash::ACLiteralHash<'static>>,
    /// Pattern ID to data mapping (lazy-loaded from buffer)
    pattern_data_map: Option<PatternDataMetadata>,
}

// SAFETY: Paraglob is Send + Sync because:
// - buffer: Both Owned(Vec<u8>) and Borrowed(&'static [u8]) are Send + Sync
// - mode: MatchMode is Copy, thus Send + Sync
// - ac_literal_hash: Contains only offsets and immutable references, Send + Sync
// - pattern_data_map: Contains only offsets, Send + Sync
// - All scratch buffers moved to thread-local storage
unsafe impl Send for Paraglob {}
// SAFETY: See above
unsafe impl Sync for Paraglob {}

impl Paraglob {
    #[cfg(feature = "bench-diagnostics")]
    fn begin_lookup_diagnostics(query_bytes_scanned: usize) {
        LOOKUP_DIAGNOSTICS.with(|diagnostics| {
            let mut diagnostics = diagnostics.borrow_mut();
            *diagnostics = LookupDiagnostics::empty();
            diagnostics.query_bytes_scanned = query_bytes_scanned;
        });
        LOOKUP_DIAGNOSTICS_ACTIVE.with(|active| active.set(true));
    }

    #[cfg(feature = "bench-diagnostics")]
    fn finish_lookup_diagnostics() -> LookupDiagnostics {
        let diagnostics = LOOKUP_DIAGNOSTICS.with(|diagnostics| diagnostics.borrow().clone());
        LOOKUP_DIAGNOSTICS_ACTIVE.with(|active| active.set(false));
        diagnostics
    }

    #[cfg(feature = "bench-diagnostics")]
    fn record_lookup_diagnostic(update: impl FnOnce(&mut LookupDiagnostics)) {
        LOOKUP_DIAGNOSTICS_ACTIVE.with(|active| {
            if active.get() {
                LOOKUP_DIAGNOSTICS.with(|diagnostics| {
                    update(&mut diagnostics.borrow_mut());
                });
            }
        });
    }

    /// Create a new empty Paraglob
    #[must_use]
    pub fn new() -> Self {
        Self::with_mode(MatchMode::CaseSensitive)
    }

    /// Create with specified match mode
    #[must_use]
    pub fn with_mode(mode: MatchMode) -> Self {
        Self {
            buffer: BufferStorage::Owned(Vec::new()),
            mode,
            ac_literal_hash: None,
            pattern_data_map: None,
        }
    }

    /// Get the match mode
    #[must_use]
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Build Paraglob from patterns
    pub fn build_from_patterns(patterns: &[&str], mode: MatchMode) -> Result<Self, ParaglobError> {
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
    /// use matchy_paraglob::Paraglob;
    /// use matchy_data_format::DataValue;
    /// use matchy_match_mode::MatchMode;
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
    /// assert_eq!(pg.pattern_count(), 2);
    /// ```
    pub fn build_from_patterns_with_data(
        patterns: &[&str],
        data: Option<&[Option<DataValue>]>,
        mode: MatchMode,
    ) -> Result<Self, ParaglobError> {
        let mut builder = ParaglobBuilder::new(mode);

        for (i, pattern) in patterns.iter().enumerate() {
            let pattern_data = data.and_then(|d| d.get(i).and_then(std::clone::Clone::clone));
            builder.add_pattern_with_data(pattern, pattern_data)?;
        }

        builder.build()
    }

    /// Find all matching pattern IDs and return lookup diagnostics.
    ///
    /// This API is available only with the `bench-diagnostics` feature and is
    /// intended for benchmarks and profiling. Normal lookup behavior is unchanged.
    #[cfg(feature = "bench-diagnostics")]
    #[doc(hidden)]
    #[must_use]
    pub fn find_all_with_diagnostics(&self, text: &str) -> (Vec<u32>, LookupDiagnostics) {
        Self::begin_lookup_diagnostics(text.len());
        let matches = self.find_all(text);
        let diagnostics = Self::finish_lookup_diagnostics();
        (matches, diagnostics)
    }

    /// Visit matching pattern IDs without allocating an owned result vector.
    ///
    /// Matches are visited before sorting or deduplication. Callers that need the
    /// same ordering as [`find_all`](Self::find_all) should collect, sort, and
    /// deduplicate the visited IDs.
    fn visit_matches_unsorted(&self, text: &str, mut visit: impl FnMut(u32)) {
        let buffer = self.buffer.as_slice();
        if buffer.is_empty() {
            return;
        }

        // SAFETY: Fast path - header is at offset 0, always aligned
        let header = unsafe {
            if buffer.len() < mem::size_of::<ParaglobHeader>() {
                return;
            }
            let ptr = buffer.as_ptr().cast::<ParaglobHeader>();
            ptr.read()
        };

        // Phase 1: Use AC automaton to find literal matches and candidate patterns
        let ac_start = header.ac_nodes_offset as usize;
        let ac_size = header.ac_edges_size as usize;

        // Reuse thread-local buffers (clear from previous query)
        CANDIDATE_BUFFER.with(|buf| buf.borrow_mut().clear());
        AC_LITERAL_BUFFER.with(|buf| buf.borrow_mut().clear());

        if ac_size > 0 {
            // Extract AC buffer and run AC matching on it
            let ac_buffer = &buffer[ac_start..ac_start + ac_size];

            // Run AC automaton matching directly on text bytes (AC handles case-insensitivity)
            let text_bytes = text.as_bytes();
            let mode = self.mode;
            AC_LITERAL_BUFFER.with(|buf| {
                Self::run_ac_matching_into_static(
                    ac_buffer,
                    text_bytes,
                    mode,
                    &mut buf.borrow_mut(),
                );
            });
            #[cfg(feature = "bench-diagnostics")]
            AC_LITERAL_BUFFER.with(|buf| {
                let ac_literal_hits = buf.borrow().len();
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.ac_literal_hits = ac_literal_hits;
                });
            });

            // Map AC literal IDs to pattern IDs using hash table lookup (O(1))
            AC_LITERAL_BUFFER.with(|ac_buf| {
                if !ac_buf.borrow().is_empty() {
                    if let Some(ref ac_hash) = self.ac_literal_hash {
                        CANDIDATE_BUFFER.with(|cand_buf| {
                            let mut candidates = cand_buf.borrow_mut();
                            for &literal_id in ac_buf.borrow().iter() {
                                ac_hash.visit_pattern_ids(literal_id, |pattern_id| {
                                    candidates.push(pattern_id);
                                });
                            }
                        });
                    }
                }
            });
            CANDIDATE_BUFFER.with(|buf| {
                let mut candidates = buf.borrow_mut();
                #[cfg(feature = "bench-diagnostics")]
                let raw_candidate_pattern_ids = candidates.len();
                candidates.sort_unstable();
                candidates.dedup();
                #[cfg(feature = "bench-diagnostics")]
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.raw_candidate_pattern_ids = raw_candidate_pattern_ids;
                });
            });
            #[cfg(feature = "bench-diagnostics")]
            CANDIDATE_BUFFER.with(|buf| {
                let candidate_pattern_ids = buf.borrow().len();
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.candidate_pattern_ids = candidate_pattern_ids;
                });
            });
        }

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
                let _entry = *entry_ref;

                // Check glob pattern using zero-copy matcher
                #[cfg(feature = "bench-diagnostics")]
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.pure_wildcard_checks += 1;
                    diagnostics.glob_verification_attempts += 1;
                });
                if let Ok(true) = Self::match_glob_from_buffer(
                    buffer,
                    wildcard.pattern_id,
                    text,
                    self.mode,
                    header.glob_segments_offset as usize,
                ) {
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.successful_glob_verifications += 1;
                    });
                    visit(wildcard.pattern_id);
                }
            }
        }

        // Check AC candidates (patterns that have literals that were found)
        CANDIDATE_BUFFER.with(|buf| {
            for &pattern_id in buf.borrow().iter() {
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
                    visit(entry.pattern_id);
                } else {
                    match Self::check_glob_candidate_before_verification(
                        buffer,
                        entry.pattern_id,
                        text,
                        self.mode,
                        header.glob_segments_offset as usize,
                    ) {
                        GlobCandidateCheck::Simple(matches) => {
                            #[cfg(feature = "bench-diagnostics")]
                            Self::record_lookup_diagnostic(|diagnostics| {
                                diagnostics.glob_verification_attempts += 1;
                            });
                            if matches {
                                #[cfg(feature = "bench-diagnostics")]
                                Self::record_lookup_diagnostic(|diagnostics| {
                                    diagnostics.successful_glob_verifications += 1;
                                });
                                visit(entry.pattern_id);
                            }
                            continue;
                        }
                        GlobCandidateCheck::FullVerification => {}
                        GlobCandidateCheck::NoMatch => continue,
                    }

                    // Check glob pattern using zero-copy matcher
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.glob_verification_attempts += 1;
                    });
                    if let Ok(true) = Self::match_glob_from_buffer(
                        buffer,
                        entry.pattern_id,
                        text,
                        self.mode,
                        header.glob_segments_offset as usize,
                    ) {
                        #[cfg(feature = "bench-diagnostics")]
                        Self::record_lookup_diagnostic(|diagnostics| {
                            diagnostics.successful_glob_verifications += 1;
                        });
                        visit(entry.pattern_id);
                    }
                }
            }
        });
    }

    /// Find the first matching pattern ID in the same sorted order used by `find_all`.
    ///
    /// This avoids allocating an owned result vector, making it suitable for
    /// offset-only lookup paths that only need one match.
    #[must_use]
    pub fn find_first(&self, text: &str) -> Option<u32> {
        let mut first = None;
        self.visit_matches_unsorted(text, |pattern_id| {
            first = Some(first.map_or(pattern_id, |current: u32| current.min(pattern_id)));
        });
        first
    }

    /// Find all matching pattern IDs
    #[must_use]
    pub fn find_all(&self, text: &str) -> Vec<u32> {
        RESULT_BUFFER.with(|buf| {
            let mut result = buf.borrow_mut();
            result.clear();

            self.visit_matches_unsorted(text, |pattern_id| {
                result.push(pattern_id);
            });

            result.sort_unstable();
            result.dedup();
            // Clone the result (caller owns it)
            // Note: This still allocates once per query, but it's unavoidable
            // without changing the API to return &[u32] or using arena allocation
            result.clone()
        })
    }

    /// Run AC automaton matching on the offset-based buffer
    /// Writes AC literal IDs into the provided HashSet (avoids allocation)
    fn run_ac_matching_into_static(
        ac_buffer: &[u8],
        text: &[u8],
        mode: MatchMode,
        matches: &mut HashSet<u32>,
    ) {
        if ac_buffer.is_empty() || text.is_empty() {
            return;
        }

        match mode {
            MatchMode::CaseSensitive => {
                Self::run_ac_matching_normalized(ac_buffer, text, matches);
            }
            MatchMode::CaseInsensitive => {
                NORMALIZED_TEXT_BUFFER.with(|buf| {
                    let mut normalized = buf.borrow_mut();
                    crate::simd_utils::ascii_lowercase(text, &mut normalized);
                    Self::run_ac_matching_normalized(ac_buffer, &normalized, matches);
                });
            }
        }
    }

    /// Run AC automaton matching on already-normalized bytes.
    fn run_ac_matching_normalized(
        ac_buffer: &[u8],
        search_text: &[u8],
        matches: &mut HashSet<u32>,
    ) {
        use crate::offset_format::ACNodeHot;

        // Pre-load root dense table offset (root is always Dense after optimization)
        // SAFETY: We verified ac_buffer is non-empty above. Root node is at offset 0,
        // ACNodeHot is 20 bytes, and the buffer contains valid serialized data.
        let root_dense_offset = unsafe {
            let root_node = ac_buffer.as_ptr().cast::<ACNodeHot>().read();
            root_node.edges_offset as usize
        };

        let mut current_offset = 0usize; // Start at root node

        for &search_ch in search_text.iter() {
            // Traverse to next state
            loop {
                if current_offset == 0 {
                    // Fast path: root is always Dense - direct table lookup
                    let target_offset = root_dense_offset + (search_ch as usize * 4);
                    if target_offset + 4 <= ac_buffer.len() {
                        let target = u32::from_le_bytes([
                            ac_buffer[target_offset],
                            ac_buffer[target_offset + 1],
                            ac_buffer[target_offset + 2],
                            ac_buffer[target_offset + 3],
                        ]);
                        if target != 0 {
                            current_offset = target as usize;
                        }
                    }
                    break;
                }

                // Try to find transition for non-root nodes
                if let Some(next_offset) =
                    Self::find_ac_transition(ac_buffer, current_offset, search_ch)
                {
                    current_offset = next_offset;
                    break;
                }

                // SAFETY: Bounds checked before pointer read. ACNodeHot is 4-byte aligned.
                let node = unsafe {
                    if current_offset + mem::size_of::<ACNodeHot>() > ac_buffer.len() {
                        break;
                    }
                    let ptr = ac_buffer.as_ptr().add(current_offset).cast::<ACNodeHot>();
                    ptr.read()
                };
                current_offset = node.failure_offset as usize;
            }

            // Collect pattern IDs at this state (skip for root - no patterns there)
            if current_offset == 0 {
                continue;
            }

            // SAFETY: Bounds checked before pointer read. ACNodeHot is 4-byte aligned.
            let node = unsafe {
                if current_offset + mem::size_of::<ACNodeHot>() > ac_buffer.len() {
                    continue;
                }
                let ptr = ac_buffer.as_ptr().add(current_offset).cast::<ACNodeHot>();
                ptr.read()
            };

            if node.pattern_count > 0 {
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                // SAFETY: Bounds checked. Pattern IDs are u32 (4-byte aligned).
                unsafe {
                    if patterns_offset + pattern_count * 4 <= ac_buffer.len() {
                        let ids_ptr = ac_buffer.as_ptr().add(patterns_offset).cast::<u32>();
                        for i in 0..pattern_count {
                            let pattern_id = ids_ptr.add(i).read();
                            matches.insert(pattern_id);
                        }
                    }
                }
            }
        }
    }

    /// Find a transition from a node for a character in AC automaton
    /// Uses state-specific encoding for optimal performance
    #[inline(always)]
    fn find_ac_transition(ac_buffer: &[u8], node_offset: usize, ch: u8) -> Option<usize> {
        use crate::offset_format::{ACNodeHot, StateKind};

        // Fast path: aligned pointer read (no validation overhead)
        // SAFETY: We validate the offset bounds before casting.
        // ACNodeHot is 16 bytes and always written at 16-byte intervals (offset 0, 16, 32, ...)
        // so it's guaranteed to be 4-byte aligned (ACNodeHot alignment requirement).
        let node = unsafe {
            if node_offset + mem::size_of::<ACNodeHot>() > ac_buffer.len() {
                return None;
            }
            let ptr = ac_buffer.as_ptr().add(node_offset).cast::<ACNodeHot>();
            ptr.read()
        };

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

                // SAFETY: Validate bounds once, then use aligned pointer for entire loop
                // ACEdge is 8 bytes, 4-byte aligned, and written sequentially with ptr.write()
                // in serialize(), so all edges are properly aligned.
                unsafe {
                    if edges_offset + count * edge_size > ac_buffer.len() {
                        return None;
                    }
                    let edge_ptr = ac_buffer.as_ptr().add(edges_offset).cast::<ACEdge>();

                    for i in 0..count {
                        let edge = edge_ptr.add(i).read();

                        if edge.character == ch {
                            return Some(edge.target_offset as usize);
                        }
                        if edge.character > ch {
                            return None;
                        }
                    }
                }
                None
            }

            StateKind::Dense => {
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
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Match text against serialized glob segments directly from buffer (zero-copy)
    ///
    /// This function reads GlobSegmentHeader structs directly from the mmap'd buffer
    /// and performs matching without allocating any heap structures.
    fn match_glob_from_buffer(
        buffer: &[u8],
        pattern_id: u32,
        text: &str,
        mode: MatchMode,
        glob_segments_offset: usize,
    ) -> Result<bool, ParaglobError> {
        // Read GlobSegmentIndex for this pattern
        let index_offset =
            glob_segments_offset + (pattern_id as usize) * mem::size_of::<GlobSegmentIndex>();

        if index_offset + mem::size_of::<GlobSegmentIndex>() > buffer.len() {
            return Ok(false); // Invalid index, treat as no match
        }

        let index_slice = &buffer[index_offset..];
        let (index_ref, _) =
            Ref::<_, GlobSegmentIndex>::from_prefix(index_slice).map_err(|_| {
                ParaglobError::SerializationError("Invalid GlobSegmentIndex".to_string())
            })?;
        let index = *index_ref;

        if let Some(matches) = Self::match_fixed_window_glob_from_buffer(
            buffer,
            text,
            index.first_segment_offset as usize,
            index.segment_count as usize,
            mode,
        ) {
            return Ok(matches);
        }

        // Match using segments directly from buffer
        let mut steps_remaining = 100_000; // Backtracking limit like GlobPattern::matches
        Self::match_segments_impl(
            buffer,
            text,
            index.first_segment_offset as usize,
            index.segment_count as usize,
            0, // text_pos
            0, // seg_idx
            mode,
            &mut steps_remaining,
        )
    }

    fn check_glob_candidate_before_verification(
        buffer: &[u8],
        pattern_id: u32,
        text: &str,
        mode: MatchMode,
        glob_segments_offset: usize,
    ) -> GlobCandidateCheck {
        let index_offset =
            glob_segments_offset + (pattern_id as usize) * mem::size_of::<GlobSegmentIndex>();

        if index_offset + mem::size_of::<GlobSegmentIndex>() > buffer.len() {
            return GlobCandidateCheck::FullVerification;
        }

        let index_slice = &buffer[index_offset..];
        let Ok((index_ref, _)) = Ref::<_, GlobSegmentIndex>::from_prefix(index_slice) else {
            return GlobCandidateCheck::FullVerification;
        };
        let index = *index_ref;

        if let Some(matches) = Self::match_fixed_window_glob_from_buffer(
            buffer,
            text,
            index.first_segment_offset as usize,
            index.segment_count as usize,
            mode,
        ) {
            return GlobCandidateCheck::Simple(matches);
        }

        if Self::glob_literal_segments_match_in_order_from_index(buffer, index, text, mode) {
            GlobCandidateCheck::FullVerification
        } else {
            GlobCandidateCheck::NoMatch
        }
    }

    fn match_fixed_window_glob_from_buffer(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        segment_count: usize,
        mode: MatchMode,
    ) -> Option<bool> {
        if Self::fixed_window_quick_reject(buffer, first_segment_offset, segment_count) {
            return None;
        }

        let shape = Self::fixed_window_shape(buffer, first_segment_offset, segment_count)?;

        if shape.end_seg_idx == shape.start_seg_idx + 1 {
            if let Some(literal) =
                Self::literal_segment_at(buffer, first_segment_offset, shape.start_seg_idx)
            {
                let text_bytes = text.as_bytes();
                return Some(match (shape.has_leading_star, shape.has_trailing_star) {
                    (true, true) => Self::find_literal_bytes(text_bytes, literal, mode).is_some(),
                    (true, false) => Self::bytes_end_with(text_bytes, literal, mode),
                    (false, true) => Self::bytes_start_with(text_bytes, literal, mode),
                    (false, false) => return None,
                });
            }
        }

        Some(match (shape.has_leading_star, shape.has_trailing_star) {
            (true, true) => Self::fixed_window_matches_anywhere(
                buffer,
                text,
                first_segment_offset,
                &shape,
                mode,
            ),
            (true, false) => {
                Self::fixed_window_matches_suffix(buffer, text, first_segment_offset, &shape, mode)
            }
            (false, true) => Self::fixed_window_matches_at(
                buffer,
                text,
                first_segment_offset,
                shape.start_seg_idx,
                shape.end_seg_idx,
                0,
                mode,
            )
            .is_some(),
            (false, false) => return None,
        })
    }

    fn fixed_window_quick_reject(
        buffer: &[u8],
        first_segment_offset: usize,
        segment_count: usize,
    ) -> bool {
        if segment_count <= 3 {
            return false;
        }

        let Some(first_type) = Self::segment_type_at(buffer, first_segment_offset, 0) else {
            return false;
        };

        if first_type == 1 {
            return Self::segment_type_at(buffer, first_segment_offset, 2) == Some(1);
        }

        Self::segment_type_at(buffer, first_segment_offset, 1) == Some(1)
    }

    fn fixed_window_shape(
        buffer: &[u8],
        first_segment_offset: usize,
        segment_count: usize,
    ) -> Option<FixedWindowShape> {
        use crate::offset_format::GlobSegmentHeader;

        if segment_count < 2 {
            return None;
        }

        let mut start_seg_idx = 0usize;
        let mut end_seg_idx = segment_count;
        let mut has_leading_star = false;
        let mut has_trailing_star = false;

        if Self::segment_type_at(buffer, first_segment_offset, 0)? == 1 {
            has_leading_star = true;
            start_seg_idx = 1;
        }

        if Self::segment_type_at(buffer, first_segment_offset, segment_count - 1)? == 1 {
            has_trailing_star = true;
            end_seg_idx -= 1;
        }

        if !has_leading_star && !has_trailing_star || start_seg_idx >= end_seg_idx {
            return None;
        }

        Self::literal_segment_at(buffer, first_segment_offset, start_seg_idx)?;

        for seg_idx in start_seg_idx..end_seg_idx {
            let seg_offset = first_segment_offset + seg_idx * mem::size_of::<GlobSegmentHeader>();
            if seg_offset + mem::size_of::<GlobSegmentHeader>() > buffer.len() {
                return None;
            }

            let seg_slice = &buffer[seg_offset..];
            let (seg_header_ref, _) = Ref::<_, GlobSegmentHeader>::from_prefix(seg_slice).ok()?;
            let seg_header = *seg_header_ref;

            match seg_header.segment_type {
                0 => {
                    Self::literal_segment_at(buffer, first_segment_offset, seg_idx)?;
                }
                2 | 3 => {}
                _ => return None,
            }
        }

        Some(FixedWindowShape {
            start_seg_idx,
            end_seg_idx,
            has_leading_star,
            has_trailing_star,
        })
    }

    fn segment_type_at(buffer: &[u8], first_segment_offset: usize, seg_idx: usize) -> Option<u8> {
        use crate::offset_format::GlobSegmentHeader;

        let seg_offset = first_segment_offset + seg_idx * mem::size_of::<GlobSegmentHeader>();
        buffer.get(seg_offset).copied()
    }

    fn fixed_window_matches_anywhere(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        shape: &FixedWindowShape,
        mode: MatchMode,
    ) -> bool {
        Self::visit_fixed_window_candidate_positions(
            buffer,
            text,
            first_segment_offset,
            shape,
            mode,
            |candidate_pos| {
                Self::fixed_window_matches_at(
                    buffer,
                    text,
                    first_segment_offset,
                    shape.start_seg_idx,
                    shape.end_seg_idx,
                    candidate_pos,
                    mode,
                )
                .is_some()
            },
        )
    }

    fn fixed_window_matches_suffix(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        shape: &FixedWindowShape,
        mode: MatchMode,
    ) -> bool {
        Self::visit_fixed_window_candidate_positions(
            buffer,
            text,
            first_segment_offset,
            shape,
            mode,
            |candidate_pos| {
                Self::fixed_window_matches_at(
                    buffer,
                    text,
                    first_segment_offset,
                    shape.start_seg_idx,
                    shape.end_seg_idx,
                    candidate_pos,
                    mode,
                )
                .is_some_and(|end_pos| end_pos == text.len())
            },
        )
    }

    fn visit_fixed_window_candidate_positions(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        shape: &FixedWindowShape,
        mode: MatchMode,
        mut visit: impl FnMut(usize) -> bool,
    ) -> bool {
        if let Some(first_literal) =
            Self::literal_segment_at(buffer, first_segment_offset, shape.start_seg_idx)
        {
            let text_bytes = text.as_bytes();
            match mode {
                MatchMode::CaseSensitive => {
                    for candidate_pos in memchr::memmem::find_iter(text_bytes, first_literal) {
                        if text.is_char_boundary(candidate_pos) && visit(candidate_pos) {
                            return true;
                        }
                    }
                }
                MatchMode::CaseInsensitive => {
                    if text_bytes.len() < first_literal.len() {
                        return false;
                    }

                    for candidate_pos in 0..=text_bytes.len() - first_literal.len() {
                        if !text.is_char_boundary(candidate_pos) {
                            continue;
                        }
                        let candidate =
                            &text_bytes[candidate_pos..candidate_pos + first_literal.len()];
                        if Self::bytes_eq_ignore_ascii_case(candidate, first_literal)
                            && visit(candidate_pos)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        false
    }

    fn fixed_window_matches_at(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        start_seg_idx: usize,
        end_seg_idx: usize,
        mut text_pos: usize,
        mode: MatchMode,
    ) -> Option<usize> {
        use crate::offset_format::GlobSegmentHeader;

        if text_pos > text.len() || !text.is_char_boundary(text_pos) {
            return None;
        }

        for seg_idx in start_seg_idx..end_seg_idx {
            let seg_offset = first_segment_offset + seg_idx * mem::size_of::<GlobSegmentHeader>();
            if seg_offset + mem::size_of::<GlobSegmentHeader>() > buffer.len() {
                return None;
            }

            let seg_slice = &buffer[seg_offset..];
            let (seg_header_ref, _) = Ref::<_, GlobSegmentHeader>::from_prefix(seg_slice).ok()?;
            let seg_header = *seg_header_ref;

            match seg_header.segment_type {
                0 => {
                    let literal = Self::literal_segment_at(buffer, first_segment_offset, seg_idx)?;
                    let remaining = text.as_bytes().get(text_pos..)?;
                    if !Self::bytes_start_with(remaining, literal, mode) {
                        return None;
                    }
                    text_pos += literal.len();
                }
                2 => {
                    let ch = text.get(text_pos..)?.chars().next()?;
                    text_pos += ch.len_utf8();
                }
                3 => {
                    let ch = text.get(text_pos..)?.chars().next()?;
                    if !Self::char_class_matches(buffer, seg_header, ch, mode)? {
                        return None;
                    }
                    text_pos += ch.len_utf8();
                }
                _ => return None,
            }
        }

        Some(text_pos)
    }

    fn char_class_matches(
        buffer: &[u8],
        seg_header: crate::offset_format::GlobSegmentHeader,
        ch: char,
        mode: MatchMode,
    ) -> Option<bool> {
        use crate::offset_format::CharClassItemEncoded;

        let ch_normalized = match mode {
            MatchMode::CaseSensitive => ch,
            MatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
        };

        let data_offset = seg_header.data_offset as usize;
        let data_len = seg_header.data_len as usize;
        let item_size = mem::size_of::<CharClassItemEncoded>();
        let item_count = data_len / item_size;

        if data_offset + data_len > buffer.len() {
            return None;
        }

        let negated = seg_header.flags & 1 != 0;
        let mut in_class = false;

        for i in 0..item_count {
            let item_offset = data_offset + i * item_size;
            let item_slice = &buffer[item_offset..];
            let (item_ref, _) = Ref::<_, CharClassItemEncoded>::from_prefix(item_slice).ok()?;
            let item = *item_ref;

            let matches_item = match item.item_type {
                0 => {
                    let class_ch = char::from_u32(item.char1)?;
                    let class_ch_normalized = match mode {
                        MatchMode::CaseSensitive => class_ch,
                        MatchMode::CaseInsensitive => class_ch.to_ascii_lowercase(),
                    };
                    ch_normalized == class_ch_normalized
                }
                1 => {
                    let start = char::from_u32(item.char1)?;
                    let end = char::from_u32(item.char2)?;
                    let start_norm = match mode {
                        MatchMode::CaseSensitive => start,
                        MatchMode::CaseInsensitive => start.to_ascii_lowercase(),
                    };
                    let end_norm = match mode {
                        MatchMode::CaseSensitive => end,
                        MatchMode::CaseInsensitive => end.to_ascii_lowercase(),
                    };
                    ch_normalized >= start_norm && ch_normalized <= end_norm
                }
                _ => false,
            };

            if matches_item {
                in_class = true;
                break;
            }
        }

        Some(if negated { !in_class } else { in_class })
    }

    /// Recursive matching implementation that works directly on serialized segments
    #[allow(clippy::too_many_arguments)]
    fn match_segments_impl(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        segment_count: usize,
        text_pos: usize,
        seg_idx: usize,
        mode: MatchMode,
        steps_remaining: &mut usize,
    ) -> Result<bool, ParaglobError> {
        use crate::offset_format::{CharClassItemEncoded, GlobSegmentHeader};

        // Check step limit to prevent exponential backtracking
        if *steps_remaining == 0 {
            return Ok(false);
        }
        *steps_remaining -= 1;
        #[cfg(feature = "bench-diagnostics")]
        Self::record_lookup_diagnostic(|diagnostics| {
            diagnostics.serialized_glob_segment_steps += 1;
        });

        // If we've consumed all segments, we match if we've also consumed all text
        if seg_idx >= segment_count {
            return Ok(text_pos >= text.len());
        }

        // Read the current segment header
        let seg_offset = first_segment_offset + seg_idx * mem::size_of::<GlobSegmentHeader>();
        if seg_offset + mem::size_of::<GlobSegmentHeader>() > buffer.len() {
            return Ok(false);
        }

        let seg_slice = &buffer[seg_offset..];
        let (seg_header_ref, _) =
            Ref::<_, GlobSegmentHeader>::from_prefix(seg_slice).map_err(|_| {
                ParaglobError::SerializationError("Invalid GlobSegmentHeader".to_string())
            })?;
        let seg_header = *seg_header_ref;

        match seg_header.segment_type {
            0 => {
                // Literal - read string directly from buffer
                let data_offset = seg_header.data_offset as usize;
                let data_len = seg_header.data_len as usize;

                if data_offset + data_len > buffer.len() {
                    return Ok(false);
                }

                let lit_bytes = &buffer[data_offset..data_offset + data_len];
                let lit = std::str::from_utf8(lit_bytes).map_err(|_| {
                    ParaglobError::InvalidPattern("Invalid UTF-8 in literal".to_string())
                })?;

                let remaining = &text[text_pos..];
                let (matches, advance_bytes) = match mode {
                    MatchMode::CaseSensitive => (remaining.starts_with(lit), lit.len()),
                    MatchMode::CaseInsensitive => {
                        let mut lit_chars = lit.chars();
                        let mut matched_bytes = 0;
                        let mut matches = true;

                        for text_char in remaining.chars() {
                            if let Some(lit_char) = lit_chars.next() {
                                if !lit_char.eq_ignore_ascii_case(&text_char) {
                                    matches = false;
                                    break;
                                }
                                matched_bytes += text_char.len_utf8();
                            } else {
                                break;
                            }
                        }

                        if matches && lit_chars.next().is_some() {
                            matches = false;
                        }

                        (matches, matched_bytes)
                    }
                };

                if matches {
                    Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        text_pos + advance_bytes,
                        seg_idx + 1,
                        mode,
                        steps_remaining,
                    )
                } else {
                    Ok(false)
                }
            }
            1 => {
                // Star - match zero or more characters
                if seg_idx + 1 >= segment_count {
                    return Ok(true); // Star at end matches everything
                }

                if let Some(next_literal) =
                    Self::next_literal_segment(buffer, first_segment_offset, seg_idx, segment_count)
                {
                    return Self::match_star_before_literal(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        text_pos,
                        seg_idx + 1,
                        mode,
                        steps_remaining,
                        next_literal,
                    );
                }

                // Try matching star with 0, 1, 2, ... characters
                let mut pos = text_pos;
                loop {
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.star_backtracking_attempts += 1;
                    });
                    if Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        pos,
                        seg_idx + 1,
                        mode,
                        steps_remaining,
                    )? {
                        return Ok(true);
                    }

                    if pos >= text.len() {
                        break;
                    }
                    if let Some(ch) = text[pos..].chars().next() {
                        pos += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                Ok(false)
            }
            2 => {
                // Question - match exactly one character
                if let Some(ch) = text[text_pos..].chars().next() {
                    Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        text_pos + ch.len_utf8(),
                        seg_idx + 1,
                        mode,
                        steps_remaining,
                    )
                } else {
                    Ok(false)
                }
            }
            3 => {
                // CharClass - read directly from buffer
                let Some(ch) = text[text_pos..].chars().next() else {
                    return Ok(false);
                };

                let ch_normalized = match mode {
                    MatchMode::CaseSensitive => ch,
                    MatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
                };

                let data_offset = seg_header.data_offset as usize;
                let data_len = seg_header.data_len as usize;
                let item_size = mem::size_of::<CharClassItemEncoded>();
                let item_count = data_len / item_size;

                if data_offset + data_len > buffer.len() {
                    return Ok(false);
                }

                let negated = seg_header.flags & 1 != 0;
                let mut in_class = false;

                for i in 0..item_count {
                    let item_offset = data_offset + i * item_size;
                    let item_slice = &buffer[item_offset..];
                    let (item_ref, _) = Ref::<_, CharClassItemEncoded>::from_prefix(item_slice)
                        .map_err(|_| {
                            ParaglobError::SerializationError(
                                "Invalid CharClassItemEncoded".to_string(),
                            )
                        })?;
                    let item = *item_ref;

                    let matches_item = match item.item_type {
                        0 => {
                            // Char
                            if let Some(class_ch) = char::from_u32(item.char1) {
                                let class_ch_normalized = match mode {
                                    MatchMode::CaseSensitive => class_ch,
                                    MatchMode::CaseInsensitive => class_ch.to_ascii_lowercase(),
                                };
                                ch_normalized == class_ch_normalized
                            } else {
                                false
                            }
                        }
                        1 => {
                            // Range
                            if let (Some(start), Some(end)) =
                                (char::from_u32(item.char1), char::from_u32(item.char2))
                            {
                                let start_norm = match mode {
                                    MatchMode::CaseSensitive => start,
                                    MatchMode::CaseInsensitive => start.to_ascii_lowercase(),
                                };
                                let end_norm = match mode {
                                    MatchMode::CaseSensitive => end,
                                    MatchMode::CaseInsensitive => end.to_ascii_lowercase(),
                                };
                                ch_normalized >= start_norm && ch_normalized <= end_norm
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };

                    if matches_item {
                        in_class = true;
                        break;
                    }
                }

                let matches = if negated { !in_class } else { in_class };

                if matches {
                    Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        text_pos + ch.len_utf8(),
                        seg_idx + 1,
                        mode,
                        steps_remaining,
                    )
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false), // Invalid segment type
        }
    }

    fn glob_literal_segments_match_in_order_from_index(
        buffer: &[u8],
        index: GlobSegmentIndex,
        text: &str,
        mode: MatchMode,
    ) -> bool {
        #[cfg(feature = "bench-diagnostics")]
        Self::record_lookup_diagnostic(|diagnostics| {
            diagnostics.literal_order_precheck_attempts += 1;
        });

        let mut search_offset = 0usize;

        for seg_idx in 0..index.segment_count as usize {
            let Some(literal) =
                Self::literal_segment_at(buffer, index.first_segment_offset as usize, seg_idx)
            else {
                continue;
            };

            let Some(relative_match) =
                Self::find_literal_bytes(&text.as_bytes()[search_offset..], literal, mode)
            else {
                return false;
            };
            search_offset += relative_match + literal.len();
        }

        true
    }

    fn literal_segment_at(
        buffer: &[u8],
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<&[u8]> {
        use crate::offset_format::GlobSegmentHeader;

        let seg_offset = first_segment_offset + seg_idx * mem::size_of::<GlobSegmentHeader>();
        if seg_offset + mem::size_of::<GlobSegmentHeader>() > buffer.len() {
            return None;
        }

        let seg_slice = &buffer[seg_offset..];
        let (seg_header_ref, _) = Ref::<_, GlobSegmentHeader>::from_prefix(seg_slice).ok()?;
        let seg_header = *seg_header_ref;
        if seg_header.segment_type != 0 || seg_header.data_len == 0 {
            return None;
        }

        let data_offset = seg_header.data_offset as usize;
        let data_len = seg_header.data_len as usize;
        if data_offset + data_len > buffer.len() {
            return None;
        }

        Some(&buffer[data_offset..data_offset + data_len])
    }

    fn find_literal_bytes(haystack: &[u8], needle: &[u8], mode: MatchMode) -> Option<usize> {
        match mode {
            MatchMode::CaseSensitive => memchr::memmem::find(haystack, needle),
            MatchMode::CaseInsensitive => {
                if haystack.len() < needle.len() {
                    return None;
                }

                (0..=haystack.len() - needle.len()).find(|&offset| {
                    Self::bytes_eq_ignore_ascii_case(
                        &haystack[offset..offset + needle.len()],
                        needle,
                    )
                })
            }
        }
    }

    fn next_literal_segment(
        buffer: &[u8],
        first_segment_offset: usize,
        seg_idx: usize,
        segment_count: usize,
    ) -> Option<&[u8]> {
        let next_seg_idx = seg_idx.checked_add(1)?;
        if next_seg_idx >= segment_count {
            return None;
        }

        Self::literal_segment_at(buffer, first_segment_offset, next_seg_idx)
    }

    #[allow(clippy::too_many_arguments)]
    fn match_star_before_literal(
        buffer: &[u8],
        text: &str,
        first_segment_offset: usize,
        segment_count: usize,
        text_pos: usize,
        next_seg_idx: usize,
        mode: MatchMode,
        steps_remaining: &mut usize,
        literal: &[u8],
    ) -> Result<bool, ParaglobError> {
        if text_pos > text.len() || !text.is_char_boundary(text_pos) {
            return Ok(false);
        }

        let remaining = &text.as_bytes()[text_pos..];

        match mode {
            MatchMode::CaseSensitive => {
                for relative_pos in memchr::memmem::find_iter(remaining, literal) {
                    let candidate_pos = text_pos + relative_pos;
                    if !text.is_char_boundary(candidate_pos) {
                        continue;
                    }
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.star_backtracking_attempts += 1;
                    });
                    if Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        candidate_pos,
                        next_seg_idx,
                        mode,
                        steps_remaining,
                    )? {
                        return Ok(true);
                    }
                }
            }
            MatchMode::CaseInsensitive => {
                if remaining.len() < literal.len() {
                    return Ok(false);
                }

                for relative_pos in 0..=remaining.len() - literal.len() {
                    let candidate_pos = text_pos + relative_pos;
                    if !text.is_char_boundary(candidate_pos) {
                        continue;
                    }
                    let candidate = &remaining[relative_pos..relative_pos + literal.len()];
                    if !Self::bytes_eq_ignore_ascii_case(candidate, literal) {
                        continue;
                    }
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.star_backtracking_attempts += 1;
                    });
                    if Self::match_segments_impl(
                        buffer,
                        text,
                        first_segment_offset,
                        segment_count,
                        candidate_pos,
                        next_seg_idx,
                        mode,
                        steps_remaining,
                    )? {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn bytes_eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left_byte, right_byte)| left_byte.eq_ignore_ascii_case(right_byte))
    }

    fn bytes_start_with(left: &[u8], prefix: &[u8], mode: MatchMode) -> bool {
        if left.len() < prefix.len() {
            return false;
        }

        match mode {
            MatchMode::CaseSensitive => left.starts_with(prefix),
            MatchMode::CaseInsensitive => {
                Self::bytes_eq_ignore_ascii_case(&left[..prefix.len()], prefix)
            }
        }
    }

    fn bytes_end_with(left: &[u8], suffix: &[u8], mode: MatchMode) -> bool {
        if left.len() < suffix.len() {
            return false;
        }

        match mode {
            MatchMode::CaseSensitive => left.ends_with(suffix),
            MatchMode::CaseInsensitive => {
                let suffix_start = left.len() - suffix.len();
                Self::bytes_eq_ignore_ascii_case(&left[suffix_start..], suffix)
            }
        }
    }

    /// Load from buffer (for deserialization)
    ///
    /// Used internally by the `serialization` module's `from_bytes()` function.
    /// Takes ownership of a `Vec<u8>` for owned buffer storage.
    ///
    /// Uses ACLiteralHash for O(1) AC literal lookups. Load time is O(1) since
    /// the hash table is already serialized in the buffer.
    pub fn from_buffer(buffer: Vec<u8>, mode: MatchMode) -> Result<Self, ParaglobError> {
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
            Some(crate::literal_hash::ACLiteralHash::from_buffer(
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
            ac_literal_hash,
            pattern_data_map,
        })
    }

    /// Load from memory-mapped buffer (zero-copy)
    ///
    /// # Safety
    ///
    /// The caller must ensure that the slice remains valid for the lifetime
    /// of this Paraglob instance. Typically used with memory-mapped files.
    ///
    /// This is truly O(1) - only validates header and stores offsets,
    /// no data copying or HashMap building.
    ///
    /// Validates UTF-8 on every pattern string read.
    pub unsafe fn from_mmap(slice: &'static [u8], mode: MatchMode) -> Result<Self, ParaglobError> {
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
            Some(crate::literal_hash::ACLiteralHash::from_buffer(hash_slice)?)
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
            ac_literal_hash,
            pattern_data_map,
        })
    }

    /// Get pattern count
    #[must_use]
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
    #[must_use]
    pub fn get_pattern_data(&self, pattern_id: u32) -> Option<DataValue> {
        self.find_pattern_data(pattern_id)
    }

    /// Find pattern data by binary search through the mapping table
    ///
    /// Format: [PatternDataMapping { pattern_id: u32, data_offset: u32, size: u32 }]...
    /// Sorted by pattern_id for binary search O(log n).
    fn find_pattern_data(&self, pattern_id: u32) -> Option<DataValue> {
        use matchy_data_format::DataDecoder;

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
    #[must_use]
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

    /// Get pattern string by ID
    #[must_use]
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

        read_cstring(buffer, entry.pattern_string_offset as usize)
            .ok()
            .map(std::string::ToString::to_string)
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
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

        assert_eq!(pg.pattern_count(), 2);
        assert!(!pg.buffer().is_empty());
    }

    #[test]
    fn test_literal_matching() {
        let patterns = vec!["hello", "world"];
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("hello world");
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&0));
        assert!(matches.contains(&1));
    }

    #[test]
    fn test_glob_matching() {
        let patterns = vec!["*.txt", "test_*"];
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("test_file.txt");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_pure_wildcard() {
        let patterns = vec!["*", "??"];
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("ab");
        assert_eq!(matches.len(), 2); // Both match
    }

    #[test]
    fn test_case_insensitive() {
        let patterns = vec!["Hello", "*.TXT"];
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();

        let matches = pg.find_all("hello test.txt");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_match() {
        let patterns = vec!["hello", "*.txt"];
        let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

        let matches = pg.find_all("goodbye world");
        assert!(matches.is_empty());
    }
}
