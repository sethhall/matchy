//! Offset-based Paraglob Pattern Matcher
//!
//! This module implements the complete Paraglob system using a unified
//! offset-based binary format. Everything is stored in a single `Vec<u8>`
//! that can be serialized to disk or read directly from a memory-mapped buffer.
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
use matchy_data_format::{DataDecoder, DataEncoder, DataValue, DecodeBudget};
use matchy_match_mode::MatchMode;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::mem;
use std::thread_local;
use zerocopy::{FromBytes, IntoBytes};

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
    let mut selected: Option<&String> = None;

    for literal in literals {
        if literal.is_empty() {
            continue;
        }

        // Replace on equal length to preserve the format's historical
        // later-literal tie behavior.
        if selected.is_none_or(|best| literal.len() >= best.len()) {
            selected = Some(literal);
        }
    }

    selected
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
        let (header, _) = ParaglobHeader::read_from_prefix(&buffer[..])
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        header
            .validate()
            .and_then(|()| header.validate_offsets(buffer.len()))
            .map_err(|error| ParaglobError::SerializationError(error.to_string()))?;

        // Load AC literal hash table from the built buffer
        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_range = ac_literal_hash_range(&header, buffer.len())?;
            let hash_slice = &buffer[hash_range];
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
            header,
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

        buffer[..header_size].copy_from_slice(header.as_bytes());

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

            buffer[entry_offset..entry_offset + pattern_entry_size]
                .copy_from_slice(entry.as_bytes());
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

            buffer[wildcard_offset..wildcard_offset + wildcard_entry_size]
                .copy_from_slice(wildcard.as_bytes());
        }

        // Write data section
        if data_section_size > 0 {
            buffer[data_section_start..data_section_start + data_section_size]
                .copy_from_slice(&data_section_bytes);
        }

        // Write pattern data mappings
        for (i, mapping) in pattern_data_mappings.iter().enumerate() {
            let mapping_offset = mappings_start + i * mapping_entry_size;
            buffer[mapping_offset..mapping_offset + mapping_entry_size]
                .copy_from_slice(mapping.as_bytes());
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
            let index_size = mem::size_of::<crate::offset_format::GlobSegmentIndex>();
            buffer[index_offset..index_offset + index_size]
                .copy_from_slice(adjusted_index.as_bytes());
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
                if let Ok((mut header, _)) =
                    crate::offset_format::GlobSegmentHeader::read_from_prefix(header_slice)
                {
                    // Adjust data_offset to be relative to buffer start
                    // Note: offsets in segment_data include index_size, but indices are written
                    // separately, so we need to subtract index_size then add glob_index_end
                    if header.data_len > 0 && header.data_offset > 0 {
                        let idx_size = u32::try_from(glob_index_size).unwrap_or(0);
                        let idx_end = u32::try_from(glob_index_end).unwrap_or(0);
                        header.data_offset = header.data_offset - idx_size + idx_end;
                    }

                    let header_end = header_offset_in_data
                        + mem::size_of::<crate::offset_format::GlobSegmentHeader>();
                    adjusted_segment_data[header_offset_in_data..header_end]
                        .copy_from_slice(header.as_bytes());
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

struct PatternDataReader<'a> {
    mappings: &'a [u8],
    mapping_count: usize,
    data_section_len: usize,
    decoder: DataDecoder<'a>,
}

fn is_decode_resource_limit(error: &str) -> bool {
    matches!(
        error,
        "Decoded value exceeds work limit"
            | "Decoded value exceeds allocation limit"
            | "String allocation failed"
            | "Bytes allocation failed"
            | "Map allocation failed"
            | "Array allocation failed"
    )
}

impl PatternDataReader<'_> {
    fn decode(
        &self,
        pattern_id: u32,
        budget: &mut DecodeBudget,
    ) -> Result<Option<DataValue>, ParaglobError> {
        let mapping_size = mem::size_of::<PatternDataMapping>();
        let mut left = 0usize;
        let mut right = self.mapping_count;

        while left < right {
            let mid = left + (right - left) / 2;
            let mapping_offset = mid.checked_mul(mapping_size).ok_or_else(|| {
                ParaglobError::Validation(
                    "Pattern mapping offset overflows address space".to_string(),
                )
            })?;
            let mapping_end = mapping_offset.checked_add(mapping_size).ok_or_else(|| {
                ParaglobError::Validation(
                    "Pattern mapping range overflows address space".to_string(),
                )
            })?;
            let mapping_slice =
                self.mappings
                    .get(mapping_offset..mapping_end)
                    .ok_or_else(|| {
                        ParaglobError::Validation(format!(
                        "Pattern mapping range {mapping_offset}..{mapping_end} is out of bounds"
                    ))
                    })?;
            let (mapping, _) =
                PatternDataMapping::read_from_prefix(mapping_slice).map_err(|_| {
                    ParaglobError::Validation(format!(
                        "Pattern mapping at relative offset {mapping_offset} is invalid"
                    ))
                })?;

            if mapping.pattern_id == pattern_id {
                let value_start = usize::try_from(mapping.data_offset).map_err(|_| {
                    ParaglobError::Validation(format!(
                        "Pattern {pattern_id} data offset is not addressable"
                    ))
                })?;
                let value_size = usize::try_from(mapping.data_size).map_err(|_| {
                    ParaglobError::Validation(format!(
                        "Pattern {pattern_id} data size is not addressable"
                    ))
                })?;

                // Existing v5 writers use zero for self-delimiting values.
                if value_size != 0 {
                    let value_end = value_start.checked_add(value_size).ok_or_else(|| {
                        ParaglobError::Validation(format!(
                            "Pattern {pattern_id} data range overflows address space"
                        ))
                    })?;
                    if value_end > self.data_section_len {
                        return Err(ParaglobError::Validation(format!(
                            "Pattern {pattern_id} data range {value_start}..{value_end} exceeds data section size {}",
                            self.data_section_len
                        )));
                    }
                }

                let value = self
                    .decoder
                    .decode_with_budget(mapping.data_offset, budget)
                    .map_err(|error| {
                        let message = format!(
                            "Pattern {pattern_id} data at offset {} could not be decoded: {error}",
                            mapping.data_offset
                        );
                        if is_decode_resource_limit(error) {
                            ParaglobError::ResourceLimitExceeded(message)
                        } else {
                            ParaglobError::Format(message)
                        }
                    })?;
                return Ok(Some(value));
            }

            if mapping.pattern_id < pattern_id {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        Ok(None)
    }
}

enum GlobCandidateCheck {
    Simple(bool),
    FullVerification(SerializedGlobPattern),
    NoMatch,
}

#[derive(Clone, Copy)]
struct SerializedGlobPattern {
    first_segment_offset: usize,
    segment_count: usize,
}

struct FixedWindowShape {
    start_seg_idx: usize,
    end_seg_idx: usize,
    has_leading_star: bool,
    has_trailing_star: bool,
    first_literal_offset: usize,
    first_literal_len: usize,
}

struct TextCharCounter<'a> {
    chars: std::str::Chars<'a>,
    observed: usize,
    exhausted: bool,
}

const MATCHING_WORK_MULTIPLIER: usize = 64;
const PER_PATTERN_GLOB_STEP_LIMIT: usize = 100_000;

/// Shared CPU-work allowance for one bounded matching operation.
///
/// Storage/cardinality limits remain at the caller-provided value. CPU work is
/// allowed a documented multiplier so sorting and normal automaton traversal do
/// not make the public cardinality ceilings unusable.
struct MatchingWorkBudget {
    remaining: usize,
}

impl MatchingWorkBudget {
    fn bounded(max_matching_work: usize) -> Self {
        Self {
            remaining: max_matching_work.saturating_mul(MATCHING_WORK_MULTIPLIER),
        }
    }

    const fn unbounded() -> Self {
        Self {
            remaining: usize::MAX,
        }
    }

    #[inline(always)]
    fn try_charge<const BOUNDED: bool>(&mut self, units: usize) -> bool {
        if !BOUNDED {
            return true;
        }
        let Some(remaining) = self.remaining.checked_sub(units) else {
            return false;
        };
        self.remaining = remaining;
        true
    }

    const fn remaining(&self) -> usize {
        self.remaining
    }
}

fn sort_dedup_work(item_count: usize) -> usize {
    if item_count == 0 {
        return 0;
    }
    let ceil_log2 = usize::BITS - item_count.max(2).saturating_sub(1).leading_zeros();
    item_count.saturating_mul(usize::try_from(ceil_log2).unwrap_or(usize::MAX))
}

fn matching_work_limit_error() -> ParaglobError {
    ParaglobError::ResourceLimitExceeded("Matching work limit exceeded".to_string())
}

impl<'a> TextCharCounter<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            chars: text.chars(),
            observed: 0,
            exhausted: false,
        }
    }

    fn at_least(&mut self, required: usize) -> bool {
        while self.observed < required && !self.exhausted {
            if self.chars.next().is_some() {
                self.observed += 1;
            } else {
                self.exhausted = true;
            }
        }
        self.observed >= required
    }

    fn exactly(&mut self, required: usize) -> bool {
        !self.at_least(required.saturating_add(1)) && self.observed == required
    }
}

#[derive(Clone, Copy)]
struct SerializedGlobSection {
    index_start: usize,
    data_start: usize,
    data_end: usize,
    pattern_count: usize,
}

impl SerializedGlobSection {
    fn from_header(header: &ParaglobHeader, buffer_len: usize) -> Option<Self> {
        let index_start = usize::try_from(header.glob_segments_offset).ok()?;
        let section_size = usize::try_from(header.glob_segments_size).ok()?;
        let data_end = index_start.checked_add(section_size)?;
        if data_end > buffer_len {
            return None;
        }

        let pattern_count = usize::try_from(header.pattern_count).ok()?;
        let index_size = pattern_count.checked_mul(mem::size_of::<GlobSegmentIndex>())?;
        let data_start = index_start.checked_add(index_size)?;
        if data_start > data_end {
            return None;
        }

        Some(Self {
            index_start,
            data_start,
            data_end,
            pattern_count,
        })
    }

    fn index(self, buffer: &[u8], pattern_id: u32) -> Option<GlobSegmentIndex> {
        let pattern_id = usize::try_from(pattern_id).ok()?;
        if pattern_id >= self.pattern_count {
            return None;
        }

        // `from_header` proved that the complete index array ends at
        // `data_start`, so a checked pattern ID makes this arithmetic safe.
        let index_size = mem::size_of::<GlobSegmentIndex>();
        let index_offset = self.index_start + pattern_id * index_size;
        let index_end = index_offset + index_size;

        let index_bytes = buffer.get(index_offset..index_end)?;
        GlobSegmentIndex::read_from_prefix(index_bytes)
            .ok()
            .map(|(index, _)| index)
    }

    fn data(self, buffer: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
        if offset < self.data_start {
            return None;
        }
        let end = offset.checked_add(len)?;
        if end > self.data_end {
            return None;
        }
        buffer.get(offset..end)
    }

    #[inline]
    fn segment_header_bytes(
        self,
        buffer: &[u8],
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<&[u8]> {
        let offset = checked_index_offset(
            first_segment_offset,
            seg_idx,
            mem::size_of::<crate::offset_format::GlobSegmentHeader>(),
        )?;
        self.data(
            buffer,
            offset,
            mem::size_of::<crate::offset_format::GlobSegmentHeader>(),
        )
    }

    #[inline]
    fn raw_segment_header(
        self,
        buffer: &[u8],
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<crate::offset_format::GlobSegmentHeader> {
        let bytes = self.segment_header_bytes(buffer, first_segment_offset, seg_idx)?;
        crate::offset_format::GlobSegmentHeader::read_from_prefix(bytes)
            .ok()
            .map(|(header, _)| header)
    }

    fn segment_header(
        self,
        buffer: &[u8],
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<crate::offset_format::GlobSegmentHeader> {
        let header = self.raw_segment_header(buffer, first_segment_offset, seg_idx)?;
        let data_len = usize::try_from(header.data_len).ok()?;
        let data_offset = usize::try_from(header.data_offset).ok()?;
        let payload = || self.data(buffer, data_offset, data_len);

        let valid_shape = match header.segment_type {
            // Literal payloads are always nonempty UTF-8 bytes.
            0 => {
                header.flags == 0
                    && data_len > 0
                    && payload().is_some_and(|bytes| std::str::from_utf8(bytes).is_ok())
            }
            // Stars and questions never carry flags or payloads.
            1 | 2 => header.flags == 0 && data_len == 0 && data_offset == 0,
            // Bit 0 is the only defined character-class flag (negation).
            3 => {
                let item_size = mem::size_of::<crate::offset_format::CharClassItemEncoded>();
                header.flags & !1 == 0
                    && data_len > 0
                    && data_len.is_multiple_of(item_size)
                    && payload().is_some()
            }
            _ => false,
        };

        valid_shape.then_some(header)
    }

    fn segments_fit(self, buffer: &[u8], first_segment_offset: usize, count: usize) -> bool {
        if count == 0 {
            return false;
        }
        count
            .checked_mul(mem::size_of::<crate::offset_format::GlobSegmentHeader>())
            .and_then(|len| self.data(buffer, first_segment_offset, len))
            .is_some()
    }

    fn pattern(self, buffer: &[u8], pattern_id: u32) -> Option<SerializedGlobPattern> {
        let index = self.index(buffer, pattern_id)?;
        let pattern = SerializedGlobPattern {
            first_segment_offset: usize::try_from(index.first_segment_offset).ok()?,
            segment_count: usize::from(index.segment_count),
        };
        self.segments_fit(buffer, pattern.first_segment_offset, pattern.segment_count)
            .then_some(pattern)
    }
}

#[derive(Clone, Copy)]
enum GlobBacktrackFrame {
    Star {
        candidate_pos: usize,
        next_seg_idx: usize,
    },
    StarBeforeLiteral {
        search_pos: usize,
        next_seg_idx: usize,
    },
}

fn checked_index_offset(base: usize, index: usize, item_size: usize) -> Option<usize> {
    index
        .checked_mul(item_size)
        .and_then(|relative| base.checked_add(relative))
}

fn ac_literal_hash_range(
    header: &ParaglobHeader,
    buffer_len: usize,
) -> Result<std::ops::Range<usize>, ParaglobError> {
    let start = usize::try_from(header.ac_literal_map_offset).map_err(|_| {
        ParaglobError::Validation("AC literal map offset is not addressable".to_string())
    })?;
    let glob_start = usize::try_from(header.glob_segments_offset).map_err(|_| {
        ParaglobError::Validation("Glob segment offset is not addressable".to_string())
    })?;
    let end = if glob_start > start && glob_start <= buffer_len {
        glob_start
    } else {
        buffer_len
    };
    if start >= end {
        return Err(ParaglobError::Validation(format!(
            "AC literal map range {start}..{end} is invalid"
        )));
    }
    Ok(start..end)
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
/// Serialized indexes are stored in one byte buffer and accessed through
/// checked views. Supports both owned buffers (built from patterns) and
/// borrowed buffers (memory-mapped files).
///
/// Literal-to-pattern mapping uses average-case O(1) hash probing. End-to-end
/// query cost also includes text traversal, emitted candidates, pure wildcards,
/// and glob verification.
///
/// # Security
///
/// Loading validates serialized envelopes and UTF-8 payloads. For untrusted or
/// resource-constrained queries, use [`Self::try_find_first_bounded`] or
/// [`Self::try_find_all_bounded`] to enforce aggregate work limits.
pub struct Paraglob {
    /// Binary buffer containing all data
    buffer: BufferStorage,
    /// Validated header copied at load time.
    header: ParaglobHeader,
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
            header: ParaglobHeader::new(),
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
    fn try_visit_matches_unsorted_impl<const BOUNDED: bool>(
        &self,
        text: &str,
        max_matching_work: usize,
        work_budget: &mut MatchingWorkBudget,
        mut visit: impl FnMut(u32) -> Result<(), ParaglobError>,
    ) -> Result<(), ParaglobError> {
        if BOUNDED && text.len() > max_matching_work {
            return Err(ParaglobError::ResourceLimitExceeded(
                "Query byte/work limit exceeded".to_string(),
            ));
        }
        if !work_budget.try_charge::<BOUNDED>(text.len()) {
            return Err(matching_work_limit_error());
        }

        let buffer = self.buffer.as_slice();
        if buffer.is_empty() {
            return Ok(());
        }

        let header = self.header;
        let glob_section = SerializedGlobSection::from_header(&header, buffer.len());

        // Phase 1: Use AC automaton to find literal matches and candidate patterns
        let Ok(ac_start) = usize::try_from(header.ac_nodes_offset) else {
            return Ok(());
        };
        let Ok(ac_size) = usize::try_from(header.ac_edges_size) else {
            return Ok(());
        };

        // Reuse thread-local buffers (clear from previous query)
        CANDIDATE_BUFFER.with(|buf| buf.borrow_mut().clear());
        AC_LITERAL_BUFFER.with(|buf| buf.borrow_mut().clear());

        if ac_size > 0 {
            // Extract AC buffer and run AC matching on it
            let Some(ac_end) = ac_start.checked_add(ac_size) else {
                return Ok(());
            };
            let Some(ac_buffer) = buffer.get(ac_start..ac_end) else {
                return Ok(());
            };

            // Run AC automaton matching directly on text bytes (AC handles case-insensitivity)
            let text_bytes = text.as_bytes();
            let mode = self.mode;
            let literal_hit_error = AC_LITERAL_BUFFER.with(|buf| {
                Self::run_ac_matching_into_static::<BOUNDED>(
                    ac_buffer,
                    text_bytes,
                    mode,
                    usize::try_from(header.ac_node_count).unwrap_or(0),
                    max_matching_work,
                    &mut buf.borrow_mut(),
                    work_budget,
                )
            });
            if let Some(message) = literal_hit_error {
                return Err(ParaglobError::ResourceLimitExceeded(message.to_string()));
            }
            #[cfg(feature = "bench-diagnostics")]
            AC_LITERAL_BUFFER.with(|buf| {
                let ac_literal_hits = buf.borrow().len();
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.ac_literal_hits = ac_literal_hits;
                });
            });

            // Map AC literal IDs to pattern IDs using hash table lookup (O(1))
            let candidate_error = AC_LITERAL_BUFFER.with(|ac_buf| {
                let mut candidate_error = None;
                if !ac_buf.borrow().is_empty() {
                    if let Some(ref ac_hash) = self.ac_literal_hash {
                        CANDIDATE_BUFFER.with(|cand_buf| {
                            let mut candidates = cand_buf.borrow_mut();
                            for &literal_id in ac_buf.borrow().iter() {
                                if !BOUNDED {
                                    ac_hash.visit_pattern_ids(literal_id, |pattern_id| {
                                        candidates.push(pattern_id);
                                    });
                                    continue;
                                }
                                let visit_result = ac_hash.try_visit_pattern_ids_while(
                                    literal_id,
                                    |units| work_budget.try_charge::<BOUNDED>(units),
                                    |pattern_id| {
                                        if candidates.len() >= max_matching_work {
                                            candidate_error =
                                                Some("Raw pattern candidate limit exceeded");
                                            return false;
                                        }
                                        if candidates.len() == candidates.capacity()
                                            && candidates.try_reserve(1).is_err()
                                        {
                                            candidate_error =
                                                Some("Raw pattern candidate allocation failed");
                                            return false;
                                        }
                                        candidates.push(pattern_id);
                                        true
                                    },
                                );
                                if visit_result.is_err() {
                                    candidate_error = Some("Matching work limit exceeded");
                                }
                                if candidate_error.is_some() {
                                    break;
                                }
                            }
                        });
                    }
                }
                candidate_error
            });
            if let Some(message) = candidate_error {
                return Err(ParaglobError::ResourceLimitExceeded(message.to_string()));
            }
            let raw_candidate_count =
                CANDIDATE_BUFFER.with(|buf| -> Result<usize, ParaglobError> {
                    let mut candidates = buf.borrow_mut();
                    let raw_candidate_pattern_ids = candidates.len();
                    if !work_budget
                        .try_charge::<BOUNDED>(sort_dedup_work(raw_candidate_pattern_ids))
                    {
                        return Err(matching_work_limit_error());
                    }
                    candidates.sort_unstable();
                    candidates.dedup();
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.raw_candidate_pattern_ids = raw_candidate_pattern_ids;
                    });
                    Ok(raw_candidate_pattern_ids)
                })?;
            #[cfg(feature = "bench-diagnostics")]
            CANDIDATE_BUFFER.with(|buf| {
                let candidate_pattern_ids = buf.borrow().len();
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.candidate_pattern_ids = candidate_pattern_ids;
                });
            });
            if BOUNDED
                && usize::try_from(header.wildcard_count)
                    .ok()
                    .and_then(|count| raw_candidate_count.checked_add(count))
                    .is_none_or(|total| total > max_matching_work)
            {
                return Err(ParaglobError::ResourceLimitExceeded(
                    "Raw pattern candidate and wildcard limit exceeded".to_string(),
                ));
            }
        } else if BOUNDED
            && usize::try_from(header.wildcard_count)
                .ok()
                .is_none_or(|count| count > max_matching_work)
        {
            return Err(ParaglobError::ResourceLimitExceeded(
                "Pure wildcard check limit exceeded".to_string(),
            ));
        }

        // CRITICAL: Always check pure wildcards first (patterns with no literals)
        // These must be checked on every query regardless of AC results
        // Wildcards are stored after pattern strings with 8-byte alignment padding
        let Some(unaligned_offset) = usize::try_from(header.pattern_strings_offset)
            .ok()
            .and_then(|offset| {
                usize::try_from(header.pattern_strings_size)
                    .ok()
                    .and_then(|size| offset.checked_add(size))
            })
        else {
            return Ok(());
        };
        let alignment = 8;
        let padding = (alignment - (unaligned_offset % alignment)) % alignment;
        let Some(wildcards_offset) = unaligned_offset.checked_add(padding) else {
            return Ok(());
        };
        let Ok(wildcard_count) = usize::try_from(header.wildcard_count) else {
            return Ok(());
        };

        if wildcard_count > 0 {
            let Some(wildcards_size) = wildcard_count.checked_mul(mem::size_of::<SingleWildcard>())
            else {
                return Ok(());
            };
            let Some(wildcards) = buffer
                .get(wildcards_offset..)
                .and_then(|tail| tail.get(..wildcards_size))
            else {
                return Ok(());
            };
            let mut text_char_counter = TextCharCounter::new(text);
            for buffer_slice in wildcards.chunks_exact(mem::size_of::<SingleWildcard>()) {
                if !work_budget.try_charge::<BOUNDED>(1) {
                    return Err(matching_work_limit_error());
                }
                let (wildcard, _) = match SingleWildcard::read_from_prefix(buffer_slice) {
                    Ok(value) => value,
                    Err(_) => continue, // Skip corrupted wildcard
                };

                // Check glob pattern using zero-copy matcher
                #[cfg(feature = "bench-diagnostics")]
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.pure_wildcard_checks += 1;
                    diagnostics.glob_verification_attempts += 1;
                });
                let matches = if let Some(section) = glob_section {
                    Self::match_glob_from_buffer::<BOUNDED>(
                        buffer,
                        wildcard.pattern_id,
                        text,
                        &mut text_char_counter,
                        self.mode,
                        section,
                        work_budget,
                    )?
                } else {
                    false
                };
                if matches {
                    #[cfg(feature = "bench-diagnostics")]
                    Self::record_lookup_diagnostic(|diagnostics| {
                        diagnostics.successful_glob_verifications += 1;
                    });
                    visit(wildcard.pattern_id)?;
                }
            }
        }

        // Check AC candidates (patterns that have literals that were found)
        let Ok(patterns_offset) = usize::try_from(header.patterns_offset) else {
            return Ok(());
        };
        let pattern_entry_size = mem::size_of::<PatternEntry>();
        let Some(pattern_entries_size) = usize::try_from(header.pattern_count)
            .ok()
            .and_then(|count| count.checked_mul(pattern_entry_size))
        else {
            return Ok(());
        };
        let Some(pattern_entries) = buffer
            .get(patterns_offset..)
            .and_then(|tail| tail.get(..pattern_entries_size))
        else {
            return Ok(());
        };
        CANDIDATE_BUFFER.with(|buf| -> Result<(), ParaglobError> {
            for &pattern_id in buf.borrow().iter() {
                if !work_budget.try_charge::<BOUNDED>(1) {
                    return Err(matching_work_limit_error());
                }
                if pattern_id >= header.pattern_count {
                    continue;
                }
                let entry_offset =
                    usize::try_from(pattern_id).unwrap_or(usize::MAX) * pattern_entry_size;
                let Some(entry_slice) =
                    pattern_entries.get(entry_offset..entry_offset + pattern_entry_size)
                else {
                    continue;
                };
                let entry_pattern_id = u32::from_le_bytes(
                    entry_slice[..4]
                        .try_into()
                        .expect("bounded pattern entry contains a four-byte ID"),
                );
                let pattern_type = entry_slice[4];

                // Check if pattern matches
                if pattern_type == 0 {
                    // Literal pattern - AC automaton already confirmed this matches!
                    // No need to read string or verify, just add to results.
                    visit(entry_pattern_id)?;
                } else {
                    let Some(glob_section) = glob_section else {
                        continue;
                    };
                    match Self::check_glob_candidate_before_verification::<BOUNDED>(
                        buffer,
                        entry_pattern_id,
                        text,
                        self.mode,
                        glob_section,
                        work_budget,
                    )? {
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
                                visit(entry_pattern_id)?;
                            }
                            continue;
                        }
                        GlobCandidateCheck::FullVerification(pattern) => {
                            // The candidate precheck already validated the
                            // serialized index/range and ruled out the fixed
                            // window path. Continue directly with the general
                            // stack-safe matcher.
                            #[cfg(feature = "bench-diagnostics")]
                            Self::record_lookup_diagnostic(|diagnostics| {
                                diagnostics.glob_verification_attempts += 1;
                            });
                            if Self::match_prepared_glob_from_buffer::<BOUNDED>(
                                buffer,
                                text,
                                self.mode,
                                glob_section,
                                pattern,
                                work_budget,
                            )? {
                                #[cfg(feature = "bench-diagnostics")]
                                Self::record_lookup_diagnostic(|diagnostics| {
                                    diagnostics.successful_glob_verifications += 1;
                                });
                                visit(entry_pattern_id)?;
                            }
                            continue;
                        }
                        GlobCandidateCheck::NoMatch => continue,
                    }
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    fn visit_matches_unsorted(&self, text: &str, mut visit: impl FnMut(u32)) {
        let mut work_budget = MatchingWorkBudget::unbounded();
        let result = self.try_visit_matches_unsorted_impl::<false>(
            text,
            usize::MAX,
            &mut work_budget,
            |pattern_id| {
                visit(pattern_id);
                Ok(())
            },
        );
        debug_assert!(
            result.is_ok(),
            "unbounded visitor cannot return a limit error"
        );
    }

    /// Find the first matching pattern ID in the same sorted order used by `find_all`.
    ///
    /// This avoids allocating an owned result vector, making it suitable for
    /// offset-only lookup paths that only need one match.
    ///
    /// This compatibility method does not impose a work limit. Use
    /// [`Self::try_find_first_bounded`] for untrusted or attacker-controlled
    /// query text or database bytes.
    #[must_use]
    pub fn find_first(&self, text: &str) -> Option<u32> {
        let mut first = None;
        self.visit_matches_unsorted(text, |pattern_id| {
            first = Some(first.map_or(pattern_id, |current: u32| current.min(pattern_id)));
        });
        first
    }

    /// Find the first matching pattern ID with an aggregate matching-work cap.
    ///
    /// The returned ID uses the same sorted ordering as [`Self::find_first`].
    /// `max_matching_work` bounds query bytes, unique AC literal hits, raw
    /// mapped candidates, and pure-wildcard checks independently. One shared
    /// CPU allowance of `64 * max_matching_work` is charged across automaton
    /// traversal, mapping, verification, and sorting. The multiplier keeps the
    /// documented cardinality ceilings usable while preventing multiplicative
    /// work amplification.
    ///
    /// # Errors
    ///
    /// Returns [`ParaglobError::ResourceLimitExceeded`] when an independent
    /// `max_matching_work` cap or the derived shared CPU allowance is exhausted,
    /// or when bounded buffer growth fails.
    pub fn try_find_first_bounded(
        &self,
        text: &str,
        max_matching_work: usize,
    ) -> Result<Option<u32>, ParaglobError> {
        let mut first = None;
        let mut visit = |pattern_id| {
            first = Some(first.map_or(pattern_id, |current: u32| current.min(pattern_id)));
            Ok(())
        };
        if max_matching_work == usize::MAX {
            let mut work_budget = MatchingWorkBudget::unbounded();
            self.try_visit_matches_unsorted_impl::<false>(
                text,
                max_matching_work,
                &mut work_budget,
                &mut visit,
            )?;
        } else {
            let mut work_budget = MatchingWorkBudget::bounded(max_matching_work);
            self.try_visit_matches_unsorted_impl::<true>(
                text,
                max_matching_work,
                &mut work_budget,
                &mut visit,
            )?;
        }
        Ok(first)
    }

    /// Find all matching pattern IDs.
    ///
    /// This compatibility method does not impose match-count or work limits.
    /// Use [`Self::try_find_all_bounded`] for untrusted or attacker-controlled
    /// query text or database bytes.
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

    /// Find all matching pattern IDs with aggregate match and work caps.
    ///
    /// Matches retain the sorted, deduplicated ordering of [`Self::find_all`].
    /// `max_matching_work` independently bounds query bytes, unique AC literal
    /// hits, raw mapped candidates, and pure-wildcard checks. One shared CPU
    /// allowance of `64 * max_matching_work` is charged across automaton
    /// traversal, mapping, verification, and sorting. `max_matches` remains a
    /// separate result-cardinality cap.
    ///
    /// # Errors
    ///
    /// Returns [`ParaglobError::ResourceLimitExceeded`] when either cardinality
    /// cap or the derived shared CPU allowance is exhausted, or when bounded
    /// buffer allocation fails.
    pub fn try_find_all_bounded(
        &self,
        text: &str,
        max_matches: usize,
        max_matching_work: usize,
    ) -> Result<Vec<u32>, ParaglobError> {
        let mut result = Vec::new();
        let mut visit = |pattern_id| {
            if result.len() >= max_matches {
                return Err(ParaglobError::ResourceLimitExceeded(
                    "Pattern match limit exceeded".to_string(),
                ));
            }
            if result.len() == result.capacity() {
                result.try_reserve(1).map_err(|_| {
                    ParaglobError::ResourceLimitExceeded(
                        "Pattern match result allocation failed".to_string(),
                    )
                })?;
            }
            result.push(pattern_id);
            Ok(())
        };
        if max_matching_work == usize::MAX {
            let mut work_budget = MatchingWorkBudget::unbounded();
            self.try_visit_matches_unsorted_impl::<false>(
                text,
                max_matching_work,
                &mut work_budget,
                &mut visit,
            )?;
        } else {
            let mut work_budget = MatchingWorkBudget::bounded(max_matching_work);
            self.try_visit_matches_unsorted_impl::<true>(
                text,
                max_matching_work,
                &mut work_budget,
                &mut visit,
            )?;
            if !work_budget.try_charge::<true>(sort_dedup_work(result.len())) {
                return Err(matching_work_limit_error());
            }
        }
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    /// Run AC automaton matching on the offset-based buffer
    /// Writes AC literal IDs into the provided HashSet (avoids allocation)
    fn run_ac_matching_into_static<const BOUNDED: bool>(
        ac_buffer: &[u8],
        text: &[u8],
        mode: MatchMode,
        node_count: usize,
        max_literal_hits: usize,
        matches: &mut HashSet<u32>,
        work_budget: &mut MatchingWorkBudget,
    ) -> Option<&'static str> {
        if ac_buffer.is_empty() || text.is_empty() || node_count == 0 {
            return None;
        }

        match mode {
            MatchMode::CaseSensitive => Self::run_ac_matching_normalized::<BOUNDED>(
                ac_buffer,
                text,
                node_count,
                max_literal_hits,
                matches,
                work_budget,
            ),
            MatchMode::CaseInsensitive => NORMALIZED_TEXT_BUFFER.with(|buf| {
                let mut normalized = buf.borrow_mut();
                if BOUNDED {
                    normalized.clear();
                    if normalized.try_reserve_exact(text.len()).is_err() {
                        return Some("Normalized query allocation failed");
                    }
                }
                crate::simd_utils::ascii_lowercase(text, &mut normalized);
                Self::run_ac_matching_normalized::<BOUNDED>(
                    ac_buffer,
                    &normalized,
                    node_count,
                    max_literal_hits,
                    matches,
                    work_budget,
                )
            }),
        }
    }

    #[inline(always)]
    fn read_ac_node(nodes: &[u8], node_offset: usize) -> Option<crate::offset_format::ACNodeHot> {
        use crate::offset_format::ACNodeHot;

        let node_size = mem::size_of::<ACNodeHot>();
        let node_bytes = nodes.get(node_offset..)?.get(..node_size)?;
        ACNodeHot::read_from_prefix(node_bytes)
            .ok()
            .map(|(node, _)| node)
    }

    #[inline(always)]
    fn read_u32_le(buffer: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(mem::size_of::<u32>())?;
        let bytes: [u8; 4] = buffer.get(offset..end)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    #[inline(always)]
    fn checked_ac_target(target_offset: u32, nodes_size: usize) -> Option<usize> {
        let target = usize::try_from(target_offset).ok()?;
        // Node reads are byte-based and therefore do not require aligned
        // offsets. Keeping this check to the actual safety invariant avoids a
        // division on every automaton transition while malformed targets still
        // fail closed in `read_ac_node`.
        if target == 0 || target >= nodes_size {
            return None;
        }
        Some(target)
    }

    /// Run AC automaton matching on already-normalized bytes.
    fn run_ac_matching_normalized<const BOUNDED: bool>(
        ac_buffer: &[u8],
        search_text: &[u8],
        node_count: usize,
        max_literal_hits: usize,
        matches: &mut HashSet<u32>,
        work_budget: &mut MatchingWorkBudget,
    ) -> Option<&'static str> {
        use crate::offset_format::{ACNodeHot, StateKind};

        let nodes_size = node_count.checked_mul(mem::size_of::<ACNodeHot>())?;
        if nodes_size > ac_buffer.len() {
            return None;
        }
        let nodes = &ac_buffer[..nodes_size];

        // Read the root by value so neither the mmap base nor a malicious
        // offset needs to be naturally aligned. Current writers use Dense,
        // while older v5 writers may use Empty, One, or Sparse.
        let root_node = Self::read_ac_node(nodes, 0)?;
        let root_kind = StateKind::from_u8(root_node.state_kind)?;
        let root_dense_table = if root_kind == StateKind::Dense {
            let Ok(root_dense_offset) = usize::try_from(root_node.edges_offset) else {
                return None;
            };
            if root_dense_offset < nodes_size
                || !root_dense_offset.is_multiple_of(mem::size_of::<u32>())
            {
                return None;
            }
            let root_dense_end = root_dense_offset.checked_add(256 * mem::size_of::<u32>())?;
            let root_dense_table = ac_buffer.get(root_dense_offset..root_dense_end)?;
            Some(root_dense_table)
        } else {
            None
        };

        let mut current_offset = 0usize; // Start at root node

        for &search_ch in search_text.iter() {
            let mut failure_hops_remaining = node_count;

            // Traverse to next state
            loop {
                if current_offset == 0 {
                    if let Some(root_dense_table) = root_dense_table {
                        // Preserve the direct-table hot path for current files.
                        if !work_budget.try_charge::<BOUNDED>(1) {
                            return Some("Matching work limit exceeded");
                        }
                        let target_offset = usize::from(search_ch) * mem::size_of::<u32>();
                        let target_bytes: [u8; 4] = root_dense_table
                            [target_offset..target_offset + mem::size_of::<u32>()]
                            .try_into()
                            .expect("u8-indexed dense lookup always contains four bytes");
                        let target = u32::from_le_bytes(target_bytes);
                        if target != 0 {
                            if let Some(target) = Self::checked_ac_target(target, nodes_size) {
                                current_offset = target;
                            }
                        }
                    } else {
                        let transition = match Self::find_ac_transition_with_budget::<BOUNDED>(
                            ac_buffer,
                            root_node,
                            search_ch,
                            nodes_size,
                            work_budget,
                        ) {
                            Ok(transition) => transition,
                            Err(error) => return Some(error),
                        };
                        if let Some(target) = transition {
                            current_offset = target;
                        }
                    }
                    break;
                }

                let Some(node) = Self::read_ac_node(nodes, current_offset) else {
                    current_offset = 0;
                    break;
                };

                // Try to find transition for non-root nodes.
                let transition = match Self::find_ac_transition_with_budget::<BOUNDED>(
                    ac_buffer,
                    node,
                    search_ch,
                    nodes_size,
                    work_budget,
                ) {
                    Ok(transition) => transition,
                    Err(error) => return Some(error),
                };
                if let Some(next_offset) = transition {
                    current_offset = next_offset;
                    break;
                }

                if failure_hops_remaining == 0 {
                    // A well-formed automaton reaches root in fewer than
                    // `node_count` hops. This also terminates malicious cycles.
                    current_offset = 0;
                    break;
                }
                if !work_budget.try_charge::<BOUNDED>(1) {
                    return Some("Matching work limit exceeded");
                }
                failure_hops_remaining -= 1;

                if node.failure_offset == 0 {
                    current_offset = 0;
                    continue;
                }
                let Some(failure_offset) = Self::checked_ac_target(node.failure_offset, nodes_size)
                else {
                    current_offset = 0;
                    break;
                };
                current_offset = failure_offset;
            }

            // Collect pattern IDs at this state (skip for root - no patterns there)
            if current_offset == 0 {
                continue;
            }

            let Some(node) = Self::read_ac_node(nodes, current_offset) else {
                current_offset = 0;
                continue;
            };

            if node.pattern_count > 0 {
                let Ok(patterns_offset) = usize::try_from(node.patterns_offset) else {
                    continue;
                };
                if patterns_offset < nodes_size
                    || !patterns_offset.is_multiple_of(mem::size_of::<u32>())
                {
                    continue;
                }
                let pattern_count = usize::from(node.pattern_count);
                let Some(patterns_size) = pattern_count.checked_mul(mem::size_of::<u32>()) else {
                    continue;
                };
                if patterns_offset
                    .checked_add(patterns_size)
                    .is_none_or(|end| end > ac_buffer.len())
                {
                    continue;
                }
                let Some(patterns) = ac_buffer
                    .get(patterns_offset..)
                    .and_then(|tail| tail.get(..pattern_count * mem::size_of::<u32>()))
                else {
                    continue;
                };
                for pattern in patterns.chunks_exact(mem::size_of::<u32>()) {
                    if !work_budget.try_charge::<BOUNDED>(1) {
                        return Some("Matching work limit exceeded");
                    }
                    let pattern_id = u32::from_le_bytes(
                        pattern
                            .try_into()
                            .expect("bounded pattern list contains four-byte entries"),
                    );
                    if !BOUNDED {
                        matches.insert(pattern_id);
                        continue;
                    }
                    if matches.len() >= max_literal_hits {
                        if matches.contains(&pattern_id) {
                            continue;
                        }
                        return Some("AC literal hit limit exceeded");
                    }
                    if matches.len() == matches.capacity() && matches.try_reserve(1).is_err() {
                        return Some("AC literal hit allocation failed");
                    }
                    matches.insert(pattern_id);
                }
            }
        }
        None
    }

    /// Find a transition from a node for a character in AC automaton
    /// Uses state-specific encoding for optimal performance
    #[inline(always)]
    fn find_ac_transition(
        ac_buffer: &[u8],
        node: crate::offset_format::ACNodeHot,
        ch: u8,
        nodes_size: usize,
    ) -> Option<usize> {
        use crate::offset_format::StateKind;

        // Dispatch on state encoding
        let kind = StateKind::from_u8(node.state_kind)?;

        match kind {
            StateKind::Empty => None,

            StateKind::One => {
                // Single inline comparison
                if node.one_char == ch {
                    Self::checked_ac_target(node.edges_offset, nodes_size)
                } else {
                    None
                }
            }

            StateKind::Sparse => {
                // Linear search through sparse edges
                let edges_offset = usize::try_from(node.edges_offset).ok()?;
                let edge_size = mem::size_of::<ACEdge>();
                let count = usize::from(node.edge_count);
                if edges_offset < nodes_size || !edges_offset.is_multiple_of(mem::size_of::<u32>())
                {
                    return None;
                }
                let edges_size = count.checked_mul(edge_size)?;
                if edges_offset.checked_add(edges_size)? > ac_buffer.len() {
                    return None;
                }

                let edges = ac_buffer.get(edges_offset..)?.get(..edges_size)?;
                for edge in edges.chunks_exact(edge_size) {
                    let edge_character = edge[0];

                    if edge_character == ch {
                        let target_start = std::mem::offset_of!(ACEdge, target_offset);
                        let target = u32::from_le_bytes(
                            edge[target_start..target_start + mem::size_of::<u32>()]
                                .try_into()
                                .expect("bounded AC edge contains a four-byte target"),
                        );
                        return Self::checked_ac_target(target, nodes_size);
                    }
                    if edge_character > ch {
                        return None;
                    }
                }
                None
            }

            StateKind::Dense => {
                let lookup_offset = usize::try_from(node.edges_offset).ok()?;
                if lookup_offset < nodes_size
                    || !lookup_offset.is_multiple_of(mem::size_of::<u32>())
                {
                    return None;
                }
                let target_offset =
                    checked_index_offset(lookup_offset, usize::from(ch), mem::size_of::<u32>())?;
                let target = Self::read_u32_le(ac_buffer, target_offset)?;
                Self::checked_ac_target(target, nodes_size)
            }
        }
    }

    #[inline(always)]
    fn find_ac_transition_with_budget<const BOUNDED: bool>(
        ac_buffer: &[u8],
        node: crate::offset_format::ACNodeHot,
        ch: u8,
        nodes_size: usize,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<Option<usize>, &'static str> {
        if BOUNDED {
            use crate::offset_format::StateKind;

            let Some(kind) = StateKind::from_u8(node.state_kind) else {
                return Ok(None);
            };
            let work = if kind == StateKind::Sparse {
                usize::from(node.edge_count).max(1)
            } else {
                1
            };
            if !work_budget.try_charge::<true>(work) {
                return Err("Matching work limit exceeded");
            }
        }

        Ok(Self::find_ac_transition(ac_buffer, node, ch, nodes_size))
    }

    /// Get the buffer (for serialization)
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn charge_glob_verification<const BOUNDED: bool>(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text_len: usize,
        pattern: SerializedGlobPattern,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<bool, ParaglobError> {
        if !BOUNDED {
            return Ok(true);
        }

        // Pay for validating the headers before using their contents to derive
        // a conservative scan bound.
        if !work_budget.try_charge::<true>(pattern.segment_count) {
            return Err(matching_work_limit_error());
        }

        let mut pattern_complexity = pattern.segment_count.max(1);
        for seg_idx in 0..pattern.segment_count {
            let Some(header) =
                glob_section.segment_header(buffer, pattern.first_segment_offset, seg_idx)
            else {
                return Ok(false);
            };
            match header.segment_type {
                // A literal may be compared at every overlapping text
                // position, especially in case-insensitive and backtracking
                // paths, so its full byte length participates in the scan
                // product.
                0 => {
                    pattern_complexity = pattern_complexity
                        .saturating_add(usize::try_from(header.data_len).unwrap_or(usize::MAX));
                }
                3 => {
                    let item_size = mem::size_of::<crate::offset_format::CharClassItemEncoded>();
                    let item_count =
                        usize::try_from(header.data_len).unwrap_or(usize::MAX) / item_size;
                    pattern_complexity = pattern_complexity.saturating_add(item_count);
                }
                _ => {}
            }
        }

        // This covers full-text literal searches, fixed-window overlap scans,
        // case-insensitive/overlapping literal byte comparisons, and every
        // character-class item that may be inspected at each text position.
        let scan_work = text_len.saturating_mul(pattern_complexity);
        if !work_budget.try_charge::<true>(scan_work) {
            return Err(matching_work_limit_error());
        }
        Ok(true)
    }

    /// Match text against serialized glob segments directly from buffer (zero-copy)
    ///
    /// This function reads `GlobSegmentHeader` values directly from the
    /// serialized buffer without copying pattern data. Matching is stack safe
    /// and keeps only the most recent `*` backtracking point.
    fn match_glob_from_buffer<const BOUNDED: bool>(
        buffer: &[u8],
        pattern_id: u32,
        text: &str,
        text_char_counter: &mut TextCharCounter<'_>,
        mode: MatchMode,
        glob_section: SerializedGlobSection,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<bool, ParaglobError> {
        let Some(pattern) = glob_section.pattern(buffer, pattern_id) else {
            return Ok(false);
        };
        if !Self::charge_glob_verification::<BOUNDED>(
            buffer,
            glob_section,
            text.len(),
            pattern,
            work_budget,
        )? {
            return Ok(false);
        }

        if let Some(matches) = Self::match_question_star_only_glob_from_buffer(
            buffer,
            glob_section,
            text_char_counter,
            pattern,
        ) {
            return Ok(matches);
        }

        if let Some(matches) = Self::match_fixed_window_glob_from_buffer(
            buffer,
            glob_section,
            text,
            pattern.first_segment_offset,
            pattern.segment_count,
            mode,
        ) {
            return Ok(matches);
        }

        Self::match_prepared_glob_from_buffer::<BOUNDED>(
            buffer,
            text,
            mode,
            glob_section,
            pattern,
            work_budget,
        )
    }

    fn match_question_star_only_glob_from_buffer(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text_char_counter: &mut TextCharCounter<'_>,
        pattern: SerializedGlobPattern,
    ) -> Option<bool> {
        let mut question_count = 0usize;
        let mut has_star = false;
        let header_size = mem::size_of::<crate::offset_format::GlobSegmentHeader>();
        let headers_size = pattern.segment_count.checked_mul(header_size)?;
        let headers = glob_section.data(buffer, pattern.first_segment_offset, headers_size)?;

        for header in headers.chunks_exact(header_size) {
            // Stars and questions have zero flags, data offset, and data length.
            // The two reserved bytes are intentionally ignored for compatibility.
            if header[1] != 0 || header[4..12].iter().any(|byte| *byte != 0) {
                return None;
            }
            match header[0] {
                1 => has_star = true,
                2 => question_count = question_count.checked_add(1)?,
                _ => return None,
            }
        }

        if has_star {
            return Some(text_char_counter.at_least(question_count));
        }

        Some(text_char_counter.exactly(question_count))
    }

    fn match_prepared_glob_from_buffer<const BOUNDED: bool>(
        buffer: &[u8],
        text: &str,
        mode: MatchMode,
        glob_section: SerializedGlobSection,
        pattern: SerializedGlobPattern,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<bool, ParaglobError> {
        // Validate each immutable serialized segment once before entering the
        // backtracking loop. The matcher can then use bounded raw header reads
        // instead of repeating payload and UTF-8 validation at every state.
        for seg_idx in 0..pattern.segment_count {
            if glob_section
                .segment_header(buffer, pattern.first_segment_offset, seg_idx)
                .is_none()
            {
                return Ok(false);
            }
        }

        // Match using segments directly from buffer
        let mut steps_remaining = if BOUNDED {
            PER_PATTERN_GLOB_STEP_LIMIT.min(work_budget.remaining())
        } else {
            PER_PATTERN_GLOB_STEP_LIMIT
        };
        let mut backtrack = None;
        Self::match_segments_impl::<BOUNDED>(
            buffer,
            glob_section,
            text,
            pattern.first_segment_offset,
            pattern.segment_count,
            0, // text_pos
            0, // seg_idx
            mode,
            &mut steps_remaining,
            &mut backtrack,
            work_budget,
        )
    }

    fn check_glob_candidate_before_verification<const BOUNDED: bool>(
        buffer: &[u8],
        pattern_id: u32,
        text: &str,
        mode: MatchMode,
        glob_section: SerializedGlobSection,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<GlobCandidateCheck, ParaglobError> {
        let Some(pattern) = glob_section.pattern(buffer, pattern_id) else {
            return Ok(GlobCandidateCheck::NoMatch);
        };

        if let Some(matches) = Self::match_single_internal_star_glob_from_buffer::<BOUNDED>(
            buffer,
            glob_section,
            text,
            pattern,
            mode,
            work_budget,
        )? {
            return Ok(GlobCandidateCheck::Simple(matches));
        }

        if !Self::charge_glob_verification::<BOUNDED>(
            buffer,
            glob_section,
            text.len(),
            pattern,
            work_budget,
        )? {
            return Ok(GlobCandidateCheck::NoMatch);
        }

        if let Some(matches) = Self::match_fixed_window_glob_from_buffer(
            buffer,
            glob_section,
            text,
            pattern.first_segment_offset,
            pattern.segment_count,
            mode,
        ) {
            return Ok(GlobCandidateCheck::Simple(matches));
        }

        if Self::glob_literal_segments_match_in_order_from_index(
            buffer,
            glob_section,
            pattern,
            text,
            mode,
        ) {
            Ok(GlobCandidateCheck::FullVerification(pattern))
        } else {
            Ok(GlobCandidateCheck::NoMatch)
        }
    }

    /// Fast path for the common `literal*literal` shape.
    ///
    /// The two literals must not overlap: the `*` may match an empty sequence,
    /// but it cannot make the same text bytes satisfy both adjacent segments.
    fn match_single_internal_star_glob_from_buffer<const BOUNDED: bool>(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        pattern: SerializedGlobPattern,
        mode: MatchMode,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<Option<bool>, ParaglobError> {
        if pattern.segment_count != 3 {
            return Ok(None);
        }
        if !work_budget.try_charge::<BOUNDED>(3) {
            return Err(matching_work_limit_error());
        }

        let prefix_header = glob_section.segment_header(buffer, pattern.first_segment_offset, 0);
        let star_header = glob_section.segment_header(buffer, pattern.first_segment_offset, 1);
        let suffix_header = glob_section.segment_header(buffer, pattern.first_segment_offset, 2);
        let (Some(prefix_header), Some(star_header), Some(suffix_header)) =
            (prefix_header, star_header, suffix_header)
        else {
            return Ok(None);
        };
        if prefix_header.segment_type != 0
            || star_header.segment_type != 1
            || suffix_header.segment_type != 0
        {
            return Ok(None);
        }

        let Some(prefix) = glob_section.data(
            buffer,
            usize::try_from(prefix_header.data_offset).unwrap_or(usize::MAX),
            usize::try_from(prefix_header.data_len).unwrap_or(usize::MAX),
        ) else {
            return Ok(None);
        };
        let Some(suffix) = glob_section.data(
            buffer,
            usize::try_from(suffix_header.data_offset).unwrap_or(usize::MAX),
            usize::try_from(suffix_header.data_len).unwrap_or(usize::MAX),
        ) else {
            return Ok(None);
        };
        if !work_budget.try_charge::<BOUNDED>(prefix.len().saturating_add(suffix.len())) {
            return Err(matching_work_limit_error());
        }
        if prefix
            .len()
            .checked_add(suffix.len())
            .is_none_or(|minimum_len| text.len() < minimum_len)
        {
            return Ok(Some(false));
        }

        let text = text.as_bytes();
        Ok(Some(
            Self::bytes_start_with(text, prefix, mode) && Self::bytes_end_with(text, suffix, mode),
        ))
    }

    fn match_fixed_window_glob_from_buffer(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        segment_count: usize,
        mode: MatchMode,
    ) -> Option<bool> {
        if Self::fixed_window_quick_reject(
            buffer,
            glob_section,
            first_segment_offset,
            segment_count,
        ) {
            return None;
        }

        let shape =
            Self::fixed_window_shape(buffer, glob_section, first_segment_offset, segment_count)?;

        if shape.end_seg_idx == shape.start_seg_idx + 1 {
            if let Some(literal) =
                glob_section.data(buffer, shape.first_literal_offset, shape.first_literal_len)
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
                glob_section,
                text,
                first_segment_offset,
                &shape,
                mode,
            ),
            (true, false) => Self::fixed_window_matches_suffix(
                buffer,
                glob_section,
                text,
                first_segment_offset,
                &shape,
                mode,
            ),
            (false, true) => Self::fixed_window_matches_at(
                buffer,
                glob_section,
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
        glob_section: SerializedGlobSection,
        first_segment_offset: usize,
        segment_count: usize,
    ) -> bool {
        if segment_count <= 3 {
            return false;
        }

        let Some(first_type) = Self::segment_type_at(buffer, glob_section, first_segment_offset, 0)
        else {
            return false;
        };

        if first_type == 1 {
            return Self::segment_type_at(buffer, glob_section, first_segment_offset, 2) == Some(1);
        }

        Self::segment_type_at(buffer, glob_section, first_segment_offset, 1) == Some(1)
    }

    fn fixed_window_shape(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        first_segment_offset: usize,
        segment_count: usize,
    ) -> Option<FixedWindowShape> {
        if segment_count < 2 {
            return None;
        }

        let mut start_seg_idx = 0usize;
        let mut end_seg_idx = segment_count;
        let mut has_leading_star = false;
        let mut has_trailing_star = false;

        let first_header = glob_section.segment_header(buffer, first_segment_offset, 0)?;
        let last_header =
            glob_section.segment_header(buffer, first_segment_offset, segment_count - 1)?;

        if first_header.segment_type == 1 {
            has_leading_star = true;
            start_seg_idx = 1;
        }

        if last_header.segment_type == 1 {
            has_trailing_star = true;
            end_seg_idx -= 1;
        }

        if !has_leading_star && !has_trailing_star || start_seg_idx >= end_seg_idx {
            return None;
        }

        let mut first_literal = None;

        for seg_idx in start_seg_idx..end_seg_idx {
            let seg_header = if seg_idx == 0 {
                first_header
            } else if seg_idx == segment_count - 1 {
                last_header
            } else {
                glob_section.segment_header(buffer, first_segment_offset, seg_idx)?
            };

            match seg_header.segment_type {
                0 => {
                    if seg_idx == start_seg_idx {
                        first_literal = Some((
                            usize::try_from(seg_header.data_offset).ok()?,
                            usize::try_from(seg_header.data_len).ok()?,
                        ));
                    }
                }
                2 | 3 => {}
                _ => return None,
            }
        }

        let (first_literal_offset, first_literal_len) = first_literal?;

        Some(FixedWindowShape {
            start_seg_idx,
            end_seg_idx,
            has_leading_star,
            has_trailing_star,
            first_literal_offset,
            first_literal_len,
        })
    }

    fn segment_type_at(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<u8> {
        glob_section
            .raw_segment_header(buffer, first_segment_offset, seg_idx)
            .map(|header| header.segment_type)
    }

    fn fixed_window_matches_anywhere(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        shape: &FixedWindowShape,
        mode: MatchMode,
    ) -> bool {
        Self::visit_fixed_window_candidate_positions(
            buffer,
            glob_section,
            text,
            shape,
            mode,
            |candidate_pos| {
                Self::fixed_window_matches_at(
                    buffer,
                    glob_section,
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
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        shape: &FixedWindowShape,
        mode: MatchMode,
    ) -> bool {
        Self::visit_fixed_window_candidate_positions(
            buffer,
            glob_section,
            text,
            shape,
            mode,
            |candidate_pos| {
                Self::fixed_window_matches_at(
                    buffer,
                    glob_section,
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
        glob_section: SerializedGlobSection,
        text: &str,
        shape: &FixedWindowShape,
        mode: MatchMode,
        mut visit: impl FnMut(usize) -> bool,
    ) -> bool {
        if let Some(first_literal) =
            glob_section.data(buffer, shape.first_literal_offset, shape.first_literal_len)
        {
            let mut search_pos = 0;
            while let Some((candidate_pos, next_search_pos)) =
                Self::next_overlapping_literal_candidate(text, first_literal, mode, search_pos)
            {
                if visit(candidate_pos) {
                    return true;
                }
                search_pos = next_search_pos;
            }
            return false;
        }

        false
    }

    #[allow(clippy::too_many_arguments)]
    fn fixed_window_matches_at(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        start_seg_idx: usize,
        end_seg_idx: usize,
        mut text_pos: usize,
        mode: MatchMode,
    ) -> Option<usize> {
        if text_pos > text.len() || !text.is_char_boundary(text_pos) {
            return None;
        }

        for seg_idx in start_seg_idx..end_seg_idx {
            // `fixed_window_shape` validated this immutable header and its
            // payload before selecting the fixed-window path. Keep the hot
            // matching loop to one bounded header read per segment.
            let seg_header =
                glob_section.raw_segment_header(buffer, first_segment_offset, seg_idx)?;

            match seg_header.segment_type {
                0 => {
                    let literal = glob_section.data(
                        buffer,
                        usize::try_from(seg_header.data_offset).ok()?,
                        usize::try_from(seg_header.data_len).ok()?,
                    )?;
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
                    if !Self::char_class_matches(buffer, glob_section, seg_header, ch, mode)? {
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
        glob_section: SerializedGlobSection,
        seg_header: crate::offset_format::GlobSegmentHeader,
        ch: char,
        mode: MatchMode,
    ) -> Option<bool> {
        use crate::offset_format::CharClassItemEncoded;

        let ch_normalized = match mode {
            MatchMode::CaseSensitive => ch,
            MatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
        };

        let data_offset = usize::try_from(seg_header.data_offset).ok()?;
        let data_len = usize::try_from(seg_header.data_len).ok()?;
        let item_size = mem::size_of::<CharClassItemEncoded>();
        let item_count = data_len / item_size;

        glob_section.data(buffer, data_offset, data_len)?;

        let negated = seg_header.flags & 1 != 0;
        let mut in_class = false;

        for i in 0..item_count {
            let item_offset = checked_index_offset(data_offset, i, item_size)?;
            let item_slice = glob_section.data(buffer, item_offset, item_size)?;
            let (item, _) = CharClassItemEncoded::read_from_prefix(item_slice).ok()?;

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
                    if start > end {
                        return None;
                    }
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
                _ => return None,
            };

            if matches_item {
                in_class = true;
            }
        }

        Some(if negated { !in_class } else { in_class })
    }

    /// Stack-safe matching implementation that works directly on serialized segments.
    ///
    /// Deterministic transitions are processed in place. Only pending `*`
    /// alternatives are stored on the heap, so even the largest valid v5
    /// segment count cannot overflow the call stack.
    #[allow(clippy::too_many_arguments)]
    fn match_segments_impl<const BOUNDED: bool>(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        segment_count: usize,
        mut text_pos: usize,
        mut seg_idx: usize,
        mode: MatchMode,
        steps_remaining: &mut usize,
        backtrack: &mut Option<GlobBacktrackFrame>,
        work_budget: &mut MatchingWorkBudget,
    ) -> Result<bool, ParaglobError> {
        loop {
            if *steps_remaining == 0 {
                if BOUNDED && work_budget.remaining() == 0 {
                    return Err(matching_work_limit_error());
                }
                return Ok(false);
            }
            if !work_budget.try_charge::<BOUNDED>(1) {
                return Err(matching_work_limit_error());
            }
            *steps_remaining -= 1;
            #[cfg(feature = "bench-diagnostics")]
            Self::record_lookup_diagnostic(|diagnostics| {
                diagnostics.serialized_glob_segment_steps += 1;
            });

            let next_state = if seg_idx >= segment_count {
                if text_pos >= text.len() {
                    return Ok(true);
                }
                None
            } else if let Some(seg_header) =
                glob_section.raw_segment_header(buffer, first_segment_offset, seg_idx)
            {
                match seg_header.segment_type {
                    0 => {
                        let literal = usize::try_from(seg_header.data_offset)
                            .ok()
                            .zip(usize::try_from(seg_header.data_len).ok())
                            .filter(|(_, len)| *len > 0)
                            .and_then(|(offset, len)| glob_section.data(buffer, offset, len));

                        if let Some(literal) = literal {
                            let Some(remaining) = text.as_bytes().get(text_pos..) else {
                                return Ok(false);
                            };
                            Self::bytes_start_with(remaining, literal, mode)
                                .then_some((text_pos + literal.len(), seg_idx + 1))
                        } else {
                            None
                        }
                    }
                    1 => {
                        let next_seg_idx = seg_idx + 1;
                        if next_seg_idx >= segment_count {
                            return Ok(true);
                        }

                        let frame = if Self::next_literal_segment(
                            buffer,
                            glob_section,
                            first_segment_offset,
                            seg_idx,
                            segment_count,
                        )
                        .is_some()
                        {
                            GlobBacktrackFrame::StarBeforeLiteral {
                                search_pos: text_pos,
                                next_seg_idx,
                            }
                        } else {
                            GlobBacktrackFrame::Star {
                                candidate_pos: text_pos,
                                next_seg_idx,
                            }
                        };
                        *backtrack = Some(frame);
                        None
                    }
                    2 => text
                        .get(text_pos..)
                        .and_then(|remaining| remaining.chars().next())
                        .map(|ch| (text_pos + ch.len_utf8(), seg_idx + 1)),
                    3 => text
                        .get(text_pos..)
                        .and_then(|remaining| remaining.chars().next())
                        .and_then(|ch| {
                            Self::char_class_matches(buffer, glob_section, seg_header, ch, mode)
                                .filter(|matches| *matches)
                                .map(|_| (text_pos + ch.len_utf8(), seg_idx + 1))
                        }),
                    _ => None,
                }
            } else {
                None
            };

            if let Some((next_text_pos, next_seg_idx)) = next_state {
                text_pos = next_text_pos;
                seg_idx = next_seg_idx;
                continue;
            }

            let Some((next_text_pos, next_seg_idx)) = Self::next_glob_backtrack_candidate(
                buffer,
                glob_section,
                text,
                first_segment_offset,
                mode,
                backtrack,
            ) else {
                return Ok(false);
            };
            text_pos = next_text_pos;
            seg_idx = next_seg_idx;
        }
    }

    fn next_glob_backtrack_candidate(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        text: &str,
        first_segment_offset: usize,
        mode: MatchMode,
        backtrack: &mut Option<GlobBacktrackFrame>,
    ) -> Option<(usize, usize)> {
        while let Some(frame) = backtrack.take() {
            let candidate = match frame {
                GlobBacktrackFrame::Star {
                    candidate_pos,
                    next_seg_idx,
                } => {
                    if candidate_pos > text.len() || !text.is_char_boundary(candidate_pos) {
                        continue;
                    }
                    if let Some(ch) = text
                        .get(candidate_pos..)
                        .and_then(|text| text.chars().next())
                    {
                        *backtrack = Some(GlobBacktrackFrame::Star {
                            candidate_pos: candidate_pos + ch.len_utf8(),
                            next_seg_idx,
                        });
                    }
                    Some((candidate_pos, next_seg_idx))
                }
                GlobBacktrackFrame::StarBeforeLiteral {
                    search_pos,
                    next_seg_idx,
                } => {
                    let Some(literal) = Self::raw_literal_segment_at(
                        buffer,
                        glob_section,
                        first_segment_offset,
                        next_seg_idx,
                    ) else {
                        continue;
                    };
                    let Some((candidate_pos, next_search_pos)) =
                        Self::next_overlapping_literal_candidate(text, literal, mode, search_pos)
                    else {
                        continue;
                    };

                    if next_search_pos
                        <= text.len().checked_sub(literal.len()).unwrap_or(usize::MAX)
                    {
                        *backtrack = Some(GlobBacktrackFrame::StarBeforeLiteral {
                            search_pos: next_search_pos,
                            next_seg_idx,
                        });
                    }
                    Some((candidate_pos, next_seg_idx))
                }
            };

            if let Some(candidate) = candidate {
                #[cfg(feature = "bench-diagnostics")]
                Self::record_lookup_diagnostic(|diagnostics| {
                    diagnostics.star_backtracking_attempts += 1;
                });
                return Some(candidate);
            }
        }

        None
    }

    fn next_overlapping_literal_candidate(
        text: &str,
        literal: &[u8],
        mode: MatchMode,
        mut search_pos: usize,
    ) -> Option<(usize, usize)> {
        if literal.is_empty() || search_pos > text.len() {
            return None;
        }

        let text_bytes = text.as_bytes();
        match mode {
            MatchMode::CaseSensitive => loop {
                let relative_pos = memchr::memmem::find(text_bytes.get(search_pos..)?, literal)?;
                let candidate_pos = search_pos.checked_add(relative_pos)?;
                if text.is_char_boundary(candidate_pos) {
                    let next_search_pos = candidate_pos
                        .checked_add(text.get(candidate_pos..)?.chars().next()?.len_utf8())?;
                    return Some((candidate_pos, next_search_pos));
                }
                search_pos = candidate_pos.checked_add(1)?;
            },
            MatchMode::CaseInsensitive => {
                let last_start = text.len().checked_sub(literal.len())?;
                while search_pos <= last_start {
                    let candidate_pos = search_pos;
                    search_pos += 1;
                    if !text.is_char_boundary(candidate_pos) {
                        continue;
                    }
                    let candidate = text_bytes.get(candidate_pos..candidate_pos + literal.len())?;
                    if Self::bytes_eq_ignore_ascii_case(candidate, literal) {
                        let next_search_pos = candidate_pos
                            .checked_add(text.get(candidate_pos..)?.chars().next()?.len_utf8())?;
                        return Some((candidate_pos, next_search_pos));
                    }
                }
                None
            }
        }
    }

    fn glob_literal_segments_match_in_order_from_index(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        pattern: SerializedGlobPattern,
        text: &str,
        mode: MatchMode,
    ) -> bool {
        #[cfg(feature = "bench-diagnostics")]
        Self::record_lookup_diagnostic(|diagnostics| {
            diagnostics.literal_order_precheck_attempts += 1;
        });

        let mut search_offset = 0usize;
        let header_size = mem::size_of::<crate::offset_format::GlobSegmentHeader>();
        let Some(headers_size) = pattern.segment_count.checked_mul(header_size) else {
            return false;
        };
        let Some(headers) = glob_section.data(buffer, pattern.first_segment_offset, headers_size)
        else {
            return false;
        };

        for header in headers.chunks_exact(header_size) {
            if header[0] != 0 {
                continue;
            }

            let data_len = usize::try_from(u32::from_le_bytes(
                header[4..8]
                    .try_into()
                    .expect("bounded glob header contains four-byte fields"),
            ))
            .unwrap_or(usize::MAX);
            let data_offset = usize::try_from(u32::from_le_bytes(
                header[8..12]
                    .try_into()
                    .expect("bounded glob header contains four-byte fields"),
            ))
            .unwrap_or(usize::MAX);
            let Some(literal) = glob_section.data(buffer, data_offset, data_len) else {
                // The full verifier will reject a malformed literal. Treat it
                // as non-filtering here so this cheap precheck cannot create a
                // false positive.
                continue;
            };

            let Some(relative_match) = text
                .as_bytes()
                .get(search_offset..)
                .and_then(|remaining| Self::find_literal_bytes(remaining, literal, mode))
            else {
                return false;
            };
            search_offset += relative_match + literal.len();
        }

        true
    }

    fn raw_literal_segment_at(
        buffer: &[u8],
        glob_section: SerializedGlobSection,
        first_segment_offset: usize,
        seg_idx: usize,
    ) -> Option<&[u8]> {
        let header = glob_section.segment_header_bytes(buffer, first_segment_offset, seg_idx)?;
        if header[0] != 0 {
            return None;
        }
        let data_len = usize::try_from(u32::from_le_bytes(
            header[4..8]
                .try_into()
                .expect("bounded glob header contains four-byte fields"),
        ))
        .ok()?;
        let data_offset = usize::try_from(u32::from_le_bytes(
            header[8..12]
                .try_into()
                .expect("bounded glob header contains four-byte fields"),
        ))
        .ok()?;
        glob_section.data(buffer, data_offset, data_len)
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
        glob_section: SerializedGlobSection,
        first_segment_offset: usize,
        seg_idx: usize,
        segment_count: usize,
    ) -> Option<&[u8]> {
        let next_seg_idx = seg_idx.checked_add(1)?;
        if next_seg_idx >= segment_count {
            return None;
        }

        Self::raw_literal_segment_at(buffer, glob_section, first_segment_offset, next_seg_idx)
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
    /// Uses ACLiteralHash for O(1) AC literal lookups. Load time validates the
    /// fixed number of top-level sections plus the serialized literal hash table.
    pub fn from_buffer(mut buffer: Vec<u8>, mode: MatchMode) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let (header, _) = ParaglobHeader::read_from_prefix(buffer.as_slice())
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;
        header
            .validate_offsets(buffer.len())
            .map_err(|e| ParaglobError::Validation(e.to_string()))?;

        // Ignore trailing bytes rather than allowing an internal offset to
        // escape the buffer length declared by the format header.
        let declared_len = usize::try_from(header.total_buffer_size).map_err(|_| {
            ParaglobError::Validation("Declared buffer size is not addressable".to_string())
        })?;
        buffer.truncate(declared_len);

        // Create AC literal hash table from the buffer
        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_range = ac_literal_hash_range(&header, buffer.len())?;
            let hash_slice = &buffer[hash_range];
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
            header,
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
    /// This validates the fixed number of top-level sections and the serialized
    /// literal hash table without copying pattern or automaton data.
    ///
    /// Validates UTF-8 on every pattern string read.
    pub unsafe fn from_mmap(slice: &'static [u8], mode: MatchMode) -> Result<Self, ParaglobError> {
        if slice.len() < mem::size_of::<ParaglobHeader>() {
            return Err(ParaglobError::SerializationError(
                "Buffer too small".to_string(),
            ));
        }

        let (header, _) = ParaglobHeader::read_from_prefix(slice)
            .map_err(|_| ParaglobError::SerializationError("Invalid header".to_string()))?;
        header
            .validate()
            .map_err(|e| ParaglobError::SerializationError(e.to_string()))?;
        header
            .validate_offsets(slice.len())
            .map_err(|e| ParaglobError::Validation(e.to_string()))?;

        let declared_len = usize::try_from(header.total_buffer_size).map_err(|_| {
            ParaglobError::Validation("Declared buffer size is not addressable".to_string())
        })?;
        let slice = &slice[..declared_len];

        let ac_literal_hash = if header.has_ac_literal_mapping() {
            let hash_range = ac_literal_hash_range(&header, slice.len())?;
            let hash_slice = &slice[hash_range];
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
            header,
            mode,
            ac_literal_hash,
            pattern_data_map,
        })
    }

    /// Get pattern count
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        usize::try_from(self.header.pattern_count).unwrap_or(0)
    }

    /// Get data associated with a pattern (v2 feature)
    ///
    /// Returns `None` if the pattern has no associated data or if the file is v1.
    ///
    /// Note: Returns owned DataValue (not reference) for lazy loading from buffer.
    /// Uses binary search through pattern data mapping table.
    ///
    /// This compatibility method treats malformed encoded data as absent. New
    /// callers that need to distinguish corruption from missing data should use
    /// [`Self::try_get_pattern_data`].
    #[must_use]
    pub fn get_pattern_data(&self, pattern_id: u32) -> Option<DataValue> {
        self.try_get_pattern_data(pattern_id).ok().flatten()
    }

    /// Try to get the data associated with a pattern.
    ///
    /// Returns `Ok(None)` when the pattern has no associated data or the file
    /// has no inline data section. Unlike [`Self::get_pattern_data`], malformed
    /// mapping entries and encoded values are reported to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ParaglobError::Validation`] when the serialized mapping or data
    /// section is out of bounds, and [`ParaglobError::Format`] when the matched
    /// value cannot be decoded. [`ParaglobError::ResourceLimitExceeded`] reports
    /// a value that exceeds the decoder's work or allocation budget.
    pub fn try_get_pattern_data(
        &self,
        pattern_id: u32,
    ) -> Result<Option<DataValue>, ParaglobError> {
        let Some(reader) = self.pattern_data_reader()? else {
            return Ok(None);
        };
        let mut budget = reader.decoder.new_budget();
        reader.decode(pattern_id, &mut budget)
    }

    /// Try to get data for several pattern IDs under one aggregate decode budget.
    ///
    /// Results preserve the input order, including duplicate IDs. An entry is
    /// `None` when the corresponding pattern has no associated inline data.
    /// All present values share one [`DecodeBudget`], so a query cannot multiply
    /// decoder work and allocation limits by requesting many values.
    ///
    /// # Errors
    ///
    /// Returns [`ParaglobError::Validation`] for malformed mapping or section
    /// ranges, [`ParaglobError::Format`] for malformed encoded values,
    /// [`ParaglobError::ResourceLimitExceeded`] when the aggregate decode budget
    /// or result-vector allocation is exhausted.
    pub fn try_get_pattern_data_many(
        &self,
        pattern_ids: &[u32],
    ) -> Result<Vec<Option<DataValue>>, ParaglobError> {
        let mut values = Vec::new();
        values.try_reserve_exact(pattern_ids.len()).map_err(|_| {
            ParaglobError::ResourceLimitExceeded(
                "Pattern data result allocation failed".to_string(),
            )
        })?;
        if pattern_ids.is_empty() {
            return Ok(values);
        }

        let Some(reader) = self.pattern_data_reader()? else {
            values.resize_with(pattern_ids.len(), || None);
            return Ok(values);
        };
        let mut budget = reader.decoder.new_budget();
        for &pattern_id in pattern_ids {
            values.push(reader.decode(pattern_id, &mut budget)?);
        }
        Ok(values)
    }

    fn pattern_data_reader(&self) -> Result<Option<PatternDataReader<'_>>, ParaglobError> {
        let Some(meta) = self.pattern_data_map else {
            return Ok(None);
        };
        let buffer = self.buffer.as_slice();

        let data_section_start =
            usize::try_from(self.header.data_section_offset).map_err(|_| {
                ParaglobError::Validation("Data section offset is not addressable".to_string())
            })?;
        let data_section_size = usize::try_from(self.header.data_section_size).map_err(|_| {
            ParaglobError::Validation("Data section size is not addressable".to_string())
        })?;
        let data_section_end = data_section_start
            .checked_add(data_section_size)
            .ok_or_else(|| {
                ParaglobError::Validation("Data section range overflows address space".to_string())
            })?;
        let data_section = buffer
            .get(data_section_start..data_section_end)
            .ok_or_else(|| {
                ParaglobError::Validation(format!(
                    "Data section range {data_section_start}..{data_section_end} is out of bounds"
                ))
            })?;
        let mapping_size = mem::size_of::<PatternDataMapping>();
        let mapping_count = usize::try_from(meta.count).map_err(|_| {
            ParaglobError::Validation("Pattern mapping count is not addressable".to_string())
        })?;
        let mappings_size = mapping_count.checked_mul(mapping_size).ok_or_else(|| {
            ParaglobError::Validation("Pattern mapping size overflows address space".to_string())
        })?;
        let mappings_end = meta.offset.checked_add(mappings_size).ok_or_else(|| {
            ParaglobError::Validation("Pattern mapping range overflows address space".to_string())
        })?;
        let mappings = buffer.get(meta.offset..mappings_end).ok_or_else(|| {
            ParaglobError::Validation(format!(
                "Pattern mapping range {}..{mappings_end} is out of bounds",
                meta.offset
            ))
        })?;

        Ok(Some(PatternDataReader {
            mappings,
            mapping_count,
            data_section_len: data_section.len(),
            decoder: DataDecoder::new(data_section, 0),
        }))
    }

    /// Check if this Paraglob has data section support (v2 format)
    #[must_use]
    pub fn has_data_section(&self) -> bool {
        self.header.has_data_section()
    }

    /// Get pattern string by ID
    #[must_use]
    pub fn get_pattern(&self, pattern_id: u32) -> Option<String> {
        let buffer = self.buffer.as_slice();
        if pattern_id >= self.header.pattern_count {
            return None;
        }

        let patterns_offset = usize::try_from(self.header.patterns_offset).ok()?;
        let entry_offset = checked_index_offset(
            patterns_offset,
            usize::try_from(pattern_id).ok()?,
            mem::size_of::<PatternEntry>(),
        )?;
        let entry_slice = buffer.get(entry_offset..)?;
        let (entry, _) = PatternEntry::read_from_prefix(entry_slice).ok()?;

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
    fn decoder_allocation_failures_are_resource_limits() {
        for error in [
            "Decoded value exceeds work limit",
            "Decoded value exceeds allocation limit",
            "String allocation failed",
            "Bytes allocation failed",
            "Map allocation failed",
            "Array allocation failed",
        ] {
            assert!(is_decode_resource_limit(error), "{error}");
        }
        assert!(!is_decode_resource_limit("Invalid type tag"));
    }

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

    #[test]
    fn serialized_multi_star_matcher_agrees_with_reference() {
        fn append_sequences(
            tokens: &[&str],
            remaining: usize,
            current: &mut String,
            patterns: &mut Vec<String>,
        ) {
            if remaining == 0 {
                if current.bytes().filter(|byte| *byte == b'*').count() >= 2 {
                    patterns.push(current.clone());
                }
                return;
            }

            for token in tokens {
                let previous_len = current.len();
                current.push_str(token);
                append_sequences(tokens, remaining - 1, current, patterns);
                current.truncate(previous_len);
            }
        }

        fn append_texts(
            alphabet: &[char],
            remaining: usize,
            current: &mut String,
            texts: &mut Vec<String>,
        ) {
            texts.push(current.clone());
            if remaining == 0 {
                return;
            }
            for &ch in alphabet {
                current.push(ch);
                append_texts(alphabet, remaining - 1, current, texts);
                current.pop();
            }
        }

        let tokens = ["*", "?", "a", "b", "[ab]", "[!a]"];
        let mut patterns = Vec::new();
        for length in 2..=4 {
            append_sequences(&tokens, length, &mut String::new(), &mut patterns);
        }

        let mut texts = Vec::new();
        append_texts(&['a', 'b'], 5, &mut String::new(), &mut texts);
        texts.extend(["é".to_string(), "aé".to_string(), "éba".to_string()]);

        for pattern in patterns {
            let reference = GlobPattern::new(&pattern, MatchMode::CaseSensitive).unwrap();
            let serialized =
                Paraglob::build_from_patterns(&[pattern.as_str()], MatchMode::CaseSensitive)
                    .unwrap();

            for text in &texts {
                assert_eq!(
                    serialized.find_all(text) == vec![0],
                    reference.matches(text),
                    "pattern {pattern:?}, text {text:?}"
                );
            }
        }
    }
}
