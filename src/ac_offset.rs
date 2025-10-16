//! Offset-based Aho-Corasick Automaton
//!
//! This module implements an Aho-Corasick automaton that builds directly into
//! the binary offset-based format. Unlike traditional implementations, this
//! creates the serialized format during construction, allowing zero-copy
//! memory-mapped operation.
//!
//! # Design
//!
//! The automaton is stored as a single `Vec<u8>` containing:
//! - AC nodes with offset-based transitions
//! - Edge arrays referenced by nodes
//! - Pattern ID arrays referenced by nodes
//!
//! All operations (both building and matching) work directly on this buffer.

use crate::error::ParaglobError;
use crate::offset_format::{ACEdge, ACNode, DenseLookup, StateKind};
use std::collections::{HashMap, VecDeque};
use std::mem;
use zerocopy::Ref;

/// Matching mode for the automaton
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-sensitive matching
    CaseSensitive,
    /// Case-insensitive matching
    CaseInsensitive,
}

/// Builder for constructing the offset-based AC automaton
///
/// This uses temporary in-memory structures during construction,
/// then serializes them into the final offset-based format.
struct ACBuilder {
    /// Temporary states during construction
    states: Vec<BuilderState>,
    /// Matching mode
    mode: MatchMode,
    /// Original patterns
    patterns: Vec<String>,
}

/// Temporary state structure used during construction
#[derive(Debug, Clone)]
struct BuilderState {
    id: u32,
    transitions: HashMap<u8, u32>,
    failure: u32,
    outputs: Vec<u32>, // Pattern IDs
    depth: u8,
}

impl BuilderState {
    fn new(id: u32, depth: u8) -> Self {
        Self {
            id,
            transitions: HashMap::new(),
            failure: 0,
            outputs: Vec::new(),
            depth,
        }
    }

    fn is_final(&self) -> bool {
        !self.outputs.is_empty()
    }

    /// Classify state encoding based on transition count
    ///
    /// # State Encoding Selection
    ///
    /// - **Empty** (0 transitions): Terminal states only, no lookups needed
    /// - **One** (1 transition): Store inline, eliminates cache miss (75-80% of states)
    /// - **Sparse** (2-8 transitions): Linear search is optimal for this range
    /// - **Dense** (9+ transitions): O(1) lookup table worth the 1KB overhead
    fn classify_state_kind(&self) -> StateKind {
        match self.transitions.len() {
            0 => StateKind::Empty,
            1 => StateKind::One,
            2..=8 => StateKind::Sparse,
            _ => StateKind::Dense, // 9+ transitions
        }
    }
}

impl ACBuilder {
    fn new(mode: MatchMode) -> Self {
        Self {
            states: vec![BuilderState::new(0, 0)], // Root
            mode,
            patterns: Vec::new(),
        }
    }

    fn add_pattern(&mut self, pattern: &str) -> Result<u32, ParaglobError> {
        let pattern_id = self.patterns.len() as u32;
        self.patterns.push(pattern.to_string());

        // Normalize pattern
        let normalized = match self.mode {
            MatchMode::CaseSensitive => pattern.as_bytes().to_vec(),
            MatchMode::CaseInsensitive => pattern.to_lowercase().into_bytes(),
        };

        // Build trie path
        let mut current = 0u32;
        let mut depth = 0u8;

        for &ch in &normalized {
            depth += 1;

            if let Some(&next) = self.states[current as usize].transitions.get(&ch) {
                current = next;
            } else {
                let new_id = self.states.len() as u32;
                self.states.push(BuilderState::new(new_id, depth));
                self.states[current as usize].transitions.insert(ch, new_id);
                current = new_id;
            }
        }

        // Add output
        self.states[current as usize].outputs.push(pattern_id);

        Ok(pattern_id)
    }

    fn build_failure_links(&mut self) {
        let mut queue = VecDeque::new();

        // Depth-1 states fail to root
        let root_children: Vec<u32> = self.states[0].transitions.values().copied().collect();

        for child in root_children {
            self.states[child as usize].failure = 0;
            queue.push_back(child);
        }

        // BFS to compute failure links
        while let Some(state_id) = queue.pop_front() {
            let transitions: Vec<(u8, u32)> = self.states[state_id as usize]
                .transitions
                .iter()
                .map(|(&ch, &next)| (ch, next))
                .collect();

            for (ch, next_state) in transitions {
                queue.push_back(next_state);

                // Find failure state
                let mut fail = self.states[state_id as usize].failure;
                let mut failure_found = false;

                // Follow failure links looking for a state with a transition for 'ch'
                while fail != 0 {
                    if let Some(&target) = self.states[fail as usize].transitions.get(&ch) {
                        self.states[next_state as usize].failure = target;
                        failure_found = true;
                        break;
                    }
                    fail = self.states[fail as usize].failure;
                }

                // If not found, check root
                if !failure_found {
                    if let Some(&target) = self.states[0].transitions.get(&ch) {
                        // Only set if target is not the node itself (avoid self-loop)
                        if target != next_state {
                            self.states[next_state as usize].failure = target;
                        } else {
                            self.states[next_state as usize].failure = 0;
                        }
                    } else {
                        self.states[next_state as usize].failure = 0;
                    }
                }

                // Merge outputs from ALL suffix states (via failure links)
                // This is critical: we need to inherit patterns from the entire failure link chain
                let mut suffix_state = self.states[next_state as usize].failure;
                while suffix_state != 0 {
                    let suffix_outputs = self.states[suffix_state as usize].outputs.clone();
                    if !suffix_outputs.is_empty() {
                        self.states[next_state as usize]
                            .outputs
                            .extend(suffix_outputs);
                    }
                    suffix_state = self.states[suffix_state as usize].failure;
                }
            }
        }
    }

    /// Serialize into offset-based format with state-specific encoding
    fn serialize(self) -> Result<Vec<u8>, ParaglobError> {
        let mut buffer = Vec::new();

        // Calculate section sizes
        let node_size = mem::size_of::<ACNode>();
        let edge_size = mem::size_of::<ACEdge>();
        let dense_size = mem::size_of::<DenseLookup>();

        let nodes_start = 0;
        let nodes_size = self.states.len() * node_size;

        // Classify states and count by type
        let state_kinds: Vec<StateKind> = self
            .states
            .iter()
            .map(|s| s.classify_state_kind())
            .collect();

        let dense_count = state_kinds
            .iter()
            .filter(|&&k| k == StateKind::Dense)
            .count();
        let sparse_edges: usize = self
            .states
            .iter()
            .zip(&state_kinds)
            .filter(|(_, &kind)| kind == StateKind::Sparse)
            .map(|(s, _)| s.transitions.len())
            .sum();

        // ONE states don't need edge arrays!
        let total_patterns: usize = self.states.iter().map(|s| s.outputs.len()).sum();

        // Layout: [Nodes][Sparse Edges][Padding][Dense Lookups][Patterns]
        let edges_start = nodes_size;
        let edges_size = sparse_edges * edge_size;

        // Calculate padding to align dense section to 64-byte boundary
        // DenseLookup now has #[repr(C, align(64))] for cache-line alignment
        let unaligned_dense_start = edges_start + edges_size;
        let dense_alignment = mem::align_of::<DenseLookup>(); // 64 bytes
        let dense_padding =
            (dense_alignment - (unaligned_dense_start % dense_alignment)) % dense_alignment;
        let dense_start = unaligned_dense_start + dense_padding;
        let dense_size_total = dense_count * dense_size;

        let patterns_start = dense_start + dense_size_total;
        let patterns_size = total_patterns * mem::size_of::<u32>();

        // Calculate total size (including alignment padding)
        let total_size = nodes_size + edges_size + dense_padding + dense_size_total + patterns_size;

        // Reasonable size limit to prevent pathological inputs from causing OOM
        // Set to 2GB which is large enough for legitimate databases but catches
        // pathological inputs early
        const MAX_BUFFER_SIZE: usize = 2_000_000_000; // 2GB

        if total_size > MAX_BUFFER_SIZE {
            return Err(ParaglobError::ResourceLimitExceeded(format!(
                "Pattern database too large: {} bytes ({} states, {} sparse edges, {} dense, {} patterns). \
                     Maximum allowed is {} bytes. This may be caused by pathological patterns \
                     with many null bytes or special characters.",
                total_size,
                self.states.len(),
                sparse_edges,
                dense_count,
                total_patterns,
                MAX_BUFFER_SIZE
            )));
        }

        // Allocate buffer
        buffer.resize(total_size, 0);

        // Verify alignment of dense section
        debug_assert_eq!(
            dense_start % dense_alignment,
            0,
            "Dense section must be {}-byte aligned, but starts at offset {} ({}% alignment)",
            dense_alignment,
            dense_start,
            dense_start % dense_alignment
        );

        // Track offsets for writing data
        let mut edge_offset = edges_start;
        let mut dense_offset = dense_start;
        let mut pattern_offset = patterns_start;

        let node_offsets: Vec<usize> = (0..self.states.len())
            .map(|i| nodes_start + i * node_size)
            .collect();

        // Write each node with state-specific encoding
        for (i, state) in self.states.iter().enumerate() {
            let node_offset = node_offsets[i];
            let kind = state_kinds[i];

            // Prepare sorted edges for this state
            let mut edges: Vec<(u8, u32)> = state
                .transitions
                .iter()
                .map(|(&ch, &target)| (ch, node_offsets[target as usize] as u32))
                .collect();
            edges.sort_by_key(|(ch, _)| *ch); // Sort for efficient lookup

            // Write state-specific transition data
            let (edges_offset_for_node, one_char, _one_target) = match kind {
                StateKind::Empty => (0u32, 0u8, 0u32),

                StateKind::One => {
                    // Store single transition inline in node!
                    let (ch, target) = edges[0];
                    (target, ch, 0u32) // edges_offset stores target for ONE states
                }

                StateKind::Sparse => {
                    // Write edges to sparse edge array
                    let sparse_offset = edge_offset;

                    for (ch, target) in &edges {
                        let edge = ACEdge::new(*ch, *target);
                        unsafe {
                            let ptr = buffer.as_mut_ptr().add(edge_offset) as *mut ACEdge;
                            ptr.write(edge);
                        }
                        edge_offset += edge_size;
                    }

                    (sparse_offset as u32, 0u8, 0u32)
                }

                StateKind::Dense => {
                    // Write dense lookup table
                    let lookup_offset = dense_offset;
                    let mut lookup = DenseLookup {
                        targets: [0u32; 256],
                    };

                    for (ch, target) in &edges {
                        lookup.targets[*ch as usize] = *target;
                    }

                    unsafe {
                        let ptr = buffer.as_mut_ptr().add(dense_offset) as *mut DenseLookup;
                        ptr.write(lookup);
                    }
                    dense_offset += dense_size;

                    (lookup_offset as u32, 0u8, 0u32)
                }
            };

            // Write pattern IDs
            let patterns_offset_for_node = if state.outputs.is_empty() {
                0u32
            } else {
                pattern_offset as u32
            };

            for &pattern_id in &state.outputs {
                unsafe {
                    let ptr = buffer.as_mut_ptr().add(pattern_offset) as *mut u32;
                    ptr.write(pattern_id);
                }
                pattern_offset += mem::size_of::<u32>();
            }

            // Write node with state-specific encoding
            let failure_offset = if state.failure == 0 {
                0
            } else {
                node_offsets[state.failure as usize]
            } as u32;

            let mut node = ACNode::new(state.id, state.depth);
            node.failure_offset = failure_offset;
            node.state_kind = kind as u8;
            node.is_final = if state.is_final() { 1 } else { 0 };

            // State-specific fields
            node.one_char = one_char;
            node.edges_offset = edges_offset_for_node;
            node.edge_count = state.transitions.len() as u16;

            // Pattern data
            node.patterns_offset = patterns_offset_for_node;
            node.pattern_count = state.outputs.len() as u16;

            unsafe {
                let ptr = buffer.as_mut_ptr().add(node_offset) as *mut ACNode;
                ptr.write(node);
            }
        }

        Ok(buffer)
    }
}

/// Offset-based Aho-Corasick automaton
///
/// All data is stored in a single byte buffer using offsets.
/// Can be used directly from memory or mmap'd files.
pub struct ACAutomaton {
    /// Binary buffer containing all automaton data
    buffer: Vec<u8>,
    /// Matching mode
    mode: MatchMode,
    /// Original patterns (needed for returning matches)
    patterns: Vec<String>,
}

impl ACAutomaton {
    /// Create a new AC automaton (initially empty)
    pub fn new(mode: MatchMode) -> Self {
        Self {
            buffer: Vec::new(),
            mode,
            patterns: Vec::new(),
        }
    }

    /// Build the automaton from patterns
    ///
    /// This constructs the offset-based binary format directly.
    pub fn build(patterns: &[&str], mode: MatchMode) -> Result<Self, ParaglobError> {
        if patterns.is_empty() {
            return Err(ParaglobError::InvalidPattern(
                "No patterns provided".to_string(),
            ));
        }

        let mut builder = ACBuilder::new(mode);

        for pattern in patterns {
            if pattern.is_empty() {
                return Err(ParaglobError::InvalidPattern("Empty pattern".to_string()));
            }
            builder.add_pattern(pattern)?; // Propagate error
        }

        builder.build_failure_links();

        let stored_patterns = builder.patterns.clone();
        let buffer = builder.serialize()?; // Propagate error

        Ok(Self {
            buffer,
            mode,
            patterns: stored_patterns,
        })
    }

    /// Find all matches with their end positions
    ///
    /// Returns (end_position, pattern_id) for each match.
    /// The end_position is the byte offset immediately after the match.
    pub fn find_with_positions(&self, text: &str) -> Vec<(usize, u32)> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let normalized = match self.mode {
            MatchMode::CaseSensitive => text.as_bytes().to_vec(),
            MatchMode::CaseInsensitive => text.to_lowercase().into_bytes(),
        };

        let mut matches = Vec::new();
        let mut current_offset = 0usize;

        for (pos, &ch) in normalized.iter().enumerate() {
            let mut next_offset = self.find_transition(current_offset, ch);

            while next_offset.is_none() && current_offset != 0 {
                let node_slice = match self.buffer.get(current_offset..) {
                    Some(s) => s,
                    None => break,
                };
                let node_ref = match Ref::<_, ACNode>::from_prefix(node_slice) {
                    Ok((r, _)) => r,
                    Err(_) => break,
                };
                let node = *node_ref;
                current_offset = node.failure_offset as usize;

                if current_offset == 0 {
                    break;
                }

                next_offset = self.find_transition(current_offset, ch);
            }

            if next_offset.is_none() {
                next_offset = self.find_transition(0, ch);
            }

            current_offset = next_offset.unwrap_or(0);

            // Collect matches at this position (end pos is pos + 1)
            let node_slice = match self.buffer.get(current_offset..) {
                Some(s) => s,
                None => continue,
            };
            let node_ref = match Ref::<_, ACNode>::from_prefix(node_slice) {
                Ok((r, _)) => r,
                Err(_) => continue,
            };
            let node = *node_ref;

            if node.pattern_count > 0 {
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                if patterns_offset + pattern_count * 4 <= self.buffer.len() {
                    let pattern_slice = &self.buffer[patterns_offset..];
                    if let Ok((ids_ref, _)) =
                        Ref::<_, [u32]>::from_prefix_with_elems(pattern_slice, pattern_count)
                    {
                        for &pattern_id in ids_ref.iter() {
                            matches.push((pos + 1, pattern_id));
                        }
                    }
                }
            }
        }

        matches
    }

    /// Find all pattern IDs that match in the text
    ///
    /// This traverses the offset-based automaton directly.
    pub fn find_pattern_ids(&self, text: &str) -> Vec<u32> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let normalized = match self.mode {
            MatchMode::CaseSensitive => text.as_bytes().to_vec(),
            MatchMode::CaseInsensitive => text.to_lowercase().into_bytes(),
        };

        let mut pattern_ids = Vec::new();
        let mut current_offset = 0usize; // Root node

        for &ch in &normalized {
            // Try to find transition from current node
            let mut next_offset = self.find_transition(current_offset, ch);

            // Follow failure links until we find a transition or reach root
            while next_offset.is_none() && current_offset != 0 {
                let node_slice = match self.buffer.get(current_offset..) {
                    Some(s) => s,
                    None => break,
                };
                let node_ref = match Ref::<_, ACNode>::from_prefix(node_slice) {
                    Ok((r, _)) => r,
                    Err(_) => break,
                };
                let node = *node_ref;
                current_offset = node.failure_offset as usize;

                if current_offset == 0 {
                    break;
                }

                next_offset = self.find_transition(current_offset, ch);
            }

            // If still no transition, try from root
            if next_offset.is_none() {
                next_offset = self.find_transition(0, ch);
            }

            // Update current position
            current_offset = next_offset.unwrap_or(0);

            // Collect pattern IDs at this state
            // Note: Patterns from suffix states were already merged during build_failure_links
            let node_slice = match self.buffer.get(current_offset..) {
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
                // Pattern IDs are always 4-byte aligned in our serialization format
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                if patterns_offset + pattern_count * 4 <= self.buffer.len() {
                    let pattern_slice = &self.buffer[patterns_offset..];
                    if let Ok((ids_ref, _)) =
                        Ref::<_, [u32]>::from_prefix_with_elems(pattern_slice, pattern_count)
                    {
                        // Zero-copy path - direct slice access
                        pattern_ids.extend_from_slice(&ids_ref);
                    }
                }
            }
        }

        // Deduplicate and sort
        pattern_ids.sort_unstable();
        pattern_ids.dedup();
        pattern_ids
    }

    /// Find a transition from a node for a character
    ///
    /// Returns the offset to the target node, or None if no transition exists.
    ///
    /// # State-Specific Optimizations
    ///
    /// This is the HOTTEST path in pattern matching. We use different lookup strategies
    /// based on the state encoding:
    ///
    /// - **EMPTY**: No transitions, immediate return
    /// - **ONE** (75-80% of states): Single inline comparison, zero indirection!
    /// - **SPARSE**: Linear search through edge array (2-8 edges)
    /// - **DENSE**: O(1) lookup table access (9+ edges)
    ///
    /// The ONE encoding is the key optimization: by storing the single transition inline,
    /// we eliminate a cache miss that would occur when loading the edge array.
    #[inline]
    fn find_transition(&self, node_offset: usize, ch: u8) -> Option<usize> {
        // Load node metadata
        let node_slice = self.buffer.get(node_offset..)?;
        let (node_ref, _) = Ref::<_, ACNode>::from_prefix(node_slice).ok()?;
        let node = *node_ref;

        // Dispatch on state encoding
        let kind = StateKind::from_u8(node.state_kind)?;

        match kind {
            StateKind::Empty => {
                // No transitions
                None
            }

            StateKind::One => {
                // HOT PATH: Single inline comparison, no indirection!
                // This eliminates a cache miss for 75-80% of transitions
                if node.one_char == ch {
                    Some(node.edges_offset as usize) // edges_offset stores target for ONE
                } else {
                    None
                }
            }

            StateKind::Sparse => {
                // Linear search through sparse edge array (2-8 edges)
                let edges_offset = node.edges_offset as usize;
                let edge_size = mem::size_of::<ACEdge>();
                let count = node.edge_count as usize;

                // Pre-check: ensure all edges are in bounds
                let total_edge_bytes = count * edge_size;
                if edges_offset + total_edge_bytes > self.buffer.len() {
                    return None;
                }

                // Linear search through sorted edges
                for i in 0..count {
                    let edge_offset = edges_offset + i * edge_size;
                    let edge_slice = &self.buffer[edge_offset..];
                    let (edge_ref, _) = Ref::<_, ACEdge>::from_prefix(edge_slice).ok()?;
                    let edge = *edge_ref;

                    if edge.character == ch {
                        return Some(edge.target_offset as usize);
                    }

                    // Early exit: edges are sorted
                    if edge.character > ch {
                        return None;
                    }
                }

                None
            }

            StateKind::Dense => {
                // O(1) lookup in dense table (9+ edges)
                let lookup_offset = node.edges_offset as usize;
                let target_offset_offset = lookup_offset + (ch as usize * 4);

                // Bounds check
                if target_offset_offset + 4 > self.buffer.len() {
                    return None;
                }

                // Read target offset directly (4 bytes, little-endian)
                let target = u32::from_le_bytes([
                    self.buffer[target_offset_offset],
                    self.buffer[target_offset_offset + 1],
                    self.buffer[target_offset_offset + 2],
                    self.buffer[target_offset_offset + 3],
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
        &self.buffer
    }

    /// Get the patterns
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Get the match mode
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Load from a buffer (for deserialization/mmap)
    pub fn from_buffer(
        buffer: Vec<u8>,
        patterns: Vec<String>,
        mode: MatchMode,
    ) -> Result<Self, ParaglobError> {
        // TODO: Validate buffer format

        Ok(Self {
            buffer,
            mode,
            patterns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        assert_eq!(ac.patterns.len(), 4);
        assert!(!ac.buffer.is_empty());
    }

    #[test]
    fn test_find_pattern_ids() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("she sells his shells");
        assert!(!ids.is_empty());

        // Should find: "she" (id=1), "he" (id=0), "his" (id=2)
        assert!(ids.contains(&0)); // "he"
        assert!(ids.contains(&1)); // "she"
        assert!(ids.contains(&2)); // "his"
    }

    #[test]
    fn test_case_insensitive() {
        let patterns = vec!["Hello", "World"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseInsensitive).unwrap();

        let ids = ac.find_pattern_ids("hello world");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&0));
        assert!(ids.contains(&1));
    }

    #[test]
    fn test_no_match() {
        let patterns = vec!["hello", "world"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("nothing here");
        assert!(ids.is_empty());
    }

    #[test]
    fn test_overlapping_patterns() {
        let patterns = vec!["test", "testing", "est"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("testing");
        assert_eq!(ids.len(), 3); // All three patterns match
    }
}
