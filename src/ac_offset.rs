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
use crate::offset_format::{ACEdge, ACNode};
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
}

impl ACBuilder {
    fn new(mode: MatchMode) -> Self {
        Self {
            states: vec![BuilderState::new(0, 0)], // Root
            mode,
            patterns: Vec::new(),
        }
    }

    fn add_pattern(&mut self, pattern: &str) -> u32 {
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

        pattern_id
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

    /// Serialize into offset-based format
    fn serialize(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Calculate section sizes
        let node_size = mem::size_of::<ACNode>();
        let edge_size = mem::size_of::<ACEdge>();

        let nodes_start = 0;
        let nodes_size = self.states.len() * node_size;

        // Count total edges and patterns
        let total_edges: usize = self.states.iter().map(|s| s.transitions.len()).sum();
        let total_patterns: usize = self.states.iter().map(|s| s.outputs.len()).sum();

        let edges_start = nodes_size;
        let edges_size = total_edges * edge_size;

        let patterns_start = edges_start + edges_size;
        let patterns_size = total_patterns * mem::size_of::<u32>();

        // Allocate buffer
        let total_size = nodes_size + edges_size + patterns_size;
        buffer.resize(total_size, 0);

        // Track offsets for each node's data
        let mut edge_offset = edges_start;
        let mut pattern_offset = patterns_start;
        let node_offsets: Vec<usize> = (0..self.states.len())
            .map(|i| nodes_start + i * node_size)
            .collect();

        // Write each node and its associated data
        for (i, state) in self.states.iter().enumerate() {
            let node_offset = node_offsets[i];

            // Create edges for this node
            let edges_offset_for_node = if state.transitions.is_empty() {
                0u32
            } else {
                edge_offset as u32
            };

            // Write edges
            let mut edges: Vec<(u8, u32)> = state
                .transitions
                .iter()
                .map(|(&ch, &target)| (ch, target))
                .collect();
            edges.sort_by_key(|(ch, _)| *ch); // Sort for binary search

            for (ch, target_id) in &edges {
                let target_offset = node_offsets[*target_id as usize];
                let edge = ACEdge::new(*ch, target_offset as u32);

                unsafe {
                    let ptr = buffer.as_mut_ptr().add(edge_offset) as *mut ACEdge;
                    ptr.write(edge);
                }

                edge_offset += edge_size;
            }

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

            // Write node
            let failure_offset = if state.failure == 0 {
                0
            } else {
                node_offsets[state.failure as usize]
            } as u32;

            let mut node = ACNode::new(state.id, state.depth);
            node.failure_offset = failure_offset;
            node.edges_offset = edges_offset_for_node;
            node.edge_count = state.transitions.len() as u16;
            node.patterns_offset = patterns_offset_for_node;
            node.pattern_count = state.outputs.len() as u16;
            node.is_final = if state.is_final() { 1 } else { 0 };

            unsafe {
                let ptr = buffer.as_mut_ptr().add(node_offset) as *mut ACNode;
                ptr.write(node);
            }
        }

        buffer
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
            builder.add_pattern(pattern);
        }

        builder.build_failure_links();

        let stored_patterns = builder.patterns.clone();
        let buffer = builder.serialize();

        Ok(Self {
            buffer,
            mode,
            patterns: stored_patterns,
        })
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
    fn find_transition(&self, node_offset: usize, ch: u8) -> Option<usize> {
        let node_slice = self.buffer.get(node_offset..)?;
        let (node_ref, _) = Ref::<_, ACNode>::from_prefix(node_slice).ok()?;
        let node = *node_ref;

        if node.edge_count == 0 {
            return None;
        }

        // Read edges safely byte-by-byte (may not be aligned)
        let edges_offset = node.edges_offset as usize;
        let edge_size = mem::size_of::<ACEdge>();

        // Binary search through edges (sorted by character)
        for i in 0..node.edge_count as usize {
            let edge_offset = edges_offset + i * edge_size;
            if edge_offset + edge_size > self.buffer.len() {
                return None;
            }

            let edge_slice = self.buffer.get(edge_offset..)?;
            let (edge_ref, _) = Ref::<_, ACEdge>::from_prefix(edge_slice).ok()?;
            let edge = *edge_ref;

            if edge.character == ch {
                return Some(edge.target_offset as usize);
            } else if edge.character > ch {
                // Edges are sorted, so we won't find it
                return None;
            }
        }

        None
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
