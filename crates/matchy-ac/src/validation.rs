//! AC Automaton validation for untrusted binary data
//!
//! This module validates offset-based AC automaton structures to ensure they are safe to use.
//! Validates node structure, edges, failure links, and graph reachability.

use crate::{ACEdge, ACNodeHot, StateKind};
use std::mem;
use zerocopy::FromBytes;

const MAX_VALIDATION_ERRORS: usize = 256;
const MAX_VALIDATION_WARNINGS: usize = 256;
const ERRORS_SUPPRESSED: &str =
    "Additional validation errors suppressed after reaching the limit of 256";
const WARNINGS_SUPPRESSED: &str =
    "Additional validation warnings suppressed after reaching the limit of 256";

fn push_capped(messages: &mut Vec<String>, message: String, limit: usize, sentinel: &str) {
    let already_has_sentinel = messages.iter().any(|existing| existing == sentinel);
    if message == sentinel && already_has_sentinel {
        return;
    }
    if messages.len() < limit {
        messages.push(message);
    } else if !already_has_sentinel {
        messages[limit - 1] = sentinel.to_string();
    }
}

/// Validation result for AC automaton structures
#[derive(Debug, Clone)]
pub struct ACValidationResult {
    /// Critical errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Non-fatal warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Statistics gathered during validation
    pub stats: ACStats,
}

/// Statistics gathered during AC automaton validation
#[derive(Debug, Clone, Default)]
pub struct ACStats {
    /// Number of AC nodes
    pub node_count: u32,
    /// State encoding distribution: [Empty, One, Sparse, Dense]
    pub state_encoding_distribution: [u32; 4],
    /// Number of orphaned nodes (unreachable from root)
    pub orphaned_count: u32,
}

impl ACValidationResult {
    fn new(node_count: usize) -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: ACStats {
                node_count: u32::try_from(node_count).unwrap_or(u32::MAX),
                state_encoding_distribution: [0; 4],
                orphaned_count: 0,
            },
        }
    }

    /// Check if validation passed (no errors)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, message: impl Into<String>) {
        push_capped(
            &mut self.errors,
            message.into(),
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    fn warning(&mut self, message: impl Into<String>) {
        push_capped(
            &mut self.warnings,
            message.into(),
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }
}

/// Validate that a range is within bounds
fn validate_range(offset: usize, size: usize, buffer_len: usize) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| end <= buffer_len)
}

/// Validate AC automaton structure in a buffer
///
/// Validates:
/// - Node bounds and alignment
/// - State kind validity
/// - Failure links
/// - Edge arrays and target offsets
/// - Pattern ID references
///
/// # Arguments
///
/// * `buffer` - The buffer containing the AC automaton data
/// * `nodes_offset` - Offset to the start of the AC nodes array
/// * `node_count` - Number of nodes in the automaton
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
/// * `strict` - If true, performs deep validation of all edges
///
/// # Returns
///
/// A `ACValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_ac_structure(
    buffer: &[u8],
    nodes_offset: usize,
    node_count: usize,
    pattern_count: u32,
    strict: bool,
) -> ACValidationResult {
    let mut result = ACValidationResult::new(node_count);

    if node_count == 0 {
        return result;
    }

    for i in 0..node_count {
        let node_offset = nodes_offset + i * mem::size_of::<ACNodeHot>();

        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            result.error(format!("AC node {i} out of bounds"));
            continue;
        }

        let node = match ACNodeHot::read_from_prefix(&buffer[node_offset..]) {
            Ok((n, _)) => n,
            Err(_) => {
                result.error(format!("Failed to read AC node {i}"));
                continue;
            }
        };

        // Validate state kind
        let state_kind = match node.state_kind {
            0 => StateKind::Empty,
            1 => StateKind::One,
            2 => StateKind::Sparse,
            3 => StateKind::Dense,
            _ => {
                result.error(format!(
                    "AC node {} has invalid state kind: {}",
                    i, node.state_kind
                ));
                continue;
            }
        };
        result.stats.state_encoding_distribution[state_kind as usize] += 1;

        // Validate failure link
        if node.failure_offset != 0 {
            let failure_node_offset = node.failure_offset as usize;
            if failure_node_offset < nodes_offset
                || failure_node_offset >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                || !(failure_node_offset - nodes_offset).is_multiple_of(mem::size_of::<ACNodeHot>())
            {
                result.error(format!(
                    "AC node {} has invalid failure link offset: {}",
                    i, node.failure_offset
                ));
            }

            // Check for self-loop (root is at offset nodes_offset)
            if failure_node_offset == node_offset && node_offset != nodes_offset {
                result.error(format!("AC node {i} has self-referencing failure link"));
            }
        }

        // Validate edges based on state kind
        match state_kind {
            StateKind::Empty => {
                if node.edge_count != 0 {
                    result.error(format!(
                        "AC node {} is Empty but has edge_count={}",
                        i, node.edge_count
                    ));
                }
            }
            StateKind::One => {
                // Single edge stored inline
                if node.edge_count != 0 {
                    result.warning(format!(
                        "AC node {} is One but has edge_count={} (should be 0)",
                        i, node.edge_count
                    ));
                }
                // Validate target offset (stored in edges_offset for One encoding)
                let target_offset = node.edges_offset as usize;
                if target_offset != 0
                    && (target_offset < nodes_offset
                        || target_offset >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                        || !(target_offset - nodes_offset)
                            .is_multiple_of(mem::size_of::<ACNodeHot>()))
                {
                    result.error(format!(
                        "AC node {i} (One) has invalid target offset: {target_offset}"
                    ));
                }
            }
            StateKind::Sparse => {
                // Validate edge array
                let edges_offset = node.edges_offset as usize;
                let edge_count = node.edge_count as usize;
                let edges_size = edge_count * mem::size_of::<ACEdge>();

                if edge_count == 0 {
                    result.error(format!("AC node {i} is Sparse but has no edges"));
                } else if !validate_range(edges_offset, edges_size, buffer.len()) {
                    result.error(format!(
                        "AC node {i} edge array out of bounds: offset={edges_offset}, count={edge_count}"
                    ));
                } else if strict {
                    // Validate each edge
                    for j in 0..edge_count {
                        let edge_offset = edges_offset + j * mem::size_of::<ACEdge>();
                        if let Ok((edge, _)) = ACEdge::read_from_prefix(&buffer[edge_offset..]) {
                            let target_offset = edge.target_offset as usize;
                            if target_offset < nodes_offset
                                || target_offset
                                    >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                                || !(target_offset - nodes_offset)
                                    .is_multiple_of(mem::size_of::<ACNodeHot>())
                            {
                                result.error(format!(
                                    "AC node {i} edge {j} has invalid target: {target_offset}"
                                ));
                            }
                        }
                    }
                }
            }
            StateKind::Dense => {
                // Validate dense lookup table (256 * 4 bytes = 1024 bytes)
                let lookup_offset = node.edges_offset as usize;
                let lookup_size = 1024;

                if !validate_range(lookup_offset, lookup_size, buffer.len()) {
                    result.error(format!(
                        "AC node {i} dense lookup out of bounds: offset={lookup_offset}"
                    ));
                }
                // Note: Cache alignment check disabled - it's a performance optimization hint for developers,
                // not a safety/security concern. mmap placement is unpredictable anyway, so file-level
                // alignment doesn't guarantee runtime alignment. The check was causing noise in validation.
                // } else if !lookup_offset.is_multiple_of(64) {
                //     result.warnings.push(format!(
                //         "AC node {} dense lookup not cache-aligned: offset={}",
                //         i, lookup_offset
                //     ));
                // }

                // Optionally validate all targets in strict mode
                if strict {
                    for j in 0..256 {
                        let target_offset_pos = lookup_offset + j * 4;
                        if target_offset_pos + 4 <= buffer.len() {
                            let target_offset = u32::from_le_bytes([
                                buffer[target_offset_pos],
                                buffer[target_offset_pos + 1],
                                buffer[target_offset_pos + 2],
                                buffer[target_offset_pos + 3],
                            ]) as usize;

                            if target_offset != 0
                                && (target_offset < nodes_offset
                                    || target_offset
                                        >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                                    || !(target_offset - nodes_offset)
                                        .is_multiple_of(mem::size_of::<ACNodeHot>()))
                            {
                                result.error(format!(
                                    "AC node {i} dense entry [{j}] has invalid target: {target_offset}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Validate pattern IDs
        if node.pattern_count > 0 {
            let patterns_offset = node.patterns_offset as usize;
            let patterns_size = (node.pattern_count as usize) * mem::size_of::<u32>();

            if validate_range(patterns_offset, patterns_size, buffer.len()) {
                // Validate each pattern ID references a valid pattern
                for j in 0..(node.pattern_count as usize) {
                    let pid_offset = patterns_offset + j * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        if pattern_id >= pattern_count {
                            result.error(format!(
                                "AC node {i} pattern ID {j} out of range: {pattern_id} (max={pattern_count})"
                            ));
                        }
                    }
                }
            } else {
                result.error(format!(
                    "AC node {} pattern IDs out of bounds: offset={}, count={}",
                    i, patterns_offset, node.pattern_count
                ));
            }
        }
    }

    result
}

/// Validate AC automaton reachability (no orphan nodes)
///
/// Performs a BFS traversal from the root node to ensure all nodes are reachable.
/// Unreachable nodes indicate a construction bug or corruption.
///
/// # Arguments
///
/// * `buffer` - The buffer containing the AC automaton data
/// * `nodes_offset` - Offset to the start of the AC nodes array
/// * `node_count` - Number of nodes in the automaton
///
/// # Returns
///
/// A `ACValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_ac_reachability(
    buffer: &[u8],
    nodes_offset: usize,
    node_count: usize,
) -> ACValidationResult {
    let mut result = ACValidationResult::new(node_count);

    if node_count == 0 {
        return result;
    }

    // Track which nodes are reachable via BFS from root
    let mut reachable = vec![false; node_count];
    let mut queue = Vec::new();

    // Start from root (node 0)
    if node_count > 0 {
        queue.push(0usize);
        reachable[0] = true;
    }

    while let Some(node_idx) = queue.pop() {
        let node_offset = nodes_offset + node_idx * mem::size_of::<ACNodeHot>();
        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            continue;
        }

        let node = match ACNodeHot::read_from_prefix(&buffer[node_offset..]) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };

        let state_kind = match node.state_kind {
            0 => StateKind::Empty,
            1 => StateKind::One,
            2 => StateKind::Sparse,
            3 => StateKind::Dense,
            _ => continue,
        };

        // Follow all edges to mark children as reachable
        match state_kind {
            StateKind::Empty => {}
            StateKind::One => {
                // Single edge stored inline in edges_offset
                let target_offset = node.edges_offset as usize;
                if target_offset >= nodes_offset
                    && target_offset < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                {
                    let target_idx = (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                    if target_idx < node_count && !reachable[target_idx] {
                        reachable[target_idx] = true;
                        queue.push(target_idx);
                    }
                }
            }
            StateKind::Sparse => {
                let edges_offset = node.edges_offset as usize;
                let edge_count = node.edge_count as usize;

                for i in 0..edge_count {
                    let edge_offset = edges_offset + i * mem::size_of::<ACEdge>();
                    if edge_offset + mem::size_of::<ACEdge>() <= buffer.len() {
                        if let Ok((edge, _)) = ACEdge::read_from_prefix(&buffer[edge_offset..]) {
                            let target_offset = edge.target_offset as usize;
                            if target_offset >= nodes_offset
                                && target_offset
                                    < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                            {
                                let target_idx =
                                    (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                                if target_idx < node_count && !reachable[target_idx] {
                                    reachable[target_idx] = true;
                                    queue.push(target_idx);
                                }
                            }
                        }
                    }
                }
            }
            StateKind::Dense => {
                let lookup_offset = node.edges_offset as usize;
                let lookup_size = 1024; // 256 * 4 bytes

                if lookup_offset + lookup_size <= buffer.len() {
                    for i in 0..256 {
                        let target_offset_pos = lookup_offset + i * 4;
                        if target_offset_pos + 4 <= buffer.len() {
                            let target_offset = u32::from_le_bytes([
                                buffer[target_offset_pos],
                                buffer[target_offset_pos + 1],
                                buffer[target_offset_pos + 2],
                                buffer[target_offset_pos + 3],
                            ]) as usize;

                            if target_offset != 0
                                && target_offset >= nodes_offset
                                && target_offset
                                    < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                            {
                                let target_idx =
                                    (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                                if target_idx < node_count && !reachable[target_idx] {
                                    reachable[target_idx] = true;
                                    queue.push(target_idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also follow failure links to ensure we reach all nodes
        if node.failure_offset != 0 {
            let failure_offset = node.failure_offset as usize;
            if failure_offset >= nodes_offset
                && failure_offset < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
            {
                let failure_idx = (failure_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                if failure_idx < node_count && !reachable[failure_idx] {
                    reachable[failure_idx] = true;
                    queue.push(failure_idx);
                }
            }
        }
    }

    // Count orphaned nodes
    let orphaned_count = reachable.iter().filter(|&&r| !r).count();
    result.stats.orphaned_count = u32::try_from(orphaned_count).unwrap_or(u32::MAX);

    if orphaned_count > 0 {
        result.warning(format!(
            "Found {orphaned_count} orphaned AC nodes (not reachable from root)"
        ));
    }

    result
}

/// Validate pattern references from AC nodes
///
/// Checks that:
/// - All pattern IDs referenced by AC nodes are valid
/// - Optionally checks that all literal patterns are referenced (pattern_entries must be provided)
///
/// # Arguments
///
/// * `buffer` - The buffer containing the AC automaton data
/// * `nodes_offset` - Offset to the start of the AC nodes array
/// * `node_count` - Number of nodes in the automaton
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
/// * `pattern_entries` - Optional slice of (pattern_id, pattern_type) for checking coverage
///   - pattern_type: 0 = literal, 1 = glob
///
/// # Returns
///
/// A `ACValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_pattern_references(
    buffer: &[u8],
    nodes_offset: usize,
    node_count: usize,
    pattern_count: u32,
    pattern_entries: Option<&[(u32, u8)]>,
) -> ACValidationResult {
    let mut result = ACValidationResult::new(node_count);

    if node_count == 0 {
        return result;
    }

    // Build a set of pattern IDs referenced by AC nodes
    let mut patterns_referenced = std::collections::HashSet::new();

    for i in 0..node_count {
        let node_offset = nodes_offset + i * mem::size_of::<ACNodeHot>();
        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            continue;
        }

        let node = match ACNodeHot::read_from_prefix(&buffer[node_offset..]) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };

        // Collect and validate pattern IDs from this node
        if node.pattern_count > 0 {
            let patterns_offset = node.patterns_offset as usize;
            let patterns_size = (node.pattern_count as usize) * mem::size_of::<u32>();

            if patterns_offset + patterns_size <= buffer.len() {
                for j in 0..(node.pattern_count as usize) {
                    let pid_offset = patterns_offset + j * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        if pattern_id >= pattern_count {
                            result.error(format!(
                                "AC node {i} references invalid pattern ID: {pattern_id} (max={pattern_count})"
                            ));
                        } else {
                            patterns_referenced.insert(pattern_id);
                        }
                    }
                }
            }
        }
    }

    // If pattern entries provided, check that all literal patterns are referenced
    if let Some(entries) = pattern_entries {
        let mut unreferenced_literals = 0;

        for (pattern_id, pattern_type) in entries {
            // Only check literal patterns (type 0)
            if *pattern_type == 0 && !patterns_referenced.contains(pattern_id) {
                unreferenced_literals += 1;
            }
        }

        if unreferenced_literals > 0 {
            result.warning(format!(
                "Found {unreferenced_literals} literal patterns not referenced by any AC node"
            ));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_result_caps_retained_findings() {
        let mut result = ACValidationResult::new(0);
        for i in 0..MAX_VALIDATION_ERRORS + 10 {
            result.error(format!("error {i}"));
        }
        for i in 0..MAX_VALIDATION_WARNINGS + 10 {
            result.warning(format!("warning {i}"));
        }

        assert_eq!(result.errors.len(), MAX_VALIDATION_ERRORS);
        assert_eq!(result.warnings.len(), MAX_VALIDATION_WARNINGS);
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|message| message.as_str() == ERRORS_SUPPRESSED)
                .count(),
            1
        );
        assert_eq!(
            result
                .warnings
                .iter()
                .filter(|message| message.as_str() == WARNINGS_SUPPRESSED)
                .count(),
            1
        );
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validate_range() {
        // Valid range
        assert!(validate_range(0, 10, 100));
        assert!(validate_range(90, 10, 100));

        // Out of bounds
        assert!(!validate_range(95, 10, 100));
        assert!(!validate_range(100, 1, 100));

        // Overflow check
        assert!(!validate_range(usize::MAX - 5, 10, usize::MAX));
    }

    #[test]
    fn test_empty_automaton() {
        let buffer = vec![0u8; 100];
        let result = validate_ac_structure(&buffer, 0, 0, 0, false);
        assert!(result.is_valid());
        assert_eq!(result.stats.node_count, 0);
    }
}
