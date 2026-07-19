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
//!
//! # Querying
//!
//! [`ACAutomaton::view`] creates a streaming query view over a newly built
//! automaton. For persisted or memory-mapped buffers, store the node count,
//! pattern count, and match mode alongside the buffer, then use
//! [`ACAutomatonView::new`] for eager validation or
//! [`ACAutomatonView::from_parts`] for lazy checked access.
//! Pattern lengths are separate metadata because they are not needed when only
//! output IDs are required.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::mem;
use std::ops::ControlFlow;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod case;

pub use case::{ACCaseAutomaton, ACCaseAutomatonView, ACCaseMatchState, ACCasePattern};

// Stable field offsets in the repr(C) serialized format.
const AC_EDGE_TARGET_OFFSET: usize = 4;
#[cfg(test)]
const AC_NODE_EDGES_OFFSET: usize = 12;

// Re-export MatchMode from shared crate
pub use matchy_match_mode::MatchMode;

// Validation module for AC automaton structures
pub mod validation;

// Re-export validation types for convenience
pub use validation::{
    validate_ac_reachability, validate_ac_structure, validate_pattern_references, ACStats,
    ACValidationResult,
};

/// Error type for AC automaton operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ACError {
    /// Invalid pattern
    InvalidPattern(String),
    /// Resource limit exceeded (e.g., too many states)
    ResourceLimitExceeded(String),
    /// Invalid input
    InvalidInput(String),
}

impl fmt::Display for ACError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "Invalid pattern: {msg}"),
            Self::ResourceLimitExceeded(msg) => write!(f, "Resource limit exceeded: {msg}"),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
        }
    }
}

impl std::error::Error for ACError {}

/// One byte-pattern occurrence. Offsets are absolute within the streaming
/// input and `end` is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ACMatch {
    /// Builder-assigned pattern identifier.
    pub pattern_id: u32,
    /// Inclusive start offset of the occurrence.
    pub start: u64,
    /// Exclusive end offset of the occurrence.
    pub end: u64,
}

/// A raw automaton output before a pattern length is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ACOutput {
    /// Builder-assigned pattern identifier.
    pub pattern_id: u32,
    /// Exclusive absolute end offset of the occurrence.
    pub end: u64,
}

/// Event emitted by the bounded, allocation-free query API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ACQueryEvent {
    /// Conservative units of transition or output work about to be performed.
    Work(usize),
    /// One pattern output at the current streaming position.
    Output(ACOutput),
}

/// Independent streaming cursor for an [`ACAutomatonView`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ACMatchState {
    current_offset: usize,
    position: u64,
}

impl ACMatchState {
    /// Number of input bytes consumed since this cursor was created or reset.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
}

// Binary format structures for offset-based AC automaton

/// State encoding type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    /// No transitions (terminal state only)
    Empty = 0,
    /// Single transition - stored inline in node (75-80% of states)
    One = 1,
    /// 2-8 transitions - sparse edge array (10-15% of states)
    Sparse = 2,
    /// 9+ transitions - dense lookup table (2-5% of states)
    Dense = 3,
}

impl StateKind {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Empty),
            1 => Some(Self::One),
            2 => Some(Self::Sparse),
            3 => Some(Self::Dense),
            _ => None,
        }
    }
}

/// AC Node hot data (checked every transition)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACNodeHot {
    /// State encoding type (StateKind enum)
    pub state_kind: u8,
    /// ONE encoding: character for single transition
    pub one_char: u8,
    /// Number of edges (SPARSE/DENSE states)
    pub edge_count: u8,
    /// Number of pattern IDs at this node
    pub pattern_count: u8,
    /// ONE encoding: target offset for single transition
    pub one_target: u32,
    /// Failure link offset
    pub failure_offset: u32,
    /// Offset to edges array (SPARSE/DENSE states)
    pub edges_offset: u32,
    /// Offset to pattern IDs array
    pub patterns_offset: u32,
}

/// AC Edge (for sparse/dense states)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACEdge {
    /// Input character (0-255)
    pub character: u8,
    /// Reserved for alignment
    pub reserved: [u8; 3],
    /// Offset to target node
    pub target_offset: u32,
}

impl ACEdge {
    fn new(character: u8, target_offset: u32) -> Self {
        Self {
            character,
            reserved: [0; 3],
            target_offset,
        }
    }
}

/// Dense lookup table (256 entries)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DenseLookup {
    /// Target offsets indexed by character (0-255)
    /// 0 means no transition for that character
    pub targets: [u32; 256],
}

/// Zero-copy query view over a serialized AC automaton.
///
/// The view borrows the encoded nodes, edges, and outputs directly. Advancing a
/// cursor never rebuilds or relocates the automaton.
pub struct ACAutomatonView<'a> {
    buffer: &'a [u8],
    nodes: &'a [u8],
    node_count: usize,
    pattern_count: u32,
    pattern_lengths: Option<&'a [usize]>,
    mode: MatchMode,
    // True only after eager structural validation or construction by
    // `ACAutomaton`'s serializer. The validated query helpers rely on this
    // provenance before performing unchecked reads.
    structurally_validated: bool,
}

impl<'a> ACAutomatonView<'a> {
    /// Validate a serialized automaton for output-ID queries.
    pub fn new(
        buffer: &'a [u8],
        node_count: usize,
        pattern_count: u32,
        mode: MatchMode,
    ) -> Result<Self, ACError> {
        Self::create(buffer, node_count, pattern_count, None, mode, true, true)
    }

    /// Create a view with constant-time envelope validation.
    ///
    /// Indirect offsets and pattern IDs are checked lazily before each use, so
    /// malformed references fail closed. Use [`Self::new`] when loading an
    /// untrusted standalone automaton and eager structural error reporting is
    /// preferred.
    pub fn from_parts(
        buffer: &'a [u8],
        node_count: usize,
        pattern_count: u32,
        mode: MatchMode,
    ) -> Result<Self, ACError> {
        Self::create(buffer, node_count, pattern_count, None, mode, false, false)
    }

    /// Create an exact-span view with constant-time envelope validation.
    ///
    /// This is the pattern-length counterpart to [`Self::from_parts`].
    pub fn from_parts_with_pattern_lengths(
        buffer: &'a [u8],
        node_count: usize,
        pattern_lengths: &'a [usize],
        mode: MatchMode,
    ) -> Result<Self, ACError> {
        let pattern_count = validate_pattern_lengths(pattern_lengths)?;
        Self::create(
            buffer,
            node_count,
            pattern_count,
            Some(pattern_lengths),
            mode,
            false,
            false,
        )
    }

    /// Validate a serialized automaton for exact-span queries.
    ///
    /// `pattern_lengths` must use the builder's pattern-ID order.
    pub fn with_pattern_lengths(
        buffer: &'a [u8],
        node_count: usize,
        pattern_lengths: &'a [usize],
        mode: MatchMode,
    ) -> Result<Self, ACError> {
        let pattern_count = validate_pattern_lengths(pattern_lengths)?;
        Self::create(
            buffer,
            node_count,
            pattern_count,
            Some(pattern_lengths),
            mode,
            true,
            true,
        )
    }

    fn create(
        buffer: &'a [u8],
        node_count: usize,
        pattern_count: u32,
        pattern_lengths: Option<&'a [usize]>,
        mode: MatchMode,
        validate_structure: bool,
        structurally_validated: bool,
    ) -> Result<Self, ACError> {
        if node_count == 0 || pattern_count == 0 {
            return Err(ACError::InvalidInput(
                "Automaton node and pattern counts must be non-zero".to_string(),
            ));
        }
        let nodes_size = node_count
            .checked_mul(mem::size_of::<ACNodeHot>())
            .ok_or_else(|| ACError::InvalidInput("AC node table size overflow".to_string()))?;
        let nodes = buffer.get(..nodes_size).ok_or_else(|| {
            ACError::InvalidInput("AC node table is outside the buffer".to_string())
        })?;
        if validate_structure {
            let validation = validate_ac_structure(buffer, 0, node_count, pattern_count, true);
            if !validation.is_valid() {
                return Err(ACError::InvalidInput(format!(
                    "Invalid serialized AC automaton: {}",
                    validation.errors.join("; ")
                )));
            }
        }
        Ok(Self {
            buffer,
            nodes,
            node_count,
            pattern_count,
            pattern_lengths,
            mode,
            structurally_validated,
        })
    }

    /// Create an independent cursor positioned at the beginning of a stream.
    #[must_use]
    pub const fn create_state(&self) -> ACMatchState {
        ACMatchState {
            current_offset: 0,
            position: 0,
        }
    }

    /// Reset a cursor without releasing any caller-owned storage.
    pub fn reset_state(&self, state: &mut ACMatchState) {
        state.current_offset = 0;
        state.position = 0;
    }

    /// Advance a cursor and visit every overlapping occurrence with an exact
    /// start and end offset.
    ///
    /// Views created by [`ACAutomaton::view`] or [`Self::with_pattern_lengths`]
    /// amortize structural validation and use a direct exact-span query path.
    /// Lazy views created by [`Self::from_parts_with_pattern_lengths`] retain
    /// checked access for every serialized offset.
    ///
    /// # Errors
    /// Returns an error if this view was created without pattern lengths.
    pub fn advance(
        &self,
        state: &mut ACMatchState,
        input: &[u8],
        mut visit: impl FnMut(ACMatch),
    ) -> Result<(), ACError> {
        let pattern_lengths = self.pattern_lengths.ok_or_else(|| {
            ACError::InvalidInput("Exact-span queries require pattern lengths".to_string())
        })?;
        if self.structurally_validated {
            self.advance_validated(state, input, pattern_lengths, visit);
            return Ok(());
        }
        let result = self.try_advance(state, input, |event| {
            if let ACQueryEvent::Output(output) = event {
                let length = usize::try_from(output.pattern_id)
                    .ok()
                    .and_then(|pattern_id| pattern_lengths.get(pattern_id))
                    .and_then(|length| u64::try_from(*length).ok());
                if let Some(length) = length {
                    visit(ACMatch {
                        pattern_id: output.pattern_id,
                        start: output.end.saturating_sub(length),
                        end: output.end,
                    });
                }
            }
            ControlFlow::<()>::Continue(())
        });
        debug_assert!(result.is_continue());
        Ok(())
    }

    /// Advance an eagerly validated automaton without rechecking every
    /// serialized offset and pattern ID. Validation establishes that all
    /// indirect reads performed below are contained within `buffer` and all
    /// node targets are aligned offsets into `nodes`.
    fn advance_validated(
        &self,
        state: &mut ACMatchState,
        input: &[u8],
        pattern_lengths: &[usize],
        mut visit: impl FnMut(ACMatch),
    ) {
        let node_size = mem::size_of::<ACNodeHot>();
        if state.current_offset >= self.nodes.len() || state.current_offset % node_size != 0 {
            state.current_offset = 0;
        }

        let root = self.read_node_validated(0);
        let root_dense_offset = (root.state_kind == StateKind::Dense as u8)
            .then(|| usize::try_from(root.edges_offset).expect("validated u32 offset fits usize"));

        for &input_byte in input {
            let search_byte = if self.mode == MatchMode::CaseInsensitive {
                input_byte.to_ascii_lowercase()
            } else {
                input_byte
            };
            let mut failure_hops_remaining = self.node_count;

            loop {
                if state.current_offset == 0 {
                    if let Some(root_dense_offset) = root_dense_offset {
                        let target = self.read_u32_validated(
                            root_dense_offset + usize::from(search_byte) * mem::size_of::<u32>(),
                        );
                        state.current_offset =
                            usize::try_from(target).expect("validated u32 offset fits usize");
                    } else {
                        state.current_offset = self
                            .find_transition_validated(root, search_byte)
                            .unwrap_or_default();
                    }
                    break;
                }

                let node = self.read_node_validated(state.current_offset);
                if let Some(target) = self.find_transition_validated(node, search_byte) {
                    state.current_offset = target;
                    break;
                }
                if failure_hops_remaining == 0 {
                    state.current_offset = 0;
                    break;
                }
                failure_hops_remaining -= 1;
                state.current_offset =
                    usize::try_from(node.failure_offset).expect("validated u32 offset fits usize");
            }

            state.position = state.position.saturating_add(1);
            if state.current_offset == 0 {
                continue;
            }

            let node = self.read_node_validated(state.current_offset);
            let patterns_offset =
                usize::try_from(node.patterns_offset).expect("validated u32 offset fits usize");
            for output_index in 0..usize::from(node.pattern_count) {
                let pattern_id =
                    self.read_u32_validated(patterns_offset + output_index * mem::size_of::<u32>());
                let length = pattern_lengths
                    [usize::try_from(pattern_id).expect("validated u32 ID fits usize")];
                let Ok(length) = u64::try_from(length) else {
                    continue;
                };
                visit(ACMatch {
                    pattern_id,
                    start: state.position.saturating_sub(length),
                    end: state.position,
                });
            }
        }
    }

    // These direct readers are confined to the eagerly validated query path.
    // They avoid repeating slice-range construction and bounds checks in the
    // per-byte AC hot loop after the same ranges were already proven valid.
    // Lazy views over externally supplied buffers never call them.
    #[inline(always)]
    fn read_node_validated(&self, offset: usize) -> ACNodeHot {
        let node_size = mem::size_of::<ACNodeHot>();
        debug_assert!(self.structurally_validated);
        debug_assert!(offset % node_size == 0);
        debug_assert!(offset.saturating_add(node_size) <= self.nodes.len());
        // SAFETY: `structurally_validated` views establish that every node
        // offset is contained in the fixed-width node table. `ACNodeHot`
        // contains only integers, so every bit pattern is valid. An unaligned
        // read also keeps this correct if the borrowed buffer itself has only
        // byte alignment.
        unsafe {
            self.nodes
                .as_ptr()
                .add(offset)
                .cast::<ACNodeHot>()
                .read_unaligned()
        }
    }

    #[inline(always)]
    fn read_u32_validated(&self, offset: usize) -> u32 {
        debug_assert!(self.structurally_validated);
        debug_assert!(offset.saturating_add(mem::size_of::<u32>()) <= self.buffer.len());
        // SAFETY: structural validation proves that every transition target
        // and output ID read here is fully contained in `buffer`; unaligned
        // access avoids imposing an alignment requirement on borrowed byte
        // storage.
        u32::from_le(unsafe {
            self.buffer
                .as_ptr()
                .add(offset)
                .cast::<u32>()
                .read_unaligned()
        })
    }

    #[inline(always)]
    fn read_u8_validated(&self, offset: usize) -> u8 {
        debug_assert!(self.structurally_validated);
        debug_assert!(offset < self.buffer.len());
        // SAFETY: structural validation proves that every sparse-edge record
        // read here is fully contained in `buffer`.
        unsafe { *self.buffer.get_unchecked(offset) }
    }

    #[inline(always)]
    fn find_transition_validated(&self, node: ACNodeHot, byte: u8) -> Option<usize> {
        match node.state_kind {
            kind if kind == StateKind::One as u8 => (node.one_char == byte)
                .then(|| usize::try_from(node.one_target).expect("validated u32 offset fits usize"))
                .filter(|target| *target != 0),
            kind if kind == StateKind::Empty as u8 => None,
            kind if kind == StateKind::Sparse as u8 => {
                let edges_offset =
                    usize::try_from(node.edges_offset).expect("validated u32 offset fits usize");
                for edge_index in 0..usize::from(node.edge_count) {
                    let edge_offset = edges_offset + edge_index * mem::size_of::<ACEdge>();
                    let edge_byte = self.read_u8_validated(edge_offset);
                    if edge_byte == byte {
                        let target = self.read_u32_validated(edge_offset + AC_EDGE_TARGET_OFFSET);
                        return Some(
                            usize::try_from(target).expect("validated u32 offset fits usize"),
                        );
                    }
                    if edge_byte > byte {
                        return None;
                    }
                }
                None
            }
            kind if kind == StateKind::Dense as u8 => {
                let lookup_offset =
                    usize::try_from(node.edges_offset).expect("validated u32 offset fits usize");
                let target = self
                    .read_u32_validated(lookup_offset + usize::from(byte) * mem::size_of::<u32>());
                (target != 0)
                    .then(|| usize::try_from(target).expect("validated u32 offset fits usize"))
            }
            _ => unreachable!("validated automaton has a known state kind"),
        }
    }

    /// Advance a cursor while exposing conservative work units and raw output
    /// IDs to an allocation-free handler.
    ///
    /// Returning `ControlFlow::Break` stops immediately. The cursor should be
    /// discarded or reset after an early break because the remaining input was
    /// not consumed.
    pub fn try_advance<B>(
        &self,
        state: &mut ACMatchState,
        input: &[u8],
        handle: impl FnMut(ACQueryEvent) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        self.try_advance_impl(state, input, true, handle)
    }

    /// Equivalent to [`try_advance`](Self::try_advance), but accepts input that
    /// has already been normalized for the automaton's match mode.
    ///
    /// For case-insensitive automata, callers must ASCII-lowercase the input.
    /// This is useful for consumers that already maintain a reusable SIMD
    /// normalization buffer.
    pub fn try_advance_normalized<B>(
        &self,
        state: &mut ACMatchState,
        input: &[u8],
        handle: impl FnMut(ACQueryEvent) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        self.try_advance_impl(state, input, false, handle)
    }

    fn try_advance_impl<B>(
        &self,
        state: &mut ACMatchState,
        input: &[u8],
        normalize_input: bool,
        mut handle: impl FnMut(ACQueryEvent) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        let node_size = mem::size_of::<ACNodeHot>();
        if state.current_offset >= self.nodes.len() || state.current_offset % node_size != 0 {
            state.current_offset = 0;
        }
        let Some(root) = self.read_node(0) else {
            return ControlFlow::Continue(());
        };
        let root_kind = StateKind::from_u8(root.state_kind).unwrap_or(StateKind::Empty);
        let root_dense_table = if root_kind == StateKind::Dense {
            usize::try_from(root.edges_offset)
                .ok()
                .filter(|offset| {
                    *offset >= self.nodes.len() && *offset % mem::size_of::<u32>() == 0
                })
                .and_then(|offset| {
                    let end = offset.checked_add(mem::size_of::<DenseLookup>())?;
                    self.buffer.get(offset..end)
                })
        } else {
            None
        };

        for &input_byte in input {
            let search_byte = if normalize_input && self.mode == MatchMode::CaseInsensitive {
                input_byte.to_ascii_lowercase()
            } else {
                input_byte
            };
            let mut failure_hops_remaining = self.node_count;

            loop {
                if state.current_offset == 0 {
                    if let Some(root_dense_table) = root_dense_table {
                        handle(ACQueryEvent::Work(1))?;
                        let target = read_u32_le(
                            root_dense_table,
                            usize::from(search_byte) * mem::size_of::<u32>(),
                        )
                        .unwrap_or(0);
                        if let Some(target) = self.checked_target(target) {
                            state.current_offset = target;
                        }
                    } else {
                        handle(ACQueryEvent::Work(transition_work(root)))?;
                        if let Some(target) = self.find_transition(root, search_byte) {
                            state.current_offset = target;
                        }
                    }
                    break;
                }

                let Some(node) = self.read_node(state.current_offset) else {
                    state.current_offset = 0;
                    break;
                };
                if StateKind::from_u8(node.state_kind).is_none() {
                    state.current_offset = 0;
                    break;
                }
                handle(ACQueryEvent::Work(transition_work(node)))?;
                if let Some(target) = self.find_transition(node, search_byte) {
                    state.current_offset = target;
                    break;
                }
                if failure_hops_remaining == 0 {
                    state.current_offset = 0;
                    break;
                }
                handle(ACQueryEvent::Work(1))?;
                failure_hops_remaining -= 1;
                if node.failure_offset == 0 {
                    state.current_offset = 0;
                    continue;
                }
                let Some(failure_offset) = self.checked_target(node.failure_offset) else {
                    state.current_offset = 0;
                    break;
                };
                state.current_offset = failure_offset;
            }

            state.position = state.position.saturating_add(1);
            if state.current_offset == 0 {
                continue;
            }
            let Some(node) = self.read_node(state.current_offset) else {
                state.current_offset = 0;
                continue;
            };
            let Some(patterns_offset) = usize::try_from(node.patterns_offset).ok() else {
                continue;
            };
            if patterns_offset < self.nodes.len() || patterns_offset % mem::size_of::<u32>() != 0 {
                continue;
            }
            let output_count = usize::from(node.pattern_count);
            let Some(outputs_size) = output_count.checked_mul(mem::size_of::<u32>()) else {
                continue;
            };
            let Some(outputs_end) = patterns_offset.checked_add(outputs_size) else {
                continue;
            };
            let Some(outputs) = self.buffer.get(patterns_offset..outputs_end) else {
                continue;
            };
            for output in outputs.chunks_exact(mem::size_of::<u32>()) {
                handle(ACQueryEvent::Work(1))?;
                let Some(pattern_id) =
                    read_u32_le(output, 0).filter(|pattern_id| *pattern_id < self.pattern_count)
                else {
                    continue;
                };
                handle(ACQueryEvent::Output(ACOutput {
                    pattern_id,
                    end: state.position,
                }))?;
            }
        }
        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn read_node(&self, offset: usize) -> Option<ACNodeHot> {
        if offset % mem::size_of::<ACNodeHot>() != 0 {
            return None;
        }
        let end = offset.checked_add(mem::size_of::<ACNodeHot>())?;
        let bytes = self.nodes.get(offset..end)?;
        ACNodeHot::read_from_prefix(bytes)
            .ok()
            .map(|(node, _)| node)
    }

    #[inline(always)]
    fn checked_target(&self, target: u32) -> Option<usize> {
        let target = usize::try_from(target).ok()?;
        (target != 0 && target < self.nodes.len()).then_some(target)
    }

    #[inline(always)]
    fn find_transition(&self, node: ACNodeHot, byte: u8) -> Option<usize> {
        match StateKind::from_u8(node.state_kind)? {
            StateKind::Empty => None,
            StateKind::One => (node.one_char == byte && node.one_target == node.edges_offset)
                .then(|| self.checked_target(node.one_target))?,
            StateKind::Sparse => {
                let edges_offset = usize::try_from(node.edges_offset).ok()?;
                if edges_offset < self.nodes.len() || edges_offset % mem::size_of::<u32>() != 0 {
                    return None;
                }
                let count = usize::from(node.edge_count);
                let edges_size = count.checked_mul(mem::size_of::<ACEdge>())?;
                let edges_end = edges_offset.checked_add(edges_size)?;
                let edges = self.buffer.get(edges_offset..edges_end)?;
                for edge in edges.chunks_exact(mem::size_of::<ACEdge>()) {
                    let edge_byte = edge[0];
                    if edge_byte == byte {
                        let target = read_u32_le(edge, AC_EDGE_TARGET_OFFSET)?;
                        return self.checked_target(target);
                    }
                    if edge_byte > byte {
                        return None;
                    }
                }
                None
            }
            StateKind::Dense => {
                let lookup_offset = usize::try_from(node.edges_offset).ok()?;
                if lookup_offset < self.nodes.len() || lookup_offset % mem::size_of::<u32>() != 0 {
                    return None;
                }
                let entry_offset = usize::from(byte).checked_mul(mem::size_of::<u32>())?;
                let target_offset = lookup_offset.checked_add(entry_offset)?;
                let target = read_u32_le(self.buffer, target_offset)?;
                self.checked_target(target)
            }
        }
    }
}

fn validate_pattern_lengths(pattern_lengths: &[usize]) -> Result<u32, ACError> {
    if pattern_lengths.contains(&0) {
        return Err(ACError::InvalidInput(
            "Pattern lengths must be non-zero".to_string(),
        ));
    }
    u32::try_from(pattern_lengths.len())
        .map_err(|_| ACError::InvalidInput("Pattern length count exceeds u32::MAX".to_string()))
}

fn transition_work(node: ACNodeHot) -> usize {
    if StateKind::from_u8(node.state_kind) == Some(StateKind::Sparse) {
        usize::from(node.edge_count).max(1)
    } else {
        1
    }
}

fn read_u32_le(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = buffer
        .get(offset..offset.checked_add(mem::size_of::<u32>())?)?
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}

// Note: Case-Insensitive Implementation
//
// Case-insensitive mode uses a memory-efficient approach:
// - Patterns are normalized to lowercase during automaton construction
// - Input text is normalized to lowercase during search (using SIMD)
// - This avoids doubling the automaton size (compared to storing both upper/lower transitions)
//
// For ~16K PSL patterns, this reduces memory usage by approximately 50%.

/// Builder for constructing the offset-based AC automaton
///
/// This uses temporary in-memory structures during construction,
/// then serializes them into the final offset-based format.
struct ACBuilder {
    /// Temporary states during construction
    states: Vec<BuilderState>,
    /// Matching mode
    mode: MatchMode,
    /// Normalized pattern lengths in builder-assigned ID order.
    pattern_lengths: Vec<usize>,
}

/// Temporary state structure used during construction
#[derive(Debug, Clone)]
struct BuilderState {
    transitions: HashMap<u8, u32>,
    failure: u32,
    outputs: Vec<u32>, // Pattern IDs
}

impl BuilderState {
    fn new() -> Self {
        Self {
            transitions: HashMap::new(),
            failure: 0,
            outputs: Vec::new(),
        }
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
            states: vec![BuilderState::new()], // Root
            mode,
            pattern_lengths: Vec::new(),
        }
    }

    /// Add a pattern to the automaton
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, patterns are normalized to lowercase here.
    /// This avoids the memory overhead of storing both uppercase and lowercase transitions.
    ///
    /// Example: Pattern "Hello" becomes "hello" with a single transition path,
    /// rather than 2^5 = 32 paths for all case combinations.
    fn add_pattern(&mut self, pattern: &[u8]) -> Result<u32, ACError> {
        let pattern_id = u32::try_from(self.pattern_lengths.len())
            .map_err(|_| ACError::ResourceLimitExceeded("Pattern count exceeds u32::MAX".into()))?;

        // Matchy's query semantics are byte-oriented and ASCII-insensitive.
        // Normalize one byte at a time so arbitrary binary patterns remain valid.
        let pattern_bytes: Vec<u8> = match self.mode {
            MatchMode::CaseSensitive => pattern.to_vec(),
            MatchMode::CaseInsensitive => pattern.iter().map(u8::to_ascii_lowercase).collect(),
        };
        self.pattern_lengths.push(pattern_bytes.len());

        // Build trie path
        let mut current = 0u32;

        for &ch in &pattern_bytes {
            // Check if transition already exists
            if let Some(&next) = self.states[current as usize].transitions.get(&ch) {
                current = next;
            } else {
                // Create new state
                let new_id = u32::try_from(self.states.len()).map_err(|_| {
                    ACError::ResourceLimitExceeded("State count exceeds u32::MAX".into())
                })?;
                self.states.push(BuilderState::new());
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
                        if target == next_state {
                            self.states[next_state as usize].failure = 0;
                        } else {
                            self.states[next_state as usize].failure = target;
                        }
                    } else {
                        self.states[next_state as usize].failure = 0;
                    }
                }

                // The failure state's outputs already include the outputs inherited
                // from its own failure chain. Copying only that list preserves every
                // suffix match without adding the same pattern ID more than once.
                let failure_state = self.states[next_state as usize].failure;
                if failure_state != 0 {
                    let suffix_outputs = self.states[failure_state as usize].outputs.clone();
                    self.states[next_state as usize]
                        .outputs
                        .extend(suffix_outputs);
                }
            }
        }
    }

    /// Serialize into offset-based format with state-specific encoding
    fn serialize(self) -> Result<Vec<u8>, ACError> {
        if let Some((state_id, state)) = self
            .states
            .iter()
            .enumerate()
            .find(|(_, state)| state.outputs.len() > usize::from(u8::MAX))
        {
            return Err(ACError::ResourceLimitExceeded(format!(
                "AC state {state_id} has {} pattern outputs; maximum is {}",
                state.outputs.len(),
                u8::MAX
            )));
        }

        let mut buffer = Vec::new();

        // Calculate section sizes - using cache-optimized ACNodeHot (20 bytes)
        let node_size = mem::size_of::<ACNodeHot>();
        let edge_size = mem::size_of::<ACEdge>();
        let dense_size = mem::size_of::<DenseLookup>();

        let nodes_start = 0;
        let nodes_size = self.states.len() * node_size;

        // Classify states and count by type
        // Root node (index 0) is ALWAYS Dense for O(1) lookup performance
        let state_kinds: Vec<StateKind> = self
            .states
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 0 {
                    StateKind::Dense
                } else {
                    s.classify_state_kind()
                }
            })
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

        // Calculate padding to align dense section to 64-byte boundary (only if we have dense lookups)
        // DenseLookup now has #[repr(C, align(64))] for cache-line alignment
        let unaligned_dense_start = edges_start + edges_size;
        let dense_alignment = mem::align_of::<DenseLookup>(); // 64 bytes
        let (dense_padding, dense_start) = if dense_count > 0 {
            let padding =
                (dense_alignment - (unaligned_dense_start % dense_alignment)) % dense_alignment;
            (padding, unaligned_dense_start + padding)
        } else {
            // No dense lookups, so no need for padding - patterns come right after edges
            (0, unaligned_dense_start)
        };
        let dense_size_total = dense_count * dense_size;

        let patterns_start = dense_start + dense_size_total;
        let patterns_size = total_patterns * mem::size_of::<u32>();

        // Calculate total size (including alignment padding only if we have dense lookups)
        let total_size = nodes_size + edges_size + dense_padding + dense_size_total + patterns_size;

        // Reasonable size limit to prevent pathological inputs from causing OOM
        // Set to 2GB which is large enough for legitimate databases but catches
        // pathological inputs early
        const MAX_BUFFER_SIZE: usize = 2_000_000_000; // 2GB

        if total_size > MAX_BUFFER_SIZE {
            return Err(ACError::ResourceLimitExceeded(format!(
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
                .map(|(&ch, &target)| {
                    let offset = node_offsets[target as usize];
                    let offset_u32 = u32::try_from(offset).map_err(|_| {
                        ACError::ResourceLimitExceeded("Node offset exceeds u32::MAX".into())
                    });
                    offset_u32.map(|o| (ch, o))
                })
                .collect::<Result<Vec<_>, _>>()?;
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
                    let sparse_offset = u32::try_from(edge_offset).map_err(|_| {
                        ACError::ResourceLimitExceeded("Sparse edge offset exceeds u32::MAX".into())
                    })?;

                    for (ch, target) in &edges {
                        let edge = ACEdge::new(*ch, *target);
                        buffer[edge_offset..edge_offset + edge_size]
                            .copy_from_slice(edge.as_bytes());
                        edge_offset += edge_size;
                    }

                    (sparse_offset, 0u8, 0u32)
                }

                StateKind::Dense => {
                    // Write dense lookup table
                    let lookup_offset = u32::try_from(dense_offset).map_err(|_| {
                        ACError::ResourceLimitExceeded(
                            "Dense lookup offset exceeds u32::MAX".into(),
                        )
                    })?;
                    let mut lookup = DenseLookup {
                        targets: [0u32; 256],
                    };

                    for (ch, target) in &edges {
                        lookup.targets[*ch as usize] = *target;
                    }

                    buffer[dense_offset..dense_offset + dense_size]
                        .copy_from_slice(lookup.as_bytes());
                    dense_offset += dense_size;

                    (lookup_offset, 0u8, 0u32)
                }
            };

            // Write pattern IDs
            let patterns_offset_for_node = if state.outputs.is_empty() {
                0u32
            } else {
                u32::try_from(pattern_offset).map_err(|_| {
                    ACError::ResourceLimitExceeded("Pattern offset exceeds u32::MAX".into())
                })?
            };

            for &pattern_id in &state.outputs {
                buffer[pattern_offset..pattern_offset + 4]
                    .copy_from_slice(&pattern_id.to_le_bytes());
                pattern_offset += mem::size_of::<u32>();
            }

            // Write cache-optimized hot node (20 bytes)
            let failure_offset = if state.failure == 0 {
                0u32
            } else {
                u32::try_from(node_offsets[state.failure as usize]).map_err(|_| {
                    ACError::ResourceLimitExceeded("Failure offset exceeds u32::MAX".into())
                })?
            };

            // Dense states do not use edge_count during lookup. Pattern output
            // counts were checked before serialization, so conversion is exact.
            let edge_count_u8 = match kind {
                StateKind::One => 0, // Single edge stored inline, not in edge array
                _ => u8::try_from(state.transitions.len()).unwrap_or(u8::MAX),
            };
            let pattern_count_u8 = u8::try_from(state.outputs.len()).map_err(|_| {
                ACError::ResourceLimitExceeded(format!("AC state {i} has too many pattern outputs"))
            })?;

            // Create hot node with optimal field ordering for cache access
            let one_target = match kind {
                StateKind::One => edges[0].1,
                _ => 0,
            };

            let node = ACNodeHot {
                state_kind: kind as u8,
                one_char,
                edge_count: edge_count_u8,
                pattern_count: pattern_count_u8,
                one_target,
                failure_offset,
                edges_offset: edges_offset_for_node,
                patterns_offset: patterns_offset_for_node,
            };

            buffer[node_offset..node_offset + node_size].copy_from_slice(node.as_bytes());
        }

        Ok(buffer)
    }
}

/// Owned offset-based Aho-Corasick automaton.
///
/// All automaton data is stored in a single byte buffer using offsets. Query
/// views borrow that buffer without rebuilding any matching structures.
pub struct ACAutomaton {
    /// Binary buffer containing all automaton data
    buffer: Vec<u8>,
    /// Number of AC nodes in the automaton
    node_count: usize,
    /// Pattern lengths in builder-assigned ID order.
    pattern_lengths: Vec<usize>,
    /// Matching mode used to normalize patterns while building.
    mode: MatchMode,
}

impl ACAutomaton {
    /// Create a new AC automaton (initially empty)
    #[must_use]
    pub fn new(mode: MatchMode) -> Self {
        Self {
            buffer: Vec::new(),
            node_count: 0,
            pattern_lengths: Vec::new(),
            mode,
        }
    }

    /// Build the automaton from patterns
    ///
    /// This constructs the offset-based binary format directly.
    pub fn build(patterns: &[&str], mode: MatchMode) -> Result<Self, ACError> {
        let byte_patterns = patterns
            .iter()
            .map(|pattern| pattern.as_bytes())
            .collect::<Vec<_>>();
        Self::build_bytes(&byte_patterns, mode)
    }

    /// Build an automaton from arbitrary byte patterns.
    ///
    /// Pattern IDs correspond to input order. Case-insensitive construction
    /// performs ASCII byte folding and leaves non-ASCII bytes unchanged.
    pub fn build_bytes(patterns: &[&[u8]], mode: MatchMode) -> Result<Self, ACError> {
        if patterns.is_empty() {
            return Err(ACError::InvalidPattern("No patterns provided".to_string()));
        }

        let mut builder = ACBuilder::new(mode);

        for pattern in patterns {
            if pattern.is_empty() {
                return Err(ACError::InvalidPattern("Empty pattern".to_string()));
            }
            builder.add_pattern(pattern)?; // Propagate error
        }

        builder.build_failure_links();
        let node_count = builder.states.len();
        let pattern_lengths = builder.pattern_lengths.clone();
        let buffer = builder.serialize()?;

        Ok(Self {
            buffer,
            node_count,
            pattern_lengths,
            mode,
        })
    }

    /// Get the buffer (for serialization)
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the number of AC nodes in the automaton
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Get the number of patterns in builder-assigned ID order.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.pattern_lengths.len()
    }

    /// Pattern lengths in builder-assigned ID order.
    #[must_use]
    pub fn pattern_lengths(&self) -> &[usize] {
        &self.pattern_lengths
    }

    /// Get the matching mode used to normalize patterns.
    #[must_use]
    pub const fn match_mode(&self) -> MatchMode {
        self.mode
    }

    /// Create a zero-copy query view over this automaton.
    ///
    /// Automata built by this type already own structurally valid buffers and
    /// non-zero pattern lengths, so creating repeated query views performs
    /// only constant-time envelope validation. Serialized or memory-mapped
    /// buffers should use [`ACAutomatonView::new`] when eager structural
    /// validation is required.
    pub fn view(&self) -> Result<ACAutomatonView<'_>, ACError> {
        let pattern_count = u32::try_from(self.pattern_lengths.len()).map_err(|_| {
            ACError::InvalidInput("Pattern length count exceeds u32::MAX".to_string())
        })?;
        ACAutomatonView::create(
            &self.buffer,
            self.node_count,
            pattern_count,
            Some(&self.pattern_lengths),
            self.mode,
            false,
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        assert!(!ac.buffer.is_empty());
    }

    #[test]
    fn empty_owned_automaton_has_no_query_view() {
        let ac = ACAutomaton::new(MatchMode::CaseSensitive);

        assert!(matches!(ac.view(), Err(ACError::InvalidInput(_))));
    }

    #[test]
    fn failure_outputs_are_inherited_once() {
        let ac = ACAutomaton::build(&["a", "ba", "cba"], MatchMode::CaseSensitive).unwrap();
        let node_size = std::mem::size_of::<ACNodeHot>();
        let terminal_offset = (ac.node_count() - 1) * node_size;
        let (terminal, _) = ACNodeHot::read_from_prefix(&ac.buffer()[terminal_offset..]).unwrap();

        assert_eq!(terminal.pattern_count, 3);
        let patterns_offset = usize::try_from(terminal.patterns_offset).unwrap();
        let pattern_bytes = &ac.buffer()
            [patterns_offset..patterns_offset + usize::from(terminal.pattern_count) * 4];
        let pattern_ids: Vec<u32> = pattern_bytes
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        assert_eq!(pattern_ids, [2, 1, 0]);
    }

    #[test]
    fn rejects_states_with_more_than_u8_max_outputs() {
        let patterns = vec!["same"; usize::from(u8::MAX) + 1];

        let error = match ACAutomaton::build(&patterns, MatchMode::CaseSensitive) {
            Ok(_) => panic!("expected excessive state outputs to be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, ACError::ResourceLimitExceeded(_)));
        assert!(error.to_string().contains("256 pattern outputs"));
    }

    #[test]
    fn accepts_exactly_u8_max_outputs() {
        let patterns = vec!["same"; usize::from(u8::MAX)];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();
        let node_size = std::mem::size_of::<ACNodeHot>();
        let terminal_offset = (ac.node_count() - 1) * node_size;
        let (terminal, _) = ACNodeHot::read_from_prefix(&ac.buffer()[terminal_offset..]).unwrap();

        assert_eq!(terminal.pattern_count, u8::MAX);
    }

    #[test]
    fn builds_patterns_longer_than_u8_max() {
        let pattern = "a".repeat(300);
        let ac = ACAutomaton::build(&[pattern.as_str()], MatchMode::CaseSensitive).unwrap();

        assert_eq!(ac.node_count(), pattern.len() + 1);
        assert!(!ac.buffer().is_empty());
    }

    #[test]
    fn string_and_byte_builders_have_identical_encoding() {
        let strings = ACAutomaton::build(&["he", "she", "hers"], MatchMode::CaseSensitive).unwrap();
        let bytes = ACAutomaton::build_bytes(
            &[b"he".as_slice(), b"she".as_slice(), b"hers".as_slice()],
            MatchMode::CaseSensitive,
        )
        .unwrap();

        assert_eq!(strings.buffer(), bytes.buffer());
        assert_eq!(strings.node_count(), bytes.node_count());
    }

    #[test]
    fn reports_overlapping_matches_across_chunks() {
        let ac = ACAutomaton::build(&["he", "she", "hers"], MatchMode::CaseSensitive).unwrap();
        let view = ACAutomatonView::from_parts_with_pattern_lengths(
            ac.buffer(),
            ac.node_count(),
            ac.pattern_lengths(),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        let mut state = view.create_state();
        let mut matches = Vec::new();

        view.advance(&mut state, b"us", |matched| matches.push(matched))
            .unwrap();
        view.advance(&mut state, b"hers", |matched| matches.push(matched))
            .unwrap();

        assert_eq!(
            matches,
            [
                ACMatch {
                    pattern_id: 1,
                    start: 1,
                    end: 4,
                },
                ACMatch {
                    pattern_id: 0,
                    start: 2,
                    end: 4,
                },
                ACMatch {
                    pattern_id: 2,
                    start: 2,
                    end: 6,
                },
            ]
        );
        assert_eq!(state.position(), 6);

        view.reset_state(&mut state);
        assert_eq!(state.position(), 0);
    }

    #[test]
    fn validated_and_checked_queries_match_across_chunk_boundaries() {
        fn collect(view: &ACAutomatonView<'_>, input: &[u8], chunk_size: usize) -> Vec<ACMatch> {
            let mut state = view.create_state();
            let mut matches = Vec::new();
            for chunk in input.chunks(chunk_size) {
                view.advance(&mut state, chunk, |matched| matches.push(matched))
                    .unwrap();
            }
            matches
        }

        let patterns = ["a", "aa", "bab", "bc", "bca", "c", "caa"];
        let input = b"ABCCABABCAABCAABAB";
        for mode in [MatchMode::CaseSensitive, MatchMode::CaseInsensitive] {
            let ac = ACAutomaton::build(&patterns, mode).unwrap();
            let owned = ac.view().unwrap();
            let validated = ACAutomatonView::with_pattern_lengths(
                ac.buffer(),
                ac.node_count(),
                ac.pattern_lengths(),
                mode,
            )
            .unwrap();
            let node_alignment = mem::align_of::<ACNodeHot>();
            assert!(node_alignment > 1);
            let mut unaligned_storage = vec![0; ac.buffer().len() + node_alignment];
            let base = unaligned_storage.as_ptr() as usize;
            let prefix = (0..node_alignment)
                .find(|prefix| (base + prefix) % node_alignment != 0)
                .expect("an alignment greater than one has a misaligned offset");
            let unaligned_buffer =
                &mut unaligned_storage[prefix..prefix.saturating_add(ac.buffer().len())];
            unaligned_buffer.copy_from_slice(ac.buffer());
            assert_ne!(unaligned_buffer.as_ptr() as usize % node_alignment, 0);
            let unaligned = ACAutomatonView::with_pattern_lengths(
                unaligned_buffer,
                ac.node_count(),
                ac.pattern_lengths(),
                mode,
            )
            .unwrap();
            let checked = ACAutomatonView::from_parts_with_pattern_lengths(
                ac.buffer(),
                ac.node_count(),
                ac.pattern_lengths(),
                mode,
            )
            .unwrap();

            for chunk_size in 1..=input.len() {
                let expected = collect(&checked, input, chunk_size);
                assert_eq!(
                    collect(&owned, input, chunk_size),
                    expected,
                    "owned query differs for {mode:?} with chunk size {chunk_size}"
                );
                assert_eq!(
                    collect(&validated, input, chunk_size),
                    expected,
                    "eagerly validated query differs for {mode:?} with chunk size {chunk_size}"
                );
                assert_eq!(
                    collect(&unaligned, input, chunk_size),
                    expected,
                    "unaligned validated query differs for {mode:?} with chunk size {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn byte_patterns_use_ascii_only_case_folding() {
        let pattern = [0xff, b'A'];
        let ac =
            ACAutomaton::build_bytes(&[pattern.as_slice()], MatchMode::CaseInsensitive).unwrap();
        let view = ac.view().unwrap();
        let mut state = view.create_state();
        let mut matches = Vec::new();

        view.advance(&mut state, &[0xff, b'a'], |matched| matches.push(matched))
            .unwrap();

        assert_eq!(
            matches,
            [ACMatch {
                pattern_id: 0,
                start: 0,
                end: 2,
            }]
        );
    }

    #[test]
    fn serialized_view_reports_output_ids_without_pattern_strings() {
        let ac = ACAutomaton::build(&["a", "aa"], MatchMode::CaseSensitive).unwrap();
        let view = ACAutomatonView::new(
            ac.buffer(),
            ac.node_count(),
            u32::try_from(ac.pattern_lengths().len()).unwrap(),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        let mut state = view.create_state();
        let mut outputs = Vec::new();

        let completed = view.try_advance(&mut state, b"aaa", |event| {
            if let ACQueryEvent::Output(output) = event {
                outputs.push(output);
            }
            ControlFlow::<()>::Continue(())
        });

        assert!(completed.is_continue());
        assert_eq!(
            outputs,
            [
                ACOutput {
                    pattern_id: 0,
                    end: 1,
                },
                ACOutput {
                    pattern_id: 1,
                    end: 2,
                },
                ACOutput {
                    pattern_id: 0,
                    end: 2,
                },
                ACOutput {
                    pattern_id: 1,
                    end: 3,
                },
                ACOutput {
                    pattern_id: 0,
                    end: 3,
                },
            ]
        );
    }

    #[test]
    fn strict_view_rejects_corrupt_offsets_and_lazy_view_fails_closed() {
        let ac = ACAutomaton::build(&["needle"], MatchMode::CaseSensitive).unwrap();
        let mut buffer = ac.buffer().to_vec();
        let root_edges = AC_NODE_EDGES_OFFSET;
        buffer[root_edges..root_edges + mem::size_of::<u32>()]
            .copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(
            ACAutomatonView::new(&buffer, ac.node_count(), 1, MatchMode::CaseSensitive,).is_err()
        );

        let view =
            ACAutomatonView::from_parts(&buffer, ac.node_count(), 1, MatchMode::CaseSensitive)
                .unwrap();
        let mut state = view.create_state();
        let mut outputs = Vec::new();
        let completed = view.try_advance(&mut state, b"needle", |event| {
            if let ACQueryEvent::Output(output) = event {
                outputs.push(output);
            }
            ControlFlow::<()>::Continue(())
        });

        assert!(completed.is_continue());
        assert!(outputs.is_empty());
    }

    #[test]
    fn serialized_view_rejects_impossible_node_table_sizes() {
        assert!(ACAutomatonView::new(&[], usize::MAX, 1, MatchMode::CaseSensitive,).is_err());
    }
}
