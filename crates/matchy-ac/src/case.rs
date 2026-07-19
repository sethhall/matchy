//! Per-pattern ASCII case semantics layered over offset-based AC automata.

use std::collections::BTreeMap;
use std::mem;

use crate::{ACAutomaton, ACAutomatonView, ACError, ACMatch, ACMatchState, MatchMode};

const NO_EXACT_CHECK: u32 = u32::MAX;
const MULTI_VARIANT_TAG: u32 = u32::MAX;

/// One arbitrary byte pattern and its ASCII case-matching mode.
///
/// Pattern identifiers in [`ACCaseAutomaton`] correspond to input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ACCasePattern<'a> {
    /// Arbitrary pattern bytes. Empty patterns are rejected.
    pub bytes: &'a [u8],
    /// Whether ASCII letter matching is case-sensitive or case-insensitive.
    pub mode: MatchMode,
}

impl<'a> ACCasePattern<'a> {
    /// Describe one pattern with explicit per-pattern case semantics.
    #[must_use]
    pub const fn new(bytes: &'a [u8], mode: MatchMode) -> Self {
        Self { bytes, mode }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FoldedPathDispatch {
    pattern_id_or_tag: u32,
    exact_offset_or_range: u32,
}

const _: () = assert!(mem::size_of::<FoldedPathDispatch>() == 8);

impl FoldedPathDispatch {
    fn singleton(variant: CaseVariant) -> Result<Self, ACError> {
        if variant.pattern_id == MULTI_VARIANT_TAG {
            return Err(ACError::ResourceLimitExceeded(
                "Singleton-optimized mixed case layout reserves pattern ID u32::MAX".to_string(),
            ));
        }
        Ok(Self {
            pattern_id_or_tag: variant.pattern_id,
            exact_offset_or_range: variant.exact_offset,
        })
    }

    fn multi(range_index: u32) -> Self {
        Self {
            pattern_id_or_tag: MULTI_VARIANT_TAG,
            exact_offset_or_range: range_index,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct VariantRange {
    start: u32,
    count: u32,
}

#[derive(Debug, Clone, Copy)]
struct CaseVariant {
    pattern_id: u32,
    exact_offset: u32,
}

enum MixedDispatch {
    Flat {
        paths: Box<[VariantRange]>,
        variants: Box<[CaseVariant]>,
    },
    SingletonOptimized {
        paths: Box<[FoldedPathDispatch]>,
        variant_ranges: Box<[VariantRange]>,
        multi_variants: Box<[CaseVariant]>,
    },
}

fn encode_case_variant(
    pattern_id: usize,
    pattern: &ACCasePattern<'_>,
    exact_bytes: &mut Vec<u8>,
) -> Result<CaseVariant, ACError> {
    let pattern_id = u32::try_from(pattern_id).map_err(|_| {
        ACError::ResourceLimitExceeded("Pattern count exceeds u32::MAX".to_string())
    })?;
    let needs_exact = pattern.mode == MatchMode::CaseSensitive
        && pattern.bytes.iter().any(u8::is_ascii_alphabetic);
    let exact_offset = if needs_exact {
        let offset = u32::try_from(exact_bytes.len()).map_err(|_| {
            ACError::ResourceLimitExceeded("Mixed case exact bytes exceed u32::MAX".to_string())
        })?;
        let _exact_end = exact_bytes
            .len()
            .checked_add(pattern.bytes.len())
            .and_then(|end| u32::try_from(end).ok())
            .ok_or_else(|| {
                ACError::ResourceLimitExceeded("Mixed case exact bytes exceed u32::MAX".to_string())
            })?;
        exact_bytes.extend_from_slice(pattern.bytes);
        offset
    } else {
        NO_EXACT_CHECK
    };
    Ok(CaseVariant {
        pattern_id,
        exact_offset,
    })
}

enum ACCaseAutomatonKind {
    Uniform(ACAutomaton),
    Split {
        sensitive: ACAutomaton,
        sensitive_ids: Box<[u32]>,
        insensitive: ACAutomaton,
        insensitive_ids: Box<[u32]>,
    },
    Mixed {
        folded: ACAutomaton,
        dispatch: MixedDispatch,
        exact_bytes: Box<[u8]>,
    },
}

/// An immutable AC matcher with independent ASCII case semantics per pattern.
///
/// Uniform pattern sets use one ordinary [`ACAutomaton`]. Mixed sets normally
/// use one folded automaton plus cold exact-pattern sidecars. If the caller's
/// lookbehind limit is insufficient, or the fused automaton reaches a format
/// resource limit that two per-mode automata avoid, construction falls back to
/// two exact streaming cursors without weakening matching semantics.
///
/// This type does not change or extend the serialized [`ACAutomaton`] format.
/// Its sidecars are ordinary owned Rust data.
pub struct ACCaseAutomaton {
    kind: ACCaseAutomatonKind,
    pattern_count: usize,
    required_lookbehind: usize,
}

#[derive(Debug, Clone, Copy)]
enum ACCaseMatchStateKind {
    Single(ACMatchState),
    Split {
        sensitive: ACMatchState,
        insensitive: ACMatchState,
    },
}

/// An independent streaming cursor for an [`ACCaseAutomaton`].
#[derive(Debug, Clone, Copy)]
pub struct ACCaseMatchState {
    kind: ACCaseMatchStateKind,
}

impl ACCaseMatchState {
    /// Number of input bytes consumed since this cursor was created or reset.
    #[must_use]
    pub fn position(&self) -> u64 {
        match self.kind {
            ACCaseMatchStateKind::Single(state) => state.position(),
            ACCaseMatchStateKind::Split {
                sensitive,
                insensitive,
            } => {
                debug_assert_eq!(sensitive.position(), insensitive.position());
                sensitive.position()
            }
        }
    }
}

enum ACCaseAutomatonViewKind<'a> {
    Uniform(ACAutomatonView<'a>),
    Split {
        sensitive: ACAutomatonView<'a>,
        sensitive_ids: &'a [u32],
        insensitive: ACAutomatonView<'a>,
        insensitive_ids: &'a [u32],
    },
    Mixed {
        folded: ACAutomatonView<'a>,
        dispatch: MixedDispatchView<'a>,
        exact_bytes: &'a [u8],
    },
}

#[derive(Clone, Copy)]
enum MixedDispatchView<'a> {
    Flat {
        paths: &'a [VariantRange],
        variants: &'a [CaseVariant],
    },
    SingletonOptimized {
        paths: &'a [FoldedPathDispatch],
        variant_ranges: &'a [VariantRange],
        multi_variants: &'a [CaseVariant],
    },
}

/// Borrowed query view over an [`ACCaseAutomaton`].
pub struct ACCaseAutomatonView<'a> {
    kind: ACCaseAutomatonViewKind<'a>,
    pattern_count: usize,
    required_lookbehind: usize,
}

impl ACCaseAutomaton {
    /// Build a per-pattern-case automaton with unrestricted raw lookbehind.
    ///
    /// Call [`Self::build_with_lookbehind_limit`] when retained streaming input
    /// must obey a caller-owned memory budget.
    pub fn build(patterns: &[ACCasePattern<'_>]) -> Result<Self, ACError> {
        Self::build_with_lookbehind_limit(patterns, usize::MAX)
    }

    /// Build while limiting the raw suffix needed for exact mixed-case checks.
    ///
    /// `max_raw_lookbehind` is a byte count. When a one-pass mixed matcher
    /// would require more, this method builds two ordinary automata instead.
    /// A limit of zero still permits a one-pass matcher when sensitive
    /// patterns need no bytes from a preceding input chunk.
    pub fn build_with_lookbehind_limit(
        patterns: &[ACCasePattern<'_>],
        max_raw_lookbehind: usize,
    ) -> Result<Self, ACError> {
        if patterns.is_empty() {
            return Err(ACError::InvalidPattern("No patterns provided".to_string()));
        }

        let has_sensitive = patterns
            .iter()
            .any(|pattern| pattern.mode == MatchMode::CaseSensitive);
        let has_insensitive = patterns
            .iter()
            .any(|pattern| pattern.mode == MatchMode::CaseInsensitive);
        if !has_sensitive || !has_insensitive {
            let expressions = patterns
                .iter()
                .map(|pattern| pattern.bytes)
                .collect::<Vec<_>>();
            let mode = if has_sensitive {
                MatchMode::CaseSensitive
            } else {
                MatchMode::CaseInsensitive
            };
            return Ok(Self {
                kind: ACCaseAutomatonKind::Uniform(ACAutomaton::build_bytes(&expressions, mode)?),
                pattern_count: patterns.len(),
                required_lookbehind: 0,
            });
        }

        let required_lookbehind = mixed_required_lookbehind(patterns);
        if required_lookbehind > max_raw_lookbehind {
            return Self::build_split(patterns);
        }
        match Self::build_mixed(patterns, required_lookbehind) {
            Ok(matcher) => Ok(matcher),
            Err(mixed_error) => Self::build_split(patterns)
                .map_err(|split_error| combined_fallback_error(&mixed_error, &split_error)),
        }
    }

    fn build_mixed(
        patterns: &[ACCasePattern<'_>],
        required_lookbehind: usize,
    ) -> Result<Self, ACError> {
        let mut folded_paths = BTreeMap::<Vec<u8>, Vec<(usize, &ACCasePattern<'_>)>>::new();
        for (pattern_id, pattern) in patterns.iter().enumerate() {
            let folded = pattern
                .bytes
                .iter()
                .map(u8::to_ascii_lowercase)
                .collect::<Vec<_>>();
            folded_paths
                .entry(folded)
                .or_default()
                .push((pattern_id, pattern));
        }

        let folded_expressions = folded_paths.keys().map(Vec::as_slice).collect::<Vec<_>>();
        let folded = ACAutomaton::build_bytes(&folded_expressions, MatchMode::CaseInsensitive)?;
        let singleton_path_count = folded_paths
            .values()
            .filter(|variants| variants.len() == 1)
            .count();
        let multi_path_count = folded_paths.len().saturating_sub(singleton_path_count);
        let mut exact_bytes = Vec::new();
        // The optimized sidecar removes one 8-byte CaseVariant for every
        // singleton path and adds one 8-byte VariantRange for every multi path.
        // Retain the flat layout unless that exchange strictly reduces memory;
        // it also avoids adding a tag/range lookup to collision-heavy outputs.
        let dispatch = if singleton_path_count > multi_path_count {
            let mut paths = Vec::with_capacity(folded_paths.len());
            let mut variant_ranges = Vec::with_capacity(multi_path_count);
            let mut multi_variants = Vec::new();
            for path_variants in folded_paths.into_values() {
                if path_variants.len() == 1 {
                    let (pattern_id, pattern) = path_variants[0];
                    paths.push(FoldedPathDispatch::singleton(encode_case_variant(
                        pattern_id,
                        pattern,
                        &mut exact_bytes,
                    )?)?);
                    continue;
                }

                let start = u32::try_from(multi_variants.len()).map_err(|_| {
                    ACError::ResourceLimitExceeded(
                        "Mixed case variant count exceeds u32::MAX".to_string(),
                    )
                })?;
                for (pattern_id, pattern) in path_variants {
                    multi_variants.push(encode_case_variant(
                        pattern_id,
                        pattern,
                        &mut exact_bytes,
                    )?);
                }
                let count = u32::try_from(multi_variants.len())
                    .ok()
                    .and_then(|end| end.checked_sub(start))
                    .ok_or_else(|| {
                        ACError::ResourceLimitExceeded(
                            "Mixed case variant count exceeds u32::MAX".to_string(),
                        )
                    })?;
                let range_index = u32::try_from(variant_ranges.len()).map_err(|_| {
                    ACError::ResourceLimitExceeded(
                        "Mixed case variant range count exceeds u32::MAX".to_string(),
                    )
                })?;
                variant_ranges.push(VariantRange { start, count });
                paths.push(FoldedPathDispatch::multi(range_index));
            }
            MixedDispatch::SingletonOptimized {
                paths: paths.into_boxed_slice(),
                variant_ranges: variant_ranges.into_boxed_slice(),
                multi_variants: multi_variants.into_boxed_slice(),
            }
        } else {
            let mut paths = Vec::with_capacity(folded_paths.len());
            let mut variants = Vec::with_capacity(patterns.len());
            for path_variants in folded_paths.into_values() {
                let start = u32::try_from(variants.len()).map_err(|_| {
                    ACError::ResourceLimitExceeded(
                        "Mixed case variant count exceeds u32::MAX".to_string(),
                    )
                })?;
                for (pattern_id, pattern) in path_variants {
                    variants.push(encode_case_variant(pattern_id, pattern, &mut exact_bytes)?);
                }
                let count = u32::try_from(variants.len())
                    .ok()
                    .and_then(|end| end.checked_sub(start))
                    .ok_or_else(|| {
                        ACError::ResourceLimitExceeded(
                            "Mixed case variant count exceeds u32::MAX".to_string(),
                        )
                    })?;
                paths.push(VariantRange { start, count });
            }
            MixedDispatch::Flat {
                paths: paths.into_boxed_slice(),
                variants: variants.into_boxed_slice(),
            }
        };

        Ok(Self {
            kind: ACCaseAutomatonKind::Mixed {
                folded,
                dispatch,
                exact_bytes: exact_bytes.into_boxed_slice(),
            },
            pattern_count: patterns.len(),
            required_lookbehind,
        })
    }

    fn build_split(patterns: &[ACCasePattern<'_>]) -> Result<Self, ACError> {
        let mut sensitive_patterns = Vec::new();
        let mut sensitive_ids = Vec::new();
        let mut insensitive_patterns = Vec::new();
        let mut insensitive_ids = Vec::new();
        for (pattern_id, pattern) in patterns.iter().enumerate() {
            let pattern_id = u32::try_from(pattern_id).map_err(|_| {
                ACError::ResourceLimitExceeded("Pattern count exceeds u32::MAX".to_string())
            })?;
            match pattern.mode {
                MatchMode::CaseSensitive => {
                    sensitive_patterns.push(pattern.bytes);
                    sensitive_ids.push(pattern_id);
                }
                MatchMode::CaseInsensitive => {
                    insensitive_patterns.push(pattern.bytes);
                    insensitive_ids.push(pattern_id);
                }
            }
        }
        Ok(Self {
            kind: ACCaseAutomatonKind::Split {
                sensitive: ACAutomaton::build_bytes(&sensitive_patterns, MatchMode::CaseSensitive)?,
                sensitive_ids: sensitive_ids.into_boxed_slice(),
                insensitive: ACAutomaton::build_bytes(
                    &insensitive_patterns,
                    MatchMode::CaseInsensitive,
                )?,
                insensitive_ids: insensitive_ids.into_boxed_slice(),
            },
            pattern_count: patterns.len(),
            required_lookbehind: 0,
        })
    }

    /// Create a borrowed query view.
    pub fn view(&self) -> Result<ACCaseAutomatonView<'_>, ACError> {
        let kind = match &self.kind {
            ACCaseAutomatonKind::Uniform(matcher) => {
                ACCaseAutomatonViewKind::Uniform(matcher.view()?)
            }
            ACCaseAutomatonKind::Split {
                sensitive,
                sensitive_ids,
                insensitive,
                insensitive_ids,
            } => ACCaseAutomatonViewKind::Split {
                sensitive: sensitive.view()?,
                sensitive_ids,
                insensitive: insensitive.view()?,
                insensitive_ids,
            },
            ACCaseAutomatonKind::Mixed {
                folded,
                dispatch,
                exact_bytes,
            } => ACCaseAutomatonViewKind::Mixed {
                folded: folded.view()?,
                dispatch: match dispatch {
                    MixedDispatch::Flat { paths, variants } => {
                        MixedDispatchView::Flat { paths, variants }
                    }
                    MixedDispatch::SingletonOptimized {
                        paths,
                        variant_ranges,
                        multi_variants,
                    } => MixedDispatchView::SingletonOptimized {
                        paths,
                        variant_ranges,
                        multi_variants,
                    },
                },
                exact_bytes,
            },
        };
        Ok(ACCaseAutomatonView {
            kind,
            pattern_count: self.pattern_count,
            required_lookbehind: self.required_lookbehind,
        })
    }

    /// Create an independent cursor at the beginning of a stream.
    #[must_use]
    pub fn create_state(&self) -> ACCaseMatchState {
        match self.kind {
            ACCaseAutomatonKind::Uniform(_) | ACCaseAutomatonKind::Mixed { .. } => {
                ACCaseMatchState {
                    kind: ACCaseMatchStateKind::Single(ACMatchState::default()),
                }
            }
            ACCaseAutomatonKind::Split { .. } => ACCaseMatchState {
                kind: ACCaseMatchStateKind::Split {
                    sensitive: ACMatchState::default(),
                    insensitive: ACMatchState::default(),
                },
            },
        }
    }

    /// Reset a cursor without releasing caller-owned storage.
    pub fn reset_state(&self, state: &mut ACCaseMatchState) {
        *state = self.create_state();
    }

    /// Advance a cursor while borrowing the raw suffix immediately before
    /// `input` for exact mixed-case verification.
    ///
    /// See [`ACCaseAutomatonView::advance`] for lookbehind and callback-order
    /// details.
    pub fn advance(
        &self,
        state: &mut ACCaseMatchState,
        input: &[u8],
        raw_lookbehind: &[u8],
        visit: impl FnMut(ACMatch),
    ) -> Result<(), ACError> {
        self.advance_filtered(state, input, raw_lookbehind, |_| true, visit)
    }

    /// Advance while suppressing patterns that are currently ineligible.
    ///
    /// See [`ACCaseAutomatonView::advance_filtered`] for predicate semantics.
    pub fn advance_filtered(
        &self,
        state: &mut ACCaseMatchState,
        input: &[u8],
        raw_lookbehind: &[u8],
        enabled: impl FnMut(u32) -> bool,
        visit: impl FnMut(ACMatch),
    ) -> Result<(), ACError> {
        self.view()?
            .advance_filtered(state, input, raw_lookbehind, enabled, visit)
    }

    /// Number of semantic patterns in builder-assigned input order.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Total nodes across the physical AC automata used by this matcher.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match &self.kind {
            ACCaseAutomatonKind::Uniform(matcher) => matcher.node_count(),
            ACCaseAutomatonKind::Split {
                sensitive,
                insensitive,
                ..
            } => sensitive
                .node_count()
                .saturating_add(insensitive.node_count()),
            ACCaseAutomatonKind::Mixed { folded, .. } => folded.node_count(),
        }
    }

    /// Encoded automaton buffers and immutable execution/case-sidecar payload bytes.
    ///
    /// This excludes the automata's pattern-length vectors, object headers,
    /// and allocator overhead.
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        match &self.kind {
            ACCaseAutomatonKind::Uniform(matcher) => matcher.memory_bytes(),
            ACCaseAutomatonKind::Split {
                sensitive,
                sensitive_ids,
                insensitive,
                insensitive_ids,
            } => sensitive
                .memory_bytes()
                .saturating_add(insensitive.memory_bytes())
                .saturating_add(mem::size_of_val(sensitive_ids.as_ref()))
                .saturating_add(mem::size_of_val(insensitive_ids.as_ref())),
            ACCaseAutomatonKind::Mixed {
                folded,
                dispatch,
                exact_bytes,
            } => {
                let dispatch_bytes = match dispatch {
                    MixedDispatch::Flat { paths, variants } => mem::size_of_val(paths.as_ref())
                        .saturating_add(mem::size_of_val(variants.as_ref())),
                    MixedDispatch::SingletonOptimized {
                        paths,
                        variant_ranges,
                        multi_variants,
                    } => mem::size_of_val(paths.as_ref())
                        .saturating_add(mem::size_of_val(variant_ranges.as_ref()))
                        .saturating_add(mem::size_of_val(multi_variants.as_ref())),
                };
                folded
                    .memory_bytes()
                    .saturating_add(dispatch_bytes)
                    .saturating_add(exact_bytes.len())
            }
        }
    }

    /// Raw suffix bytes required to preserve exact sensitive matches across
    /// input chunks. Split and uniform representations return zero.
    #[must_use]
    pub const fn required_lookbehind(&self) -> usize {
        self.required_lookbehind
    }

    /// Number of physical AC passes over each input chunk.
    #[must_use]
    pub fn scan_count(&self) -> usize {
        match self.kind {
            ACCaseAutomatonKind::Split { .. } => 2,
            ACCaseAutomatonKind::Uniform(_) | ACCaseAutomatonKind::Mixed { .. } => 1,
        }
    }
}

impl<'a> ACCaseAutomatonView<'a> {
    /// Create an independent cursor at the beginning of a stream.
    #[must_use]
    pub fn create_state(&self) -> ACCaseMatchState {
        match self.kind {
            ACCaseAutomatonViewKind::Uniform(_) | ACCaseAutomatonViewKind::Mixed { .. } => {
                ACCaseMatchState {
                    kind: ACCaseMatchStateKind::Single(ACMatchState::default()),
                }
            }
            ACCaseAutomatonViewKind::Split { .. } => ACCaseMatchState {
                kind: ACCaseMatchStateKind::Split {
                    sensitive: ACMatchState::default(),
                    insensitive: ACMatchState::default(),
                },
            },
        }
    }

    /// Reset a cursor without releasing caller-owned storage.
    pub fn reset_state(&self, state: &mut ACCaseMatchState) {
        *state = self.create_state();
    }

    /// Advance while borrowing the exact raw suffix immediately before input.
    ///
    /// The suffix is never retained. It can be shared by every matcher that
    /// advances the same semantic stream. The available suffix must contain
    /// at least `min(required_lookbehind(), state.position())` bytes whenever
    /// `input` is nonempty. Callers with a smaller memory budget should build
    /// with that limit so construction selects the two-pass fallback.
    ///
    /// All valid occurrences are emitted, but callback order is unspecified
    /// and can differ between the one-pass and fallback representations.
    pub fn advance(
        &self,
        state: &mut ACCaseMatchState,
        input: &[u8],
        raw_lookbehind: &[u8],
        visit: impl FnMut(ACMatch),
    ) -> Result<(), ACError> {
        self.advance_filtered(state, input, raw_lookbehind, |_| true, visit)
    }

    /// Advance while emitting only patterns accepted by `enabled`.
    ///
    /// Filtering happens before mixed representations perform exact-case
    /// verification, allowing callers to avoid work for temporarily inactive
    /// patterns. The predicate is an eligibility query, not an occurrence
    /// notification: it may be called for a folded candidate whose exact
    /// spelling does not match, and call order and count are representation
    /// details. It should therefore be stable and free of side effects for the
    /// duration of this call.
    pub fn advance_filtered(
        &self,
        state: &mut ACCaseMatchState,
        input: &[u8],
        raw_lookbehind: &[u8],
        mut enabled: impl FnMut(u32) -> bool,
        mut visit: impl FnMut(ACMatch),
    ) -> Result<(), ACError> {
        match (&self.kind, &mut state.kind) {
            (ACCaseAutomatonViewKind::Uniform(matcher), ACCaseMatchStateKind::Single(state)) => {
                matcher.advance(state, input, |matched| {
                    if enabled(matched.pattern_id) {
                        visit(matched);
                    }
                })
            }
            (
                ACCaseAutomatonViewKind::Split {
                    sensitive,
                    sensitive_ids,
                    insensitive,
                    insensitive_ids,
                },
                ACCaseMatchStateKind::Split {
                    sensitive: sensitive_state,
                    insensitive: insensitive_state,
                },
            ) => {
                sensitive.advance(sensitive_state, input, |mut matched| {
                    let Some(pattern_id) = usize::try_from(matched.pattern_id)
                        .ok()
                        .and_then(|pattern| sensitive_ids.get(pattern))
                        .copied()
                    else {
                        return;
                    };
                    matched.pattern_id = pattern_id;
                    if enabled(pattern_id) {
                        visit(matched);
                    }
                })?;
                insensitive.advance(insensitive_state, input, |mut matched| {
                    let Some(pattern_id) = usize::try_from(matched.pattern_id)
                        .ok()
                        .and_then(|pattern| insensitive_ids.get(pattern))
                        .copied()
                    else {
                        return;
                    };
                    matched.pattern_id = pattern_id;
                    if enabled(pattern_id) {
                        visit(matched);
                    }
                })
            }
            (
                ACCaseAutomatonViewKind::Mixed {
                    folded,
                    dispatch,
                    exact_bytes,
                },
                ACCaseMatchStateKind::Single(state),
            ) => {
                let input_position = state.position();
                let available_stream = usize::try_from(input_position).unwrap_or(usize::MAX);
                let required = self.required_lookbehind.min(available_stream);
                if !input.is_empty() && raw_lookbehind.len() < required {
                    return Err(ACError::InvalidInput(format!(
                        "Mixed case advance requires {required} raw lookbehind bytes, got {}",
                        raw_lookbehind.len()
                    )));
                }
                let exact = ExactInputSpan {
                    raw_lookbehind,
                    input_position,
                    input,
                };
                folded.advance(state, input, |matched| match dispatch {
                    MixedDispatchView::Flat { paths, variants } => {
                        let Some(path) = usize::try_from(matched.pattern_id)
                            .ok()
                            .and_then(|pattern| paths.get(pattern))
                        else {
                            return;
                        };
                        let Some(start) = usize::try_from(path.start).ok() else {
                            return;
                        };
                        let Some(count) = usize::try_from(path.count).ok() else {
                            return;
                        };
                        let Some(length) =
                            usize::try_from(matched.end.saturating_sub(matched.start)).ok()
                        else {
                            return;
                        };
                        for variant in variants
                            .get(start..start.saturating_add(count))
                            .unwrap_or_default()
                        {
                            if !enabled(variant.pattern_id) {
                                continue;
                            }
                            if variant.exact_offset != NO_EXACT_CHECK {
                                let Some(offset) = usize::try_from(variant.exact_offset).ok()
                                else {
                                    continue;
                                };
                                let Some(expected) =
                                    exact_bytes.get(offset..offset.saturating_add(length))
                                else {
                                    continue;
                                };
                                if !exact.matches(matched.start, expected) {
                                    continue;
                                }
                            }
                            visit(ACMatch {
                                pattern_id: variant.pattern_id,
                                start: matched.start,
                                end: matched.end,
                            });
                        }
                    }
                    MixedDispatchView::SingletonOptimized {
                        paths,
                        variant_ranges,
                        multi_variants,
                    } => {
                        let Some(path) = usize::try_from(matched.pattern_id)
                            .ok()
                            .and_then(|pattern| paths.get(pattern))
                            .copied()
                        else {
                            return;
                        };
                        let Some(length) =
                            usize::try_from(matched.end.saturating_sub(matched.start)).ok()
                        else {
                            return;
                        };
                        if path.pattern_id_or_tag != MULTI_VARIANT_TAG {
                            if !enabled(path.pattern_id_or_tag) {
                                return;
                            }
                            if path.exact_offset_or_range != NO_EXACT_CHECK {
                                let Some(offset) = usize::try_from(path.exact_offset_or_range).ok()
                                else {
                                    return;
                                };
                                let Some(expected) =
                                    exact_bytes.get(offset..offset.saturating_add(length))
                                else {
                                    return;
                                };
                                if !exact.matches(matched.start, expected) {
                                    return;
                                }
                            }
                            visit(ACMatch {
                                pattern_id: path.pattern_id_or_tag,
                                start: matched.start,
                                end: matched.end,
                            });
                            return;
                        }

                        let Some(range) = usize::try_from(path.exact_offset_or_range)
                            .ok()
                            .and_then(|index| variant_ranges.get(index))
                        else {
                            return;
                        };
                        let Some(start) = usize::try_from(range.start).ok() else {
                            return;
                        };
                        let Some(count) = usize::try_from(range.count).ok() else {
                            return;
                        };
                        for variant in multi_variants
                            .get(start..start.saturating_add(count))
                            .unwrap_or_default()
                        {
                            if !enabled(variant.pattern_id) {
                                continue;
                            }
                            if variant.exact_offset != NO_EXACT_CHECK {
                                let Some(offset) = usize::try_from(variant.exact_offset).ok()
                                else {
                                    continue;
                                };
                                let Some(expected) =
                                    exact_bytes.get(offset..offset.saturating_add(length))
                                else {
                                    continue;
                                };
                                if !exact.matches(matched.start, expected) {
                                    continue;
                                }
                            }
                            visit(ACMatch {
                                pattern_id: variant.pattern_id,
                                start: matched.start,
                                end: matched.end,
                            });
                        }
                    }
                })
            }
            _ => Err(ACError::InvalidInput(
                "Case matcher state is incompatible with this representation".to_string(),
            )),
        }
    }

    /// Number of semantic patterns in builder-assigned input order.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Raw suffix bytes required for exact cross-chunk sensitive matches.
    #[must_use]
    pub const fn required_lookbehind(&self) -> usize {
        self.required_lookbehind
    }

    /// Number of physical AC passes over each input chunk.
    #[must_use]
    pub fn scan_count(&self) -> usize {
        match self.kind {
            ACCaseAutomatonViewKind::Split { .. } => 2,
            ACCaseAutomatonViewKind::Uniform(_) | ACCaseAutomatonViewKind::Mixed { .. } => 1,
        }
    }
}

struct ExactInputSpan<'a> {
    raw_lookbehind: &'a [u8],
    input_position: u64,
    input: &'a [u8],
}

impl ExactInputSpan<'_> {
    fn matches(&self, start: u64, expected: &[u8]) -> bool {
        let Some(end) = start.checked_add(expected.len() as u64) else {
            return false;
        };
        let input_end = self
            .input_position
            .saturating_add(u64::try_from(self.input.len()).unwrap_or(u64::MAX));
        if end > input_end {
            return false;
        }
        if start >= self.input_position {
            let Some(offset) = usize::try_from(start - self.input_position).ok() else {
                return false;
            };
            return self
                .input
                .get(offset..offset.saturating_add(expected.len()))
                == Some(expected);
        }

        let Some(prefix_len) = usize::try_from(self.input_position - start).ok() else {
            return false;
        };
        if prefix_len > expected.len() || prefix_len > self.raw_lookbehind.len() {
            return false;
        }
        let lookbehind_offset = self.raw_lookbehind.len() - prefix_len;
        self.raw_lookbehind.get(lookbehind_offset..) == Some(&expected[..prefix_len])
            && self.input.get(..expected.len().saturating_sub(prefix_len))
                == Some(&expected[prefix_len..])
    }
}

fn mixed_required_lookbehind(patterns: &[ACCasePattern<'_>]) -> usize {
    patterns
        .iter()
        .filter(|pattern| {
            pattern.mode == MatchMode::CaseSensitive
                && pattern.bytes.iter().any(u8::is_ascii_alphabetic)
        })
        .map(|pattern| pattern.bytes.len().saturating_sub(1))
        .max()
        .unwrap_or(0)
}

fn combined_fallback_error(mixed_error: &ACError, split_error: &ACError) -> ACError {
    let message = format!(
        "Mixed case automaton failed ({mixed_error}); split fallback failed ({split_error})"
    );
    match split_error {
        ACError::InvalidPattern(_) => ACError::InvalidPattern(message),
        ACError::ResourceLimitExceeded(_) => ACError::ResourceLimitExceeded(message),
        ACError::InvalidInput(_) => ACError::InvalidInput(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(mut matches: Vec<ACMatch>) -> Vec<ACMatch> {
        matches.sort_by_key(|matched| (matched.end, matched.start, matched.pattern_id));
        matches
    }

    fn collect_chunks(matcher: &ACCaseAutomaton, input: &[u8], chunk_size: usize) -> Vec<ACMatch> {
        let mut state = matcher.create_state();
        let mut history = Vec::new();
        let mut matches = Vec::new();
        let retain = matcher.required_lookbehind();
        for chunk in input.chunks(chunk_size) {
            matcher
                .advance(&mut state, chunk, &history, |matched| {
                    matches.push(matched);
                })
                .unwrap();
            history.extend_from_slice(chunk);
            if history.len() > retain {
                history.drain(..history.len() - retain);
            }
        }
        assert_eq!(state.position(), input.len() as u64);
        sorted(matches)
    }

    fn collect_filtered_chunks(
        matcher: &ACCaseAutomaton,
        input: &[u8],
        chunk_size: usize,
        eligible: &[bool],
    ) -> Vec<ACMatch> {
        let mut state = matcher.create_state();
        let mut history = Vec::new();
        let mut matches = Vec::new();
        let retain = matcher.required_lookbehind();
        for chunk in input.chunks(chunk_size) {
            matcher
                .advance_filtered(
                    &mut state,
                    chunk,
                    &history,
                    |pattern_id| {
                        usize::try_from(pattern_id)
                            .ok()
                            .and_then(|pattern_id| eligible.get(pattern_id))
                            .copied()
                            .unwrap_or(false)
                    },
                    |matched| matches.push(matched),
                )
                .unwrap();
            history.extend_from_slice(chunk);
            if history.len() > retain {
                history.drain(..history.len() - retain);
            }
        }
        assert_eq!(state.position(), input.len() as u64);
        sorted(matches)
    }

    fn reference_filtered_matches(
        patterns: &[ACCasePattern<'_>],
        input: &[u8],
        eligible: &[bool],
    ) -> Vec<ACMatch> {
        let mut matches = Vec::new();
        for (pattern_id, pattern) in patterns.iter().enumerate() {
            if !eligible.get(pattern_id).copied().unwrap_or(false) {
                continue;
            }
            for (start, candidate) in input.windows(pattern.bytes.len()).enumerate() {
                let matches_case = match pattern.mode {
                    MatchMode::CaseSensitive => candidate == pattern.bytes,
                    MatchMode::CaseInsensitive => candidate
                        .iter()
                        .zip(pattern.bytes)
                        .all(|(&actual, &expected)| actual.eq_ignore_ascii_case(&expected)),
                };
                if matches_case {
                    matches.push(ACMatch {
                        pattern_id: u32::try_from(pattern_id).unwrap(),
                        start: u64::try_from(start).unwrap(),
                        end: u64::try_from(start + pattern.bytes.len()).unwrap(),
                    });
                }
            }
        }
        sorted(matches)
    }

    #[test]
    fn uniform_modes_match_the_existing_automaton() {
        let bytes = [b"he".as_slice(), b"she".as_slice(), b"hers".as_slice()];
        let input = b"uSHers-he";
        for mode in [MatchMode::CaseSensitive, MatchMode::CaseInsensitive] {
            let patterns = bytes
                .iter()
                .map(|bytes| ACCasePattern::new(bytes, mode))
                .collect::<Vec<_>>();
            let matcher = ACCaseAutomaton::build(&patterns).unwrap();
            assert_eq!(matcher.scan_count(), 1);
            assert_eq!(matcher.required_lookbehind(), 0);

            let ordinary = ACAutomaton::build_bytes(&bytes, mode).unwrap();
            let view = ordinary.view().unwrap();
            let mut state = view.create_state();
            let mut expected = Vec::new();
            for chunk in input.chunks(2) {
                view.advance(&mut state, chunk, |matched| expected.push(matched))
                    .unwrap();
            }
            assert_eq!(collect_chunks(&matcher, input, 2), sorted(expected));
        }
    }

    #[test]
    fn mixed_folded_paths_preserve_exact_variants_at_every_chunk_size() {
        let patterns = [
            ACCasePattern::new(b"AbC", MatchMode::CaseSensitive),
            ACCasePattern::new(b"aBc", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABC", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"AbC", MatchMode::CaseSensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        assert_eq!(matcher.pattern_count(), 4);
        assert_eq!(matcher.scan_count(), 1);
        assert_eq!(matcher.required_lookbehind(), 2);

        for (input, expected_ids) in [
            (b"AbC".as_slice(), vec![0, 2, 3]),
            (b"aBc".as_slice(), vec![1, 2]),
            (b"abc".as_slice(), vec![2]),
        ] {
            for chunk_size in 1..=input.len() {
                let matches = collect_chunks(&matcher, input, chunk_size);
                assert_eq!(
                    matches
                        .iter()
                        .map(|matched| matched.pattern_id)
                        .collect::<Vec<_>>(),
                    expected_ids,
                    "chunk size {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn mixed_layout_inlines_singleton_dispatch() {
        assert_eq!(mem::size_of::<FoldedPathDispatch>(), 8);

        let patterns = [
            ACCasePattern::new(b"Alpha", MatchMode::CaseSensitive),
            ACCasePattern::new(b"BRAVO", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"123", MatchMode::CaseSensitive),
            ACCasePattern::new(b"Dupe", MatchMode::CaseSensitive),
            ACCasePattern::new(b"DUPE", MatchMode::CaseInsensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        let ACCaseAutomatonKind::Mixed {
            folded, dispatch, ..
        } = &matcher.kind
        else {
            panic!("mixed pattern modes should select the fused layout");
        };
        let MixedDispatch::SingletonOptimized {
            paths,
            variant_ranges,
            multi_variants,
        } = dispatch
        else {
            panic!("singleton-heavy paths should select the optimized sidecar");
        };

        assert_eq!(folded.pattern_count(), paths.len());
        assert_eq!(paths.len(), 4);
        assert_eq!(variant_ranges.len(), 1);
        assert_eq!(multi_variants.len(), 2);
        assert_eq!(
            multi_variants
                .iter()
                .map(|variant| variant.pattern_id)
                .collect::<Vec<_>>(),
            [3, 4]
        );

        let exact_singleton = paths
            .iter()
            .find(|path| path.pattern_id_or_tag == 0)
            .unwrap();
        assert_ne!(exact_singleton.exact_offset_or_range, NO_EXACT_CHECK);
        for pattern_id in [1, 2] {
            let unconditional = paths
                .iter()
                .find(|path| path.pattern_id_or_tag == pattern_id)
                .unwrap();
            assert_eq!(unconditional.exact_offset_or_range, NO_EXACT_CHECK);
        }
        let multi = paths
            .iter()
            .find(|path| path.pattern_id_or_tag == MULTI_VARIANT_TAG)
            .unwrap();
        assert_eq!(multi.exact_offset_or_range, 0);
        assert_eq!(variant_ranges[0].start, 0);
        assert_eq!(variant_ranges[0].count, 2);
    }

    #[test]
    fn mixed_layout_keeps_flat_dispatch_for_collision_heavy_sets() {
        for patterns in [
            vec![
                ACCasePattern::new(b"Alpha", MatchMode::CaseSensitive),
                ACCasePattern::new(b"ALPHA", MatchMode::CaseInsensitive),
                ACCasePattern::new(b"bravo", MatchMode::CaseInsensitive),
            ],
            vec![
                ACCasePattern::new(b"Alpha", MatchMode::CaseSensitive),
                ACCasePattern::new(b"ALPHA", MatchMode::CaseInsensitive),
                ACCasePattern::new(b"Bravo", MatchMode::CaseSensitive),
                ACCasePattern::new(b"BRAVO", MatchMode::CaseInsensitive),
                ACCasePattern::new(b"charlie", MatchMode::CaseInsensitive),
            ],
        ] {
            let matcher = ACCaseAutomaton::build(&patterns).unwrap();
            let ACCaseAutomatonKind::Mixed { dispatch, .. } = &matcher.kind else {
                panic!("mixed pattern modes should select the fused layout");
            };
            assert!(matches!(dispatch, MixedDispatch::Flat { .. }));
        }
    }

    #[test]
    fn mixed_singleton_exact_matches_across_every_chunk_boundary() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"other", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"123", MatchMode::CaseSensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        let input = b"xxAbCd-abcd-OTHER-123";
        for chunk_size in 1..=input.len() {
            let matches = collect_chunks(&matcher, input, chunk_size);
            assert_eq!(
                matches
                    .iter()
                    .map(|matched| matched.pattern_id)
                    .collect::<Vec<_>>(),
                [0, 1, 2],
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn mixed_singleton_dispatch_respects_filtering() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"other", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"123", MatchMode::CaseSensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        assert!(matches!(
            &matcher.kind,
            ACCaseAutomatonKind::Mixed {
                dispatch: MixedDispatch::SingletonOptimized { .. },
                ..
            }
        ));

        let mut state = matcher.create_state();
        let mut matches = Vec::new();
        matcher
            .advance_filtered(
                &mut state,
                b"AbCd abcd OTHER 123",
                &[],
                |pattern_id| pattern_id != 1,
                |matched| matches.push(matched),
            )
            .unwrap();
        assert_eq!(
            matches
                .iter()
                .map(|matched| matched.pattern_id)
                .collect::<Vec<_>>(),
            [0, 2]
        );
    }

    #[test]
    fn eligibility_filter_preserves_uniform_mixed_and_split_matches() {
        let uniform_patterns = [
            ACCasePattern::new(b"ab", MatchMode::CaseSensitive),
            ACCasePattern::new(b"bc", MatchMode::CaseSensitive),
        ];
        let uniform = ACCaseAutomaton::build(&uniform_patterns).unwrap();
        let mut uniform_state = uniform.create_state();
        let mut uniform_matches = Vec::new();
        uniform
            .advance_filtered(
                &mut uniform_state,
                b"abc",
                &[],
                |pattern_id| pattern_id == 1,
                |matched| uniform_matches.push(matched),
            )
            .unwrap();
        assert_eq!(
            uniform_matches,
            [ACMatch {
                pattern_id: 1,
                start: 1,
                end: 3
            }]
        );

        let mixed_patterns = [
            ACCasePattern::new(b"AbC", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABC", MatchMode::CaseInsensitive),
        ];
        let mixed = ACCaseAutomaton::build(&mixed_patterns).unwrap();
        let mut mixed_state = mixed.create_state();
        let mut mixed_matches = Vec::new();
        mixed
            .advance_filtered(
                &mut mixed_state,
                b"AbC abc",
                &[],
                |pattern_id| pattern_id == 0,
                |matched| mixed_matches.push(matched),
            )
            .unwrap();
        assert_eq!(
            mixed_matches,
            [ACMatch {
                pattern_id: 0,
                start: 0,
                end: 3
            }]
        );
        assert_eq!(mixed_state.position(), 7);

        let split = ACCaseAutomaton::build_with_lookbehind_limit(&mixed_patterns, 0).unwrap();
        assert_eq!(split.scan_count(), 2);
        let mut split_state = split.create_state();
        let mut split_matches = Vec::new();
        split
            .advance_filtered(
                &mut split_state,
                b"AbC abc",
                &[],
                |pattern_id| pattern_id == 1,
                |matched| split_matches.push(matched),
            )
            .unwrap();
        assert_eq!(
            split_matches,
            [
                ACMatch {
                    pattern_id: 1,
                    start: 0,
                    end: 3
                },
                ACMatch {
                    pattern_id: 1,
                    start: 4,
                    end: 7
                },
            ]
        );
        assert_eq!(split_state.position(), 7);
    }

    #[test]
    fn mixed_failure_outputs_and_ascii_only_folding_are_exact() {
        let binary_sensitive = [0xff, b'A'];
        let binary_insensitive = [0xff, b'A'];
        let patterns = [
            ACCasePattern::new(b"a", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ba", MatchMode::CaseSensitive),
            ACCasePattern::new(b"CBA", MatchMode::CaseInsensitive),
            ACCasePattern::new(&binary_sensitive, MatchMode::CaseSensitive),
            ACCasePattern::new(&binary_insensitive, MatchMode::CaseInsensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();

        assert_eq!(
            collect_chunks(&matcher, b"cba", 1)
                .iter()
                .map(|matched| matched.pattern_id)
                .collect::<Vec<_>>(),
            [2, 1, 0]
        );
        assert_eq!(
            collect_chunks(&matcher, &[0xff, b'a'], 1)
                .iter()
                .map(|matched| matched.pattern_id)
                .collect::<Vec<_>>(),
            [4, 0]
        );
    }

    #[test]
    fn short_lookbehind_rejects_advance_without_mutating_state() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABCD", MatchMode::CaseInsensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        let mut state = matcher.create_state();
        let mut matches = Vec::new();
        matcher
            .advance(&mut state, b"AbC", &[], |matched| matches.push(matched))
            .unwrap();
        let error = matcher
            .advance(&mut state, b"d", &[], |matched| matches.push(matched))
            .unwrap_err();
        assert!(matches!(error, ACError::InvalidInput(_)));
        assert_eq!(state.position(), 3);
        assert!(matches.is_empty());

        matcher
            .advance(&mut state, b"d", b"AbC", |matched| matches.push(matched))
            .unwrap();
        assert_eq!(
            matches
                .iter()
                .map(|matched| matched.pattern_id)
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn lookbehind_limit_selects_exact_streaming_fallback() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABCD", MatchMode::CaseInsensitive),
        ];
        let matcher = ACCaseAutomaton::build_with_lookbehind_limit(&patterns, 0).unwrap();
        assert_eq!(matcher.scan_count(), 2);
        assert_eq!(matcher.required_lookbehind(), 0);

        for input in [b"AbCd".as_slice(), b"abcd".as_slice()] {
            let expected = collect_chunks(&matcher, input, input.len());
            for chunk_size in 1..=input.len() {
                assert_eq!(collect_chunks(&matcher, input, chunk_size), expected);
            }
        }
    }

    #[test]
    fn fused_resource_limit_falls_back_to_valid_per_mode_automata() {
        let storage = (1..=256)
            .map(|length| vec![b'a'; length])
            .collect::<Vec<_>>();
        let patterns = storage
            .iter()
            .enumerate()
            .map(|(pattern, bytes)| {
                ACCasePattern::new(
                    bytes,
                    if pattern < 128 {
                        MatchMode::CaseSensitive
                    } else {
                        MatchMode::CaseInsensitive
                    },
                )
            })
            .collect::<Vec<_>>();
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        assert_eq!(matcher.scan_count(), 2);
        assert_eq!(matcher.required_lookbehind(), 0);

        let input = vec![b'a'; 256];
        let mut state = matcher.create_state();
        let mut seen = vec![false; patterns.len()];
        for chunk in input.chunks(37) {
            matcher
                .advance(&mut state, chunk, &[], |matched| {
                    seen[matched.pattern_id as usize] = true;
                })
                .unwrap();
        }
        assert!(seen.into_iter().all(|matched| matched));
        assert_eq!(state.position(), 256);
    }

    #[test]
    fn independent_states_and_reset_do_not_share_streaming_case() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABCD", MatchMode::CaseInsensitive),
        ];
        let matcher = ACCaseAutomaton::build(&patterns).unwrap();
        let view = matcher.view().unwrap();
        let mut state_a = view.create_state();
        let mut state_b = view.create_state();
        let mut matches_a = Vec::new();
        let mut matches_b = Vec::new();

        view.advance(&mut state_a, b"AbC", &[], |_| {}).unwrap();
        view.advance(&mut state_b, b"abc", &[], |_| {}).unwrap();
        view.advance(&mut state_a, b"d", b"AbC", |matched| {
            matches_a.push(matched.pattern_id);
        })
        .unwrap();
        view.advance(&mut state_b, b"d", b"abc", |matched| {
            matches_b.push(matched.pattern_id);
        })
        .unwrap();

        assert_eq!(matches_a, [0, 1]);
        assert_eq!(matches_b, [1]);
        view.reset_state(&mut state_a);
        assert_eq!(state_a.position(), 0);
        assert_eq!(state_b.position(), 4);
    }

    #[test]
    fn large_mixed_and_split_sidecars_match_filtered_reference_across_chunks() {
        let mut storage = vec![
            (b"a".to_vec(), MatchMode::CaseSensitive),
            (b"A".to_vec(), MatchMode::CaseInsensitive),
            (b"ba".to_vec(), MatchMode::CaseSensitive),
            (b"CBA".to_vec(), MatchMode::CaseInsensitive),
            (b"AbCd".to_vec(), MatchMode::CaseSensitive),
            (b"ABCD".to_vec(), MatchMode::CaseInsensitive),
            (vec![0xff, b'A'], MatchMode::CaseSensitive),
            (vec![0xff, b'A'], MatchMode::CaseInsensitive),
        ];
        storage.extend((0..192).map(|index| {
            (
                format!("sparse-sensitive-{index:03}-AbCdEfGhIjKl").into_bytes(),
                MatchMode::CaseSensitive,
            )
        }));
        storage.extend((0..192).map(|index| {
            (
                format!("sparse-insensitive-{index:03}-MnOpQrStUvWx").into_bytes(),
                MatchMode::CaseInsensitive,
            )
        }));
        let patterns = storage
            .iter()
            .map(|(bytes, mode)| ACCasePattern::new(bytes, *mode))
            .collect::<Vec<_>>();

        let mixed = ACCaseAutomaton::build(&patterns).unwrap();
        assert!(mixed.required_lookbehind() > 0);
        let ACCaseAutomatonKind::Mixed { folded, .. } = &mixed.kind else {
            panic!("unrestricted lookbehind should select the mixed representation");
        };
        assert!(
            folded.root_pair_filter.is_some(),
            "large mixed automaton should receive a root-pair sidecar"
        );

        let split = ACCaseAutomaton::build_with_lookbehind_limit(&patterns, 0).unwrap();
        let ACCaseAutomatonKind::Split {
            sensitive,
            insensitive,
            ..
        } = &split.kind
        else {
            panic!("zero lookbehind should force the split representation");
        };
        assert!(
            sensitive.root_pair_filter.is_some(),
            "large sensitive split automaton should receive a root-pair sidecar"
        );
        assert!(
            insensitive.root_pair_filter.is_some(),
            "large insensitive split automaton should receive a root-pair sidecar"
        );

        let mut input = b"zzAbCd/abcd/CBA/cba/ba/".to_vec();
        input.extend_from_slice(&[0xff, b'A', b'/', 0xff, b'a', b'/']);
        input.extend_from_slice(b"sparse-sensitive-042-AbCdEfGhIjKl/");
        input.extend_from_slice(b"SPARSE-SENSITIVE-042-ABCDEFGHIJKL/");
        input.extend_from_slice(b"SPARSE-INSENSITIVE-037-MNOPQRSTUVWX/");

        let mut first_mask = (0..patterns.len())
            .map(|pattern_id| pattern_id % 3 != 1)
            .collect::<Vec<_>>();
        // Keep both exact and folded variants of "AbCd" eligible while
        // suppressing other candidates sharing folded paths.
        first_mask[4] = true;
        first_mask[5] = true;
        first_mask[7] = false;
        let second_mask = (0..patterns.len())
            .map(|pattern_id| {
                pattern_id == 0
                    || pattern_id == 4
                    || pattern_id == 7
                    || pattern_id == 8 + 42
                    || pattern_id == 8 + 192 + 37
            })
            .collect::<Vec<_>>();

        for (mask_index, eligible) in [first_mask, second_mask].iter().enumerate() {
            let expected = reference_filtered_matches(&patterns, &input, eligible);
            for chunk_size in 1..=input.len() {
                assert_eq!(
                    collect_filtered_chunks(&mixed, &input, chunk_size, eligible),
                    expected,
                    "mixed mask {mask_index}, chunk size {chunk_size}"
                );
                assert_eq!(
                    collect_filtered_chunks(&split, &input, chunk_size, eligible),
                    expected,
                    "split mask {mask_index}, chunk size {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn mixed_and_split_match_two_ordinary_automata_exhaustively() {
        let binary_sensitive = [0xff, b'A'];
        let binary_insensitive = [0xff, b'A'];
        let patterns = [
            ACCasePattern::new(b"a", MatchMode::CaseSensitive),
            ACCasePattern::new(b"A", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"aB", MatchMode::CaseSensitive),
            ACCasePattern::new(b"Ab", MatchMode::CaseSensitive),
            ACCasePattern::new(b"AB", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"ba", MatchMode::CaseSensitive),
            ACCasePattern::new(&binary_sensitive, MatchMode::CaseSensitive),
            ACCasePattern::new(&binary_insensitive, MatchMode::CaseInsensitive),
        ];
        let mixed = ACCaseAutomaton::build(&patterns).unwrap();
        let split = ACCaseAutomaton::build_with_lookbehind_limit(&patterns, 0).unwrap();
        assert_eq!(mixed.scan_count(), 1);
        assert_eq!(split.scan_count(), 2);

        let sensitive = patterns
            .iter()
            .enumerate()
            .filter(|(_, pattern)| pattern.mode == MatchMode::CaseSensitive)
            .collect::<Vec<_>>();
        let insensitive = patterns
            .iter()
            .enumerate()
            .filter(|(_, pattern)| pattern.mode == MatchMode::CaseInsensitive)
            .collect::<Vec<_>>();
        let sensitive_expressions = sensitive
            .iter()
            .map(|(_, pattern)| pattern.bytes)
            .collect::<Vec<_>>();
        let insensitive_expressions = insensitive
            .iter()
            .map(|(_, pattern)| pattern.bytes)
            .collect::<Vec<_>>();
        let sensitive_matcher =
            ACAutomaton::build_bytes(&sensitive_expressions, MatchMode::CaseSensitive).unwrap();
        let insensitive_matcher =
            ACAutomaton::build_bytes(&insensitive_expressions, MatchMode::CaseInsensitive).unwrap();

        let alphabet = [b'a', b'A', b'b', b'B', 0xff];
        let mut inputs = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..=4 {
            let mut next = Vec::with_capacity(frontier.len().saturating_mul(alphabet.len()));
            for prefix in &frontier {
                for byte in alphabet {
                    let mut input = prefix.clone();
                    input.push(byte);
                    next.push(input);
                }
            }
            inputs.extend(next.iter().cloned());
            frontier = next;
        }

        for input in inputs {
            for chunk_size in 1..=input.len().max(1) {
                let mut expected = Vec::new();
                let sensitive_view = sensitive_matcher.view().unwrap();
                let insensitive_view = insensitive_matcher.view().unwrap();
                let mut sensitive_state = sensitive_view.create_state();
                let mut insensitive_state = insensitive_view.create_state();
                for chunk in input.chunks(chunk_size) {
                    sensitive_view
                        .advance(&mut sensitive_state, chunk, |mut matched| {
                            let local_id = usize::try_from(matched.pattern_id).unwrap();
                            matched.pattern_id = u32::try_from(sensitive[local_id].0).unwrap();
                            expected.push(matched);
                        })
                        .unwrap();
                    insensitive_view
                        .advance(&mut insensitive_state, chunk, |mut matched| {
                            let local_id = usize::try_from(matched.pattern_id).unwrap();
                            matched.pattern_id = u32::try_from(insensitive[local_id].0).unwrap();
                            expected.push(matched);
                        })
                        .unwrap();
                }
                let expected = sorted(expected);
                assert_eq!(
                    collect_chunks(&mixed, &input, chunk_size),
                    expected,
                    "mixed input {input:?}, chunk size {chunk_size}"
                );
                assert_eq!(
                    collect_chunks(&split, &input, chunk_size),
                    expected,
                    "split input {input:?}, chunk size {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn empty_pattern_errors_preserve_the_invalid_pattern_class() {
        let patterns = [
            ACCasePattern::new(b"", MatchMode::CaseSensitive),
            ACCasePattern::new(b"x", MatchMode::CaseInsensitive),
        ];
        assert!(matches!(
            ACCaseAutomaton::build(&patterns),
            Err(ACError::InvalidPattern(_))
        ));
    }
}
