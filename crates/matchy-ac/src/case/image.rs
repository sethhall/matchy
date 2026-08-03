//! Versioned, mmap-safe image for per-pattern case automata.

use std::mem;

use crate::{ACAutomaton, ACError, MatchMode};

use super::{
    ACCaseAutomaton, ACCaseAutomatonKind, ACCaseAutomatonView, ACCaseAutomatonViewKind,
    CaseVariant, CaseVariants, ExactAutomatonView, FoldedPathDispatch, FoldedPathDispatches,
    MixedDispatch, MixedDispatchView, U32Values, VariantRange, VariantRanges, MULTI_VARIANT_TAG,
    NO_EXACT_CHECK,
};

const MAGIC: &[u8; 8] = b"MACCASE\0";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 160;
const DESCRIPTOR_SIZE: usize = 32;
const FIRST_DESCRIPTOR: usize = 32;
const SECOND_DESCRIPTOR: usize = FIRST_DESCRIPTOR + DESCRIPTOR_SIZE;
const MAX_IMAGE_BYTES: usize = 2_000_000_000;
const RECORD_SIZE: usize = 8;

const KIND_UNIFORM: u8 = 0;
const KIND_SPLIT: u8 = 1;
const KIND_MIXED_FLAT: u8 = 2;
const KIND_MIXED_SINGLETON: u8 = 3;

const SENSITIVE_IDS_REGION: usize = 96;
const INSENSITIVE_IDS_REGION: usize = 104;
const PATHS_REGION: usize = 112;
const RANGES_REGION: usize = 120;
const VARIANTS_REGION: usize = 128;
const EXACT_BYTES_REGION: usize = 136;

#[derive(Clone, Copy, Default)]
struct Region {
    offset: usize,
    len: usize,
}

#[derive(Clone, Copy, Default)]
struct AutomatonLayout {
    buffer: Region,
    lengths: Region,
}

#[derive(Default)]
struct ImageLayout {
    automata: [AutomatonLayout; 2],
    sensitive_ids: Region,
    insensitive_ids: Region,
    paths: Region,
    ranges: Region,
    variants: Region,
    exact_bytes: Region,
    total: usize,
}

enum Sidecars<'a> {
    None,
    Split {
        sensitive_ids: &'a [u32],
        insensitive_ids: &'a [u32],
    },
    MixedFlat {
        paths: &'a [VariantRange],
        variants: &'a [CaseVariant],
        exact_bytes: &'a [u8],
    },
    MixedSingleton {
        paths: &'a [FoldedPathDispatch],
        ranges: &'a [VariantRange],
        variants: &'a [CaseVariant],
        exact_bytes: &'a [u8],
    },
}

struct ImageParts<'a> {
    kind: u8,
    first: &'a ACAutomaton,
    second: Option<&'a ACAutomaton>,
    sidecars: Sidecars<'a>,
}

impl<'a> ImageParts<'a> {
    fn from_automaton(matcher: &'a ACCaseAutomaton) -> Self {
        match &matcher.kind {
            ACCaseAutomatonKind::Uniform(first) => Self {
                kind: KIND_UNIFORM,
                first,
                second: None,
                sidecars: Sidecars::None,
            },
            ACCaseAutomatonKind::Split {
                sensitive,
                sensitive_ids,
                insensitive,
                insensitive_ids,
            } => Self {
                kind: KIND_SPLIT,
                first: sensitive,
                second: Some(insensitive),
                sidecars: Sidecars::Split {
                    sensitive_ids,
                    insensitive_ids,
                },
            },
            ACCaseAutomatonKind::Mixed {
                folded,
                dispatch: MixedDispatch::Flat { paths, variants },
                exact_bytes,
            } => Self {
                kind: KIND_MIXED_FLAT,
                first: folded,
                second: None,
                sidecars: Sidecars::MixedFlat {
                    paths,
                    variants,
                    exact_bytes,
                },
            },
            ACCaseAutomatonKind::Mixed {
                folded,
                dispatch:
                    MixedDispatch::SingletonOptimized {
                        paths,
                        variant_ranges,
                        multi_variants,
                    },
                exact_bytes,
            } => Self {
                kind: KIND_MIXED_SINGLETON,
                first: folded,
                second: None,
                sidecars: Sidecars::MixedSingleton {
                    paths,
                    ranges: variant_ranges,
                    variants: multi_variants,
                    exact_bytes,
                },
            },
        }
    }
}

impl ACCaseAutomaton {
    /// Encode this matcher as one versioned, self-contained binary image.
    ///
    /// The image contains only fixed-width little-endian values, file-relative
    /// offsets, embedded AC buffers, and immutable sidecars. It can be stored
    /// verbatim and later queried directly from memory-mapped bytes with
    /// [`ACCaseAutomatonView::from_image`]. Mutable stream state is not part of
    /// the image.
    pub fn to_image(&self) -> Result<Vec<u8>, ACError> {
        let parts = ImageParts::from_automaton(self);
        let layout = ImageLayout::new(&parts)?;
        let mut image = vec![0_u8; layout.total];

        image[..MAGIC.len()].copy_from_slice(MAGIC);
        write_u16(&mut image, 8, VERSION)?;
        write_u16(
            &mut image,
            10,
            u16::try_from(HEADER_SIZE).map_err(size_error)?,
        )?;
        write_u32(&mut image, 12, wire_u32(layout.total)?)?;
        image[16] = parts.kind;
        image[17] = if parts.second.is_some() { 2 } else { 1 };
        write_u32(&mut image, 20, wire_u32(self.pattern_count)?)?;
        write_u32(&mut image, 24, wire_u32(self.required_lookbehind)?)?;

        encode_automaton(
            &mut image,
            FIRST_DESCRIPTOR,
            parts.first,
            layout.automata[0],
        )?;
        if let Some(second) = parts.second {
            encode_automaton(&mut image, SECOND_DESCRIPTOR, second, layout.automata[1])?;
        }

        match parts.sidecars {
            Sidecars::None => {}
            Sidecars::Split {
                sensitive_ids,
                insensitive_ids,
            } => {
                encode_u32_values(&mut image, layout.sensitive_ids, sensitive_ids)?;
                encode_u32_values(&mut image, layout.insensitive_ids, insensitive_ids)?;
            }
            Sidecars::MixedFlat {
                paths,
                variants,
                exact_bytes,
            } => {
                encode_ranges(&mut image, layout.paths, paths)?;
                encode_variants(&mut image, layout.variants, variants)?;
                copy_region(&mut image, layout.exact_bytes, exact_bytes)?;
            }
            Sidecars::MixedSingleton {
                paths,
                ranges,
                variants,
                exact_bytes,
            } => {
                encode_dispatches(&mut image, layout.paths, paths)?;
                encode_ranges(&mut image, layout.ranges, ranges)?;
                encode_variants(&mut image, layout.variants, variants)?;
                copy_region(&mut image, layout.exact_bytes, exact_bytes)?;
            }
        }

        encode_region_header(
            &mut image,
            SENSITIVE_IDS_REGION,
            layout.sensitive_ids,
            mem::size_of::<u32>(),
        )?;
        encode_region_header(
            &mut image,
            INSENSITIVE_IDS_REGION,
            layout.insensitive_ids,
            mem::size_of::<u32>(),
        )?;
        encode_region_header(&mut image, PATHS_REGION, layout.paths, RECORD_SIZE)?;
        encode_region_header(&mut image, RANGES_REGION, layout.ranges, RECORD_SIZE)?;
        encode_region_header(&mut image, VARIANTS_REGION, layout.variants, RECORD_SIZE)?;
        encode_region_header(&mut image, EXACT_BYTES_REGION, layout.exact_bytes, 1)?;

        Ok(image)
    }
}

impl<'a> ACCaseAutomatonView<'a> {
    /// Verify and open a zero-copy matcher over a complete case image.
    ///
    /// Validation checks the versioned envelope, canonical region topology,
    /// every embedded AC structure, sidecar ranges, pattern identifiers, and
    /// exact-byte references before returning the view. The returned matcher
    /// borrows `image`; it does not relocate or rebuild immutable data.
    pub fn from_image(image: &'a [u8]) -> Result<Self, ACError> {
        Decoder::new(image)?.decode()
    }
}

impl ImageLayout {
    fn new(parts: &ImageParts<'_>) -> Result<Self, ACError> {
        let mut result = Self::default();
        let mut cursor = HEADER_SIZE;
        result.automata[0] = layout_automaton(&mut cursor, parts.first)?;
        if let Some(second) = parts.second {
            result.automata[1] = layout_automaton(&mut cursor, second)?;
        }
        match parts.sidecars {
            Sidecars::None => {}
            Sidecars::Split {
                sensitive_ids,
                insensitive_ids,
            } => {
                result.sensitive_ids =
                    layout_records(&mut cursor, sensitive_ids.len(), mem::size_of::<u32>())?;
                result.insensitive_ids =
                    layout_records(&mut cursor, insensitive_ids.len(), mem::size_of::<u32>())?;
            }
            Sidecars::MixedFlat {
                paths,
                variants,
                exact_bytes,
            } => {
                result.paths = layout_records(&mut cursor, paths.len(), RECORD_SIZE)?;
                result.variants = layout_records(&mut cursor, variants.len(), RECORD_SIZE)?;
                result.exact_bytes = layout_records(&mut cursor, exact_bytes.len(), 1)?;
            }
            Sidecars::MixedSingleton {
                paths,
                ranges,
                variants,
                exact_bytes,
            } => {
                result.paths = layout_records(&mut cursor, paths.len(), RECORD_SIZE)?;
                result.ranges = layout_records(&mut cursor, ranges.len(), RECORD_SIZE)?;
                result.variants = layout_records(&mut cursor, variants.len(), RECORD_SIZE)?;
                result.exact_bytes = layout_records(&mut cursor, exact_bytes.len(), 1)?;
            }
        }
        if cursor > MAX_IMAGE_BYTES || u32::try_from(cursor).is_err() {
            return Err(ACError::ResourceLimitExceeded(
                "Case automaton image exceeds the supported size".to_string(),
            ));
        }
        result.total = cursor;
        Ok(result)
    }
}

fn layout_automaton(cursor: &mut usize, matcher: &ACAutomaton) -> Result<AutomatonLayout, ACError> {
    Ok(AutomatonLayout {
        buffer: layout_records(cursor, matcher.buffer().len(), 1)?,
        lengths: layout_records(
            cursor,
            matcher.pattern_lengths().len(),
            mem::size_of::<u32>(),
        )?,
    })
}

fn layout_records(cursor: &mut usize, count: usize, record_size: usize) -> Result<Region, ACError> {
    if count == 0 {
        return Ok(Region::default());
    }
    let offset = align4(*cursor)?;
    let bytes = count.checked_mul(record_size).ok_or_else(size_error_unit)?;
    *cursor = offset.checked_add(bytes).ok_or_else(size_error_unit)?;
    Ok(Region { offset, len: bytes })
}

fn align4(value: usize) -> Result<usize, ACError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(size_error_unit)
}

fn encode_automaton(
    image: &mut [u8],
    descriptor: usize,
    matcher: &ACAutomaton,
    layout: AutomatonLayout,
) -> Result<(), ACError> {
    encode_raw_region(image, descriptor, layout.buffer)?;
    write_u32(image, descriptor + 8, wire_u32(matcher.node_count())?)?;
    write_u32(image, descriptor + 12, wire_u32(matcher.pattern_count())?)?;
    image[descriptor + 16] = encode_mode(matcher.match_mode());
    encode_counted_region(
        image,
        descriptor + 20,
        layout.lengths,
        mem::size_of::<u32>(),
    )?;
    copy_region(image, layout.buffer, matcher.buffer())?;
    let lengths = matcher
        .pattern_lengths()
        .iter()
        .map(|&length| wire_u32(length))
        .collect::<Result<Vec<_>, _>>()?;
    encode_u32_values(image, layout.lengths, &lengths)
}

fn encode_u32_values(image: &mut [u8], region: Region, values: &[u32]) -> Result<(), ACError> {
    if region.len != values.len().saturating_mul(mem::size_of::<u32>()) {
        return Err(size_error_unit());
    }
    for (index, value) in values.iter().enumerate() {
        write_u32(image, region.offset + index * 4, *value)?;
    }
    Ok(())
}

fn encode_ranges(image: &mut [u8], region: Region, values: &[VariantRange]) -> Result<(), ACError> {
    for (index, value) in values.iter().enumerate() {
        let offset = region.offset + index * RECORD_SIZE;
        write_u32(image, offset, value.start)?;
        write_u32(image, offset + 4, value.count)?;
    }
    Ok(())
}

fn encode_variants(
    image: &mut [u8],
    region: Region,
    values: &[CaseVariant],
) -> Result<(), ACError> {
    for (index, value) in values.iter().enumerate() {
        let offset = region.offset + index * RECORD_SIZE;
        write_u32(image, offset, value.pattern_id)?;
        write_u32(image, offset + 4, value.exact_offset)?;
    }
    Ok(())
}

fn encode_dispatches(
    image: &mut [u8],
    region: Region,
    values: &[FoldedPathDispatch],
) -> Result<(), ACError> {
    for (index, value) in values.iter().enumerate() {
        let offset = region.offset + index * RECORD_SIZE;
        write_u32(image, offset, value.pattern_id_or_tag)?;
        write_u32(image, offset + 4, value.exact_offset_or_range)?;
    }
    Ok(())
}

fn encode_region_header(
    image: &mut [u8],
    header: usize,
    region: Region,
    record_size: usize,
) -> Result<(), ACError> {
    encode_counted_region(image, header, region, record_size)
}

fn encode_counted_region(
    image: &mut [u8],
    header: usize,
    region: Region,
    record_size: usize,
) -> Result<(), ACError> {
    write_u32(image, header, wire_u32(region.offset)?)?;
    write_u32(image, header + 4, wire_u32(region.len / record_size)?)
}

fn encode_raw_region(image: &mut [u8], header: usize, region: Region) -> Result<(), ACError> {
    write_u32(image, header, wire_u32(region.offset)?)?;
    write_u32(image, header + 4, wire_u32(region.len)?)
}

fn copy_region(image: &mut [u8], region: Region, values: &[u8]) -> Result<(), ACError> {
    if region.len != values.len() {
        return Err(size_error_unit());
    }
    image
        .get_mut(
            region.offset
                ..region
                    .offset
                    .checked_add(region.len)
                    .ok_or_else(size_error_unit)?,
        )
        .ok_or_else(size_error_unit)?
        .copy_from_slice(values);
    Ok(())
}

struct DecodedAutomaton<'a> {
    matcher: ExactAutomatonView<'a>,
    node_count: u32,
    pattern_count: u32,
    mode: MatchMode,
    pattern_lengths: U32Values<'a>,
}

struct Decoder<'a> {
    image: &'a [u8],
    kind: u8,
    pattern_count: u32,
    required_lookbehind: u32,
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(image: &'a [u8]) -> Result<Self, ACError> {
        if image.len() < HEADER_SIZE {
            return Err(invalid("Case automaton image is truncated"));
        }
        if image.len() > MAX_IMAGE_BYTES {
            return Err(invalid("Case automaton image exceeds the supported size"));
        }
        if image.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid("Case automaton image has invalid magic"));
        }
        if read_u16(image, 8)? != VERSION {
            return Err(invalid("Case automaton image has an unsupported version"));
        }
        if usize::from(read_u16(image, 10)?) != HEADER_SIZE
            || usize::try_from(read_u32(image, 12)?).ok() != Some(image.len())
        {
            return Err(invalid("Case automaton image has a noncanonical envelope"));
        }
        let kind = image[16];
        let expected_automata = if kind == KIND_SPLIT { 2 } else { 1 };
        if !matches!(
            kind,
            KIND_UNIFORM | KIND_SPLIT | KIND_MIXED_FLAT | KIND_MIXED_SINGLETON
        ) || image[17] != expected_automata
            || read_u16(image, 18)? != 0
            || read_u32(image, 28)? != 0
            || image[144..HEADER_SIZE].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("Case automaton image has invalid tags or flags"));
        }
        let pattern_count = read_u32(image, 20)?;
        if pattern_count == 0 {
            return Err(invalid("Case automaton image has no semantic patterns"));
        }
        Ok(Self {
            image,
            kind,
            pattern_count,
            required_lookbehind: read_u32(image, 24)?,
            cursor: HEADER_SIZE,
        })
    }

    fn decode(mut self) -> Result<ACCaseAutomatonView<'a>, ACError> {
        let first = self.decode_automaton(FIRST_DESCRIPTOR)?;
        let second = if self.kind == KIND_SPLIT {
            Some(self.decode_automaton(SECOND_DESCRIPTOR)?)
        } else {
            if self.image[SECOND_DESCRIPTOR..SECOND_DESCRIPTOR + DESCRIPTOR_SIZE]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(invalid("Case automaton image has an unused descriptor"));
            }
            None
        };
        let node_count = first
            .node_count
            .saturating_add(second.as_ref().map_or(0, |automaton| automaton.node_count));

        let sensitive_ids = self.decode_values(SENSITIVE_IDS_REGION)?;
        let insensitive_ids = self.decode_values(INSENSITIVE_IDS_REGION)?;
        let paths = self.decode_records(PATHS_REGION, RECORD_SIZE)?;
        let ranges = self.decode_records(RANGES_REGION, RECORD_SIZE)?;
        let variants = self.decode_records(VARIANTS_REGION, RECORD_SIZE)?;
        let exact_bytes = self.decode_records(EXACT_BYTES_REGION, 1)?;
        if self.cursor != self.image.len() {
            return Err(invalid("Case automaton image has trailing or gapped data"));
        }

        let kind = match self.kind {
            KIND_UNIFORM => {
                require_empty(&[
                    sensitive_ids,
                    insensitive_ids,
                    paths,
                    ranges,
                    variants,
                    exact_bytes,
                ])?;
                if first.pattern_count != self.pattern_count || self.required_lookbehind != 0 {
                    return Err(invalid("Uniform case image metadata is inconsistent"));
                }
                ACCaseAutomatonViewKind::Uniform(first.matcher)
            }
            KIND_SPLIT => {
                require_empty(&[paths, ranges, variants, exact_bytes])?;
                let second = second.ok_or_else(|| invalid("Split case image is incomplete"))?;
                if first.mode != MatchMode::CaseSensitive
                    || second.mode != MatchMode::CaseInsensitive
                    || sensitive_ids.len() / mem::size_of::<u32>()
                        != usize::try_from(first.pattern_count).unwrap_or(usize::MAX)
                    || insensitive_ids.len() / mem::size_of::<u32>()
                        != usize::try_from(second.pattern_count).unwrap_or(usize::MAX)
                    || first.pattern_count.saturating_add(second.pattern_count)
                        != self.pattern_count
                    || self.required_lookbehind != 0
                {
                    return Err(invalid("Split case image metadata is inconsistent"));
                }
                verify_split_ids(sensitive_ids, insensitive_ids, self.pattern_count)?;
                ACCaseAutomatonViewKind::Split {
                    sensitive: first.matcher,
                    sensitive_ids: U32Values::wire(sensitive_ids)?,
                    insensitive: second.matcher,
                    insensitive_ids: U32Values::wire(insensitive_ids)?,
                }
            }
            KIND_MIXED_FLAT => {
                require_empty(&[sensitive_ids, insensitive_ids, ranges])?;
                if first.mode != MatchMode::CaseInsensitive
                    || paths.len() / RECORD_SIZE
                        != usize::try_from(first.pattern_count).unwrap_or(usize::MAX)
                    || variants.len() / RECORD_SIZE
                        != usize::try_from(self.pattern_count).unwrap_or(usize::MAX)
                {
                    return Err(invalid("Mixed flat case image metadata is inconsistent"));
                }
                let paths = VariantRanges::Wire(paths);
                let variants = CaseVariants::Wire(variants);
                verify_flat(
                    paths,
                    variants,
                    first.pattern_lengths,
                    exact_bytes,
                    self.pattern_count,
                    self.required_lookbehind,
                )?;
                ACCaseAutomatonViewKind::Mixed {
                    folded: first.matcher,
                    dispatch: MixedDispatchView::Flat { paths, variants },
                    exact_bytes,
                }
            }
            KIND_MIXED_SINGLETON => {
                require_empty(&[sensitive_ids, insensitive_ids])?;
                if first.mode != MatchMode::CaseInsensitive
                    || paths.len() / RECORD_SIZE
                        != usize::try_from(first.pattern_count).unwrap_or(usize::MAX)
                {
                    return Err(invalid(
                        "Mixed singleton case image metadata is inconsistent",
                    ));
                }
                let paths = FoldedPathDispatches::Wire(paths);
                let ranges = VariantRanges::Wire(ranges);
                let variants = CaseVariants::Wire(variants);
                verify_singleton(
                    paths,
                    ranges,
                    variants,
                    first.pattern_lengths,
                    exact_bytes,
                    self.pattern_count,
                    self.required_lookbehind,
                )?;
                ACCaseAutomatonViewKind::Mixed {
                    folded: first.matcher,
                    dispatch: MixedDispatchView::SingletonOptimized {
                        paths,
                        variant_ranges: ranges,
                        multi_variants: variants,
                    },
                    exact_bytes,
                }
            }
            _ => unreachable!("case image kind was validated"),
        };

        Ok(ACCaseAutomatonView {
            kind,
            pattern_count: usize::try_from(self.pattern_count).unwrap_or(usize::MAX),
            node_count: usize::try_from(node_count).unwrap_or(usize::MAX),
            required_lookbehind: usize::try_from(self.required_lookbehind).unwrap_or(usize::MAX),
        })
    }

    fn decode_automaton(&mut self, descriptor: usize) -> Result<DecodedAutomaton<'a>, ACError> {
        if self.image[descriptor + 17..descriptor + 20]
            .iter()
            .any(|byte| *byte != 0)
            || read_u32(self.image, descriptor + 28)? != 0
        {
            return Err(invalid("Case image AC descriptor has reserved data"));
        }
        let buffer = self.decode_raw_region(descriptor)?;
        let node_count = read_u32(self.image, descriptor + 8)?;
        let pattern_count = read_u32(self.image, descriptor + 12)?;
        if node_count == 0 || pattern_count == 0 {
            return Err(invalid("Case image AC descriptor is empty"));
        }
        let mode = decode_mode(self.image[descriptor + 16])?;
        let pattern_lengths = self.decode_region(descriptor + 20, mem::size_of::<u32>())?;
        if pattern_lengths.len() / mem::size_of::<u32>()
            != usize::try_from(pattern_count).unwrap_or(usize::MAX)
        {
            return Err(invalid("Case image AC pattern lengths are inconsistent"));
        }
        let pattern_lengths = U32Values::wire(pattern_lengths)?;
        let matcher = ExactAutomatonView::from_wire(
            buffer,
            usize::try_from(node_count).unwrap_or(usize::MAX),
            pattern_count,
            mode,
            pattern_lengths,
        )?;
        Ok(DecodedAutomaton {
            matcher,
            node_count,
            pattern_count,
            mode,
            pattern_lengths,
        })
    }

    fn decode_values(&mut self, header: usize) -> Result<&'a [u8], ACError> {
        self.decode_region(header, mem::size_of::<u32>())
    }

    fn decode_records(&mut self, header: usize, size: usize) -> Result<&'a [u8], ACError> {
        self.decode_region(header, size)
    }

    fn decode_raw_region(&mut self, header: usize) -> Result<&'a [u8], ACError> {
        let offset = usize::try_from(read_u32(self.image, header)?).unwrap_or(usize::MAX);
        let bytes = usize::try_from(read_u32(self.image, header + 4)?).unwrap_or(usize::MAX);
        self.take_region(offset, bytes, bytes != 0)
    }

    fn decode_region(&mut self, header: usize, record_size: usize) -> Result<&'a [u8], ACError> {
        let offset = usize::try_from(read_u32(self.image, header)?).unwrap_or(usize::MAX);
        let count = usize::try_from(read_u32(self.image, header + 4)?).unwrap_or(usize::MAX);
        let bytes = count.checked_mul(record_size).ok_or_else(size_error_unit)?;
        self.take_region(offset, bytes, count != 0)
    }

    fn take_region(
        &mut self,
        offset: usize,
        bytes: usize,
        present: bool,
    ) -> Result<&'a [u8], ACError> {
        if !present {
            if offset != 0 || bytes != 0 {
                return Err(invalid("Case image has a noncanonical empty region"));
            }
            return Ok(&[]);
        }
        let expected = align4(self.cursor)?;
        if offset != expected {
            return Err(invalid("Case image regions are not canonical and dense"));
        }
        if self.image[self.cursor..expected]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid("Case image alignment padding is not zero"));
        }
        let end = offset.checked_add(bytes).ok_or_else(size_error_unit)?;
        let result = self
            .image
            .get(offset..end)
            .ok_or_else(|| invalid("Case image region is out of bounds"))?;
        self.cursor = end;
        Ok(result)
    }
}

fn verify_split_ids(
    sensitive: &[u8],
    insensitive: &[u8],
    pattern_count: u32,
) -> Result<(), ACError> {
    let sensitive = U32Values::wire(sensitive)?;
    let insensitive = U32Values::wire(insensitive)?;
    let mut left = sensitive.iter().peekable();
    let mut right = insensitive.iter().peekable();
    for expected in 0..pattern_count {
        let actual = match (left.peek(), right.peek()) {
            (Some(left_value), Some(right_value)) if left_value < right_value => left.next(),
            (Some(_), Some(_)) => right.next(),
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => None,
        };
        if actual != Some(expected) {
            return Err(invalid("Split case image pattern IDs are not a partition"));
        }
    }
    if left.next().is_some() || right.next().is_some() {
        return Err(invalid("Split case image has extra pattern IDs"));
    }
    Ok(())
}

fn verify_flat(
    paths: VariantRanges<'_>,
    variants: CaseVariants<'_>,
    lengths: U32Values<'_>,
    exact_bytes: &[u8],
    pattern_count: u32,
    required_lookbehind: u32,
) -> Result<(), ACError> {
    let mut verifier = VariantVerifier::new(pattern_count, exact_bytes)?;
    let mut variant_cursor = 0_usize;
    let mut singleton_paths = 0_usize;
    for path_index in 0..paths.len() {
        let path_id = u32::try_from(path_index).map_err(size_error)?;
        let path = paths
            .get(path_id)
            .ok_or_else(|| invalid("Mixed flat case path is missing"))?;
        if usize::try_from(path.start).ok() != Some(variant_cursor) || path.count == 0 {
            return Err(invalid("Mixed flat case ranges are not canonical"));
        }
        let count = usize::try_from(path.count).unwrap_or(usize::MAX);
        if count == 1 {
            singleton_paths = singleton_paths.saturating_add(1);
        }
        if variant_cursor
            .checked_add(count)
            .map_or(true, |end| end > variants.len())
        {
            return Err(invalid("Mixed flat case range is out of bounds"));
        }
        let length = lengths
            .get(path_id)
            .ok_or_else(|| invalid("Mixed flat case path length is missing"))?;
        for variant in variants.range(variant_cursor, count) {
            verifier.visit(variant, length)?;
            variant_cursor = variant_cursor.saturating_add(1);
        }
    }
    if variant_cursor != variants.len() {
        return Err(invalid("Mixed flat case variants are not fully referenced"));
    }
    if singleton_paths > paths.len().saturating_sub(singleton_paths) {
        return Err(invalid("Mixed flat dispatch is not the canonical layout"));
    }
    verifier.finish(required_lookbehind)
}

fn verify_singleton(
    paths: FoldedPathDispatches<'_>,
    ranges: VariantRanges<'_>,
    variants: CaseVariants<'_>,
    lengths: U32Values<'_>,
    exact_bytes: &[u8],
    pattern_count: u32,
    required_lookbehind: u32,
) -> Result<(), ACError> {
    let mut verifier = VariantVerifier::new(pattern_count, exact_bytes)?;
    let mut range_cursor = 0_usize;
    let mut variant_cursor = 0_usize;
    for path_index in 0..paths.len() {
        let path_id = u32::try_from(path_index).map_err(size_error)?;
        let path = paths
            .get(path_id)
            .ok_or_else(|| invalid("Mixed singleton case path is missing"))?;
        let length = lengths
            .get(path_id)
            .ok_or_else(|| invalid("Mixed singleton case path length is missing"))?;
        if path.pattern_id_or_tag != MULTI_VARIANT_TAG {
            verifier.visit(
                CaseVariant {
                    pattern_id: path.pattern_id_or_tag,
                    exact_offset: path.exact_offset_or_range,
                },
                length,
            )?;
            continue;
        }
        if usize::try_from(path.exact_offset_or_range).ok() != Some(range_cursor) {
            return Err(invalid("Mixed singleton range indexes are not canonical"));
        }
        let range = ranges
            .get(path.exact_offset_or_range)
            .ok_or_else(|| invalid("Mixed singleton range is missing"))?;
        if usize::try_from(range.start).ok() != Some(variant_cursor) || range.count < 2 {
            return Err(invalid("Mixed singleton variant ranges are not canonical"));
        }
        let count = usize::try_from(range.count).unwrap_or(usize::MAX);
        if variant_cursor
            .checked_add(count)
            .map_or(true, |end| end > variants.len())
        {
            return Err(invalid("Mixed singleton variant range is out of bounds"));
        }
        for variant in variants.range(variant_cursor, count) {
            verifier.visit(variant, length)?;
            variant_cursor = variant_cursor.saturating_add(1);
        }
        range_cursor = range_cursor.saturating_add(1);
    }
    if range_cursor != ranges.len() || variant_cursor != variants.len() {
        return Err(invalid(
            "Mixed singleton sidecars are not fully and densely referenced",
        ));
    }
    if paths.len().saturating_sub(range_cursor) <= range_cursor {
        return Err(invalid(
            "Mixed singleton dispatch is not the canonical layout",
        ));
    }
    verifier.finish(required_lookbehind)
}

struct VariantVerifier<'a> {
    seen: Vec<u8>,
    expected_count: u32,
    count: u32,
    exact_bytes: &'a [u8],
    exact_cursor: usize,
    required_lookbehind: u32,
}

impl<'a> VariantVerifier<'a> {
    fn new(pattern_count: u32, exact_bytes: &'a [u8]) -> Result<Self, ACError> {
        let bits = usize::try_from(pattern_count).unwrap_or(usize::MAX);
        let bytes = bits.checked_add(7).ok_or_else(size_error_unit)? / 8;
        let mut seen = Vec::new();
        seen.try_reserve_exact(bytes).map_err(|_| {
            ACError::ResourceLimitExceeded("Case image pattern verifier allocation failed".into())
        })?;
        seen.resize(bytes, 0);
        Ok(Self {
            seen,
            expected_count: pattern_count,
            count: 0,
            exact_bytes,
            exact_cursor: 0,
            required_lookbehind: 0,
        })
    }

    fn visit(&mut self, variant: CaseVariant, length: u32) -> Result<(), ACError> {
        let pattern = usize::try_from(variant.pattern_id).unwrap_or(usize::MAX);
        let byte = self
            .seen
            .get_mut(pattern / 8)
            .ok_or_else(|| invalid("Mixed case image pattern ID is out of range"))?;
        let mask = 1_u8 << (pattern % 8);
        if *byte & mask != 0 {
            return Err(invalid("Mixed case image repeats a semantic pattern ID"));
        }
        *byte |= mask;
        self.count = self.count.saturating_add(1);
        if variant.exact_offset == NO_EXACT_CHECK {
            return Ok(());
        }
        if usize::try_from(variant.exact_offset).ok() != Some(self.exact_cursor) {
            return Err(invalid("Mixed case exact bytes are not canonical"));
        }
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        self.exact_cursor = self
            .exact_cursor
            .checked_add(length)
            .ok_or_else(size_error_unit)?;
        if self.exact_cursor > self.exact_bytes.len() {
            return Err(invalid("Mixed case exact bytes are out of bounds"));
        }
        self.required_lookbehind = self
            .required_lookbehind
            .max(u32::try_from(length.saturating_sub(1)).unwrap_or(u32::MAX));
        Ok(())
    }

    fn finish(self, required_lookbehind: u32) -> Result<(), ACError> {
        if self.count != self.expected_count
            || self.exact_cursor != self.exact_bytes.len()
            || self.required_lookbehind != required_lookbehind
        {
            return Err(invalid(
                "Mixed case image semantic metadata is inconsistent",
            ));
        }
        Ok(())
    }
}

fn require_empty(regions: &[&[u8]]) -> Result<(), ACError> {
    if regions.iter().any(|region| !region.is_empty()) {
        Err(invalid(
            "Case image contains sidecars for another representation",
        ))
    } else {
        Ok(())
    }
}

fn encode_mode(mode: MatchMode) -> u8 {
    match mode {
        MatchMode::CaseSensitive => 0,
        MatchMode::CaseInsensitive => 1,
    }
}

fn decode_mode(tag: u8) -> Result<MatchMode, ACError> {
    match tag {
        0 => Ok(MatchMode::CaseSensitive),
        1 => Ok(MatchMode::CaseInsensitive),
        _ => Err(invalid("Case image AC descriptor has an invalid mode")),
    }
}

fn wire_u32(value: usize) -> Result<u32, ACError> {
    u32::try_from(value).map_err(size_error)
}

fn size_error<T>(_: T) -> ACError {
    size_error_unit()
}

fn size_error_unit() -> ACError {
    ACError::ResourceLimitExceeded("Case automaton image size overflow".to_string())
}

fn invalid(message: &str) -> ACError {
    ACError::InvalidInput(message.to_string())
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), ACError> {
    output
        .get_mut(offset..offset.checked_add(2).ok_or_else(size_error_unit)?)
        .ok_or_else(size_error_unit)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), ACError> {
    output
        .get_mut(offset..offset.checked_add(4).ok_or_else(size_error_unit)?)
        .ok_or_else(size_error_unit)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ACError> {
    let bytes: [u8; 2] = input
        .get(offset..offset.checked_add(2).ok_or_else(size_error_unit)?)
        .ok_or_else(|| invalid("Case image header is truncated"))?
        .try_into()
        .map_err(|_| invalid("Case image u16 field is truncated"))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ACError> {
    let bytes: [u8; 4] = input
        .get(offset..offset.checked_add(4).ok_or_else(size_error_unit)?)
        .ok_or_else(|| invalid("Case image field is truncated"))?
        .try_into()
        .map_err(|_| invalid("Case image u32 field is truncated"))?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ACCaseMatchState, ACCasePattern, ACMatch};

    fn sorted(mut matches: Vec<ACMatch>) -> Vec<ACMatch> {
        matches.sort_by_key(|matched| (matched.end, matched.start, matched.pattern_id));
        matches
    }

    fn collect_owned(matcher: &ACCaseAutomaton, input: &[u8], chunk_size: usize) -> Vec<ACMatch> {
        let mut state = matcher.create_state();
        collect_chunks(
            input,
            chunk_size,
            matcher.required_lookbehind(),
            &mut state,
            |state, chunk, history, visit| matcher.advance(state, chunk, history, visit),
        )
    }

    fn collect_view(
        matcher: &ACCaseAutomatonView<'_>,
        input: &[u8],
        chunk_size: usize,
    ) -> Vec<ACMatch> {
        let mut state = matcher.create_state();
        collect_chunks(
            input,
            chunk_size,
            matcher.required_lookbehind(),
            &mut state,
            |state, chunk, history, visit| matcher.advance(state, chunk, history, visit),
        )
    }

    fn collect_chunks(
        input: &[u8],
        chunk_size: usize,
        retain: usize,
        state: &mut ACCaseMatchState,
        mut advance: impl FnMut(
            &mut ACCaseMatchState,
            &[u8],
            &[u8],
            &mut dyn FnMut(ACMatch),
        ) -> Result<(), ACError>,
    ) -> Vec<ACMatch> {
        let mut history = Vec::new();
        let mut matches = Vec::new();
        for chunk in input.chunks(chunk_size) {
            advance(state, chunk, &history, &mut |matched| matches.push(matched)).unwrap();
            history.extend_from_slice(chunk);
            if history.len() > retain {
                history.drain(..history.len() - retain);
            }
        }
        assert_eq!(state.position(), u64::try_from(input.len()).unwrap());
        sorted(matches)
    }

    fn representations() -> Vec<(u8, ACCaseAutomaton, &'static [u8])> {
        let uniform_patterns = [
            ACCasePattern::new(b"Alpha", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"beta", MatchMode::CaseInsensitive),
        ];
        let split_patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"other", MatchMode::CaseInsensitive),
        ];
        let flat_patterns = [
            ACCasePattern::new(b"Alpha", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ALPHA", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"bravo", MatchMode::CaseInsensitive),
        ];
        let singleton_patterns = [
            ACCasePattern::new(b"Alpha", MatchMode::CaseSensitive),
            ACCasePattern::new(b"BRAVO", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"123", MatchMode::CaseSensitive),
            ACCasePattern::new(b"Dupe", MatchMode::CaseSensitive),
            ACCasePattern::new(b"DUPE", MatchMode::CaseInsensitive),
        ];
        vec![
            (
                KIND_UNIFORM,
                ACCaseAutomaton::build(&uniform_patterns).unwrap(),
                b"xxALPHA-beta",
            ),
            (
                KIND_SPLIT,
                ACCaseAutomaton::build_with_lookbehind_limit(&split_patterns, 0).unwrap(),
                b"xxAbCd-abcd-OTHER",
            ),
            (
                KIND_MIXED_FLAT,
                ACCaseAutomaton::build(&flat_patterns).unwrap(),
                b"xxAlpha-ALPHA-BRAVO",
            ),
            (
                KIND_MIXED_SINGLETON,
                ACCaseAutomaton::build(&singleton_patterns).unwrap(),
                b"xxAlpha-alpha-BRAVO-123-Dupe-dupe",
            ),
        ]
    }

    #[test]
    fn every_case_representation_round_trips_and_matches_from_unaligned_bytes() {
        for (kind, matcher, input) in representations() {
            let image = matcher.to_image().unwrap();
            assert_eq!(image[16], kind);
            assert_eq!(matcher.to_image().unwrap(), image);

            let mut unaligned = vec![0xA5];
            unaligned.extend_from_slice(&image);
            let view = ACCaseAutomatonView::from_image(&unaligned[1..]).unwrap();
            assert_eq!(view.pattern_count(), matcher.pattern_count());
            assert_eq!(view.node_count(), matcher.node_count());
            assert_eq!(view.scan_count(), matcher.scan_count());
            assert_eq!(view.required_lookbehind(), matcher.required_lookbehind());
            for chunk_size in 1..=input.len() {
                assert_eq!(
                    collect_view(&view, input, chunk_size),
                    collect_owned(&matcher, input, chunk_size),
                    "kind={kind} chunk={chunk_size}",
                );
            }
        }
    }

    #[test]
    fn image_view_preserves_mixed_filtering_and_exact_case() {
        let patterns = [
            ACCasePattern::new(b"AbCd", MatchMode::CaseSensitive),
            ACCasePattern::new(b"ABCD", MatchMode::CaseInsensitive),
            ACCasePattern::new(b"other", MatchMode::CaseInsensitive),
        ];
        let image = ACCaseAutomaton::build(&patterns)
            .unwrap()
            .to_image()
            .unwrap();
        let view = ACCaseAutomatonView::from_image(&image).unwrap();
        let mut state = view.create_state();
        let mut matches = Vec::new();
        view.advance_filtered(
            &mut state,
            b"abcd AbCd OTHER",
            &[],
            |pattern| pattern != 1,
            |matched| matches.push(matched),
        )
        .unwrap();
        assert_eq!(
            matches
                .into_iter()
                .map(|matched| matched.pattern_id)
                .collect::<Vec<_>>(),
            [0, 2]
        );
    }

    #[test]
    fn image_verifier_rejects_truncation_and_corrupt_topology() {
        let (_, matcher, _) = representations()
            .into_iter()
            .find(|(kind, _, _)| *kind == KIND_MIXED_SINGLETON)
            .unwrap();
        let image = matcher.to_image().unwrap();
        for length in 0..image.len() {
            assert!(
                ACCaseAutomatonView::from_image(&image[..length]).is_err(),
                "truncation length {length}"
            );
        }

        let mut trailing = image.clone();
        trailing.push(0);
        assert!(ACCaseAutomatonView::from_image(&trailing).is_err());

        let mut tag = image.clone();
        tag[16] = u8::MAX;
        assert!(ACCaseAutomatonView::from_image(&tag).is_err());

        let mut reserved = image.clone();
        reserved[144] = 1;
        assert!(ACCaseAutomatonView::from_image(&reserved).is_err());

        let mut node_count = image.clone();
        write_u32(&mut node_count, FIRST_DESCRIPTOR + 8, 0).unwrap();
        assert!(ACCaseAutomatonView::from_image(&node_count).is_err());

        let mut ac_structure = image.clone();
        let buffer = usize::try_from(read_u32(&ac_structure, FIRST_DESCRIPTOR).unwrap()).unwrap();
        ac_structure[buffer] = u8::MAX;
        assert!(ACCaseAutomatonView::from_image(&ac_structure).is_err());

        let mut sidecar = image;
        let path_offset = read_u32(&sidecar, PATHS_REGION).unwrap();
        write_u32(&mut sidecar, PATHS_REGION, path_offset.saturating_add(4)).unwrap();
        assert!(ACCaseAutomatonView::from_image(&sidecar).is_err());
    }
}
