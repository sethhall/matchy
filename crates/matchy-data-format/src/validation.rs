//! Validation for MMDB data section encoding
//!
//! Provides validation of decoded DataValue structures to ensure:
//! - UTF-8 validity in strings (critical for safety)
//! - Structural integrity of data values
//!
//! These validations are building blocks that can be used by higher-level
//! validators (like MMDB validation) that understand file structure.

use crate::{DataDecoder, DataValue};

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

/// Validation result for data format checks
#[derive(Debug, Clone)]
pub struct DataFormatValidationResult {
    /// Errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Validation statistics
    pub stats: DataFormatStats,
}

impl DataFormatValidationResult {
    /// Create a new empty validation result
    #[must_use]
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: DataFormatStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error
    pub fn error(&mut self, msg: String) {
        push_capped(
            &mut self.errors,
            msg,
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    /// Add a warning
    pub fn warning(&mut self, msg: String) {
        push_capped(
            &mut self.warnings,
            msg,
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }
}

impl Default for DataFormatValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from data format validation
#[derive(Debug, Clone, Default)]
pub struct DataFormatStats {
    /// Number of strings validated
    pub strings_checked: u32,
    /// Number of maps validated
    pub maps_checked: u32,
    /// Number of arrays validated
    pub arrays_checked: u32,
    /// Total values validated
    pub values_checked: u32,
}

/// Validate UTF-8 in a decoded data value at the given offset
///
/// This function attempts to decode a value from the data section buffer
/// and recursively validates all strings within it.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `offset` - Offset within data section to decode from
/// * `base_offset` - Base offset for pointer calculations (0 for standalone)
///
/// # Returns
/// * `Ok(count)` - Number of strings validated (all valid)
/// * `Err(msg)` - Error message if invalid UTF-8 found or decode failed
pub fn validate_data_value_utf8(
    data_section: &[u8],
    offset: usize,
    base_offset: usize,
) -> Result<u32, String> {
    let decoder = DataDecoder::new(data_section, base_offset);
    let offset_u32 =
        u32::try_from(offset).map_err(|_| format!("Offset {offset} exceeds u32::MAX"))?;

    match decoder.decode(offset_u32) {
        Ok(value) => validate_value_strings_utf8(&value),
        Err(e) => Err(format!("Failed to decode data value: {e}")),
    }
}

/// Recursively validate UTF-8 in all strings within a DataValue
///
/// This function traverses the DataValue structure and counts all strings,
/// verifying they are valid UTF-8. Since DataValue::String already guarantees
/// UTF-8 validity (enforced during decoding), this primarily serves as a
/// structural validator and counter.
///
/// # Arguments
/// * `value` - DataValue to validate
///
/// # Returns
/// * `Ok(count)` - Number of strings found (all valid UTF-8)
/// * `Err(msg)` - Error message if validation fails
///
/// # Note
/// The DataDecoder already enforces UTF-8 validity when creating String variants,
/// so this function won't find invalid UTF-8 in properly decoded values.
/// It's useful for:
/// - Counting strings in a structure
/// - Detecting decode issues early
/// - Providing structural validation
pub fn validate_value_strings_utf8(value: &DataValue) -> Result<u32, String> {
    let mut count = 0u32;

    match value {
        DataValue::String(_s) => {
            // String is already validated UTF-8 when decoded
            count += 1;
        }
        DataValue::Map(map) => {
            for val in map.values() {
                // Map keys are always strings, and already validated
                count += 1;
                // Recursively validate values
                count += validate_value_strings_utf8(val)?;
            }
        }
        DataValue::Array(arr) => {
            for val in arr {
                count += validate_value_strings_utf8(val)?;
            }
        }
        // Other types don't contain strings
        DataValue::Pointer(_)
        | DataValue::Double(_)
        | DataValue::Bytes(_)
        | DataValue::Uint16(_)
        | DataValue::Uint32(_)
        | DataValue::Int32(_)
        | DataValue::Uint64(_)
        | DataValue::Uint128(_)
        | DataValue::Bool(_)
        | DataValue::Float(_)
        | DataValue::Timestamp(_) => {}
    }

    Ok(count)
}

/// Validate data section structure by attempting to decode values
///
/// This validates the values reachable from the supplied root offsets. A raw
/// MMDB data section is not self-describing, so callers must provide roots to
/// obtain decoding coverage.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `base_offset` - Base offset for pointer calculations
/// * `offsets_to_check` - Root offsets to validate. If empty, no values are
///   decoded and the result contains a warning.
///
/// # Returns
/// Validation result with errors, warnings, and statistics
#[must_use]
pub fn validate_data_section(
    data_section: &[u8],
    base_offset: usize,
    offsets_to_check: &[u32],
) -> DataFormatValidationResult {
    let mut result = DataFormatValidationResult::new();

    if data_section.is_empty() {
        result.warning("Data section is empty".to_string());
        return result;
    }

    let decoder = DataDecoder::new(data_section, base_offset);

    // If specific offsets provided, check those
    if offsets_to_check.is_empty() {
        // If no specific offsets, just validate that the section is well-formed
        result.warning("No specific offsets to validate".to_string());
    } else {
        for &offset in offsets_to_check {
            match decoder.decode(offset) {
                Ok(value) => {
                    result.stats.values_checked += 1;
                    match validate_value_strings_utf8(&value) {
                        Ok(count) => {
                            result.stats.strings_checked += count;
                        }
                        Err(e) => {
                            result.error(format!("Invalid UTF-8 at offset {offset}: {e}"));
                        }
                    }

                    // Update type-specific stats
                    update_stats_for_value(&value, &mut result.stats);
                }
                Err(e) => {
                    result.error(format!("Failed to decode at offset {offset}: {e}"));
                }
            }
        }
    }

    result
}

/// Update statistics based on value type
fn update_stats_for_value(value: &DataValue, stats: &mut DataFormatStats) {
    match value {
        DataValue::Map(m) => {
            stats.maps_checked += 1;
            for val in m.values() {
                update_stats_for_value(val, stats);
            }
        }
        DataValue::Array(arr) => {
            stats.arrays_checked += 1;
            for val in arr {
                update_stats_for_value(val, stats);
            }
        }
        _ => {}
    }
}

/// Maximum safe depth for pointer chains in MMDB data
pub const MAX_POINTER_DEPTH: usize = 32;

/// Maximum reasonable total nesting depth (arrays/maps + pointers)
pub const MAX_TOTAL_DEPTH: usize = 64;

/// Validation error types for MMDB data section pointer chains
#[derive(Debug)]
pub enum PointerValidationError {
    /// Cycle detected in pointer chain
    Cycle { offset: usize },
    /// Depth limit exceeded
    DepthExceeded { depth: usize },
    /// Invalid offset encountered
    InvalidOffset { offset: usize, reason: String },
    /// Invalid type ID
    InvalidType { offset: usize, type_id: u8 },
}

impl std::fmt::Display for PointerValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cycle { offset } => {
                write!(f, "Pointer cycle detected at offset {offset}")
            }
            Self::DepthExceeded { depth } => {
                write!(f, "Depth {depth} exceeds limit")
            }
            Self::InvalidOffset { offset, reason } => {
                write!(f, "Invalid offset {offset} ({reason})")
            }
            Self::InvalidType { offset, type_id } => {
                write!(f, "Invalid type {type_id} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for PointerValidationError {}

/// Result of MMDB data section pointer validation
#[derive(Debug, Clone)]
pub struct PointerValidationResult {
    /// Errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Statistics
    pub stats: PointerValidationStats,
}

/// Statistics from pointer validation
#[derive(Debug, Clone, Default)]
pub struct PointerValidationStats {
    /// Number of pointers checked
    pub pointers_checked: usize,
    /// Number of cycles detected
    pub cycles_detected: usize,
    /// Maximum depth found
    pub max_depth: usize,
    /// Invalid pointers found
    pub invalid_pointers: usize,
}

impl PointerValidationResult {
    /// Create new empty result
    #[must_use]
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: PointerValidationStats::default(),
        }
    }

    /// Check if validation passed
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error while retaining at most the validation-report limit.
    pub fn error(&mut self, msg: String) {
        push_capped(
            &mut self.errors,
            msg,
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    /// Add a warning while retaining at most the validation-report limit.
    pub fn warning(&mut self, msg: String) {
        push_capped(
            &mut self.warnings,
            msg,
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }
}

impl Default for PointerValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a data value and all pointers it contains
///
/// Returns the maximum depth of pointer chains encountered.
/// Detects cycles using the visited set.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `offset` - Offset within data section to start validation
/// * `path` - Set of offsets in the current traversal path (for cycle detection)
/// * `depth` - Current depth in pointer chain
///
/// # Returns
/// * `Ok(max_depth)` - Maximum depth reached
/// * `Err` - Validation error encountered
///
/// # Note
/// The `path` set tracks ancestors in the current traversal path, not all visited nodes.
/// This allows legitimate pointer reuse (data deduplication) while still detecting true cycles
/// where a value references itself or an ancestor.
pub fn validate_data_value_pointers(
    data_section: &[u8],
    offset: usize,
    path: &mut std::collections::HashSet<usize>,
    depth: usize,
) -> Result<usize, PointerValidationError> {
    PointerWalker::new(data_section, path).validate(offset, depth)
}

const VALIDATION_WORK_MULTIPLIER: usize = 8;
// Keep the logical expansion budget aligned with `DataDecoder`: memoization
// avoids reparsing shared targets, but a cached reuse still consumes the work
// that decoding the shared value would perform.
const MIN_VALIDATION_WORK_BUDGET: usize = 64 * 1024;
const MAX_VALIDATION_WORK_BUDGET: usize = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    String,
    Other,
}

#[derive(Clone, Copy)]
struct WalkResult {
    end: usize,
    kind: ValueKind,
    max_total_depth: usize,
    max_pointer_depth: usize,
    expanded_work: usize,
}

#[derive(Clone, Copy)]
struct CachedPointerTarget {
    end: usize,
    kind: ValueKind,
    total_depth_span: usize,
    pointer_depth_span: usize,
    expanded_work: usize,
}

struct PointerWalker<'data, 'path> {
    data: &'data [u8],
    path: &'path mut std::collections::HashSet<usize>,
    validated_pointer_targets: std::collections::HashMap<usize, CachedPointerTarget>,
    work_remaining: usize,
}

impl<'data, 'path> PointerWalker<'data, 'path> {
    fn new(data: &'data [u8], path: &'path mut std::collections::HashSet<usize>) -> Self {
        Self {
            data,
            path,
            validated_pointer_targets: std::collections::HashMap::new(),
            work_remaining: data
                .len()
                .saturating_mul(VALIDATION_WORK_MULTIPLIER)
                .clamp(MIN_VALIDATION_WORK_BUDGET, MAX_VALIDATION_WORK_BUDGET),
        }
    }

    fn validate(
        &mut self,
        offset: usize,
        pointer_depth: usize,
    ) -> Result<usize, PointerValidationError> {
        self.walk_value(offset, pointer_depth, pointer_depth)
            .map(|result| result.max_pointer_depth)
    }

    fn walk_value(
        &mut self,
        offset: usize,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<WalkResult, PointerValidationError> {
        self.ensure_depth(total_depth, pointer_depth)?;
        let work_before = self.work_remaining;
        self.charge_work(offset, 1)?;

        let Some(&ctrl) = self.data.get(offset) else {
            return Err(PointerValidationError::InvalidOffset {
                offset,
                reason: "Offset beyond data section".to_string(),
            });
        };
        if !self.path.insert(offset) {
            return Err(PointerValidationError::Cycle { offset });
        }

        let result = (|| {
            let mut cursor = offset
                .checked_add(1)
                .ok_or_else(|| self.invalid_offset(offset, "Control-byte offset overflow"))?;
            let type_id = ctrl >> 5;
            let payload = ctrl & 0x1f;

            match type_id {
                0 => self.walk_extended(offset, &mut cursor, payload, total_depth, pointer_depth),
                1 => {
                    let target = self.decode_pointer_offset(&mut cursor, payload)?;
                    let pointed = self.walk_pointer_target(
                        target,
                        total_depth.saturating_add(1),
                        pointer_depth.saturating_add(1),
                    )?;
                    Ok(WalkResult {
                        end: cursor,
                        kind: pointed.kind,
                        max_total_depth: pointed.max_total_depth,
                        max_pointer_depth: pointed.max_pointer_depth.max(pointer_depth + 1),
                        expanded_work: 0,
                    })
                }
                2 => {
                    let size = self.decode_size(&mut cursor, payload)?;
                    let end = self.payload_end(cursor, size, "String data out of bounds")?;
                    std::str::from_utf8(&self.data[cursor..end]).map_err(|_| {
                        self.invalid_offset(cursor, "String contains invalid UTF-8")
                    })?;
                    Ok(WalkResult {
                        end,
                        kind: ValueKind::String,
                        max_total_depth: 0,
                        max_pointer_depth: pointer_depth,
                        expanded_work: 0,
                    })
                }
                3 => {
                    let size = self.decode_size(&mut cursor, payload)?;
                    self.fixed_scalar(cursor, size, 8, pointer_depth, "Double")
                }
                4 => {
                    let size = self.decode_size(&mut cursor, payload)?;
                    let end = self.payload_end(cursor, size, "Bytes data out of bounds")?;
                    Ok(self.scalar(end, pointer_depth))
                }
                5 => {
                    let size = self.decode_size(&mut cursor, payload)?;
                    self.bounded_scalar(cursor, size, 2, pointer_depth, "Uint16")
                }
                6 => {
                    let size = self.decode_size(&mut cursor, payload)?;
                    self.bounded_scalar(cursor, size, 4, pointer_depth, "Uint32")
                }
                7 => self.walk_map(&mut cursor, payload, total_depth, pointer_depth),
                _ => Err(PointerValidationError::InvalidType { offset, type_id }),
            }
        })();

        self.path.remove(&offset);
        result.map(|mut result| {
            result.max_total_depth = result.max_total_depth.max(total_depth);
            result.max_pointer_depth = result.max_pointer_depth.max(pointer_depth);
            result.expanded_work = work_before - self.work_remaining;
            result
        })
    }

    fn walk_pointer_target(
        &mut self,
        offset: usize,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<WalkResult, PointerValidationError> {
        self.ensure_depth(total_depth, pointer_depth)?;

        // A cached target may still be an ancestor of the pointer currently
        // being followed. Check the active path before consulting the cache so
        // memoization cannot hide a cycle.
        if self.path.contains(&offset) {
            return Err(PointerValidationError::Cycle { offset });
        }

        if let Some(cached) = self.validated_pointer_targets.get(&offset).copied() {
            let max_total_depth = total_depth.saturating_add(cached.total_depth_span);
            let max_pointer_depth = pointer_depth.saturating_add(cached.pointer_depth_span);
            self.ensure_depth(max_total_depth, max_pointer_depth)?;
            self.charge_work(offset, cached.expanded_work)?;

            return Ok(WalkResult {
                end: cached.end,
                kind: cached.kind,
                max_total_depth,
                max_pointer_depth,
                expanded_work: cached.expanded_work,
            });
        }

        let result = self.walk_value(offset, total_depth, pointer_depth)?;
        let cached = CachedPointerTarget {
            end: result.end,
            kind: result.kind,
            total_depth_span: result.max_total_depth.saturating_sub(total_depth),
            pointer_depth_span: result.max_pointer_depth.saturating_sub(pointer_depth),
            expanded_work: result.expanded_work,
        };
        self.validated_pointer_targets
            .try_reserve(1)
            .map_err(|_| self.invalid_offset(offset, "Pointer-target cache allocation failed"))?;
        self.validated_pointer_targets.insert(offset, cached);

        Ok(result)
    }

    fn ensure_depth(
        &self,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<(), PointerValidationError> {
        if total_depth > MAX_TOTAL_DEPTH || pointer_depth > MAX_POINTER_DEPTH {
            return Err(PointerValidationError::DepthExceeded {
                depth: total_depth.max(pointer_depth),
            });
        }
        Ok(())
    }

    fn charge_work(&mut self, offset: usize, work: usize) -> Result<(), PointerValidationError> {
        self.work_remaining = self
            .work_remaining
            .checked_sub(work)
            .ok_or_else(|| self.invalid_offset(offset, "Validation work limit exceeded"))?;
        Ok(())
    }

    fn walk_extended(
        &mut self,
        offset: usize,
        cursor: &mut usize,
        payload: u8,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<WalkResult, PointerValidationError> {
        let raw_type = self.take_byte(cursor, "Extended type truncated")?;
        let extended_type = u16::from(raw_type) + 7;

        match extended_type {
            8 => {
                let size = self.decode_size(cursor, payload)?;
                self.bounded_scalar(*cursor, size, 4, pointer_depth, "Int32")
            }
            9 => {
                let size = self.decode_size(cursor, payload)?;
                self.bounded_scalar(*cursor, size, 8, pointer_depth, "Uint64")
            }
            10 => {
                let size = self.decode_size(cursor, payload)?;
                self.bounded_scalar(*cursor, size, 16, pointer_depth, "Uint128")
            }
            11 => self.walk_array(cursor, payload, total_depth, pointer_depth),
            14 => {
                if payload > 1 {
                    return Err(self.invalid_offset(offset, "Boolean size must be 0 or 1"));
                }
                Ok(self.scalar(*cursor, pointer_depth))
            }
            15 => {
                let size = self.decode_size(cursor, payload)?;
                self.fixed_scalar(*cursor, size, 4, pointer_depth, "Float")
            }
            128 => {
                let size = self.decode_size(cursor, payload)?;
                self.fixed_scalar(*cursor, size, 8, pointer_depth, "Timestamp")
            }
            id => match u8::try_from(id) {
                Ok(type_id) => Err(PointerValidationError::InvalidType { offset, type_id }),
                Err(_) => Err(self.invalid_offset(offset, "Extended type ID exceeds u8")),
            },
        }
    }

    fn walk_array(
        &mut self,
        cursor: &mut usize,
        payload: u8,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<WalkResult, PointerValidationError> {
        let count = self.decode_size(cursor, payload)?;
        let remaining = self.data.len().saturating_sub(*cursor);
        if count > remaining {
            return Err(self.invalid_offset(*cursor, "Array count exceeds remaining bytes"));
        }

        let mut max_total_depth = total_depth;
        let mut max_pointer_depth = pointer_depth;
        for _ in 0..count {
            let child = self.walk_value(*cursor, total_depth.saturating_add(1), pointer_depth)?;
            *cursor = child.end;
            max_total_depth = max_total_depth.max(child.max_total_depth);
            max_pointer_depth = max_pointer_depth.max(child.max_pointer_depth);
        }
        Ok(WalkResult {
            end: *cursor,
            kind: ValueKind::Other,
            max_total_depth,
            max_pointer_depth,
            expanded_work: 0,
        })
    }

    fn walk_map(
        &mut self,
        cursor: &mut usize,
        payload: u8,
        total_depth: usize,
        pointer_depth: usize,
    ) -> Result<WalkResult, PointerValidationError> {
        let count = self.decode_size(cursor, payload)?;
        let remaining = self.data.len().saturating_sub(*cursor);
        if count > remaining / 2 {
            return Err(self.invalid_offset(*cursor, "Map count exceeds remaining bytes"));
        }

        let mut max_total_depth = total_depth;
        let mut max_pointer_depth = pointer_depth;
        for _ in 0..count {
            let key_offset = *cursor;
            let key = self.walk_value(key_offset, total_depth.saturating_add(1), pointer_depth)?;
            if key.kind != ValueKind::String {
                return Err(self.invalid_offset(key_offset, "Map key does not resolve to a string"));
            }
            *cursor = key.end;

            let value = self.walk_value(*cursor, total_depth.saturating_add(1), pointer_depth)?;
            *cursor = value.end;
            max_total_depth = max_total_depth
                .max(key.max_total_depth)
                .max(value.max_total_depth);
            max_pointer_depth = max_pointer_depth
                .max(key.max_pointer_depth)
                .max(value.max_pointer_depth);
        }
        Ok(WalkResult {
            end: *cursor,
            kind: ValueKind::Other,
            max_total_depth,
            max_pointer_depth,
            expanded_work: 0,
        })
    }

    fn decode_size(
        &self,
        cursor: &mut usize,
        size_bits: u8,
    ) -> Result<usize, PointerValidationError> {
        match size_bits {
            0..=28 => Ok(usize::from(size_bits)),
            29 => Ok(29 + usize::from(self.take_byte(cursor, "Size byte out of bounds")?)),
            30 => {
                let bytes = self.take(cursor, 2, "Size bytes out of bounds")?;
                Ok(29 + 256 + usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            }
            31 => {
                let bytes = self.take(cursor, 3, "Size bytes out of bounds")?;
                Ok(29
                    + 256
                    + 65_536
                    + (usize::from(bytes[0]) << 16)
                    + (usize::from(bytes[1]) << 8)
                    + usize::from(bytes[2]))
            }
            _ => Err(self.invalid_offset(*cursor, "Invalid size encoding")),
        }
    }

    fn decode_pointer_offset(
        &self,
        cursor: &mut usize,
        payload: u8,
    ) -> Result<usize, PointerValidationError> {
        let high = usize::from(payload & 0x7);
        match (payload >> 3) & 0x3 {
            0 => {
                let bytes = self.take(cursor, 1, "Pointer data truncated")?;
                Ok((high << 8) | usize::from(bytes[0]))
            }
            1 => {
                let bytes = self.take(cursor, 2, "Pointer data truncated")?;
                Ok(2_048 + (high << 16) + (usize::from(bytes[0]) << 8) + usize::from(bytes[1]))
            }
            2 => {
                let bytes = self.take(cursor, 3, "Pointer data truncated")?;
                Ok(526_336
                    + (high << 24)
                    + (usize::from(bytes[0]) << 16)
                    + (usize::from(bytes[1]) << 8)
                    + usize::from(bytes[2]))
            }
            3 => {
                let bytes = self.take(cursor, 4, "Pointer data truncated")?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            }
            _ => Err(self.invalid_offset(*cursor, "Invalid pointer size bits")),
        }
    }

    fn bounded_scalar(
        &self,
        cursor: usize,
        size: usize,
        maximum: usize,
        pointer_depth: usize,
        name: &str,
    ) -> Result<WalkResult, PointerValidationError> {
        if size > maximum {
            return Err(self.invalid_offset(cursor, &format!("{name} size exceeds {maximum}")));
        }
        let end = self.payload_end(cursor, size, &format!("{name} data out of bounds"))?;
        Ok(self.scalar(end, pointer_depth))
    }

    fn fixed_scalar(
        &self,
        cursor: usize,
        size: usize,
        expected: usize,
        pointer_depth: usize,
        name: &str,
    ) -> Result<WalkResult, PointerValidationError> {
        if size != expected {
            return Err(self.invalid_offset(cursor, &format!("{name} size must be {expected}")));
        }
        let end = self.payload_end(cursor, size, &format!("{name} data out of bounds"))?;
        Ok(self.scalar(end, pointer_depth))
    }

    fn scalar(&self, end: usize, pointer_depth: usize) -> WalkResult {
        WalkResult {
            end,
            kind: ValueKind::Other,
            max_total_depth: 0,
            max_pointer_depth: pointer_depth,
            expanded_work: 0,
        }
    }

    fn payload_end(
        &self,
        cursor: usize,
        size: usize,
        reason: &str,
    ) -> Result<usize, PointerValidationError> {
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| self.invalid_offset(cursor, reason))?;
        if end > self.data.len() {
            return Err(self.invalid_offset(cursor, reason));
        }
        Ok(end)
    }

    fn take_byte(&self, cursor: &mut usize, reason: &str) -> Result<u8, PointerValidationError> {
        let bytes = self.take(cursor, 1, reason)?;
        Ok(bytes[0])
    }

    fn take(
        &self,
        cursor: &mut usize,
        size: usize,
        reason: &str,
    ) -> Result<&'data [u8], PointerValidationError> {
        let start = *cursor;
        let end = self.payload_end(start, size, reason)?;
        *cursor = end;
        Ok(&self.data[start..end])
    }

    fn invalid_offset(&self, offset: usize, reason: &str) -> PointerValidationError {
        PointerValidationError::InvalidOffset {
            offset,
            reason: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DataEncoder;
    use std::collections::{HashMap, HashSet};

    fn assert_capped_findings(errors: &[String], warnings: &[String]) {
        assert_eq!(errors.len(), MAX_VALIDATION_ERRORS);
        assert_eq!(warnings.len(), MAX_VALIDATION_WARNINGS);
        assert_eq!(
            errors
                .iter()
                .filter(|message| message.as_str() == ERRORS_SUPPRESSED)
                .count(),
            1
        );
        assert_eq!(
            warnings
                .iter()
                .filter(|message| message.as_str() == WARNINGS_SUPPRESSED)
                .count(),
            1
        );
    }

    #[test]
    fn validation_results_cap_retained_findings() {
        let mut data_result = DataFormatValidationResult::new();
        let mut pointer_result = PointerValidationResult::new();
        for i in 0..MAX_VALIDATION_ERRORS + 10 {
            data_result.error(format!("data error {i}"));
            pointer_result.error(format!("pointer error {i}"));
        }
        for i in 0..MAX_VALIDATION_WARNINGS + 10 {
            data_result.warning(format!("data warning {i}"));
            pointer_result.warning(format!("pointer warning {i}"));
        }

        assert_capped_findings(&data_result.errors, &data_result.warnings);
        assert_capped_findings(&pointer_result.errors, &pointer_result.warnings);
        assert!(!data_result.is_valid());
        assert!(!pointer_result.is_valid());
    }

    #[test]
    fn test_validate_simple_string() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::String("test".to_string());
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_validate_map_with_strings() {
        let mut encoder = DataEncoder::new();
        let mut map = HashMap::new();
        map.insert("key1".to_string(), DataValue::String("value1".to_string()));
        map.insert("key2".to_string(), DataValue::String("value2".to_string()));
        map.insert("num".to_string(), DataValue::Uint32(42));

        let value = DataValue::Map(map);
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        // 3 keys + 2 string values = 5 strings total
        // (Note: string interning may create pointers, but those are resolved during decode)
        assert_eq!(count, 5);
    }

    #[test]
    fn test_validate_nested_structure() {
        let mut encoder = DataEncoder::new();

        // Build nested structure with strings at various levels
        let mut inner_map = HashMap::new();
        inner_map.insert("inner".to_string(), DataValue::String("nested".to_string()));

        let mut outer_map = HashMap::new();
        outer_map.insert("outer".to_string(), DataValue::String("top".to_string()));
        outer_map.insert("nested".to_string(), DataValue::Map(inner_map));

        let value = DataValue::Map(outer_map);
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        // Outer: 2 keys + 1 string value = 3
        // Inner: 1 key + 1 string value = 2
        // Total = 5 strings
        assert_eq!(count, 5);
    }

    #[test]
    fn test_validate_array_with_strings() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::Array(vec![
            DataValue::String("a".to_string()),
            DataValue::String("b".to_string()),
            DataValue::Uint32(123),
        ]);

        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        assert_eq!(count, 2); // 2 strings in array
    }

    #[test]
    fn test_validate_data_section() {
        let mut encoder = DataEncoder::new();
        let value1 = DataValue::String("first".to_string());
        let value2 = DataValue::String("second".to_string());

        let offset1 = encoder.encode(&value1);
        let offset2 = encoder.encode(&value2);
        let data = encoder.into_bytes();

        let result = validate_data_section(&data, 0, &[offset1, offset2]);
        assert!(result.is_valid());
        assert_eq!(result.stats.values_checked, 2);
        assert_eq!(result.stats.strings_checked, 2);
    }

    #[test]
    fn test_validate_invalid_offset() {
        // Create some actual data so we're not dealing with empty section warning
        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::String("test".to_string()));
        let data = encoder.into_bytes();

        // Now try to validate an invalid offset
        let result = validate_data_section(&data, 0, &[999]);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_empty_data_section() {
        let data: Vec<u8> = Vec::new();
        let result = validate_data_section(&data, 0, &[]);
        // Empty is not an error, just a warning
        assert!(result.is_valid());
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn pointer_validator_rejects_self_cycle() {
        let data = [0x20, 0x00];
        let error = validate_data_value_pointers(&data, 0, &mut HashSet::new(), 0)
            .expect_err("self-pointer must be rejected");
        assert!(matches!(error, PointerValidationError::Cycle { offset: 0 }));
    }

    #[test]
    fn pointer_validator_rejects_two_value_cycle() {
        let data = [0x20, 0x02, 0x20, 0x00];
        let error = validate_data_value_pointers(&data, 0, &mut HashSet::new(), 0)
            .expect_err("pointer cycle must be rejected");
        assert!(matches!(error, PointerValidationError::Cycle { offset: 0 }));
    }

    #[test]
    fn pointer_validator_follows_pointer_map_keys() {
        // map(1), key pointer -> offset 4, empty uint16 value, string key "k"
        let data = [0xe1, 0x20, 0x04, 0xa0, 0x41, b'k'];
        let depth = validate_data_value_pointers(&data, 0, &mut HashSet::new(), 0)
            .expect("pointer-valued string key should validate");
        assert_eq!(depth, 1);

        let cyclic_key = [0xe1, 0x20, 0x00, 0xa0];
        let error = validate_data_value_pointers(&cyclic_key, 0, &mut HashSet::new(), 0)
            .expect_err("cycle in a pointer-valued key must be rejected");
        assert!(matches!(error, PointerValidationError::Cycle { offset: 0 }));
    }

    #[test]
    fn pointer_validator_understands_arrays_and_timestamp_extension() {
        // Standard MMDB extended array: control, extended type, elements.
        let array = [0x02, 0x04, 0x40, 0x40];
        validate_data_value_pointers(&array, 0, &mut HashSet::new(), 0)
            .expect("valid array should pass");

        let mut timestamp = vec![0x08, 121];
        timestamp.extend_from_slice(&42_i64.to_be_bytes());
        validate_data_value_pointers(&timestamp, 0, &mut HashSet::new(), 0)
            .expect("Matchy timestamp should pass");
    }

    #[test]
    fn pointer_validator_rejects_truncated_and_overflowing_values() {
        let cases: &[&[u8]] = &[
            &[0x42, b'a'],                   // truncated two-byte string
            &[0x1f, 0x04, 0xff, 0xff, 0xff], // maximum-count truncated array
            &[0x00, 249],                    // extended type does not fit in u8
            &[0x67; 8],                      // double declares seven bytes
        ];

        for data in cases {
            assert!(
                validate_data_value_pointers(data, 0, &mut HashSet::new(), 0).is_err(),
                "malformed value unexpectedly passed: {data:02x?}"
            );
        }
    }

    #[test]
    fn pointer_validator_enforces_structural_and_pointer_depth() {
        let mut nested_arrays = Vec::new();
        for _ in 0..=MAX_TOTAL_DEPTH {
            nested_arrays.extend_from_slice(&[0x01, 0x04]);
        }
        nested_arrays.push(0x40);
        assert!(matches!(
            validate_data_value_pointers(&nested_arrays, 0, &mut HashSet::new(), 0),
            Err(PointerValidationError::DepthExceeded { .. })
        ));

        let chain_len = MAX_POINTER_DEPTH + 2;
        let mut pointer_chain = Vec::with_capacity(chain_len * 2 + 1);
        for index in 0..chain_len {
            let target = (index + 1) * 2;
            pointer_chain.push(0x20 | u8::try_from((target >> 8) & 0x7).unwrap());
            pointer_chain.push(u8::try_from(target & 0xff).unwrap());
        }
        pointer_chain.push(0x40);
        assert!(matches!(
            validate_data_value_pointers(&pointer_chain, 0, &mut HashSet::new(), 0),
            Err(PointerValidationError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn pointer_validator_accepts_moderate_repeated_pointer_sharing() {
        fn push_array_header(buffer: &mut Vec<u8>, count: usize) {
            assert!(count < 285);
            buffer.extend_from_slice(&[29, 0x04, u8::try_from(count - 29).unwrap()]);
        }

        fn push_short_pointer(buffer: &mut Vec<u8>, offset: usize) {
            assert!(offset < 2_048);
            buffer.push(0x20 | u8::try_from((offset >> 8) & 0x7).unwrap());
            buffer.push(u8::try_from(offset & 0xff).unwrap());
        }

        let mut data = Vec::new();
        push_array_header(&mut data, 100);
        data.extend(std::iter::repeat_n(0x40, 100));

        let root_offset = data.len();
        push_array_header(&mut data, 100);
        for _ in 0..100 {
            push_short_pointer(&mut data, 0);
        }

        let max_pointer_depth =
            validate_data_value_pointers(&data, root_offset, &mut HashSet::new(), 0)
                .expect("moderate pointer sharing accepted by the decoder should validate");
        assert_eq!(max_pointer_depth, 1);
    }

    #[test]
    fn pointer_target_cache_rebases_depth_for_each_use_site() {
        const TARGET_NESTING: usize = 10;
        const OUTER_NESTING: usize = 53;

        let mut data = Vec::new();
        for _ in 0..TARGET_NESTING {
            data.extend_from_slice(&[0x01, 0x04]);
        }
        data.push(0x40);

        let root_offset = data.len();
        data.extend_from_slice(&[0x02, 0x04]);
        data.extend_from_slice(&[0x20, 0x00]);
        for _ in 0..OUTER_NESTING {
            data.extend_from_slice(&[0x01, 0x04]);
        }
        data.extend_from_slice(&[0x20, 0x00]);

        // The first pointer validates and caches target zero at a shallow
        // depth. The second reaches the same target deeply enough that its
        // cached nested span crosses MAX_TOTAL_DEPTH and must still fail.
        assert!(matches!(
            validate_data_value_pointers(&data, root_offset, &mut HashSet::new(), 0),
            Err(PointerValidationError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn pointer_target_cache_rebases_pointer_depth_for_each_use_site() {
        const TARGET_POINTERS: usize = 4;
        const OUTER_POINTERS: usize = 28;

        fn push_short_pointer(buffer: &mut Vec<u8>, offset: usize) {
            assert!(offset < 2_048);
            buffer.push(0x20 | u8::try_from((offset >> 8) & 0x7).unwrap());
            buffer.push(u8::try_from(offset & 0xff).unwrap());
        }

        let mut data = Vec::new();
        for index in 0..TARGET_POINTERS {
            push_short_pointer(&mut data, (index + 1) * 2);
        }
        data.push(0x40);

        let root_offset = data.len();
        data.extend_from_slice(&[0x02, 0x04]);
        push_short_pointer(&mut data, 0);
        let outer_start = data.len() + 2;
        push_short_pointer(&mut data, outer_start);

        for index in 0..OUTER_POINTERS {
            let target = if index + 1 == OUTER_POINTERS {
                0
            } else {
                outer_start + (index + 1) * 2
            };
            push_short_pointer(&mut data, target);
        }

        // The shallow use caches target zero with its four-pointer span. The
        // outer chain reaches that target at depth 29, so reusing the cached
        // span would cross MAX_POINTER_DEPTH even though the entry depth does
        // not.
        assert!(matches!(
            validate_data_value_pointers(&data, root_offset, &mut HashSet::new(), 0),
            Err(PointerValidationError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn pointer_validator_limits_repeated_pointer_expansion() {
        const LEVELS: usize = 20;
        let mut data = Vec::with_capacity(LEVELS * 6 + 1);
        for level in 0..LEVELS {
            let target = (level + 1) * 6;
            let pointer = [
                0x20 | u8::try_from((target >> 8) & 0x7).unwrap(),
                u8::try_from(target & 0xff).unwrap(),
            ];
            data.extend_from_slice(&[0x02, 0x04]);
            data.extend_from_slice(&pointer);
            data.extend_from_slice(&pointer);
        }
        data.push(0x40);

        let error = validate_data_value_pointers(&data, 0, &mut HashSet::new(), 0)
            .expect_err("pointer expansion must have a finite work budget");
        let PointerValidationError::InvalidOffset { reason, .. } = error else {
            panic!("expected work-limit error, got {error:?}");
        };
        assert_eq!(reason, "Validation work limit exceeded");
    }
}
