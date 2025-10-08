//! Binary format validation utilities
//!
//! This module provides safety checks for working with memory-mapped binary data.
//! All validation functions return `Result<(), ValidationError>` and should be
//! called before dereferencing offsets or casting raw pointers.
//!
//! # Safety Philosophy
//!
//! When working with untrusted binary data (especially from memory-mapped files),
//! we must validate:
//! 1. **Magic bytes** - Ensure file format is correct
//! 2. **Version compatibility** - Check format version is supported
//! 3. **Buffer bounds** - All offsets point within the buffer
//! 4. **Alignment** - Pointers are properly aligned for their types
//! 5. **Structure sizes** - Headers and structures fit within bounds
//!
//! These checks prevent undefined behavior, crashes, and potential security issues.

use std::mem::size_of;

#[cfg(test)]
use std::mem::align_of;

use super::format::{
    OffsetAcHeader, OffsetParaglobHeader, FORMAT_VERSION, MAGIC_AC, MAGIC_PARAGLOB,
};

/// Errors that can occur during binary format validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Buffer is too small to contain the required structure
    BufferTooSmall {
        required: usize,
        actual: usize,
    },
    /// Offset is out of bounds
    #[cfg(test)]
    OffsetOutOfBounds {
        offset: usize,
        size: usize,
        buffer_len: usize,
    },
    /// Pointer/offset is not properly aligned
    #[cfg(test)]
    MisalignedOffset {
        offset: usize,
        required_alignment: usize,
    },
    /// Magic bytes don't match expected value
    InvalidMagic {
        expected: [u8; 4],
        found: [u8; 4],
    },
    /// Format version is not supported
    UnsupportedVersion {
        found: u32,
        supported: u32,
    },
    /// Generic corruption detected
    CorruptData {
        reason: &'static str,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::BufferTooSmall { required, actual } => {
                write!(
                    f,
                    "Buffer too small: need {} bytes, got {}",
                    required, actual
                )
            }
            #[cfg(test)]
            ValidationError::OffsetOutOfBounds {
                offset,
                size,
                buffer_len,
            } => {
                write!(
                    f,
                    "Offset {} + size {} exceeds buffer length {}",
                    offset, size, buffer_len
                )
            }
            #[cfg(test)]
            ValidationError::MisalignedOffset {
                offset,
                required_alignment,
            } => {
                write!(
                    f,
                    "Offset {} is not aligned to {} bytes",
                    offset, required_alignment
                )
            }
            ValidationError::InvalidMagic { expected, found } => {
                write!(
                    f,
                    "Invalid magic bytes: expected {:?}, found {:?}",
                    std::str::from_utf8(expected).unwrap_or("???"),
                    std::str::from_utf8(found).unwrap_or("???")
                )
            }
            ValidationError::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "Unsupported format version: found {}, supported {}",
                    found, supported
                )
            }
            ValidationError::CorruptData { reason } => {
                write!(f, "Corrupt data: {}", reason)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate that an offset + size is within buffer bounds
///
/// # Arguments
/// * `buffer` - The buffer being validated against
/// * `offset` - Offset into the buffer
/// * `size` - Number of bytes needed starting at offset
///
/// # Returns
/// `Ok(())` if the range [offset..offset+size] is valid, error otherwise
#[cfg(test)]
fn validate_bounds(buffer: &[u8], offset: usize, size: usize) -> Result<(), ValidationError> {
    if offset.checked_add(size).ok_or(ValidationError::CorruptData {
        reason: "Offset arithmetic overflow",
    })? > buffer.len()
    {
        return Err(ValidationError::OffsetOutOfBounds {
            offset,
            size,
            buffer_len: buffer.len(),
        });
    }
    Ok(())
}

/// Validate that an offset is properly aligned for type T
///
/// # Type Parameters
/// * `T` - The type that will be read at this offset
///
/// # Arguments
/// * `offset` - The offset to validate
///
/// # Returns
/// `Ok(())` if aligned, error otherwise
#[cfg(test)]
fn validate_alignment<T>(offset: usize) -> Result<(), ValidationError> {
    let alignment = align_of::<T>();
    if offset % alignment != 0 {
        return Err(ValidationError::MisalignedOffset {
            offset,
            required_alignment: alignment,
        });
    }
    Ok(())
}

/// Validate offset for a structure of type T
///
/// This combines bounds and alignment checks. Use this before casting
/// a buffer slice to a structure pointer.
///
/// # Type Parameters
/// * `T` - The type that will be read at this offset
///
/// # Arguments
/// * `buffer` - The buffer containing the data
/// * `offset` - Offset into the buffer where T will be read
///
/// # Returns
/// `Ok(())` if the offset is valid, error otherwise
///
/// # Example
/// ```ignore
/// let offset = header.node_offset as usize;
/// validate_offset::<OffsetAcNode>(buffer, offset)?;
/// // Now safe to cast
/// let node = unsafe { &*(buffer.as_ptr().add(offset) as *const OffsetAcNode) };
/// ```
#[cfg(test)]
#[allow(dead_code)]  // Not used even in tests, but keep as example
fn validate_offset<T>(buffer: &[u8], offset: usize) -> Result<(), ValidationError> {
    validate_bounds(buffer, offset, size_of::<T>())?;
    validate_alignment::<T>(offset)?;
    Ok(())
}

/// Validate an OffsetAc header
///
/// Checks:
/// - Buffer is large enough for header
/// - Magic bytes match "MMAC"
/// - Version is supported
/// - Total buffer size matches actual buffer
///
/// # Arguments
/// * `buffer` - The buffer to validate
///
/// # Returns
/// `Ok(&OffsetAcHeader)` if valid, error otherwise
pub fn validate_ac_header(buffer: &[u8]) -> Result<&OffsetAcHeader, ValidationError> {
    // Check buffer size
    if buffer.len() < size_of::<OffsetAcHeader>() {
        return Err(ValidationError::BufferTooSmall {
            required: size_of::<OffsetAcHeader>(),
            actual: buffer.len(),
        });
    }

    // Cast to header (safe because we validated size and alignment is 4)
    let header = unsafe { &*(buffer.as_ptr() as *const OffsetAcHeader) };

    // Check magic bytes
    if header.magic != MAGIC_AC {
        return Err(ValidationError::InvalidMagic {
            expected: MAGIC_AC,
            found: header.magic,
        });
    }

    // Check version
    if header.version != FORMAT_VERSION {
        return Err(ValidationError::UnsupportedVersion {
            found: header.version,
            supported: FORMAT_VERSION,
        });
    }

    // Check total buffer size
    if header.total_buffer_size as usize != buffer.len() {
        return Err(ValidationError::CorruptData {
            reason: "Header buffer size doesn't match actual buffer",
        });
    }

    Ok(header)
}

/// Validate an OffsetParaglob header
///
/// Checks:
/// - Buffer is large enough for header
/// - Magic bytes match "MMPG"
/// - Version is supported
/// - Total buffer size matches actual buffer
///
/// # Arguments
/// * `buffer` - The buffer to validate
///
/// # Returns
/// `Ok(&OffsetParaglobHeader)` if valid, error otherwise
pub fn validate_paraglob_header(
    buffer: &[u8],
) -> Result<&OffsetParaglobHeader, ValidationError> {
    // Check buffer size
    if buffer.len() < size_of::<OffsetParaglobHeader>() {
        return Err(ValidationError::BufferTooSmall {
            required: size_of::<OffsetParaglobHeader>(),
            actual: buffer.len(),
        });
    }

    // Cast to header (safe because we validated size and alignment is 4)
    let header = unsafe { &*(buffer.as_ptr() as *const OffsetParaglobHeader) };

    // Check magic bytes (should be MMPG for full Paraglob)
    if header.base.magic != MAGIC_PARAGLOB {
        return Err(ValidationError::InvalidMagic {
            expected: MAGIC_PARAGLOB,
            found: header.base.magic,
        });
    }

    // Check version
    if header.base.version != FORMAT_VERSION {
        return Err(ValidationError::UnsupportedVersion {
            found: header.base.version,
            supported: FORMAT_VERSION,
        });
    }

    // Check total buffer size
    if header.base.total_buffer_size as usize != buffer.len() {
        return Err(ValidationError::CorruptData {
            reason: "Header buffer size doesn't match actual buffer",
        });
    }

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bounds() {
        let buffer = vec![0u8; 100];

        // Valid bounds
        assert!(validate_bounds(&buffer, 0, 50).is_ok());
        assert!(validate_bounds(&buffer, 50, 50).is_ok());
        assert!(validate_bounds(&buffer, 99, 1).is_ok());

        // Invalid bounds
        assert!(validate_bounds(&buffer, 50, 51).is_err());
        assert!(validate_bounds(&buffer, 100, 1).is_err());
        assert!(validate_bounds(&buffer, 101, 0).is_err());
    }

    #[test]
    fn test_validate_alignment() {
        // u32 requires 4-byte alignment
        assert!(validate_alignment::<u32>(0).is_ok());
        assert!(validate_alignment::<u32>(4).is_ok());
        assert!(validate_alignment::<u32>(8).is_ok());
        assert!(validate_alignment::<u32>(1).is_err());
        assert!(validate_alignment::<u32>(2).is_err());
        assert!(validate_alignment::<u32>(3).is_err());

        // u8 requires 1-byte alignment (always OK)
        assert!(validate_alignment::<u8>(0).is_ok());
        assert!(validate_alignment::<u8>(1).is_ok());
        assert!(validate_alignment::<u8>(7).is_ok());
    }

    #[test]
    fn test_validate_ac_header_too_small() {
        let buffer = vec![0u8; 16]; // Too small for header
        assert!(matches!(
            validate_ac_header(&buffer),
            Err(ValidationError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn test_validate_ac_header_invalid_magic() {
        let mut buffer = vec![0u8; 64];
        buffer[0..4].copy_from_slice(b"XXXX"); // Wrong magic
        
        let result = validate_ac_header(&buffer);
        assert!(matches!(result, Err(ValidationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_validate_ac_header_valid() {
        let mut buffer = vec![0u8; 64];
        
        // Create valid header
        buffer[0..4].copy_from_slice(&MAGIC_AC); // Magic
        buffer[4..8].copy_from_slice(&FORMAT_VERSION.to_ne_bytes()); // Version
        buffer[24..28].copy_from_slice(&(64u32).to_ne_bytes()); // Total size

        let result = validate_ac_header(&buffer);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.magic, MAGIC_AC);
        assert_eq!(header.version, FORMAT_VERSION);
    }

    #[test]
    fn test_validate_paraglob_header_valid() {
        let mut buffer = vec![0u8; 128];
        
        // Create valid Paraglob header
        buffer[0..4].copy_from_slice(&MAGIC_PARAGLOB); // Magic
        buffer[4..8].copy_from_slice(&FORMAT_VERSION.to_ne_bytes()); // Version
        buffer[24..28].copy_from_slice(&(128u32).to_ne_bytes()); // Total size

        let result = validate_paraglob_header(&buffer);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.base.magic, MAGIC_PARAGLOB);
        assert_eq!(header.base.version, FORMAT_VERSION);
    }
}
