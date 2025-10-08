//! Memory-mapped file support for paraglob files.
//!
//! This module provides safe, validated access to memory-mapped paraglob files.
//! It handles file opening, header validation, and provides safe accessors to
//! the underlying data structures.
//!
//! # Safety
//!
//! While memory-mapped files are inherently unsafe (file contents can change),
//! this module provides a safe API by:
//! - Validating all headers on open
//! - Checking file size constraints
//! - Using safe Rust types for all public APIs
//! - Providing bounds-checked accessors
//!
//! # Example
//!
//! ```no_run
//! use paraglob_rs::mmap::MmapFile;
//!
//! let mmap = MmapFile::open("database.paraglob")?;
//! let header = mmap.ac_header();
//! println!("Magic: {:?}", &header.magic);
//! println!("Size: {} bytes", mmap.size());
//! # Ok::<(), paraglob_rs::mmap::MmapError>(())
//! ```

use crate::binary::{OffsetAcHeader, OffsetParaglobHeader, validate_ac_header, validate_paraglob_header};
use memmap2::Mmap;
use std::fs::File;
use std::io;
use std::path::Path;
use std::fmt;

/// Errors that can occur when working with memory-mapped files.
#[derive(Debug)]
pub enum MmapError {
    /// Failed to open the file
    Io(io::Error),
    /// File is too small to contain a valid header
    FileTooSmall {
        /// Actual file size in bytes
        size: usize,
        /// Minimum required size in bytes
        required: usize,
    },
    /// Invalid AC header
    InvalidAcHeader(String),
    /// Invalid Paraglob header
    InvalidParaglobHeader(String),
}

impl fmt::Display for MmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmapError::Io(e) => write!(f, "I/O error: {}", e),
            MmapError::FileTooSmall { size, required } => {
                write!(f, "File too small: {} bytes (need at least {})", size, required)
            }
            MmapError::InvalidAcHeader(msg) => write!(f, "Invalid AC header: {}", msg),
            MmapError::InvalidParaglobHeader(msg) => write!(f, "Invalid Paraglob header: {}", msg),
        }
    }
}

impl std::error::Error for MmapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MmapError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MmapError {
    fn from(err: io::Error) -> Self {
        MmapError::Io(err)
    }
}

/// A memory-mapped paraglob file with validated headers.
///
/// This type provides safe, validated access to a memory-mapped paraglob file.
/// The file is automatically unmapped when the `MmapFile` is dropped.
///
/// # Thread Safety
///
/// `MmapFile` is `Send` but not `Sync`. Multiple threads can own separate
/// `MmapFile` instances, but a single instance should not be shared across
/// threads without synchronization.
pub struct MmapFile {
    /// The memory-mapped file
    mmap: Mmap,
    /// Size of the mapped region
    size: usize,
}

impl MmapFile {
    /// Open and memory-map a paraglob file.
    ///
    /// This function:
    /// 1. Opens the file
    /// 2. Memory-maps it
    /// 3. Validates the AC/Paraglob header
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened
    /// - The file is too small
    /// - The AC/Paraglob header is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use paraglob_rs::mmap::MmapFile;
    ///
    /// let mmap = MmapFile::open("database.paraglob")?;
    /// # Ok::<(), paraglob_rs::mmap::MmapError>(())
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MmapError> {
        let file = File::open(path.as_ref())?;
        let mmap = unsafe { Mmap::map(&file)? };
        let size = mmap.len();

        // Check minimum size for AC header
        let min_size = std::mem::size_of::<OffsetAcHeader>();
        if size < min_size {
            return Err(MmapError::FileTooSmall {
                size,
                required: min_size,
            });
        }

        // Try to validate as Paraglob first (which includes AC), then fall back to AC-only
        let buffer = &mmap[..];
        let _is_paraglob = if size >= std::mem::size_of::<OffsetParaglobHeader>() {
            // Try to validate as full Paraglob format
            match validate_paraglob_header(buffer) {
                Ok(_) => true,
                Err(_) => {
                    // Not Paraglob, try AC
                    validate_ac_header(buffer)
                        .map_err(|e| MmapError::InvalidAcHeader(e.to_string()))?;
                    false
                }
            }
        } else {
            // Too small for Paraglob, must be AC-only
            validate_ac_header(buffer)
                .map_err(|e| MmapError::InvalidAcHeader(e.to_string()))?;
            false
        };

        Ok(MmapFile { mmap, size })
    }

    /// Get a reference to the AC header.
    ///
    /// This returns the base `OffsetAcHeader` which is present in both AC-only
    /// and full Paraglob files.
    ///
    /// # Safety
    ///
    /// This is safe because we validated the header in `open()`.
    pub fn ac_header(&self) -> &OffsetAcHeader {
        unsafe {
            // SAFETY: We validated this in open() and the size cannot change
            &*(self.mmap.as_ptr() as *const OffsetAcHeader)
        }
    }

    /// Get a reference to the Paraglob header, if this is a Paraglob file.
    ///
    /// Returns `None` if this is an AC-only file.
    pub fn paraglob_header(&self) -> Option<&OffsetParaglobHeader> {
        if self.size < std::mem::size_of::<OffsetParaglobHeader>() {
            return None;
        }
        // Check if this is a Paraglob file by looking at magic bytes
        let header = self.ac_header();
        if header.magic == crate::binary::MAGIC_PARAGLOB {
            unsafe {
                // SAFETY: We validated this in open()
                Some(&*(self.mmap.as_ptr() as *const OffsetParaglobHeader))
            }
        } else {
            None
        }
    }

    /// Get the size of the memory-mapped file in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice of the entire mapped memory.
    ///
    /// # Safety
    ///
    /// While this function is safe to call, the contents of a memory-mapped file
    /// can theoretically change if another process modifies the file. However,
    /// this is unlikely in practice and the returned slice is still memory-safe.
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap[..]
    }

    /// Check if this file is a full Paraglob file (vs AC-only).
    pub fn is_paraglob(&self) -> bool {
        self.paraglob_header().is_some()
    }

    /// Get a slice at a specific offset with bounds checking.
    ///
    /// Returns `None` if the offset + length would exceed the file size.
    pub fn get_slice(&self, offset: usize, length: usize) -> Option<&[u8]> {
        if offset.checked_add(length)? > self.size {
            return None;
        }
        Some(&self.mmap[offset..offset + length])
    }
}

impl fmt::Debug for MmapFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapFile")
            .field("size", &self.size)
            .field("is_paraglob", &self.is_paraglob())
            .field("header", &self.ac_header())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file(data: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_empty_file() {
        let file = create_test_file(&[]);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::FileTooSmall { .. })));
    }

    #[test]
    fn test_file_too_small() {
        let file = create_test_file(&[0; 10]);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::FileTooSmall { .. })));
    }

    #[test]
    fn test_invalid_magic() {
        use std::mem::size_of;
        let header_size = size_of::<OffsetAcHeader>();
        let mut data = vec![0u8; header_size];
        // Wrong magic bytes
        data[0..4].copy_from_slice(b"XXXX");
        // But set a valid total_buffer_size so it doesn't fail for that reason
        data[24..28].copy_from_slice(&(header_size as u32).to_ne_bytes());
        let file = create_test_file(&data);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::InvalidAcHeader(_))));
    }

    #[test]
    fn test_valid_ac_header() {
        use std::mem::size_of;
        let header_size = size_of::<OffsetAcHeader>();
        let mut data = vec![0u8; header_size];
        
        // Valid MMAC magic ("MMAC")
        data[0..4].copy_from_slice(b"MMAC");
        // Version 1
        data[4..8].copy_from_slice(&1u32.to_ne_bytes());
        // node_count = 0
        data[8..12].copy_from_slice(&0u32.to_ne_bytes());
        // root_node_offset = 0
        data[12..16].copy_from_slice(&0u32.to_ne_bytes());
        // meta_word_count = 0
        data[16..20].copy_from_slice(&0u32.to_ne_bytes());
        // meta_word_table_offset = 0
        data[20..24].copy_from_slice(&0u32.to_ne_bytes());
        // total_buffer_size = header_size
        data[24..28].copy_from_slice(&(header_size as u32).to_ne_bytes());
        // reserved = 0
        data[28..32].copy_from_slice(&0u32.to_ne_bytes());
        
        let file = create_test_file(&data);
        let mmap = MmapFile::open(file.path()).expect("Failed to open valid AC file");
        assert_eq!(mmap.size(), data.len());
        assert!(!mmap.is_paraglob());
        assert_eq!(mmap.ac_header().magic, *b"MMAC");
    }

    #[test]
    fn test_get_slice() {
        use std::mem::size_of;
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let header_size = size_of::<OffsetAcHeader>();
        let total_size = header_size + payload.len();
        let mut data = vec![0u8; header_size];
        
        // Valid MMAC header
        data[0..4].copy_from_slice(b"MMAC");
        data[4..8].copy_from_slice(&1u32.to_ne_bytes());
        data[8..12].copy_from_slice(&0u32.to_ne_bytes());
        data[12..16].copy_from_slice(&0u32.to_ne_bytes());
        data[16..20].copy_from_slice(&0u32.to_ne_bytes());
        data[20..24].copy_from_slice(&0u32.to_ne_bytes());
        data[24..28].copy_from_slice(&(total_size as u32).to_ne_bytes());
        data[28..32].copy_from_slice(&0u32.to_ne_bytes());
        data.extend_from_slice(&payload);
        
        let file = create_test_file(&data);
        let mmap = MmapFile::open(file.path()).unwrap();
        
        // Valid slice
        let offset = header_size;
        let slice = mmap.get_slice(offset, 4).unwrap();
        assert_eq!(slice, &[1, 2, 3, 4]);
        
        // Out of bounds
        assert!(mmap.get_slice(mmap.size(), 1).is_none());
        assert!(mmap.get_slice(0, mmap.size() + 1).is_none());
    }

    #[test]
    fn test_nonexistent_file() {
        let result = MmapFile::open("/nonexistent/path/to/file.paraglob");
        assert!(matches!(result, Err(MmapError::Io(_))));
    }
}
