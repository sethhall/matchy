//! C API for paraglob
//!
//! This module provides a stable C ABI for use from C and C++ programs.

use crate::mmap::{MmapFile, MmapError};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

/// Opaque database handle for C API
///
/// This wraps a `Box<MmapFile>` but is opaque to C clients.
#[repr(C)]
pub struct paraglob_db {
    _private: [u8; 0],
}

// Internal conversion helpers
impl paraglob_db {
    /// Convert a Box<MmapFile> to an opaque pointer
    fn from_mmap(mmap: Box<MmapFile>) -> *mut Self {
        Box::into_raw(mmap) as *mut Self
    }

    /// Convert opaque pointer back to Box<MmapFile>
    /// # Safety
    /// Pointer must have come from from_mmap
    unsafe fn into_mmap(ptr: *mut Self) -> Box<MmapFile> {
        Box::from_raw(ptr as *mut MmapFile)
    }

    /// Borrow the MmapFile without taking ownership
    /// # Safety
    /// Pointer must be valid and from from_mmap
    unsafe fn as_mmap<'a>(ptr: *const Self) -> &'a MmapFile {
        &*(ptr as *const MmapFile)
    }
}

/// Error codes for C API
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum paraglob_error_t {
    /// Operation succeeded
    PARAGLOB_SUCCESS = 0,
    /// File not found
    PARAGLOB_ERROR_FILE_NOT_FOUND = -1,
    /// Invalid file format
    PARAGLOB_ERROR_INVALID_FORMAT = -2,
    /// Corrupt data
    PARAGLOB_ERROR_CORRUPT_DATA = -3,
    /// Out of memory
    PARAGLOB_ERROR_OUT_OF_MEMORY = -4,
    /// Invalid parameter
    PARAGLOB_ERROR_INVALID_PARAM = -5,
    /// File too small
    PARAGLOB_ERROR_FILE_TOO_SMALL = -6,
    /// I/O error
    PARAGLOB_ERROR_IO = -7,
}

// Convert Rust errors to C error codes
impl From<MmapError> for paraglob_error_t {
    fn from(err: MmapError) -> Self {
        match err {
            MmapError::Io(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    paraglob_error_t::PARAGLOB_ERROR_FILE_NOT_FOUND
                } else {
                    paraglob_error_t::PARAGLOB_ERROR_IO
                }
            }
            MmapError::FileTooSmall { .. } => paraglob_error_t::PARAGLOB_ERROR_FILE_TOO_SMALL,
            MmapError::InvalidAcHeader(_) => paraglob_error_t::PARAGLOB_ERROR_INVALID_FORMAT,
            MmapError::InvalidParaglobHeader(_) => paraglob_error_t::PARAGLOB_ERROR_INVALID_FORMAT,
        }
    }
}

/// Open database from file using memory mapping
///
/// Opens and validates a paraglob file, returning a handle that can be used
/// for queries. The file is memory-mapped for efficient zero-copy access.
///
/// # Parameters
/// * `filename` - Path to the paraglob file (null-terminated C string)
/// * `error_out` - Optional pointer to store error code on failure
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure (check error_out for details)
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
/// * `error_out` must be NULL or a valid pointer
///
/// # Example
/// ```c
/// paraglob_error_t error;
/// paraglob_db* db = paraglob_open_mmap("/path/to/file.paraglob", &error);
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open: error %d\n", error);
///     return 1;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_open_mmap(
    filename: *const c_char,
    error_out: *mut paraglob_error_t,
) -> *mut paraglob_db {
    // Initialize error to success
    if !error_out.is_null() {
        *error_out = paraglob_error_t::PARAGLOB_SUCCESS;
    }

    // Validate input
    if filename.is_null() {
        if !error_out.is_null() {
            *error_out = paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM;
        }
        return std::ptr::null_mut();
    }

    // Convert C string to Rust
    let path_cstr = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => {
            if !error_out.is_null() {
                *error_out = paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM;
            }
            return std::ptr::null_mut();
        }
    };

    // Open the memory-mapped file
    match MmapFile::open(Path::new(path_cstr)) {
        Ok(mmap) => {
            // Success - return opaque pointer
            paraglob_db::from_mmap(Box::new(mmap))
        }
        Err(e) => {
            // Failure - set error and return NULL
            if !error_out.is_null() {
                *error_out = paraglob_error_t::from(e);
            }
            std::ptr::null_mut()
        }
    }
}

/// Close database and free all resources
///
/// Closes the memory-mapped file and frees all associated resources.
/// After this call, the handle is invalid and must not be used.
///
/// # Safety
/// * `db` must be a valid handle returned from `paraglob_open_mmap`
/// * `db` must not be used after this call
/// * Calling with NULL is safe (no-op)
///
/// # Example
/// ```c
/// paraglob_close(db);
/// db = NULL;  // Good practice
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_close(db: *mut paraglob_db) {
    if !db.is_null() {
        // Convert back to Box and let it drop
        let _mmap = paraglob_db::into_mmap(db);
        // _mmap is dropped here, closing the file
    }
}

/// Get the size of the memory-mapped file in bytes
///
/// # Safety
/// * `db` must be a valid handle from `paraglob_open_mmap`
///
/// # Returns
/// Size in bytes, or 0 if db is NULL
#[no_mangle]
pub unsafe extern "C" fn paraglob_get_size(db: *const paraglob_db) -> usize {
    if db.is_null() {
        return 0;
    }
    paraglob_db::as_mmap(db).size()
}

/// Check if the database is a full Paraglob file (vs AC-only)
///
/// # Safety
/// * `db` must be a valid handle from `paraglob_open_mmap`
///
/// # Returns
/// * 1 if this is a full Paraglob file
/// * 0 if this is an AC-only file or db is NULL
#[no_mangle]
pub unsafe extern "C" fn paraglob_is_paraglob(db: *const paraglob_db) -> i32 {
    if db.is_null() {
        return 0;
    }
    if paraglob_db::as_mmap(db).is_paraglob() {
        1
    } else {
        0
    }
}
