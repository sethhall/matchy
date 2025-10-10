//! Clean Matchy C API
//!
//! This module provides a modern, clean C API for building and querying databases
//! containing IP addresses and patterns. This is the primary public API.

use crate::data_section::DataValue;
use crate::database::{Database as RustDatabase, QueryResult};
use crate::glob::MatchMode;
use crate::mmdb_builder::MmdbBuilder;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// ============================================================================
// ERROR CODES
// ============================================================================

/// Success code
pub const MATCHY_SUCCESS: i32 = 0;
/// File not found error
pub const MATCHY_ERROR_FILE_NOT_FOUND: i32 = -1;
/// Invalid format error
pub const MATCHY_ERROR_INVALID_FORMAT: i32 = -2;
/// Corrupt data error
pub const MATCHY_ERROR_CORRUPT_DATA: i32 = -3;
/// Out of memory error
pub const MATCHY_ERROR_OUT_OF_MEMORY: i32 = -4;
/// Invalid parameter error
pub const MATCHY_ERROR_INVALID_PARAM: i32 = -5;
/// I/O error
pub const MATCHY_ERROR_IO: i32 = -6;

// ============================================================================
// OPAQUE HANDLES
// ============================================================================

/// Opaque database builder handle
#[repr(C)]
pub struct matchy_builder_t {
    _private: [u8; 0],
}

/// Opaque database handle
#[repr(C)]
pub struct matchy_t {
    _private: [u8; 0],
}

/// Query result
#[repr(C)]
pub struct matchy_result_t {
    /// Whether a match was found
    pub found: bool,
    /// JSON string of the result data (null-terminated, caller must free with matchy_free_string)
    pub data_json: *mut c_char,
    /// Network prefix length (for IP results)
    pub prefix_len: u8,
}

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct MatchyBuilderInternal {
    builder: MmdbBuilder,
}

struct MatchyInternal {
    database: RustDatabase,
}

// Conversion helpers for opaque types
impl matchy_builder_t {
    fn from_internal(internal: Box<MatchyBuilderInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyBuilderInternal> {
        Box::from_raw(ptr as *mut MatchyBuilderInternal)
    }

    unsafe fn as_internal_mut(ptr: *mut Self) -> &'static mut MatchyBuilderInternal {
        &mut *(ptr as *mut MatchyBuilderInternal)
    }
}

impl matchy_t {
    fn from_internal(internal: Box<MatchyInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyInternal> {
        Box::from_raw(ptr as *mut MatchyInternal)
    }

    unsafe fn as_internal(ptr: *const Self) -> &'static MatchyInternal {
        &*(ptr as *const MatchyInternal)
    }
}

// ============================================================================
// DATABASE BUILDING API
// ============================================================================

/// Create a new database builder
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on allocation failure
///
/// # Example
/// ```c
/// matchy_builder_t *builder = matchy_builder_new();
/// if (builder == NULL) {
///     fprintf(stderr, "Failed to create builder\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub extern "C" fn matchy_builder_new() -> *mut matchy_builder_t {
    let builder = MmdbBuilder::new(MatchMode::CaseSensitive);
    let internal = Box::new(MatchyBuilderInternal { builder });
    matchy_builder_t::from_internal(internal)
}

/// Add an entry with associated data (as JSON)
///
/// Automatically detects whether the key is an IP address, CIDR range, or pattern.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `key` - IP address, CIDR, or pattern (null-terminated C string, must not be NULL)
/// * `json_data` - Associated data as JSON (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `key` must be a valid null-terminated C string
/// * `json_data` must be a valid null-terminated C string containing valid JSON
///
/// # Example
/// ```c
/// matchy_builder_add(builder, "1.2.3.4", "{\"threat_level\": \"high\"}");
/// matchy_builder_add(builder, "10.0.0.0/8", "{\"type\": \"internal\"}");
/// matchy_builder_add(builder, "*.evil.com", "{\"category\": \"malware\"}");
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_add(
    builder: *mut matchy_builder_t,
    key: *const c_char,
    json_data: *const c_char,
) -> i32 {
    if builder.is_null() || key.is_null() || json_data.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let json_str = match CStr::from_ptr(json_data).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    // Parse JSON to HashMap<String, DataValue>
    let data: HashMap<String, DataValue> = match serde_json::from_str(json_str) {
        Ok(d) => d,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    match internal.builder.add_entry(key_str, data) {
        Ok(_) => MATCHY_SUCCESS,
        Err(_) => MATCHY_ERROR_INVALID_FORMAT,
    }
}

/// Set database description
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `description` - Description text (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `description` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_set_description(
    builder: *mut matchy_builder_t,
    description: *const c_char,
) -> i32 {
    if builder.is_null() || description.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let desc_str = match CStr::from_ptr(description).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    // Create new builder with description
    let old_builder = std::mem::replace(
        &mut internal.builder,
        MmdbBuilder::new(MatchMode::CaseSensitive),
    );
    internal.builder = old_builder.with_description("en", desc_str);

    MATCHY_SUCCESS
}

/// Build and save database to file
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `filename` - Path where file should be written (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `filename` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// if (matchy_builder_save(builder, "threats.db") != MATCHY_SUCCESS) {
///     fprintf(stderr, "Failed to save database\n");
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_save(
    builder: *mut matchy_builder_t,
    filename: *const c_char,
) -> i32 {
    if builder.is_null() || filename.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let path = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    let bytes = match internal.builder.build() {
        Ok(b) => b,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    match std::fs::write(path, bytes) {
        Ok(_) => MATCHY_SUCCESS,
        Err(_) => MATCHY_ERROR_IO,
    }
}

/// Build and return database in memory
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `buffer` - Pointer to receive the buffer pointer (must not be NULL)
/// * `size` - Pointer to receive the buffer size (must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `buffer` and `size` must be valid pointers
/// * Caller must free the returned buffer with libc::free()
///
/// # Example
/// ```c
/// uint8_t *buffer = NULL;
/// size_t size = 0;
/// if (matchy_builder_build(builder, &buffer, &size) == MATCHY_SUCCESS) {
///     // Use buffer...
///     free(buffer);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_build(
    builder: *mut matchy_builder_t,
    buffer: *mut *mut u8,
    size: *mut usize,
) -> i32 {
    if builder.is_null() || buffer.is_null() || size.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let internal = matchy_builder_t::as_internal_mut(builder);
    let bytes = match internal.builder.build() {
        Ok(b) => b,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    // Allocate buffer using libc::malloc so C can free it
    let buf_size = bytes.len();
    let buf_ptr = libc::malloc(buf_size) as *mut u8;
    if buf_ptr.is_null() {
        return MATCHY_ERROR_OUT_OF_MEMORY;
    }

    // Copy data
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, buf_size);

    *buffer = buf_ptr;
    *size = buf_size;

    MATCHY_SUCCESS
}

/// Free builder
///
/// # Parameters
/// * `builder` - Builder handle (may be NULL)
///
/// # Safety
/// * `builder` must be NULL or a valid pointer from matchy_builder_new
/// * Must not be used after calling this function
/// * Calling with NULL is safe (no-op)
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_free(builder: *mut matchy_builder_t) {
    if !builder.is_null() {
        let _ = matchy_builder_t::into_internal(builder);
    }
}

// ============================================================================
// DATABASE QUERYING API
// ============================================================================

/// Open database from file (memory-mapped)
///
/// Opens a database file using memory mapping for optimal performance.
/// The file is not loaded into memory - it's accessed on-demand.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_t *db = matchy_open("threats.db");
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open database\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_open(filename: *const c_char) -> *mut matchy_t {
    if filename.is_null() {
        return ptr::null_mut();
    }

    let path = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match RustDatabase::open(path) {
        Ok(db) => {
            let internal = Box::new(MatchyInternal { database: db });
            matchy_t::from_internal(internal)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Open database from memory buffer (zero-copy)
///
/// Creates a database handle from a memory buffer. No data is copied.
///
/// # Parameters
/// * `buffer` - Pointer to database data (must not be NULL)
/// * `size` - Size of buffer in bytes (must be > 0)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `buffer` must be valid for the lifetime of the database handle
/// * Caller must not modify or free buffer while handle exists
#[no_mangle]
pub unsafe extern "C" fn matchy_open_buffer(buffer: *const u8, size: usize) -> *mut matchy_t {
    if buffer.is_null() || size == 0 {
        return ptr::null_mut();
    }

    let slice = slice::from_raw_parts(buffer, size);
    match RustDatabase::from_bytes(slice.to_vec()) {
        Ok(db) => {
            let internal = Box::new(MatchyInternal { database: db });
            matchy_t::from_internal(internal)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Close database
///
/// Closes the database and frees all associated resources.
///
/// # Parameters
/// * `db` - Database handle (may be NULL)
///
/// # Safety
/// * `db` must be NULL or a valid pointer from matchy_open
/// * Must not be used after calling this function
/// * Calling with NULL is safe (no-op)
///
/// # Example
/// ```c
/// matchy_close(db);
/// db = NULL;  // Good practice
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_close(db: *mut matchy_t) {
    if !db.is_null() {
        let _ = matchy_t::into_internal(db);
    }
}

/// Unified query interface - automatically detects IP vs pattern
///
/// Queries the database with an IP address or pattern. The function automatically
/// detects the query type and uses the appropriate lookup method.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `query` - IP address or pattern to search (null-terminated C string, must not be NULL)
///
/// # Returns
/// * matchy_result_t with found=true if match found
/// * matchy_result_t with found=false if no match
/// * Caller must free result with matchy_free_result
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `query` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "1.2.3.4");
/// if (result.found && result.data_json) {
///     printf("Found: %s\n", result.data_json);
///     matchy_free_result(&result);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_query(
    db: *const matchy_t,
    query: *const c_char,
) -> matchy_result_t {
    if db.is_null() || query.is_null() {
        return matchy_result_t {
            found: false,
            data_json: ptr::null_mut(),
            prefix_len: 0,
        };
    }

    let query_str = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => {
            return matchy_result_t {
                found: false,
                data_json: ptr::null_mut(),
                prefix_len: 0,
            }
        }
    };

    let internal = matchy_t::as_internal(db);
    match internal.database.lookup(query_str) {
        Ok(Some(QueryResult::Ip { data, prefix_len })) => {
            // Convert data to JSON string
            let json_str = match serde_json::to_string(&data) {
                Ok(s) => s,
                Err(_) => {
                    return matchy_result_t {
                        found: false,
                        data_json: ptr::null_mut(),
                        prefix_len: 0,
                    }
                }
            };

            let c_str = match CString::new(json_str) {
                Ok(s) => s,
                Err(_) => {
                    return matchy_result_t {
                        found: false,
                        data_json: ptr::null_mut(),
                        prefix_len: 0,
                    }
                }
            };

            matchy_result_t {
                found: true,
                data_json: c_str.into_raw(),
                prefix_len,
            }
        }
        Ok(Some(QueryResult::Pattern {
            pattern_ids: _,
            data,
        })) => {
            // For patterns, return the first match's data
            if let Some(Some(first_data)) = data.first() {
                let json_str = match serde_json::to_string(&first_data) {
                    Ok(s) => s,
                    Err(_) => {
                        return matchy_result_t {
                            found: false,
                            data_json: ptr::null_mut(),
                            prefix_len: 0,
                        }
                    }
                };

                let c_str = match CString::new(json_str) {
                    Ok(s) => s,
                    Err(_) => {
                        return matchy_result_t {
                            found: false,
                            data_json: ptr::null_mut(),
                            prefix_len: 0,
                        }
                    }
                };

                return matchy_result_t {
                    found: true,
                    data_json: c_str.into_raw(),
                    prefix_len: 0,
                };
            }
            matchy_result_t {
                found: false,
                data_json: ptr::null_mut(),
                prefix_len: 0,
            }
        }
        _ => matchy_result_t {
            found: false,
            data_json: ptr::null_mut(),
            prefix_len: 0,
        },
    }
}

/// Free query result
///
/// Frees the memory allocated for a query result.
///
/// # Parameters
/// * `result` - Pointer to result from matchy_query (must not be NULL)
///
/// # Safety
/// * `result` must be a valid pointer to a result from matchy_query
/// * Must not be called twice on the same result
#[no_mangle]
pub unsafe extern "C" fn matchy_free_result(result: *mut matchy_result_t) {
    if !result.is_null() && !(*result).data_json.is_null() {
        let _ = CString::from_raw((*result).data_json);
        (*result).data_json = ptr::null_mut();
    }
}

/// Free a string returned by matchy
///
/// # Parameters
/// * `string` - String pointer returned by matchy (may be NULL)
///
/// # Safety
/// * `string` must be NULL or a pointer returned by matchy
/// * Must not be called twice on the same pointer
#[no_mangle]
pub unsafe extern "C" fn matchy_free_string(string: *mut c_char) {
    if !string.is_null() {
        let _ = CString::from_raw(string);
    }
}

/// Get library version string
///
/// # Returns
/// * Version string (e.g., "0.4.0")
/// * Pointer is valid for program lifetime, do not free
#[no_mangle]
pub extern "C" fn matchy_version() -> *const c_char {
    // Use the version from Cargo.toml, automatically updated at compile time
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
