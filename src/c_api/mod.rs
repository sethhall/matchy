//! C API for paraglob
//!
//! This module provides a stable C ABI for use from C and C++ programs.

use crate::mmap::{MmapFile, MmapError};
use crate::paraglob_offset::Paraglob;
use crate::glob::MatchMode as GlobMatchMode;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::slice;

/// Opaque database handle for C API
///
/// This wraps both the MmapFile and the Paraglob instance.
#[repr(C)]
pub struct paraglob_db {
    _private: [u8; 0],
}

/// Opaque builder handle for C API
///
/// Used for incrementally building a pattern database.
#[repr(C)]
pub struct paraglob_builder {
    _private: [u8; 0],
}

/// Storage mode for the database
enum DbStorage {
    /// Memory-mapped file (owns the MmapFile)
    Mmap(MmapFile),
    /// External buffer (does not own the buffer)
    Buffer,
}

/// Internal structure for builder
struct ParaglobBuilderInternal {
    patterns: Vec<String>,
    case_sensitive: bool,
}

/// Internal structure that actually holds the data
struct ParaglobDbInternal {
    storage: DbStorage,
    paraglob: Paraglob,
}

// Internal conversion helpers
impl paraglob_db {
    /// Convert internal structure to opaque pointer
    fn from_internal(internal: Box<ParaglobDbInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    /// Convert opaque pointer back to internal structure
    /// # Safety
    /// Pointer must have come from from_internal
    unsafe fn into_internal(ptr: *mut Self) -> Box<ParaglobDbInternal> {
        Box::from_raw(ptr as *mut ParaglobDbInternal)
    }

    /// Borrow the internal structure without taking ownership
    /// # Safety
    /// Pointer must be valid and from from_internal
    unsafe fn as_internal<'a>(ptr: *const Self) -> &'a ParaglobDbInternal {
        &*(ptr as *const ParaglobDbInternal)
    }

    /// Mutable borrow of internal structure
    /// # Safety
    /// Pointer must be valid and from from_internal
    unsafe fn as_internal_mut<'a>(ptr: *mut Self) -> &'a mut ParaglobDbInternal {
        &mut *(ptr as *mut ParaglobDbInternal)
    }
}

impl paraglob_builder {
    /// Convert internal structure to opaque pointer
    fn from_internal(internal: Box<ParaglobBuilderInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    /// Convert opaque pointer back to internal structure
    /// # Safety
    /// Pointer must have come from from_internal
    unsafe fn into_internal(ptr: *mut Self) -> Box<ParaglobBuilderInternal> {
        Box::from_raw(ptr as *mut ParaglobBuilderInternal)
    }

    /// Mutable borrow of internal structure
    /// # Safety
    /// Pointer must be valid and from from_internal
    unsafe fn as_internal_mut<'a>(ptr: *mut Self) -> &'a mut ParaglobBuilderInternal {
        &mut *(ptr as *mut ParaglobBuilderInternal)
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
/// paraglob_db* db = paraglob_open_mmap("patterns.pgb");
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open database\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_open_mmap(
    filename: *const c_char,
) -> *mut paraglob_db {
    // Validate input
    if filename.is_null() {
        return std::ptr::null_mut();
    }

    // Convert C string to Rust
    let path_cstr = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Open the memory-mapped file
    let mmap = match MmapFile::open(Path::new(path_cstr)) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Paraglob instance from the mmap
    let slice = mmap.as_slice();
    // SAFETY: We're extending the lifetime to 'static, which is safe because
    // we're keeping the MmapFile alive in the same structure
    let static_slice: &'static [u8] = std::mem::transmute(slice);
    
    let paraglob = match Paraglob::from_mmap(static_slice, GlobMatchMode::CaseSensitive) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create internal structure
    let internal = Box::new(ParaglobDbInternal {
        storage: DbStorage::Mmap(mmap),
        paraglob,
    });

    paraglob_db::from_internal(internal)
}

/// Open database from memory buffer (zero-copy)
///
/// Creates a database handle from a memory buffer containing pattern data
/// in binary format. No data is copied - the database operates directly
/// on the provided buffer.
///
/// # Parameters
/// * `buffer` - Pointer to pattern data in memory (binary format)
/// * `size` - Size of buffer in bytes
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `buffer` must be valid for the lifetime of the returned handle
/// * Caller must not modify or free buffer while handle exists
///
/// # Example
/// ```c
/// uint8_t* data = ...; // Load from somewhere
/// size_t size = ...;
/// paraglob_db* db = paraglob_open_buffer(data, size);
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open from buffer\n");
///     return 1;
/// }
/// // Use db...
/// paraglob_close(db);
/// // Now you can free data
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_open_buffer(
    buffer: *const u8,
    size: usize,
) -> *mut paraglob_db {
    // Validate input
    if buffer.is_null() || size == 0 {
        return std::ptr::null_mut();
    }

    // Create a slice from the buffer
    let slice: &'static [u8] = slice::from_raw_parts(buffer, size);

    // Create Paraglob from the buffer
    let paraglob = match Paraglob::from_mmap(slice, GlobMatchMode::CaseSensitive) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create internal structure (Buffer mode - doesn't own the buffer)
    let internal = Box::new(ParaglobDbInternal {
        storage: DbStorage::Buffer,
        paraglob,
    });

    paraglob_db::from_internal(internal)
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
        let _internal = paraglob_db::into_internal(db);
        // _internal is dropped here, closing the file and freeing resources
    }
}

/// Find all patterns that match the input text
///
/// Searches the input text and returns pattern IDs for all glob patterns
/// that match. Matching runs in O(n) time where n is the text length.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `text` - Input text to search, null-terminated (must not be NULL)
/// * `result_count` - Pointer to receive match count (must not be NULL)
///
/// # Returns
/// * Heap-allocated array of pattern IDs (must be freed with paraglob_free_results)
/// * NULL if no matches found (*result_count will be 0)
/// * NULL on error (*result_count undefined)
///
/// # Safety
/// * `db` must be a valid handle
/// * `text` must be a valid null-terminated C string
/// * `result_count` must be a valid pointer
///
/// # Example
/// ```c
/// size_t count = 0;
/// int* matches = paraglob_find_all(db, "test.txt", &count);
/// if (matches) {
///     for (size_t i = 0; i < count; i++) {
///         printf("Pattern %d matched\n", matches[i]);
///     }
///     paraglob_free_results(matches);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_find_all(
    db: *mut paraglob_db,
    text: *const c_char,
    result_count: *mut libc::size_t,
) -> *mut libc::c_int {
    // Validate inputs
    if db.is_null() || text.is_null() || result_count.is_null() {
        if !result_count.is_null() {
            *result_count = 0;
        }
        return std::ptr::null_mut();
    }

    // Convert C string to Rust
    let text_str = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => {
            *result_count = 0;
            return std::ptr::null_mut();
        }
    };

    // Get mutable reference to internal structure
    let internal = paraglob_db::as_internal_mut(db);

    // Perform matching
    let matches = internal.paraglob.find_all(text_str);

    *result_count = matches.len();

    if matches.is_empty() {
        return std::ptr::null_mut();
    }

    // Allocate result array using malloc (so it can be freed with free())
    let size = matches.len() * std::mem::size_of::<libc::c_int>();
    let ptr = libc::malloc(size) as *mut libc::c_int;
    
    if ptr.is_null() {
        *result_count = 0;
        return std::ptr::null_mut();
    }

    // Copy matches into the allocated buffer
    for (i, pattern_id) in matches.iter().enumerate() {
        *ptr.add(i) = *pattern_id as libc::c_int;
    }

    ptr
}

/// Free search results array
///
/// Frees the array returned by paraglob_find_all(). Safe to call with NULL.
///
/// # Parameters
/// * `results` - Array returned by paraglob_find_all() (may be NULL)
///
/// # Safety
/// * `results` must be NULL or a pointer returned from paraglob_find_all()
/// * Must not be called twice on the same pointer
///
/// # Example
/// ```c
/// int* matches = paraglob_find_all(db, "test.txt", &count);
/// // ... use matches ...
/// paraglob_free_results(matches);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_free_results(results: *mut libc::c_int) {
    if results.is_null() {
        return;
    }
    // Free the malloc'd memory
    libc::free(results as *mut libc::c_void);
}

/// Get number of patterns in the database
///
/// Returns the total count of glob patterns stored in the database.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Number of patterns in database
/// * 0 if db is NULL or invalid
///
/// # Safety
/// * `db` must be a valid handle
///
/// # Example
/// ```c
/// size_t count = paraglob_pattern_count(db);
/// printf("Database contains %zu patterns\n", count);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_pattern_count(db: *const paraglob_db) -> libc::size_t {
    if db.is_null() {
        return 0;
    }
    let internal = paraglob_db::as_internal(db);
    internal.paraglob.pattern_count()
}

/// Get database binary format version
///
/// Returns the version number of the binary format used by this database.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Format version number (e.g., 1, 2, 3...)
/// * 0 if db is NULL or invalid
///
/// # Safety
/// * `db` must be a valid handle
///
/// # Example
/// ```c
/// uint32_t version = paraglob_version(db);
/// printf("Binary format version: %u\n", version);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_version(db: *const paraglob_db) -> u32 {
    if db.is_null() {
        return 0;
    }
    let internal = paraglob_db::as_internal(db);
    
    // Get version from the mmap if available, otherwise from paraglob buffer
    match &internal.storage {
        DbStorage::Mmap(mmap) => mmap.paraglob_header().version,
        DbStorage::Buffer => {
            // Read version from the buffer header
            let buffer = internal.paraglob.buffer();
            if buffer.len() < std::mem::size_of::<crate::offset_format::ParaglobHeader>() {
                return 0;
            }
            // Read the version field (at offset 8 after the 8-byte magic)
            let version_bytes = &buffer[8..12];
            u32::from_ne_bytes([version_bytes[0], version_bytes[1], version_bytes[2], version_bytes[3]])
        }
    }
}

// ============================================================================
// Builder API
// ============================================================================

/// Create a new pattern builder
///
/// Creates a builder for incrementally adding patterns before compilation.
/// After adding all patterns, call paraglob_builder_compile() to create
/// a usable database.
///
/// # Parameters
/// * `case_sensitive` - If non-zero, matching will be case-sensitive
///
/// # Returns
/// * Non-null pointer to builder on success
/// * NULL on allocation failure
///
/// # Safety
/// * Returned pointer must be freed with paraglob_builder_free() or
///   consumed with paraglob_builder_compile()
///
/// # Example
/// ```c
/// paraglob_builder* builder = paraglob_builder_new(1);  // case-sensitive
/// if (builder == NULL) {
///     fprintf(stderr, "Failed to create builder\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_builder_new(
    case_sensitive: libc::c_int,
) -> *mut paraglob_builder {
    let internal = Box::new(ParaglobBuilderInternal {
        patterns: Vec::new(),
        case_sensitive: case_sensitive != 0,
    });
    
    paraglob_builder::from_internal(internal)
}

/// Add a pattern to the builder
///
/// Adds a glob pattern to the builder. Patterns are deduplicated.
/// Must call paraglob_builder_compile() after adding all patterns.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `pattern` - Glob pattern string, null-terminated (must not be NULL)
///
/// # Returns
/// * PARAGLOB_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid handle from paraglob_builder_new()
/// * `pattern` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// paraglob_builder* builder = paraglob_builder_new(1);
/// paraglob_builder_add(builder, "*.txt");
/// paraglob_builder_add(builder, "*.log");
/// paraglob_builder_add(builder, "data_*");
/// paraglob_db* db = paraglob_builder_compile(builder);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_builder_add(
    builder: *mut paraglob_builder,
    pattern: *const c_char,
) -> paraglob_error_t {
    // Validate inputs
    if builder.is_null() || pattern.is_null() {
        return paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM;
    }
    
    // Convert C string to Rust
    let pattern_str = match CStr::from_ptr(pattern).to_str() {
        Ok(s) => s,
        Err(_) => return paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM,
    };
    
    // Add to patterns (deduplicate)
    let internal = paraglob_builder::as_internal_mut(builder);
    if !internal.patterns.contains(&pattern_str.to_string()) {
        internal.patterns.push(pattern_str.to_string());
    }
    
    paraglob_error_t::PARAGLOB_SUCCESS
}

/// Compile builder into a usable database
///
/// Finalizes the pattern builder and creates a compiled database ready
/// for matching. This consumes the builder - it cannot be used after
/// this call succeeds.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
///
/// # Returns
/// * Non-null pointer to compiled database on success
/// * NULL on compilation failure (builder is still freed)
///
/// # Safety
/// * `builder` must be a valid handle from paraglob_builder_new()
/// * `builder` must not be used after this call (even if NULL is returned)
///
/// # Example
/// ```c
/// paraglob_builder* builder = paraglob_builder_new(1);
/// paraglob_builder_add(builder, "*.txt");
/// paraglob_builder_add(builder, "*.log");
/// 
/// paraglob_db* db = paraglob_builder_compile(builder);
/// // builder is now invalid - don't use it
/// 
/// if (db == NULL) {
///     fprintf(stderr, "Failed to compile patterns\n");
///     return 1;
/// }
/// 
/// // Use db...
/// paraglob_close(db);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_builder_compile(
    builder: *mut paraglob_builder,
) -> *mut paraglob_db {
    // Validate input
    if builder.is_null() {
        return std::ptr::null_mut();
    }
    
    // Take ownership of builder
    let internal = paraglob_builder::into_internal(builder);
    
    if internal.patterns.is_empty() {
        return std::ptr::null_mut();
    }
    
    // Convert patterns to &str slice
    let pattern_refs: Vec<&str> = internal.patterns.iter().map(|s| s.as_str()).collect();
    
    // Determine match mode
    let mode = if internal.case_sensitive {
        GlobMatchMode::CaseSensitive
    } else {
        GlobMatchMode::CaseInsensitive
    };
    
    // Build the paraglob
    let paraglob = match Paraglob::build_from_patterns(&pattern_refs, mode) {
        Ok(pg) => pg,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Create database internal structure
    let db_internal = Box::new(ParaglobDbInternal {
        storage: DbStorage::Buffer,
        paraglob,
    });
    
    paraglob_db::from_internal(db_internal)
}

/// Free a pattern builder without compiling
///
/// Frees a builder if you decide not to compile it. If you call
/// paraglob_builder_compile(), you don't need to call this.
///
/// # Parameters
/// * `builder` - Builder handle (may be NULL)
///
/// # Safety
/// * `builder` must be NULL or a valid handle from paraglob_builder_new()
/// * `builder` must not be used after this call
/// * Calling with NULL is safe (no-op)
///
/// # Example
/// ```c
/// paraglob_builder* builder = paraglob_builder_new(1);
/// // ... decide not to use it ...
/// paraglob_builder_free(builder);
/// builder = NULL;
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_builder_free(builder: *mut paraglob_builder) {
    if !builder.is_null() {
        // Convert back to Box and let it drop
        let _internal = paraglob_builder::into_internal(builder);
        // _internal is dropped here
    }
}

/// Save a database to a file
///
/// Writes the compiled database to a binary file that can be loaded
/// later with paraglob_open_mmap() for instant startup.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `filename` - Path where file should be written (must not be NULL)
///
/// # Returns
/// * PARAGLOB_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `db` must be a valid handle
/// * `filename` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// paraglob_builder* builder = paraglob_builder_new(1);
/// paraglob_builder_add(builder, "*.txt");
/// paraglob_db* db = paraglob_builder_compile(builder);
/// 
/// if (paraglob_save(db, "patterns.pgb") != PARAGLOB_SUCCESS) {
///     fprintf(stderr, "Failed to save database\n");
/// }
/// 
/// paraglob_close(db);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_save(
    db: *const paraglob_db,
    filename: *const c_char,
) -> paraglob_error_t {
    // Validate inputs
    if db.is_null() || filename.is_null() {
        return paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM;
    }
    
    // Convert filename to Rust
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return paraglob_error_t::PARAGLOB_ERROR_INVALID_PARAM,
    };
    
    let internal = paraglob_db::as_internal(db);
    
    // Get buffer from paraglob
    let buffer = internal.paraglob.buffer();
    
    // Write to file
    use std::io::Write;
    let mut file = match std::fs::File::create(path_str) {
        Ok(f) => f,
        Err(_) => return paraglob_error_t::PARAGLOB_ERROR_IO,
    };
    
    if file.write_all(buffer).is_err() {
        return paraglob_error_t::PARAGLOB_ERROR_IO;
    }
    
    if file.sync_all().is_err() {
        return paraglob_error_t::PARAGLOB_ERROR_IO;
    }
    
    paraglob_error_t::PARAGLOB_SUCCESS
}

/// Get buffer pointer and size from database
///
/// Returns a pointer to the internal binary buffer and its size.
/// This is useful for embedding the database or writing it manually.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `size` - Pointer to receive buffer size (must not be NULL)
///
/// # Returns
/// * Pointer to buffer on success
/// * NULL on failure
///
/// # Safety
/// * `db` must be a valid handle
/// * `size` must be a valid pointer
/// * The returned buffer is owned by `db` - do not free it
/// * The buffer is valid until `db` is closed
///
/// # Example
/// ```c
/// paraglob_db* db = ...; // build from patterns
/// size_t size = 0;
/// const uint8_t* buffer = paraglob_get_buffer(db, &size);
/// if (buffer) {
///     // Write to custom storage
///     fwrite(buffer, 1, size, output_file);
/// }
/// paraglob_close(db);
/// ```
#[no_mangle]
pub unsafe extern "C" fn paraglob_get_buffer(
    db: *const paraglob_db,
    size: *mut usize,
) -> *const u8 {
    // Validate inputs
    if db.is_null() || size.is_null() {
        if !size.is_null() {
            *size = 0;
        }
        return std::ptr::null();
    }
    
    let internal = paraglob_db::as_internal(db);
    let buffer = internal.paraglob.buffer();
    
    *size = buffer.len();
    buffer.as_ptr()
}
