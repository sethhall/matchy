//! Clean Matchy C API
//!
//! This module provides a modern, clean C API for building and querying databases
//! containing IP addresses and patterns. This is the primary public API.

use crate::database::{Database, DatabaseError, ReloadEvent};
use crate::schema_validation::SchemaValidator;
use crate::schemas::{get_schema_info, is_known_database_type};
use crate::DatabaseBuilder;
use chrono::TimeZone;
use matchy_data_format::DataValue;
use matchy_match_mode::MatchMode;
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::fmt::Write;
use std::mem;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Mutex;

struct CCallbackAdapter {
    callback: unsafe extern "C" fn(event: *const matchy_reload_event_t, user_data: *mut c_void),
    user_data: *mut c_void,
}

// SAFETY: CCallbackAdapter is Send+Sync because the C callback and user_data
// are provided by the caller who guarantees thread-safety of their usage
unsafe impl Send for CCallbackAdapter {}
// SAFETY: See above
unsafe impl Sync for CCallbackAdapter {}

impl CCallbackAdapter {
    fn invoke(&self, event: &ReloadEvent) {
        let path_cstring =
            std::ffi::CString::new(event.path.to_string_lossy().as_ref()).unwrap_or_default();
        let error_cstring = event
            .error
            .as_ref()
            .and_then(|e| std::ffi::CString::new(e.as_str()).ok());

        let c_event = matchy_reload_event_t {
            path: path_cstring.as_ptr(),
            success: event.success,
            error: error_cstring
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(ptr::null()),
            generation: event.generation,
        };

        // SAFETY: Callback and user_data validity guaranteed by C caller contract
        unsafe { (self.callback)(&c_event, self.user_data) };
    }
}

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
/// Schema validation error
pub const MATCHY_ERROR_SCHEMA_VALIDATION: i32 = -7;
/// Unknown schema error
pub const MATCHY_ERROR_UNKNOWN_SCHEMA: i32 = -8;
/// Internal panic caught at the FFI boundary
pub const MATCHY_ERROR_INTERNAL: i32 = -12;

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

/// Query result with offset-only data ownership
#[repr(C)]
pub struct matchy_result_t {
    /// Whether a match was found
    pub found: bool,
    /// Network prefix length (for IP results)
    pub prefix_len: u8,
    /// Result type: 0=not found, 1=ip, 2=pattern
    pub _result_type: u8,
    /// Internal format-specific data token (use matchy_aget_value to decode)
    pub _data_offset: u32,
    /// Internal database reference (for decoding)
    pub _db_ref: *const matchy_t,
}

fn empty_matchy_result() -> matchy_result_t {
    matchy_result_t {
        found: false,
        prefix_len: 0,
        _result_type: 0,
        _data_offset: 0,
        _db_ref: ptr::null(),
    }
}

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct MatchyBuilderInternal {
    builder: DatabaseBuilder,
    /// Optional schema validator (set via matchy_builder_set_schema)
    validator: Option<SchemaValidator>,
}

struct MatchyInternal {
    database: Database,
    value_cache: Mutex<EntryDataStorage>,
}

/// Maximum estimated storage retained for C string and byte results on one
/// database handle. Cached values cannot be evicted because their pointers are
/// promised to remain valid until the handle is closed.
const ENTRY_DATA_STORAGE_LIMIT: usize = 64 * 1024 * 1024;

/// A lookup path cannot be deeper than a value accepted by the data decoder.
const MAX_LOOKUP_PATH_COMPONENTS: usize = matchy_data_format::MAX_TOTAL_DEPTH;

impl MatchyInternal {
    fn new(database: Database) -> Self {
        Self {
            database,
            value_cache: Mutex::new(EntryDataStorage::default()),
        }
    }
}

pub(super) fn ffi_guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => fallback,
    }
}

// Conversion helpers for opaque types
impl matchy_builder_t {
    fn from_internal(internal: Box<MatchyBuilderInternal>) -> *mut Self {
        Box::into_raw(internal).cast::<Self>()
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyBuilderInternal> {
        Box::from_raw(ptr.cast::<MatchyBuilderInternal>())
    }

    unsafe fn as_internal_mut(ptr: *mut Self) -> &'static mut MatchyBuilderInternal {
        &mut *ptr.cast::<MatchyBuilderInternal>()
    }
}

impl matchy_t {
    fn from_internal(internal: Box<MatchyInternal>) -> *mut Self {
        Box::into_raw(internal).cast::<Self>()
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyInternal> {
        Box::from_raw(ptr.cast::<MatchyInternal>())
    }

    unsafe fn as_internal(ptr: *const Self) -> &'static MatchyInternal {
        &*ptr.cast::<MatchyInternal>()
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
    ffi_guard(ptr::null_mut(), || {
        let builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let internal = Box::new(MatchyBuilderInternal {
            builder,
            validator: None,
        });
        matchy_builder_t::from_internal(internal)
    })
}

/// Set case-insensitive matching mode
///
/// When enabled, all pattern/literal lookups will be case-insensitive.
/// IP lookups are always case-insensitive regardless of this setting.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `case_insensitive` - true for case-insensitive, false for case-sensitive (default)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * MATCHY_ERROR_INVALID_PARAM if builder is NULL
///
/// # Safety
/// * `builder` must be a valid pointer returned by `matchy_builder_new()` or NULL
/// * `builder` must not have been freed with `matchy_builder_free()`
///
/// # Example
/// ```c
/// matchy_builder_t *builder = matchy_builder_new();
/// matchy_builder_set_case_insensitive(builder, true);
/// // Entries like "Evil.COM" will match queries for "evil.com", "EVIL.COM", etc.
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_set_case_insensitive(
    builder: *mut matchy_builder_t,
    case_insensitive: bool,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if builder.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let internal = matchy_builder_t::as_internal_mut(builder);
        let match_mode = if case_insensitive {
            MatchMode::CaseInsensitive
        } else {
            MatchMode::CaseSensitive
        };
        internal.builder.set_match_mode(match_mode);

        MATCHY_SUCCESS
    })
}

/// Enable schema validation for a known database type
///
/// When a schema is set, all entries added via matchy_builder_add() will be
/// validated against the schema. Invalid entries will cause add to return
/// MATCHY_ERROR_SCHEMA_VALIDATION.
///
/// Known database types:
/// - "threatdb" - Threat intelligence database (ThreatDB-v1 schema)
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `schema_name` - Name of a known schema (e.g., "threatdb")
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * MATCHY_ERROR_UNKNOWN_SCHEMA if the schema name is not recognized
/// * MATCHY_ERROR_INVALID_PARAM if builder or schema_name is NULL
///
/// # Safety
/// * `builder` must be a valid pointer returned by `matchy_builder_new()` or NULL
/// * `builder` must not have been freed with `matchy_builder_free()`
/// * `schema_name` must be a valid null-terminated C string or NULL
///
/// # Example
/// ```c
/// matchy_builder_t *builder = matchy_builder_new();
/// int result = matchy_builder_set_schema(builder, "threatdb");
/// if (result != MATCHY_SUCCESS) {
///     fprintf(stderr, "Unknown schema\n");
///     return 1;
/// }
/// // Now all entries will be validated against ThreatDB schema
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_set_schema(
    builder: *mut matchy_builder_t,
    schema_name: *const c_char,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if builder.is_null() || schema_name.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let name = match CStr::from_ptr(schema_name).to_str() {
            Ok(s) => s,
            Err(_) => return MATCHY_ERROR_INVALID_PARAM,
        };

        // Check if this is a known schema
        if !is_known_database_type(name) {
            return MATCHY_ERROR_UNKNOWN_SCHEMA;
        }

        // Create validator
        let validator = match SchemaValidator::new(name) {
            Ok(v) => v,
            Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
        };

        // Get the canonical database type and set it
        let internal = matchy_builder_t::as_internal_mut(builder);
        if let Some(info) = get_schema_info(name) {
            // DatabaseBuilder's with_database_type takes ownership and returns Self
            // We need to use a placeholder to swap it out
            let placeholder = DatabaseBuilder::new(MatchMode::CaseSensitive);
            let old_builder = std::mem::replace(&mut internal.builder, placeholder);
            internal.builder = old_builder.with_database_type(info.database_type);
        }
        internal.validator = Some(validator);

        MATCHY_SUCCESS
    })
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
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
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

        // Parse JSON to DataValue (supports nested structures)
        let data: DataValue = match serde_json::from_str(json_str) {
            Ok(d) => d,
            Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
        };

        // Wrap in a map if it's not already a map
        let data_map = match data {
            DataValue::Map(m) => m,
            _ => {
                // Single value - wrap it in a map with "value" key
                let mut map = HashMap::new();
                map.insert("value".to_string(), data);
                map
            }
        };

        let internal = matchy_builder_t::as_internal_mut(builder);

        // Validate against schema if one is set
        if let Some(ref validator) = internal.validator {
            if validator.validate(&data_map).is_err() {
                return MATCHY_ERROR_SCHEMA_VALIDATION;
            }
        }

        match internal.builder.add_entry(key_str, data_map) {
            Ok(_) => MATCHY_SUCCESS,
            Err(_) => MATCHY_ERROR_INVALID_FORMAT,
        }
    })
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
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
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
            DatabaseBuilder::new(MatchMode::CaseSensitive),
        );
        internal.builder = old_builder.with_description("en", desc_str);

        MATCHY_SUCCESS
    })
}

/// Set the update URL for the database
///
/// When set, this URL is stored in the database metadata. Applications using
/// auto_update will fetch updates from this URL.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `url` - Update URL (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * MATCHY_ERROR_INVALID_PARAM if parameters invalid
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `url` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_builder_set_update_url(builder, "https://example.com/threats.mxy");
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_set_update_url(
    builder: *mut matchy_builder_t,
    url: *const c_char,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if builder.is_null() || url.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let url_str = match CStr::from_ptr(url).to_str() {
            Ok(s) => s,
            Err(_) => return MATCHY_ERROR_INVALID_PARAM,
        };

        let internal = matchy_builder_t::as_internal_mut(builder);
        let old_builder = std::mem::replace(
            &mut internal.builder,
            DatabaseBuilder::new(MatchMode::CaseSensitive),
        );
        internal.builder = old_builder.with_update_url(url_str);

        MATCHY_SUCCESS
    })
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
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if builder.is_null() || filename.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let path = match CStr::from_ptr(filename).to_str() {
            Ok(s) => s,
            Err(_) => return MATCHY_ERROR_INVALID_PARAM,
        };

        let internal = matchy_builder_t::as_internal_mut(builder);
        // Replace builder with a dummy one to take ownership
        let builder_to_build = std::mem::replace(
            &mut internal.builder,
            DatabaseBuilder::new(MatchMode::CaseSensitive),
        );
        let bytes = match builder_to_build.build() {
            Ok(b) => b,
            Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
        };

        match std::fs::write(path, bytes) {
            Ok(_) => MATCHY_SUCCESS,
            Err(_) => MATCHY_ERROR_IO,
        }
    })
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
/// uintptr_t size = 0;
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
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if builder.is_null() || buffer.is_null() || size.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let internal = matchy_builder_t::as_internal_mut(builder);
        // Replace builder with a dummy one to take ownership
        let builder_to_build = std::mem::replace(
            &mut internal.builder,
            DatabaseBuilder::new(MatchMode::CaseSensitive),
        );
        let bytes = match builder_to_build.build() {
            Ok(b) => b,
            Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
        };

        // Allocate buffer using libc::malloc so C can free it
        let buf_size = bytes.len();
        let buf_ptr = libc::malloc(buf_size).cast::<u8>();
        if buf_ptr.is_null() {
            return MATCHY_ERROR_OUT_OF_MEMORY;
        }

        // Copy data
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, buf_size);

        *buffer = buf_ptr;
        *size = buf_size;

        MATCHY_SUCCESS
    })
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
    ffi_guard((), || {
        if !builder.is_null() {
            let _ = matchy_builder_t::into_internal(builder);
        }
    });
}

// ============================================================================
// DATABASE QUERYING API
// ============================================================================

/// Reload callback event information
///
/// Information passed to reload callbacks when database reloads occur.
#[repr(C)]
pub struct matchy_reload_event_t {
    /// Path to database file (null-terminated C string)
    /// Valid only for duration of callback - copy if needed
    pub path: *const c_char,

    /// Whether reload succeeded
    /// true = successful reload, false = reload failed
    pub success: bool,

    /// Error message if reload failed (null if success)
    /// Valid only for duration of callback - copy if needed
    pub error: *const c_char,

    /// Generation counter (increments on each successful reload)
    /// Can be used to detect if database has changed since last check
    pub generation: u64,
}

/// Reload callback function type
///
/// Called when database reload completes (success or failure).
/// Called from watcher thread - keep processing minimal!
///
/// # Parameters
/// * `event` - Reload event information (valid only during callback)
/// * `user_data` - User-provided context pointer from matchy_open_options_t
///
/// # Safety
/// * Callback must be thread-safe
/// * Do not call matchy_* functions from callback (potential deadlock)
/// * Copy event.path and event.error if you need them after callback returns
/// * user_data must match what was provided in options
///
/// # Example
/// ```c
/// void on_reload(const matchy_reload_event_t *event, void *user_data) {
///     if (event->success) {
///         printf("Database reloaded: %s (generation %lu)\n",
///                event->path, event->generation);
///     } else {
///         fprintf(stderr, "Reload failed: %s - %s\n",
///                 event->path, event->error);
///     }
/// }
/// ```
#[allow(non_camel_case_types)]
pub type matchy_reload_callback_t =
    Option<unsafe extern "C" fn(event: *const matchy_reload_event_t, user_data: *mut c_void)>;

/// Database opening options
///
/// Configure how databases are loaded, including cache, reload, and update settings.
#[repr(C)]
pub struct matchy_open_options_t {
    /// LRU cache capacity
    /// 0 = disable cache, >0 = cache at most this many entries.
    /// Estimated retained result heap is also capped at 64 MiB per thread
    /// across at most 16 recent database generations.
    /// Default: 10000
    pub cache_capacity: u32,

    /// Enable automatic reload when database file changes
    /// false = no watching (default), true = auto-reload on file changes
    /// Default: false
    ///
    /// When enabled, the database watches its source file and automatically
    /// reloads when changes are detected. All queries transparently use the
    /// latest version. Adds ~10-20ns overhead per query due to read lock.
    pub auto_reload: bool,

    /// Enable automatic updates from database's embedded URL (requires auto-update feature)
    /// false = no network updates (default), true = check for updates periodically
    /// Default: false
    ///
    /// When enabled, periodically checks the database's embedded update URL for new versions
    /// using HTTP conditional GET (ETag). Database must have an update URL embedded in metadata.
    /// Updates are downloaded to cache_dir (or system default), not the original file.
    pub auto_update: bool,

    /// How often to check for remote updates, in seconds
    /// Only used when auto_update is true
    /// Default: 3600 (1 hour)
    pub update_interval_secs: u32,

    /// Cache directory for downloaded updates (optional)
    /// If NULL, uses system default (~/.cache/matchy/ on Unix)
    /// Default: NULL
    pub cache_dir: *const c_char,

    /// Reload callback function (optional)
    /// Called when database reload completes (success or failure)
    /// Set to NULL to disable callback
    /// Default: NULL
    pub reload_callback: matchy_reload_callback_t,

    /// User data pointer passed to reload callback
    /// Can be any pointer - callback receives it as-is
    /// Default: NULL
    pub reload_callback_user_data: *mut c_void,
}

impl Default for matchy_open_options_t {
    fn default() -> Self {
        Self {
            cache_capacity: 10000,
            auto_reload: false,
            auto_update: false,
            update_interval_secs: 3600,
            cache_dir: ptr::null(),
            reload_callback: None,
            reload_callback_user_data: ptr::null_mut(),
        }
    }
}

/// Initialize database opening options with defaults
///
/// Sets default values:
/// - cache_capacity = 10000
/// - auto_reload = false
///
/// # Parameters
/// * `options` - Pointer to options struct to initialize (must not be NULL)
///
/// # Safety
/// * `options` must be a valid pointer
///
/// # Example
/// ```c
/// matchy_open_options_t opts;
/// matchy_init_open_options(&opts);
/// opts.cache_capacity = 100000;  // Custom size
/// opts.auto_reload = true;        // Enable auto-reload
/// matchy_t *db = matchy_open_with_options("threats.mxy", &opts);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_init_open_options(options: *mut matchy_open_options_t) {
    ffi_guard((), || {
        if options.is_null() {
            return;
        }
        *options = matchy_open_options_t::default();
    });
}

/// Open database with custom options
///
/// Opens a database file with configurable cache size, auto-reload, and auto-update settings.
/// The mapped inode must remain immutable while the handle is open. For reloads,
/// write a complete replacement file and atomically rename it over the watched
/// path; do not rewrite or truncate the existing file in place.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
/// * `options` - Opening options (must not be NULL)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
/// * `options` must be a valid pointer
///
/// # Example
/// ```c
/// // High-performance mode with auto-reload
/// matchy_open_options_t opts;
/// matchy_init_open_options(&opts);
/// opts.cache_capacity = 100000; // Large cache
/// opts.auto_reload = true;      // Watch file for changes
///
/// matchy_t *db = matchy_open_with_options("threats.mxy", &opts);
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open database\n");
///     return 1;
/// }
///
/// // Queries automatically use latest database version
/// matchy_result_t result = matchy_query(db, "1.2.3.4");
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_open_with_options(
    filename: *const c_char,
    options: *const matchy_open_options_t,
) -> *mut matchy_t {
    ffi_guard(ptr::null_mut(), || {
        if filename.is_null() || options.is_null() {
            return ptr::null_mut();
        }

        let path = match CStr::from_ptr(filename).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        let opts = &*options;

        let mut opener = Database::from(path);

        if opts.cache_capacity == 0 {
            opener = opener.no_cache();
        } else {
            opener = opener.cache_capacity(opts.cache_capacity as usize);
        }

        if opts.auto_reload {
            opener = opener.watch();
        }

        #[cfg(feature = "auto-update")]
        if opts.auto_update {
            opener = opener
                .auto_update()
                .update_interval(std::time::Duration::from_secs(u64::from(
                    opts.update_interval_secs,
                )));

            if !opts.cache_dir.is_null() {
                if let Ok(dir) = CStr::from_ptr(opts.cache_dir).to_str() {
                    opener = opener.cache_dir(dir);
                }
            }
        }

        if let Some(callback) = opts.reload_callback {
            let adapter = CCallbackAdapter {
                callback,
                user_data: opts.reload_callback_user_data,
            };
            opener = opener.on_reload(move |event: ReloadEvent| {
                adapter.invoke(&event);
            });
        }

        match opener.open() {
            Ok(db) => {
                let internal = Box::new(MatchyInternal::new(db));
                matchy_t::from_internal(internal)
            }
            Err(_) => ptr::null_mut(),
        }
    })
}

/// Open database from file (memory-mapped) - SAFE mode
///
/// Opens a database file using memory mapping for optimal performance.
/// The file is not loaded into memory - it's accessed on-demand.
///
/// Keep the mapped file's inode immutable until `matchy_close()`. Publish an
/// update by writing a complete new file and atomically replacing the path;
/// never truncate or rewrite the mapped inode in place.
///
/// This validates UTF-8 on pattern string reads. Use for untrusted databases.
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
    ffi_guard(ptr::null_mut(), || {
        // Delegate to matchy_open_with_options with default settings
        let opts = matchy_open_options_t::default();
        matchy_open_with_options(filename, &opts)
    })
}

/// Open database from memory buffer.
///
/// Creates a database handle from a memory buffer. The buffer is copied into
/// the database handle, so the caller may modify or free the source buffer
/// after this function returns.
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
/// * `buffer` must point to a valid readable buffer of `size` bytes for the
///   duration of this call. The database copies the buffer before returning.
#[no_mangle]
pub unsafe extern "C" fn matchy_open_buffer(buffer: *const u8, size: usize) -> *mut matchy_t {
    ffi_guard(ptr::null_mut(), || {
        if buffer.is_null() || size == 0 {
            return ptr::null_mut();
        }

        let slice = slice::from_raw_parts(buffer, size);
        match Database::from_bytes(slice.to_vec()) {
            Ok(db) => {
                let internal = Box::new(MatchyInternal::new(db));
                matchy_t::from_internal(internal)
            }
            Err(_) => ptr::null_mut(),
        }
    })
}

/// Database statistics
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct matchy_stats_t {
    /// Total number of queries executed
    pub total_queries: u64,
    /// Queries that found a match
    pub queries_with_match: u64,
    /// Queries that found no match
    pub queries_without_match: u64,
    /// Cache hits (query served from cache)
    pub cache_hits: u64,
    /// Cache misses (query required lookup)
    pub cache_misses: u64,
    /// Number of IP address queries
    pub ip_queries: u64,
    /// Number of string queries (literal or pattern)
    pub string_queries: u64,
}

/// Get database statistics
///
/// Returns statistics about query performance, cache effectiveness,
/// and query distribution.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `stats` - Pointer to stats structure to fill (must not be NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `stats` must be a valid pointer to matchy_stats_t
///
/// # Example
/// ```c
/// matchy_stats_t stats;
/// matchy_get_stats(db, &stats);
/// printf("Total queries: %llu\n", stats.total_queries);
///
/// // Calculate hit rate
/// double cache_hit_rate = 0.0;
/// if (stats.cache_hits + stats.cache_misses > 0) {
///     cache_hit_rate = (double)stats.cache_hits /
///                      (stats.cache_hits + stats.cache_misses);
/// }
/// printf("Cache hit rate: %.1f%%\n", cache_hit_rate * 100.0);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_get_stats(db: *const matchy_t, stats: *mut matchy_stats_t) {
    ffi_guard((), || {
        if db.is_null() || stats.is_null() {
            return;
        }

        let internal = matchy_t::as_internal(db);
        let rust_stats = internal.database.stats();

        *stats = matchy_stats_t {
            total_queries: rust_stats.total_queries,
            queries_with_match: rust_stats.queries_with_match,
            queries_without_match: rust_stats.queries_without_match,
            cache_hits: rust_stats.cache_hits,
            cache_misses: rust_stats.cache_misses,
            ip_queries: rust_stats.ip_queries,
            string_queries: rust_stats.string_queries,
        };
    });
}

/// Clear the query cache
///
/// Removes all cached query results. Useful for benchmarking or
/// forcing fresh lookups.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
///
/// # Example
/// ```c
/// // Do some queries (fills cache)
/// matchy_query(db, "example.com");
///
/// // Clear cache to force fresh lookups
/// matchy_clear_cache(db);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_clear_cache(db: *const matchy_t) {
    ffi_guard((), || {
        if db.is_null() {
            return;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.clear_cache();
    });
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
    ffi_guard((), || {
        if !db.is_null() {
            let _ = matchy_t::into_internal(db);
        }
    });
}

/// Unified query interface - automatically detects IP vs pattern
///
/// Queries the database with an IP address or pattern. The function automatically
/// detects the query type and uses the appropriate lookup method.
///
/// Returns an offset/token-only result. Use matchy_result_get_entry() to access
/// structured data on demand, or matchy_result_to_json() to convert it to JSON.
/// With auto-reload enabled, this token is not bound to the database generation;
/// a reload between query and data navigation can invalidate its meaning. Use a
/// non-watching handle when snapshot-stable deferred data access is required.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `query` - IP address or pattern to search (null-terminated C string, must not be NULL)
///
/// # Returns
/// * matchy_result_t with found=true if match found
/// * matchy_result_t with found=false if there is no match or if lookup data is
///   malformed or exceeds a runtime resource limit; this compatibility API has
///   no per-query error channel
/// * Caller must free result with matchy_free_result
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `query` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "1.2.3.4");
/// if (result.found) {
///     // Option 1: Get as JSON
///     char *json = matchy_result_to_json(&result);
///     if (json != NULL) {
///         printf("Found: %s\n", json);
///         matchy_free_string(json);
///     }
///     
///     // Option 2: Access structured data
///     matchy_entry_s entry;
///     matchy_result_get_entry(&result, &entry);
///     // ... use matchy_aget_value()
/// }
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_query(
    db: *const matchy_t,
    query: *const c_char,
) -> matchy_result_t {
    ffi_guard(empty_matchy_result(), || {
        if db.is_null() || query.is_null() {
            return empty_matchy_result();
        }

        let query_str = match CStr::from_ptr(query).to_str() {
            Ok(s) => s,
            Err(_) => return empty_matchy_result(),
        };

        let internal = matchy_t::as_internal(db);
        match internal.database.lookup_ref(query_str) {
            Ok(lookup_ref) if lookup_ref.found => matchy_result_t {
                found: true,
                prefix_len: lookup_ref.prefix_len,
                _result_type: lookup_ref.result_type,
                _data_offset: lookup_ref.data_offset,
                _db_ref: db,
            },
            _ => empty_matchy_result(),
        }
    })
}

/// Unified query interface - writes result into provided struct pointer
///
/// Same as matchy_query but writes to a provided pointer instead of returning by value.
/// This is more FFI-friendly for some languages/platforms (like Java JNA on ARM64).
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `query` - IP address or pattern to search (null-terminated C string, must not be NULL)
/// * `result` - Pointer to result struct to fill (must not be NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `query` must be a valid null-terminated C string
/// * `result` must be a valid pointer to a matchy_result_t
///
/// # Example
/// ```c
/// matchy_result_t result;
/// matchy_query_into(db, "1.2.3.4", &result);
/// if (result.found) {
///     // Use result...
/// }
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_query_into(
    db: *const matchy_t,
    query: *const c_char,
    result: *mut matchy_result_t,
) {
    ffi_guard((), || {
        if result.is_null() {
            return;
        }
        *result = matchy_query(db, query);
    });
}

/// Free query result (no-op for the offset-only result struct)
///
/// This function exists for ABI compatibility but does nothing since
/// matchy_result_t now uses offsets instead of heap-allocated data.
///
/// # Parameters
/// * `result` - Pointer to result from matchy_query (may be NULL)
///
/// # Safety
/// * Safe to call with any pointer including NULL
#[no_mangle]
pub unsafe extern "C" fn matchy_free_result(_result: *mut matchy_result_t) {
    ffi_guard((), || {
        // No-op: matchy_result_t now stores offsets, not heap pointers
    });
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
    ffi_guard((), || {
        if !string.is_null() {
            let _ = CString::from_raw(string);
        }
    });
}

/// Get library version string
///
/// # Returns
/// * Version string (e.g., "0.4.0")
/// * Pointer is valid for program lifetime, do not free
#[no_mangle]
pub extern "C" fn matchy_version() -> *const c_char {
    ffi_guard(ptr::null(), || {
        // Use the version from Cargo.toml, automatically updated at compile time
        concat!(env!("CARGO_PKG_VERSION"), "\0")
            .as_ptr()
            .cast::<c_char>()
    })
}

/// Get database format description
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Format string ("IP database", "Pattern database", or "Combined IP+Pattern database")
/// * Pointer is valid for database lifetime, do not free
/// * NULL if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_format(db: *const matchy_t) -> *const c_char {
    ffi_guard(ptr::null(), || {
        if db.is_null() {
            return ptr::null();
        }

        let internal = matchy_t::as_internal(db);
        let format_str = internal.database.format();
        format_str.as_ptr().cast::<c_char>()
    })
}

/// Check if database supports IP address lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains IP data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_ip_data(db: *const matchy_t) -> bool {
    ffi_guard(false, || {
        if db.is_null() {
            return false;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.has_ip_data()
    })
}

/// Check if database supports string lookups (literals or globs)
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains literal or glob data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_string_data(db: *const matchy_t) -> bool {
    ffi_guard(false, || {
        if db.is_null() {
            return false;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.has_string_data()
    })
}

/// Check if database supports literal (exact string) lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains literal hash data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_literal_data(db: *const matchy_t) -> bool {
    ffi_guard(false, || {
        if db.is_null() {
            return false;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.has_literal_data()
    })
}

/// Check if database supports glob pattern lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains glob pattern data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_glob_data(db: *const matchy_t) -> bool {
    ffi_guard(false, || {
        if db.is_null() {
            return false;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.has_glob_data()
    })
}

/// Check if database supports pattern matching (deprecated)
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains pattern data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
///
/// # Deprecated
/// Use matchy_has_literal_data or matchy_has_glob_data instead
#[no_mangle]
#[deprecated(
    since = "0.5.0",
    note = "Use matchy_has_literal_data or matchy_has_glob_data instead"
)]
pub unsafe extern "C" fn matchy_has_pattern_data(db: *const matchy_t) -> bool {
    ffi_guard(false, || {
        if db.is_null() {
            return false;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.has_string_data()
    })
}

/// Get database metadata as JSON string
///
/// Returns MMDB metadata if available (for IP or combined databases).
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * JSON string containing metadata (caller must free with matchy_free_string)
/// * NULL if no metadata available or db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_metadata(db: *const matchy_t) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if db.is_null() {
            return ptr::null_mut();
        }

        let internal = matchy_t::as_internal(db);
        match internal.database.metadata() {
            Some(metadata) => {
                // Convert metadata to JSON string
                match serde_json::to_string(&metadata) {
                    Ok(json_str) => match CString::new(json_str) {
                        Ok(c_str) => c_str.into_raw(),
                        Err(_) => ptr::null_mut(),
                    },
                    Err(_) => ptr::null_mut(),
                }
            }
            None => ptr::null_mut(),
        }
    })
}

/// Get pattern string by ID
///
/// Returns the pattern string for a given pattern ID.
/// Only works for pattern or combined databases.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `pattern_id` - Pattern ID
///
/// # Returns
/// * Pattern string (caller must free with matchy_free_string)
/// * NULL if pattern ID not found or db has no patterns
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_get_pattern_string(
    db: *const matchy_t,
    pattern_id: u32,
) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if db.is_null() {
            return ptr::null_mut();
        }

        let internal = matchy_t::as_internal(db);

        // Get pattern string from database
        if let Some(pattern_str) = internal.database.get_pattern_string(pattern_id) {
            match CString::new(pattern_str) {
                Ok(c_str) => return c_str.into_raw(),
                Err(_) => return ptr::null_mut(),
            }
        }

        ptr::null_mut()
    })
}

/// Get total number of patterns in database
///
/// Returns the number of patterns in the database.
/// Only works for pattern or combined databases.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Number of patterns (0 if no patterns or db is NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_pattern_count(db: *const matchy_t) -> usize {
    ffi_guard(0, || {
        if db.is_null() {
            return 0;
        }

        let internal = matchy_t::as_internal(db);
        internal.database.pattern_count()
    })
}

// ============================================================================
// ENHANCED API - STRUCTURED DATA ACCESS
// ============================================================================

/// MMDB data type constants (matching libmaxminddb)
/// Extended type marker (internal use)
pub const MATCHY_DATA_TYPE_EXTENDED: u32 = 0;
/// Pointer type for data section references
pub const MATCHY_DATA_TYPE_POINTER: u32 = 1;
/// UTF-8 encoded string
pub const MATCHY_DATA_TYPE_UTF8_STRING: u32 = 2;
/// Double precision float (64-bit)
pub const MATCHY_DATA_TYPE_DOUBLE: u32 = 3;
/// Byte array / binary data
pub const MATCHY_DATA_TYPE_BYTES: u32 = 4;
/// Unsigned 16-bit integer
pub const MATCHY_DATA_TYPE_UINT16: u32 = 5;
/// Unsigned 32-bit integer
pub const MATCHY_DATA_TYPE_UINT32: u32 = 6;
/// Map/dictionary type
pub const MATCHY_DATA_TYPE_MAP: u32 = 7;
/// Signed 32-bit integer
pub const MATCHY_DATA_TYPE_INT32: u32 = 8;
/// Unsigned 64-bit integer
pub const MATCHY_DATA_TYPE_UINT64: u32 = 9;
/// Unsigned 128-bit integer
pub const MATCHY_DATA_TYPE_UINT128: u32 = 10;
/// Array type
pub const MATCHY_DATA_TYPE_ARRAY: u32 = 11;
/// Boolean type
pub const MATCHY_DATA_TYPE_BOOLEAN: u32 = 14;
/// Single precision float (32-bit)
pub const MATCHY_DATA_TYPE_FLOAT: u32 = 15;

/// Additional error codes for structured data API
/// Invalid lookup path specified
pub const MATCHY_ERROR_LOOKUP_PATH_INVALID: i32 = -9;
/// No data available at the specified path
pub const MATCHY_ERROR_NO_DATA: i32 = -10;
/// Failed to parse data value
pub const MATCHY_ERROR_DATA_PARSE: i32 = -11;

/// Entry data union (matches MMDB layout for compatibility)
#[repr(C)]
#[derive(Copy, Clone)]
pub union matchy_entry_data_value_u {
    /// Pointer to data section offset
    pub pointer: u32,
    /// Null-terminated UTF-8 string pointer
    pub utf8_string: *const c_char,
    /// 64-bit floating point value
    pub double_value: f64,
    /// Pointer to byte array
    pub bytes: *const u8,
    /// 16-bit unsigned integer value
    pub uint16: u16,
    /// 32-bit unsigned integer value
    pub uint32: u32,
    /// 32-bit signed integer value
    pub int32: i32,
    /// 64-bit unsigned integer value
    pub uint64: u64,
    /// 128-bit unsigned integer value (as byte array)
    pub uint128: [u8; 16],
    /// Boolean value
    pub boolean: bool,
    /// 32-bit floating point value
    pub float_value: f32,
}

/// Entry data structure (like MMDB_entry_data_s)
#[repr(C)]
pub struct matchy_entry_data_t {
    /// Whether data was found
    pub has_data: bool,
    /// Data type (one of MATCHY_DATA_TYPE_* constants)
    pub type_: u32,
    /// Actual data value
    pub value: matchy_entry_data_value_u,
    /// Size in bytes (for strings, bytes, maps, arrays)
    pub data_size: u32,
    /// Internal offset (for debugging)
    pub offset: u32,
}

/// Entry handle (like MMDB_entry_s)
#[repr(C)]
pub struct matchy_entry_s {
    /// Database handle
    pub db: *const matchy_t,
    /// Internal format-specific data token
    pub _data_offset: u32,
}

/// Entry data list node (like MMDB_entry_data_list_s)
#[repr(C)]
pub struct matchy_entry_data_list_t {
    /// The entry data for this node
    pub entry_data: matchy_entry_data_t,
    /// Pointer to the next node in the list (NULL if last)
    pub next: *mut Self,
}

struct EntryDataStorage {
    strings: Vec<CString>,
    bytes: Vec<Vec<u8>>,
    retained_bytes: usize,
    retained_bytes_limit: usize,
}

/// Private backing node large enough for both the native Matchy prefix and
/// libmaxminddb's trailing `pool` field. Public layouts remain unchanged;
/// compatibility callers may safely read `pool`, which is always NULL.
#[repr(C)]
struct CompatEntryDataListNode {
    node: matchy_entry_data_list_t,
    pool: *mut c_void,
}

impl CompatEntryDataListNode {
    fn new(entry_data: matchy_entry_data_t) -> Self {
        Self {
            node: matchy_entry_data_list_t {
                entry_data,
                next: ptr::null_mut(),
            },
            pool: ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct OwnedEntryDataList {
    node: CompatEntryDataListNode,
    remaining_nodes: Vec<CompatEntryDataListNode>,
    _storage: EntryDataStorage,
    allocation_capacity: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryDataConversionError {
    InvalidData,
    ResourceExhausted,
}

/// Return the exact additional capacity for exponential, fallible Vec growth
/// and its estimated allocation size. Growing to 1, 2, 4, ... preserves
/// amortized O(1) appends without relying on infallible `Vec::push` growth.
fn amortized_vec_growth<T>(values: &Vec<T>) -> Result<(usize, usize), EntryDataConversionError> {
    if values.len() < values.capacity() {
        return Ok((0, 0));
    }
    let target_capacity = if values.capacity() == 0 {
        1
    } else {
        values
            .capacity()
            .checked_mul(2)
            .ok_or(EntryDataConversionError::ResourceExhausted)?
    };
    let additional_capacity = target_capacity
        .checked_sub(values.len())
        .ok_or(EntryDataConversionError::ResourceExhausted)?;
    let estimated_bytes = target_capacity
        .checked_sub(values.capacity())
        .and_then(|count| count.checked_mul(mem::size_of::<T>()))
        .ok_or(EntryDataConversionError::ResourceExhausted)?;
    Ok((additional_capacity, estimated_bytes))
}

impl Default for EntryDataStorage {
    fn default() -> Self {
        Self::with_limit(ENTRY_DATA_STORAGE_LIMIT)
    }
}

impl EntryDataStorage {
    fn with_limit(retained_bytes_limit: usize) -> Self {
        Self {
            strings: Vec::new(),
            bytes: Vec::new(),
            retained_bytes: 0,
            retained_bytes_limit,
        }
    }

    /// Conservatively reserve part of the lifetime budget. Reservations are
    /// not rolled back after an allocation failure: doing so keeps repeated
    /// failed calls bounded as well.
    fn reserve_estimated_bytes(
        &mut self,
        additional: usize,
    ) -> Result<(), EntryDataConversionError> {
        let retained_bytes = self
            .retained_bytes
            .checked_add(additional)
            .ok_or(EntryDataConversionError::ResourceExhausted)?;
        if retained_bytes > self.retained_bytes_limit {
            return Err(EntryDataConversionError::ResourceExhausted);
        }
        self.retained_bytes = retained_bytes;
        Ok(())
    }

    fn retain_string(
        &mut self,
        string: &[u8],
    ) -> Result<(*const c_char, u32), EntryDataConversionError> {
        if string.contains(&0) {
            return Err(EntryDataConversionError::InvalidData);
        }

        let data_size =
            u32::try_from(string.len()).map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        let allocation_size = string
            .len()
            .checked_add(1)
            .ok_or(EntryDataConversionError::ResourceExhausted)?;
        let (additional_capacity, storage_growth) = amortized_vec_growth(&self.strings)?;
        let estimated_size = storage_growth
            .checked_add(allocation_size)
            .ok_or(EntryDataConversionError::ResourceExhausted)?;
        self.reserve_estimated_bytes(estimated_size)?;

        if additional_capacity != 0 {
            self.strings
                .try_reserve_exact(additional_capacity)
                .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        }
        let mut nul_terminated = Vec::new();
        nul_terminated
            .try_reserve_exact(allocation_size)
            .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        nul_terminated.extend_from_slice(string);
        nul_terminated.push(0);

        let string = CString::from_vec_with_nul(nul_terminated)
            .map_err(|_| EntryDataConversionError::InvalidData)?;
        let pointer = string.as_ptr();
        self.strings.push(string);
        Ok((pointer, data_size))
    }

    fn retain_bytes(&mut self, bytes: &[u8]) -> Result<(*const u8, u32), EntryDataConversionError> {
        let data_size =
            u32::try_from(bytes.len()).map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        let (additional_capacity, storage_growth) = amortized_vec_growth(&self.bytes)?;
        let estimated_size = storage_growth
            .checked_add(bytes.len())
            .ok_or(EntryDataConversionError::ResourceExhausted)?;
        self.reserve_estimated_bytes(estimated_size)?;

        if additional_capacity != 0 {
            self.bytes
                .try_reserve_exact(additional_capacity)
                .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
        retained.extend_from_slice(bytes);
        let pointer = retained.as_ptr();
        self.bytes.push(retained);
        Ok((pointer, data_size))
    }
}

impl matchy_entry_data_t {
    /// Create empty entry data
    fn empty() -> Self {
        Self {
            has_data: false,
            type_: 0,
            value: matchy_entry_data_value_u { uint32: 0 },
            data_size: 0,
            offset: 0,
        }
    }

    /// Convert DataValue to entry_data_t
    /// Strings and byte arrays are stored in the cache to keep pointers alive.
    fn from_data_value(
        value: &DataValue,
        storage: &mut EntryDataStorage,
    ) -> Result<Self, EntryDataConversionError> {
        let (type_, data_value, data_size) = match value {
            DataValue::Pointer(offset) => (
                MATCHY_DATA_TYPE_POINTER,
                matchy_entry_data_value_u { pointer: *offset },
                0,
            ),
            DataValue::String(s) => {
                let (pointer, data_size) = storage.retain_string(s.as_bytes())?;
                (
                    MATCHY_DATA_TYPE_UTF8_STRING,
                    matchy_entry_data_value_u {
                        utf8_string: pointer,
                    },
                    data_size,
                )
            }
            DataValue::Double(d) => (
                MATCHY_DATA_TYPE_DOUBLE,
                matchy_entry_data_value_u { double_value: *d },
                8,
            ),
            DataValue::Bytes(b) => {
                let (pointer, data_size) = storage.retain_bytes(b)?;
                (
                    MATCHY_DATA_TYPE_BYTES,
                    matchy_entry_data_value_u { bytes: pointer },
                    data_size,
                )
            }
            DataValue::Uint16(n) => (
                MATCHY_DATA_TYPE_UINT16,
                matchy_entry_data_value_u { uint16: *n },
                2,
            ),
            DataValue::Uint32(n) => (
                MATCHY_DATA_TYPE_UINT32,
                matchy_entry_data_value_u { uint32: *n },
                4,
            ),
            DataValue::Map(m) => (
                MATCHY_DATA_TYPE_MAP,
                matchy_entry_data_value_u { uint32: 0 },
                u32::try_from(m.len()).map_err(|_| EntryDataConversionError::InvalidData)?,
            ),
            DataValue::Int32(n) => (
                MATCHY_DATA_TYPE_INT32,
                matchy_entry_data_value_u { int32: *n },
                4,
            ),
            DataValue::Uint64(n) => (
                MATCHY_DATA_TYPE_UINT64,
                matchy_entry_data_value_u { uint64: *n },
                8,
            ),
            DataValue::Uint128(n) => {
                let bytes = n.to_be_bytes();
                (
                    MATCHY_DATA_TYPE_UINT128,
                    matchy_entry_data_value_u { uint128: bytes },
                    16,
                )
            }
            DataValue::Array(a) => (
                MATCHY_DATA_TYPE_ARRAY,
                matchy_entry_data_value_u { uint32: 0 },
                u32::try_from(a.len()).map_err(|_| EntryDataConversionError::InvalidData)?,
            ),
            DataValue::Bool(b) => (
                MATCHY_DATA_TYPE_BOOLEAN,
                matchy_entry_data_value_u { boolean: *b },
                1,
            ),
            DataValue::Float(f) => (
                MATCHY_DATA_TYPE_FLOAT,
                matchy_entry_data_value_u { float_value: *f },
                4,
            ),
            DataValue::Timestamp(epoch) => {
                // The largest chrono timestamp and an i64 decimal both fit in
                // this stack buffer. Formatting therefore performs no heap
                // allocation before the lifetime-cache budget is checked.
                struct TimestampBuffer {
                    bytes: [u8; 64],
                    len: usize,
                }

                impl Write for TimestampBuffer {
                    fn write_str(&mut self, value: &str) -> std::fmt::Result {
                        let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
                        let target = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
                        target.copy_from_slice(value.as_bytes());
                        self.len = end;
                        Ok(())
                    }
                }

                let mut formatted = TimestampBuffer {
                    bytes: [0; 64],
                    len: 0,
                };
                if let Some(timestamp) = chrono::Utc.timestamp_opt(*epoch, 0).single() {
                    write!(&mut formatted, "{}", timestamp.format("%Y-%m-%dT%H:%M:%SZ"))
                        .map_err(|_| EntryDataConversionError::InvalidData)?;
                } else {
                    write!(&mut formatted, "{epoch}")
                        .map_err(|_| EntryDataConversionError::InvalidData)?;
                }
                let (pointer, data_size) =
                    storage.retain_string(&formatted.bytes[..formatted.len])?;
                (
                    MATCHY_DATA_TYPE_UTF8_STRING,
                    matchy_entry_data_value_u {
                        utf8_string: pointer,
                    },
                    data_size,
                )
            }
        };

        Ok(Self {
            has_data: true,
            type_,
            value: data_value,
            data_size,
            offset: 0,
        })
    }

    /// Convert a map key to the UTF-8 node expected by MMDB-style flattened
    /// maps without allocating an intermediate owned `DataValue::String`.
    fn from_map_key(
        key: &str,
        storage: &mut EntryDataStorage,
    ) -> Result<Self, EntryDataConversionError> {
        let (pointer, data_size) = storage.retain_string(key.as_bytes())?;
        Ok(Self {
            has_data: true,
            type_: MATCHY_DATA_TYPE_UTF8_STRING,
            value: matchy_entry_data_value_u {
                utf8_string: pointer,
            },
            data_size,
            offset: 0,
        })
    }
}

/// Navigate into DataValue using a path of string keys
fn navigate_path<'a>(mut value: &'a DataValue, path: &[&str]) -> Option<&'a DataValue> {
    for key in path {
        match value {
            DataValue::Map(m) => {
                value = m.get(*key)?;
            }
            DataValue::Array(a) => {
                // Try to parse key as array index
                let idx: usize = key.parse().ok()?;
                value = a.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(value)
}

/// Get entry handle from query result
///
/// This extracts the entry handle which can be used for data navigation.
///
/// # Parameters
/// * `result` - Query result (must not be NULL, must have found=true)
/// * `entry` - Output entry handle (must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS on success
/// * MATCHY_ERROR_NO_DATA if result not found
/// * MATCHY_ERROR_INVALID_PARAM if parameters invalid
///
/// # Safety
/// * `result` must be valid result from matchy_query
/// * `entry` must be valid pointer to output struct
/// * Result must not have been freed
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "8.8.8.8");
/// if (result.found) {
///     matchy_entry_s entry;
///     matchy_result_get_entry(&result, &entry);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_result_get_entry(
    result: *const matchy_result_t,
    entry: *mut matchy_entry_s,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if result.is_null() || entry.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let res = &*result;
        if !res.found {
            return MATCHY_ERROR_NO_DATA;
        }

        (*entry).db = res._db_ref;
        (*entry)._data_offset = res._data_offset;

        MATCHY_SUCCESS
    })
}

// Note: Full varargs support (matchy_get_value) should be provided as a C macro
// or wrapper function that calls matchy_aget_value. For now, we provide the
// array-based version which is more portable.

/// Get value using array of strings for path
///
/// Like matchy_get_value but takes an array of strings instead of varargs.
///
/// # Parameters
/// * `entry` - Entry handle
/// * `entry_data` - Output data
/// * `path` - NULL-terminated array of string pointers
///
/// # Returns
/// * Same as matchy_get_value
/// * String and byte pointers written to `entry_data` remain valid until the
///   database handle is closed. To preserve that lifetime, each such value is
///   retained by the handle and is never evicted.
/// * MATCHY_ERROR_OUT_OF_MEMORY if the handle's 64 MiB retained-value budget
///   is exhausted. Previously returned pointers remain valid after this error.
/// * MATCHY_ERROR_INVALID_PARAM if the path exceeds the decoder's nesting
///   limit or contains invalid UTF-8.
///
/// # Safety
/// * Same as matchy_get_value
/// * `path` must be NULL-terminated array
///
/// # Example
/// ```c
/// const char *path[] = {"country", "iso_code", NULL};
/// matchy_aget_value(&entry, &data, path);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_aget_value(
    entry: *const matchy_entry_s,
    entry_data: *mut matchy_entry_data_t,
    path: *const *const c_char,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if entry.is_null() || entry_data.is_null() || path.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let mut path_vec = Vec::new();
        if path_vec
            .try_reserve_exact(MAX_LOOKUP_PATH_COMPONENTS)
            .is_err()
        {
            (*entry_data) = matchy_entry_data_t::empty();
            return MATCHY_ERROR_OUT_OF_MEMORY;
        }
        for index in 0..=MAX_LOOKUP_PATH_COMPONENTS {
            let component = *path.add(index);
            if component.is_null() {
                break;
            }
            if index == MAX_LOOKUP_PATH_COMPONENTS {
                (*entry_data) = matchy_entry_data_t::empty();
                return MATCHY_ERROR_INVALID_PARAM;
            }
            match CStr::from_ptr(component).to_str() {
                Ok(s) => path_vec.push(s),
                Err(_) => {
                    (*entry_data) = matchy_entry_data_t::empty();
                    return MATCHY_ERROR_INVALID_PARAM;
                }
            }
        }

        let db = (*entry).db;
        if db.is_null() {
            (*entry_data) = matchy_entry_data_t::empty();
            return MATCHY_ERROR_NO_DATA;
        }

        let internal = matchy_t::as_internal(db);
        let data = match internal.database.decode_at_offset((*entry)._data_offset) {
            Ok(d) => d,
            Err(error) => {
                (*entry_data) = matchy_entry_data_t::empty();
                return if matches!(error, DatabaseError::Unsupported(_)) {
                    MATCHY_ERROR_NO_DATA
                } else {
                    MATCHY_ERROR_DATA_PARSE
                };
            }
        };

        let target = match navigate_path(&data, &path_vec) {
            Some(v) => v,
            None => {
                (*entry_data) = matchy_entry_data_t::empty();
                return MATCHY_ERROR_LOOKUP_PATH_INVALID;
            }
        };

        let mut value_cache = match internal.value_cache.lock() {
            Ok(cache) => cache,
            Err(_) => {
                (*entry_data) = matchy_entry_data_t::empty();
                return MATCHY_ERROR_DATA_PARSE;
            }
        };

        match matchy_entry_data_t::from_data_value(target, &mut value_cache) {
            Ok(d) => {
                (*entry_data) = d;
                MATCHY_SUCCESS
            }
            Err(EntryDataConversionError::InvalidData) => {
                (*entry_data) = matchy_entry_data_t::empty();
                MATCHY_ERROR_DATA_PARSE
            }
            Err(EntryDataConversionError::ResourceExhausted) => {
                (*entry_data) = matchy_entry_data_t::empty();
                MATCHY_ERROR_OUT_OF_MEMORY
            }
        }
    })
}

fn build_entry_data_list(
    value: &DataValue,
    retained_bytes_limit: usize,
) -> Result<*mut matchy_entry_data_list_t, EntryDataConversionError> {
    let mut storage = EntryDataStorage::with_limit(retained_bytes_limit);
    // Account for the owner fields which are not already represented by the
    // first compatibility-sized list node. The remaining nodes and retained
    // values are charged as they are appended below.
    storage.reserve_estimated_bytes(
        mem::size_of::<OwnedEntryDataList>()
            .saturating_sub(mem::size_of::<CompatEntryDataListNode>()),
    )?;

    let mut first_node = None;
    let mut remaining_nodes = Vec::new();

    fn flatten_data(
        value: &DataValue,
        first_node: &mut Option<CompatEntryDataListNode>,
        remaining_nodes: &mut Vec<CompatEntryDataListNode>,
        storage: &mut EntryDataStorage,
    ) -> Result<(), EntryDataConversionError> {
        fn reserve_node(
            first_node: &Option<CompatEntryDataListNode>,
            remaining_nodes: &mut Vec<CompatEntryDataListNode>,
            storage: &mut EntryDataStorage,
        ) -> Result<(), EntryDataConversionError> {
            if first_node.is_none() {
                storage.reserve_estimated_bytes(mem::size_of::<CompatEntryDataListNode>())?;
            } else {
                let (additional_capacity, storage_growth) = amortized_vec_growth(remaining_nodes)?;
                storage.reserve_estimated_bytes(storage_growth)?;
                if additional_capacity != 0 {
                    remaining_nodes
                        .try_reserve_exact(additional_capacity)
                        .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
                }
            }
            Ok(())
        }

        fn append_node(
            entry_data: matchy_entry_data_t,
            first_node: &mut Option<CompatEntryDataListNode>,
            remaining_nodes: &mut Vec<CompatEntryDataListNode>,
        ) {
            let node = CompatEntryDataListNode::new(entry_data);
            if first_node.is_none() {
                *first_node = Some(node);
            } else {
                remaining_nodes.push(node);
            }
        }

        reserve_node(first_node, remaining_nodes, storage)?;
        let entry_data = matchy_entry_data_t::from_data_value(value, storage)?;
        append_node(entry_data, first_node, remaining_nodes);

        match value {
            DataValue::Map(map) => {
                for (key, child) in map {
                    reserve_node(first_node, remaining_nodes, storage)?;
                    let key_entry = matchy_entry_data_t::from_map_key(key, storage)?;
                    append_node(key_entry, first_node, remaining_nodes);
                    flatten_data(child, first_node, remaining_nodes, storage)?;
                }
            }
            DataValue::Array(array) => {
                for child in array {
                    flatten_data(child, first_node, remaining_nodes, storage)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    flatten_data(value, &mut first_node, &mut remaining_nodes, &mut storage)?;
    let mut first_node = first_node.ok_or(EntryDataConversionError::InvalidData)?;

    let remaining_base = remaining_nodes.as_mut_ptr();
    let remaining_len = remaining_nodes.len();
    for (index, node) in remaining_nodes.iter_mut().enumerate() {
        node.node.next = if index + 1 < remaining_len {
            remaining_base
                .wrapping_add(index + 1)
                .cast::<matchy_entry_data_list_t>()
        } else {
            ptr::null_mut()
        };
    }
    if !remaining_nodes.is_empty() {
        first_node.node.next = remaining_base.cast::<matchy_entry_data_list_t>();
    }

    // Stable Rust has no fallible Box allocation. A one-element Vec provides
    // equivalent stable ownership while allowing allocation failure to be
    // returned to C instead of aborting or leaking a partially-built list.
    let mut allocation = Vec::new();
    allocation
        .try_reserve_exact(1)
        .map_err(|_| EntryDataConversionError::ResourceExhausted)?;
    let allocation_capacity = allocation.capacity();
    allocation.push(OwnedEntryDataList {
        node: first_node,
        remaining_nodes,
        _storage: storage,
        allocation_capacity,
    });
    let list = allocation.as_mut_ptr().cast::<matchy_entry_data_list_t>();
    mem::forget(allocation);
    Ok(list)
}

/// Get full entry data as linked list (tree traversal)
///
/// This function traverses the entire data structure and returns it as
/// a flattened linked list. Arrays contain their recursively expanded values.
/// Maps contain each UTF-8 key immediately followed by its recursively
/// expanded value, matching libmaxminddb's list ordering.
///
/// # Parameters
/// * `entry` - Entry handle
/// * `entry_data_list` - Output list pointer
///
/// # Returns
/// * MATCHY_SUCCESS on success
/// * MATCHY_ERROR_OUT_OF_MEMORY if the list's 64 MiB estimated storage budget
///   is exceeded or an allocation fails
/// * MATCHY_ERROR_DATA_PARSE if a retained value is malformed
/// * Other error codes on failure
///
/// # Safety
/// * `entry` must be valid
/// * `entry_data_list` must be valid pointer
/// * Caller must free result with matchy_free_entry_data_list
///
/// # Example
/// ```c
/// matchy_entry_data_list_t *list = NULL;
/// if (matchy_get_entry_data_list(&entry, &list) == MATCHY_SUCCESS) {
///     for (matchy_entry_data_list_t *p = list; p != NULL; p = p->next) {
///         // Process p->entry_data
///     }
///     matchy_free_entry_data_list(list);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_get_entry_data_list(
    entry: *const matchy_entry_s,
    entry_data_list: *mut *mut matchy_entry_data_list_t,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if entry.is_null() || entry_data_list.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        *entry_data_list = ptr::null_mut();

        let db = (*entry).db;
        if db.is_null() {
            return MATCHY_ERROR_NO_DATA;
        }

        let internal = matchy_t::as_internal(db);
        let data = match internal.database.decode_at_offset((*entry)._data_offset) {
            Ok(d) => d,
            Err(DatabaseError::Unsupported(_)) => return MATCHY_ERROR_NO_DATA,
            Err(_) => return MATCHY_ERROR_DATA_PARSE,
        };
        match build_entry_data_list(&data, ENTRY_DATA_STORAGE_LIMIT) {
            Ok(list) => {
                *entry_data_list = list;
                MATCHY_SUCCESS
            }
            Err(EntryDataConversionError::InvalidData) => MATCHY_ERROR_DATA_PARSE,
            Err(EntryDataConversionError::ResourceExhausted) => MATCHY_ERROR_OUT_OF_MEMORY,
        }
    })
}

/// Free entry data list
///
/// Frees the linked list returned by matchy_get_entry_data_list.
///
/// # Parameters
/// * `list` - List to free (may be NULL)
///
/// # Safety
/// * `list` must be from matchy_get_entry_data_list or NULL
/// * Must not be freed twice
#[no_mangle]
pub unsafe extern "C" fn matchy_free_entry_data_list(list: *mut matchy_entry_data_list_t) {
    ffi_guard((), || {
        if list.is_null() {
            return;
        }

        let owner = list.cast::<OwnedEntryDataList>();
        let allocation_capacity = (*owner).allocation_capacity;
        let _ = Vec::from_raw_parts(owner, 1, allocation_capacity);
    });
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Get the update URL from database metadata
///
/// Returns the update URL stored in the database metadata (if any).
/// This is set during database build with matchy_builder_set_update_url().
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * URL string (caller must free with matchy_free_string)
/// * NULL if no update URL is set or db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
///
/// # Example
/// ```c
/// char *url = matchy_get_update_url(db);
/// if (url) {
///     printf("Update URL: %s\n", url);
///     matchy_free_string(url);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_get_update_url(db: *const matchy_t) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if db.is_null() {
            return ptr::null_mut();
        }

        let internal = matchy_t::as_internal(db);
        match internal.database.update_url() {
            Some(url) => match CString::new(url) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            None => ptr::null_mut(),
        }
    })
}

/// Check if auto-update feature is available
///
/// Returns whether the library was compiled with auto-update support.
/// When auto-update is available, you can set auto_update=true in
/// matchy_open_options_t to enable automatic background updates.
///
/// # Returns
/// * true if auto-update feature is compiled in
/// * false if not available (updates from URL will not work)
///
/// # Example
/// ```c
/// if (matchy_has_auto_update()) {
///     opts.auto_update = true;
///     opts.update_interval_secs = 3600;  // Check hourly
/// }
/// ```
#[no_mangle]
pub extern "C" fn matchy_has_auto_update() -> bool {
    ffi_guard(false, || {
        #[cfg(feature = "auto-update")]
        {
            true
        }
        #[cfg(not(feature = "auto-update"))]
        {
            false
        }
    })
}

/// Convert query result data to JSON string
///
/// This is a convenience function to convert the structured DataValue
/// to a JSON string for simple use cases.
///
/// # Parameters
/// * `result` - Query result (must not be NULL, must have found=true)
///
/// # Returns
/// * JSON string (caller must free with matchy_free_string)
/// * NULL if result is NULL, not found, or conversion fails
///
/// # Safety
/// * `result` must be a valid pointer to a result from matchy_query
/// * Result must not have been freed
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "8.8.8.8");
/// if (result.found) {
///     char *json = matchy_result_to_json(&result);
///     if (json) {
///         printf("Data: %s\n", json);
///         matchy_free_string(json);
///     }
/// }
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_result_to_json(result: *const matchy_result_t) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if result.is_null() || !(*result).found || (*result)._db_ref.is_null() {
            return ptr::null_mut();
        }

        let internal = matchy_t::as_internal((*result)._db_ref);
        let data = match internal.database.decode_at_offset((*result)._data_offset) {
            Ok(d) => d,
            Err(_) => return ptr::null_mut(),
        };

        let json_str = match serde_json::to_string(&data) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match CString::new(json_str) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    })
}

// ============================================================================
// VALIDATION API
// ============================================================================

/// Standard validation level - runtime envelope checks plus sampled reachable MMDB data.
///
/// For a known `database_type`, schema validation still checks every referenced
/// entry at this level.
pub const MATCHY_VALIDATION_STANDARD: i32 = 0;
/// Strict validation level - exhaustive MMDB records plus deep component checks.
pub const MATCHY_VALIDATION_STRICT: i32 = 1;

/// Validate a database file
///
/// Checks a `.mxy` database file at the requested coverage level.
/// Returns `MATCHY_SUCCESS` when the bytes read passed those checks, or an error
/// code when validation failed. Standard validation is sampled; use Strict for
/// untrusted input and impose deployment-appropriate resource limits.
///
/// A successful result applies only to the bytes read by this call. If the path
/// can be replaced before it is opened, validate a protected immutable snapshot
/// or bind the result to a content digest.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
/// * `level` - Validation level (MATCHY_VALIDATION_STANDARD or _STRICT)
/// * `error_message` - Pointer to receive error message (may be NULL if not needed)
///   If non-NULL and validation fails, receives a string that must be freed with matchy_free_string
///
/// # Returns
/// * MATCHY_SUCCESS (0) if database is valid
/// * Error code < 0 if validation failed or parameters invalid
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
/// * If `error_message` is non-NULL, caller must free the returned string
///
/// # Example
/// ```c
/// char *error = NULL;
/// int result = matchy_validate("/path/to/database.mxy", MATCHY_VALIDATION_STRICT, &error);
/// if (result != MATCHY_SUCCESS) {
///     fprintf(stderr, "Validation failed: %s\n", error ? error : "unknown error");
///     if (error) matchy_free_string(error);
///     return 1;
/// }
/// printf("The bytes read passed strict validation.\n");
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_validate(
    filename: *const c_char,
    level: i32,
    error_message: *mut *mut c_char,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        use crate::validation::{validate_database, ValidationLevel};
        use std::path::Path;

        if filename.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        let path_str = match CStr::from_ptr(filename).to_str() {
            Ok(s) => s,
            Err(_) => return MATCHY_ERROR_INVALID_PARAM,
        };

        let validation_level = match level {
            MATCHY_VALIDATION_STANDARD => ValidationLevel::Standard,
            MATCHY_VALIDATION_STRICT => ValidationLevel::Strict,
            _ => return MATCHY_ERROR_INVALID_PARAM,
        };

        match validate_database(Path::new(path_str), validation_level) {
            Ok(report) => {
                if report.is_valid() {
                    MATCHY_SUCCESS
                } else {
                    // Validation failed - populate error message if requested
                    if !error_message.is_null() {
                        let error_text = if report.errors.is_empty() {
                            "Validation failed (no error details)".to_string()
                        } else {
                            report.errors.join("; ")
                        };

                        if let Ok(c_str) = CString::new(error_text) {
                            *error_message = c_str.into_raw();
                        } else {
                            *error_message = ptr::null_mut();
                        }
                    }
                    MATCHY_ERROR_CORRUPT_DATA
                }
            }
            Err(_) => {
                if !error_message.is_null() {
                    if let Ok(c_str) = CString::new("Failed to validate database") {
                        *error_message = c_str.into_raw();
                    }
                }
                MATCHY_ERROR_IO
            }
        }
    })
}

// ============================================================================
// EXTRACTOR API
// ============================================================================

use crate::extractor::{ExtractedItem, Extractor, ExtractorBuilder, HashType};

// Extraction flags (bitmask)
/// Extract domain names (e.g., "example.com")
pub const MATCHY_EXTRACT_DOMAINS: u32 = 1 << 0;
/// Extract email addresses (e.g., "user@example.com")
pub const MATCHY_EXTRACT_EMAILS: u32 = 1 << 1;
/// Extract IPv4 addresses
pub const MATCHY_EXTRACT_IPV4: u32 = 1 << 2;
/// Extract IPv6 addresses
pub const MATCHY_EXTRACT_IPV6: u32 = 1 << 3;
/// Extract file hashes (MD5, SHA1, SHA256, SHA384, SHA512)
pub const MATCHY_EXTRACT_HASHES: u32 = 1 << 4;
/// Extract Bitcoin addresses
pub const MATCHY_EXTRACT_BITCOIN: u32 = 1 << 5;
/// Extract Ethereum addresses
pub const MATCHY_EXTRACT_ETHEREUM: u32 = 1 << 6;
/// Extract Monero addresses
pub const MATCHY_EXTRACT_MONERO: u32 = 1 << 7;
/// Extract all supported types
pub const MATCHY_EXTRACT_ALL: u32 = 0xFF;

// Item type constants (returned in match results)
/// Domain name
pub const MATCHY_ITEM_TYPE_DOMAIN: u8 = 0;
/// Email address
pub const MATCHY_ITEM_TYPE_EMAIL: u8 = 1;
/// IPv4 address
pub const MATCHY_ITEM_TYPE_IPV4: u8 = 2;
/// IPv6 address
pub const MATCHY_ITEM_TYPE_IPV6: u8 = 3;
/// MD5 hash (32 hex characters)
pub const MATCHY_ITEM_TYPE_MD5: u8 = 4;
/// SHA1 hash (40 hex characters)
pub const MATCHY_ITEM_TYPE_SHA1: u8 = 5;
/// SHA256 hash (64 hex characters)
pub const MATCHY_ITEM_TYPE_SHA256: u8 = 6;
/// SHA384 hash (96 hex characters)
pub const MATCHY_ITEM_TYPE_SHA384: u8 = 7;
/// SHA512 hash (128 hex characters)
pub const MATCHY_ITEM_TYPE_SHA512: u8 = 8;
/// Bitcoin address
pub const MATCHY_ITEM_TYPE_BITCOIN: u8 = 9;
/// Ethereum address
pub const MATCHY_ITEM_TYPE_ETHEREUM: u8 = 10;
/// Monero address
pub const MATCHY_ITEM_TYPE_MONERO: u8 = 11;

/// Opaque extractor handle
#[repr(C)]
pub struct matchy_extractor_t {
    _private: [u8; 0],
}

/// A single extracted match
#[repr(C)]
pub struct matchy_match_t {
    /// Item type (one of MATCHY_ITEM_TYPE_* constants)
    pub item_type: u8,
    /// The extracted value as a null-terminated string
    /// Valid for the lifetime of the matchy_matches_t
    pub value: *const c_char,
    /// Byte offset where the match starts in the input
    pub start: usize,
    /// Byte offset where the match ends in the input (exclusive)
    pub end: usize,
}

/// Array of extracted matches
#[repr(C)]
pub struct matchy_matches_t {
    /// Pointer to array of matches
    pub items: *const matchy_match_t,
    /// Number of matches
    pub count: usize,
    /// Internal pointer (do not use)
    _internal: *mut c_void,
}

// Internal storage for matches (keeps strings alive)
struct MatchesInternal {
    matches: Vec<matchy_match_t>,
    #[allow(dead_code)] // Kept to extend CString lifetimes for FFI pointers
    strings: Vec<CString>,
}

impl matchy_extractor_t {
    fn from_internal(internal: Box<Extractor>) -> *mut Self {
        Box::into_raw(internal).cast::<Self>()
    }

    unsafe fn to_internal(ptr: *mut Self) -> Box<Extractor> {
        Box::from_raw(ptr.cast::<Extractor>())
    }

    unsafe fn as_internal(ptr: *const Self) -> &'static Extractor {
        &*ptr.cast::<Extractor>()
    }
}

/// Get item type constant from ExtractedItem
fn item_type_from_extracted(item: &ExtractedItem) -> u8 {
    match item {
        ExtractedItem::Domain(_) => MATCHY_ITEM_TYPE_DOMAIN,
        ExtractedItem::Email(_) => MATCHY_ITEM_TYPE_EMAIL,
        ExtractedItem::Ipv4(_) => MATCHY_ITEM_TYPE_IPV4,
        ExtractedItem::Ipv6(_) => MATCHY_ITEM_TYPE_IPV6,
        ExtractedItem::Hash(HashType::Md5, _) => MATCHY_ITEM_TYPE_MD5,
        ExtractedItem::Hash(HashType::Sha1, _) => MATCHY_ITEM_TYPE_SHA1,
        ExtractedItem::Hash(HashType::Sha256, _) => MATCHY_ITEM_TYPE_SHA256,
        ExtractedItem::Hash(HashType::Sha384, _) => MATCHY_ITEM_TYPE_SHA384,
        ExtractedItem::Hash(HashType::Sha512, _) => MATCHY_ITEM_TYPE_SHA512,
        ExtractedItem::Bitcoin(_) => MATCHY_ITEM_TYPE_BITCOIN,
        ExtractedItem::Ethereum(_) => MATCHY_ITEM_TYPE_ETHEREUM,
        ExtractedItem::Monero(_) => MATCHY_ITEM_TYPE_MONERO,
    }
}

/// Create an extractor with specified extraction types
///
/// # Parameters
/// * `flags` - Bitmask of MATCHY_EXTRACT_* flags specifying what to extract
///
/// # Returns
/// * Non-null extractor handle on success
/// * NULL on failure
///
/// # Example
/// ```c
/// // Extract everything
/// matchy_extractor_t *ext = matchy_extractor_create(MATCHY_EXTRACT_ALL);
///
/// // Extract only domains and IPs
/// matchy_extractor_t *ext = matchy_extractor_create(
///     MATCHY_EXTRACT_DOMAINS | MATCHY_EXTRACT_IPV4 | MATCHY_EXTRACT_IPV6
/// );
/// ```
#[no_mangle]
pub extern "C" fn matchy_extractor_create(flags: u32) -> *mut matchy_extractor_t {
    ffi_guard(ptr::null_mut(), || {
        let builder = ExtractorBuilder::new()
            .extract_domains((flags & MATCHY_EXTRACT_DOMAINS) != 0)
            .extract_emails((flags & MATCHY_EXTRACT_EMAILS) != 0)
            .extract_ipv4((flags & MATCHY_EXTRACT_IPV4) != 0)
            .extract_ipv6((flags & MATCHY_EXTRACT_IPV6) != 0)
            .extract_hashes((flags & MATCHY_EXTRACT_HASHES) != 0)
            .extract_bitcoin((flags & MATCHY_EXTRACT_BITCOIN) != 0)
            .extract_ethereum((flags & MATCHY_EXTRACT_ETHEREUM) != 0)
            .extract_monero((flags & MATCHY_EXTRACT_MONERO) != 0);

        match builder.build() {
            Ok(extractor) => matchy_extractor_t::from_internal(Box::new(extractor)),
            Err(_) => ptr::null_mut(),
        }
    })
}

/// Extract patterns from a chunk of data
///
/// Extracts all enabled pattern types (domains, IPs, emails, hashes, crypto)
/// from the input data in a single pass.
///
/// # Parameters
/// * `extractor` - Extractor handle (must not be NULL)
/// * `data` - Input data buffer (must not be NULL)
/// * `len` - Length of input data in bytes
/// * `matches` - Output matches structure (must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS on success
/// * MATCHY_ERROR_INVALID_PARAM if any parameter is NULL
///
/// # Memory Management
/// Caller must free the matches with matchy_matches_free()
///
/// # Example
/// ```c
/// matchy_extractor_t *extractor = matchy_extractor_create(MATCHY_EXTRACT_ALL);
/// const char *text = "Check evil.com and 192.168.1.1";
/// matchy_matches_t matches;
///
/// if (matchy_extractor_extract_chunk(extractor, (const uint8_t *)text, strlen(text), &matches) == MATCHY_SUCCESS) {
///     for (size_t i = 0; i < matches.count; i++) {
///         printf("%s: %s\n",
///                matchy_item_type_name(matches.items[i].item_type),
///                matches.items[i].value);
///     }
///     matchy_matches_free(&matches);
/// }
/// matchy_extractor_free(extractor);
/// ```
///
/// # Safety
/// * `extractor` must be a valid pointer returned by `matchy_extractor_create`
/// * `data` must point to a valid buffer of at least `len` bytes
/// * `matches` must be a valid pointer to an uninitialized `matchy_matches_t`
#[no_mangle]
pub unsafe extern "C" fn matchy_extractor_extract_chunk(
    extractor: *const matchy_extractor_t,
    data: *const u8,
    len: usize,
    matches: *mut matchy_matches_t,
) -> i32 {
    ffi_guard(MATCHY_ERROR_INTERNAL, || {
        if extractor.is_null() || data.is_null() || matches.is_null() {
            return MATCHY_ERROR_INVALID_PARAM;
        }

        (*matches).items = ptr::null();
        (*matches).count = 0;
        (*matches)._internal = ptr::null_mut();

        let ext = matchy_extractor_t::as_internal(extractor);
        let chunk = slice::from_raw_parts(data, len);

        // Extract matches
        let rust_matches = ext.extract_from_chunk(chunk);

        // Convert to C representation
        let mut strings = Vec::with_capacity(rust_matches.len());
        let mut c_matches = Vec::with_capacity(rust_matches.len());

        for m in rust_matches {
            let value_str = m.item.as_value();
            let c_string = match CString::new(value_str) {
                Ok(s) => s,
                Err(_) => continue, // Skip invalid strings
            };

            c_matches.push(matchy_match_t {
                item_type: item_type_from_extracted(&m.item),
                value: c_string.as_ptr(),
                start: m.span.0,
                end: m.span.1,
            });
            strings.push(c_string);
        }

        // Store internal data and populate output
        let internal = Box::new(MatchesInternal {
            matches: c_matches,
            strings,
        });

        (*matches).items = internal.matches.as_ptr();
        (*matches).count = internal.matches.len();
        (*matches)._internal = Box::into_raw(internal).cast::<c_void>();

        MATCHY_SUCCESS
    })
}

/// Free the matches returned by matchy_extractor_extract_chunk
///
/// # Parameters
/// * `matches` - Matches structure to free (must not be NULL)
///
/// # Safety
/// * Must not use the matches after calling this function
#[no_mangle]
pub unsafe extern "C" fn matchy_matches_free(matches: *mut matchy_matches_t) {
    ffi_guard((), || {
        if matches.is_null() {
            return;
        }

        if !(*matches)._internal.is_null() {
            let _ = Box::from_raw((*matches)._internal.cast::<MatchesInternal>());
            (*matches)._internal = ptr::null_mut();
            (*matches).items = ptr::null();
            (*matches).count = 0;
        }
    });
}

/// Free the extractor
///
/// # Parameters
/// * `extractor` - Extractor handle (may be NULL)
///
/// # Safety
/// * Must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn matchy_extractor_free(extractor: *mut matchy_extractor_t) {
    ffi_guard((), || {
        if !extractor.is_null() {
            let _ = matchy_extractor_t::to_internal(extractor);
        }
    });
}

/// Get the string name for an item type constant
///
/// # Parameters
/// * `item_type` - One of the MATCHY_ITEM_TYPE_* constants
///
/// # Returns
/// * Static string like "Domain", "Email", "IPv4", etc.
/// * "Unknown" for invalid type values
///
/// # Note
/// The returned string is static and must not be freed.
#[no_mangle]
pub extern "C" fn matchy_item_type_name(item_type: u8) -> *const c_char {
    ffi_guard(ptr::null(), || {
        static DOMAIN: &[u8] = b"Domain\0";
        static EMAIL: &[u8] = b"Email\0";
        static IPV4: &[u8] = b"IPv4\0";
        static IPV6: &[u8] = b"IPv6\0";
        static MD5: &[u8] = b"MD5\0";
        static SHA1: &[u8] = b"SHA1\0";
        static SHA256: &[u8] = b"SHA256\0";
        static SHA384: &[u8] = b"SHA384\0";
        static SHA512: &[u8] = b"SHA512\0";
        static BITCOIN: &[u8] = b"Bitcoin\0";
        static ETHEREUM: &[u8] = b"Ethereum\0";
        static MONERO: &[u8] = b"Monero\0";
        static UNKNOWN: &[u8] = b"Unknown\0";

        let name = match item_type {
            MATCHY_ITEM_TYPE_DOMAIN => DOMAIN,
            MATCHY_ITEM_TYPE_EMAIL => EMAIL,
            MATCHY_ITEM_TYPE_IPV4 => IPV4,
            MATCHY_ITEM_TYPE_IPV6 => IPV6,
            MATCHY_ITEM_TYPE_MD5 => MD5,
            MATCHY_ITEM_TYPE_SHA1 => SHA1,
            MATCHY_ITEM_TYPE_SHA256 => SHA256,
            MATCHY_ITEM_TYPE_SHA384 => SHA384,
            MATCHY_ITEM_TYPE_SHA512 => SHA512,
            MATCHY_ITEM_TYPE_BITCOIN => BITCOIN,
            MATCHY_ITEM_TYPE_ETHEREUM => ETHEREUM,
            MATCHY_ITEM_TYPE_MONERO => MONERO,
            _ => UNKNOWN,
        };
        name.as_ptr().cast::<c_char>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn build_test_db_bytes() -> Vec<u8> {
        build_test_db_bytes_with_source("unit-test")
    }

    fn build_test_db_bytes_with_source(source: &str) -> Vec<u8> {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert("source".to_string(), DataValue::String(source.to_string()));
        builder.add_entry("1.1.1.1", data).unwrap();
        builder.build().unwrap()
    }

    fn estimated_string_size(value: &str) -> usize {
        mem::size_of::<CString>() + value.len() + 1
    }

    #[test]
    fn entry_data_storage_preserves_pointers_and_enforces_its_budget() {
        let value = DataValue::String("same".to_string());
        let per_value = estimated_string_size("same");
        let mut storage = EntryDataStorage::with_limit(per_value * 2);

        let first = matchy_entry_data_t::from_data_value(&value, &mut storage).unwrap();
        let second = matchy_entry_data_t::from_data_value(&value, &mut storage).unwrap();
        assert_eq!(storage.strings.len(), 2);
        assert!(matches!(
            matchy_entry_data_t::from_data_value(&value, &mut storage),
            Err(EntryDataConversionError::ResourceExhausted)
        ));
        assert!(matches!(
            matchy_entry_data_t::from_data_value(
                &DataValue::String("different".to_string()),
                &mut storage,
            ),
            Err(EntryDataConversionError::ResourceExhausted)
        ));

        // SAFETY: Both pointers refer to CString allocations retained by
        // `storage`, which remains alive for the duration of these reads.
        unsafe {
            assert_eq!(CStr::from_ptr(first.value.utf8_string).to_bytes(), b"same");
            assert_eq!(CStr::from_ptr(second.value.utf8_string).to_bytes(), b"same");
        }
    }

    #[test]
    fn entry_data_storage_charges_empty_value_overhead() {
        let string_cost = estimated_string_size("");
        let mut strings = EntryDataStorage::with_limit(string_cost);
        matchy_entry_data_t::from_data_value(&DataValue::String(String::new()), &mut strings)
            .unwrap();
        assert!(matches!(
            matchy_entry_data_t::from_data_value(&DataValue::String(String::new()), &mut strings,),
            Err(EntryDataConversionError::ResourceExhausted)
        ));

        let bytes_cost = mem::size_of::<Vec<u8>>();
        let mut bytes = EntryDataStorage::with_limit(bytes_cost);
        matchy_entry_data_t::from_data_value(&DataValue::Bytes(Vec::new()), &mut bytes).unwrap();
        assert!(matches!(
            matchy_entry_data_t::from_data_value(&DataValue::Bytes(Vec::new()), &mut bytes),
            Err(EntryDataConversionError::ResourceExhausted)
        ));
    }

    #[test]
    fn entry_data_storage_preserves_byte_and_timestamp_results() {
        let payload = vec![1, 2, 3, 4];
        let byte_cost = mem::size_of::<Vec<u8>>() + payload.len();
        let mut bytes = EntryDataStorage::with_limit(byte_cost);
        let retained =
            matchy_entry_data_t::from_data_value(&DataValue::Bytes(payload.clone()), &mut bytes)
                .unwrap();
        assert!(matches!(
            matchy_entry_data_t::from_data_value(&DataValue::Bytes(payload), &mut bytes),
            Err(EntryDataConversionError::ResourceExhausted)
        ));
        // SAFETY: The returned pointer is retained by `bytes` and its reported
        // size is the four-byte payload supplied above.
        unsafe {
            assert_eq!(
                slice::from_raw_parts(retained.value.bytes, 4),
                &[1, 2, 3, 4]
            );
        }

        let mut timestamp_storage = EntryDataStorage::default();
        let timestamp =
            matchy_entry_data_t::from_data_value(&DataValue::Timestamp(0), &mut timestamp_storage)
                .unwrap();
        // SAFETY: The pointer is retained by `timestamp_storage`.
        unsafe {
            assert_eq!(
                CStr::from_ptr(timestamp.value.utf8_string).to_bytes(),
                b"1970-01-01T00:00:00Z"
            );
        }
    }

    #[test]
    fn entry_data_conversion_distinguishes_malformed_strings() {
        let mut storage = EntryDataStorage::default();
        assert!(matches!(
            matchy_entry_data_t::from_data_value(
                &DataValue::String("bad\0value".to_string()),
                &mut storage,
            ),
            Err(EntryDataConversionError::InvalidData)
        ));
        assert!(storage.strings.is_empty());
        assert_eq!(storage.retained_bytes, 0);
    }

    #[test]
    fn entry_data_list_has_an_aggregate_budget_and_valid_storage() {
        let value = DataValue::Array(vec![
            DataValue::String("first".to_string()),
            DataValue::String("second".to_string()),
        ]);
        let owner_overhead = mem::size_of::<OwnedEntryDataList>()
            .saturating_sub(mem::size_of::<CompatEntryDataListNode>());
        let two_nodes_and_first_string = owner_overhead
            + 2 * mem::size_of::<CompatEntryDataListNode>()
            + estimated_string_size("first");
        assert_eq!(
            build_entry_data_list(&value, two_nodes_and_first_string).unwrap_err(),
            EntryDataConversionError::ResourceExhausted
        );

        let list = build_entry_data_list(&value, 4096).unwrap();
        // SAFETY: `list` was created by build_entry_data_list. Its retained
        // strings remain owned until the matching free call below.
        unsafe {
            assert_eq!((*list).entry_data.type_, MATCHY_DATA_TYPE_ARRAY);
            let first = (*list).next;
            assert!(!first.is_null());
            assert_eq!(
                CStr::from_ptr((*first).entry_data.value.utf8_string).to_bytes(),
                b"first"
            );
            let second = (*first).next;
            assert!(!second.is_null());
            assert_eq!(
                CStr::from_ptr((*second).entry_data.value.utf8_string).to_bytes(),
                b"second"
            );
            assert!((*second).next.is_null());
            matchy_free_entry_data_list(list);
        }
    }

    #[test]
    fn mmdb_entry_data_list_has_null_pool_and_map_key_value_order() {
        use crate::c_api::maxminddb_compat::{
            MMDB_entry_data_list_s, MMDB_entry_s, MMDB_free_entry_data_list,
            MMDB_get_entry_data_list,
        };

        assert_eq!(
            mem::size_of::<CompatEntryDataListNode>(),
            mem::size_of::<MMDB_entry_data_list_s>()
        );
        assert_eq!(
            mem::align_of::<CompatEntryDataListNode>(),
            mem::align_of::<MMDB_entry_data_list_s>()
        );

        let bytes = build_test_db_bytes();
        // SAFETY: The test owns every handle and C string used here, keeps the
        // database alive through list traversal, and frees each resource once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null());
            let query = CString::new("1.1.1.1").unwrap();
            let result = matchy_query(db, query.as_ptr());
            let mut matchy_entry = matchy_entry_s {
                db: ptr::null(),
                _data_offset: 0,
            };
            assert_eq!(
                matchy_result_get_entry(&result, &mut matchy_entry),
                MATCHY_SUCCESS
            );
            let mut mmdb_entry = MMDB_entry_s {
                mmdb: ptr::null(),
                _matchy_entry: matchy_entry,
            };
            let mut list: *mut MMDB_entry_data_list_s = ptr::null_mut();
            assert_eq!(MMDB_get_entry_data_list(&mut mmdb_entry, &mut list), 0);

            assert!(!list.is_null());
            assert_eq!((*list).entry_data.type_, MATCHY_DATA_TYPE_MAP);
            assert!((*list).pool.is_null());

            let key = (*list).next;
            assert!(!key.is_null());
            assert_eq!((*key).entry_data.type_, MATCHY_DATA_TYPE_UTF8_STRING);
            assert_eq!(
                CStr::from_ptr((*key).entry_data.value.utf8_string).to_bytes(),
                b"source"
            );
            assert!((*key).pool.is_null());

            let value = (*key).next;
            assert!(!value.is_null());
            assert_eq!((*value).entry_data.type_, MATCHY_DATA_TYPE_UTF8_STRING);
            assert_eq!(
                CStr::from_ptr((*value).entry_data.value.utf8_string).to_bytes(),
                b"unit-test"
            );
            assert!((*value).pool.is_null());
            assert!((*value).next.is_null());

            MMDB_free_entry_data_list(list);
            matchy_close(db);
        }
    }

    #[test]
    fn pattern_only_c_query_entry_and_aget_decode_inline_data() {
        use matchy_paraglob::Paraglob;

        let mut metadata = HashMap::new();
        metadata.insert("kind".to_string(), DataValue::String("inline".to_string()));
        let paraglob = Paraglob::build_from_patterns_with_data(
            &["*.pattern.test"],
            Some(&[Some(DataValue::Map(metadata))]),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        let bytes = paraglob.buffer();

        // SAFETY: All C pointers are derived from values kept alive through
        // the call sequence, and the database handle is closed exactly once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null());
            let query = CString::new("value.pattern.test").unwrap();
            let result = matchy_query(db, query.as_ptr());
            assert!(result.found);

            let mut entry = matchy_entry_s {
                db: ptr::null(),
                _data_offset: 0,
            };
            assert_eq!(matchy_result_get_entry(&result, &mut entry), MATCHY_SUCCESS);

            let key = CString::new("kind").unwrap();
            let path = [key.as_ptr(), ptr::null()];
            let mut value = matchy_entry_data_t::empty();
            assert_eq!(
                matchy_aget_value(&entry, &mut value, path.as_ptr()),
                MATCHY_SUCCESS
            );
            assert_eq!(value.type_, MATCHY_DATA_TYPE_UTF8_STRING);
            assert_eq!(
                CStr::from_ptr(value.value.utf8_string).to_bytes(),
                b"inline"
            );

            matchy_close(db);
        }
    }

    #[test]
    fn pattern_only_c_navigation_reports_no_data_for_valid_match() {
        use matchy_paraglob::Paraglob;

        let paraglob =
            Paraglob::build_from_patterns(&["*.pattern.test"], MatchMode::CaseSensitive).unwrap();
        let bytes = paraglob.buffer();

        // SAFETY: All pointers refer to live local values, and the handle and
        // optional list are released exactly once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null());
            let query = CString::new("value.pattern.test").unwrap();
            let result = matchy_query(db, query.as_ptr());
            assert!(result.found);

            let mut entry = matchy_entry_s {
                db: ptr::null(),
                _data_offset: 0,
            };
            assert_eq!(matchy_result_get_entry(&result, &mut entry), MATCHY_SUCCESS);

            let path: [*const c_char; 1] = [ptr::null()];
            let mut value = matchy_entry_data_t::empty();
            assert_eq!(
                matchy_aget_value(&entry, &mut value, path.as_ptr()),
                MATCHY_ERROR_NO_DATA
            );

            let mut list = ptr::null_mut();
            assert_eq!(
                matchy_get_entry_data_list(&entry, &mut list),
                MATCHY_ERROR_NO_DATA
            );
            assert!(list.is_null());
            matchy_close(db);
        }
    }

    #[test]
    fn matchy_aget_value_reports_cache_exhaustion_without_invalidating_old_pointer() {
        let bytes = build_test_db_bytes();

        // SAFETY: The test uses handles and pointers created here, keeps all
        // backing C strings alive, and closes the database exactly once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null());
            let internal = matchy_t::as_internal(db);
            *internal.value_cache.lock().unwrap() =
                EntryDataStorage::with_limit(estimated_string_size("unit-test"));

            let query = CString::new("1.1.1.1").unwrap();
            let result = matchy_query(db, query.as_ptr());
            let mut entry = matchy_entry_s {
                db: ptr::null(),
                _data_offset: 0,
            };
            assert_eq!(matchy_result_get_entry(&result, &mut entry), MATCHY_SUCCESS);

            let source = CString::new("source").unwrap();
            let path = [source.as_ptr(), ptr::null()];
            let mut first = matchy_entry_data_t::empty();
            assert_eq!(
                matchy_aget_value(&entry, &mut first, path.as_ptr()),
                MATCHY_SUCCESS
            );
            let first_pointer = first.value.utf8_string;
            assert_eq!(CStr::from_ptr(first_pointer).to_bytes(), b"unit-test");

            let mut second = matchy_entry_data_t::empty();
            assert_eq!(
                matchy_aget_value(&entry, &mut second, path.as_ptr()),
                MATCHY_ERROR_OUT_OF_MEMORY
            );
            assert!(!second.has_data);
            assert_eq!(CStr::from_ptr(first_pointer).to_bytes(), b"unit-test");

            matchy_close(db);
        }
    }

    #[test]
    fn matchy_aget_value_maps_malformed_data_and_overlong_paths() {
        let bytes = build_test_db_bytes_with_source("bad\0value");

        // SAFETY: The test uses handles and pointers created here, keeps all
        // backing C strings/path storage alive, and closes the database once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null());
            let query = CString::new("1.1.1.1").unwrap();
            let result = matchy_query(db, query.as_ptr());
            let mut entry = matchy_entry_s {
                db: ptr::null(),
                _data_offset: 0,
            };
            assert_eq!(matchy_result_get_entry(&result, &mut entry), MATCHY_SUCCESS);

            let source = CString::new("source").unwrap();
            let path = [source.as_ptr(), ptr::null()];
            let mut output = matchy_entry_data_t::empty();
            assert_eq!(
                matchy_aget_value(&entry, &mut output, path.as_ptr()),
                MATCHY_ERROR_DATA_PARSE
            );
            assert!(!output.has_data);

            let mut overlong_path = vec![source.as_ptr(); MAX_LOOKUP_PATH_COMPONENTS + 1];
            overlong_path.push(ptr::null());
            assert_eq!(
                matchy_aget_value(&entry, &mut output, overlong_path.as_ptr()),
                MATCHY_ERROR_INVALID_PARAM
            );
            assert!(!output.has_data);

            matchy_close(db);
        }
    }

    #[test]
    fn test_matchy_query_updates_c_api_stats() {
        let bytes = build_test_db_bytes();

        // SAFETY: The test passes valid pointers created in this scope, keeps the
        // backing byte buffer alive until after close, and closes the returned handle once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null(), "test database should open through C API");

            let query = CString::new("1.1.1.1").unwrap();
            let result = matchy_query(db, query.as_ptr());
            assert!(result.found, "C API query should find test IP");

            let mut stats = matchy_stats_t {
                total_queries: 0,
                queries_with_match: 0,
                queries_without_match: 0,
                cache_hits: 0,
                cache_misses: 0,
                ip_queries: 0,
                string_queries: 0,
            };
            matchy_get_stats(db, &mut stats);

            assert_eq!(stats.total_queries, 1);
            assert_eq!(stats.queries_with_match, 1);
            assert_eq!(stats.ip_queries, 1);

            matchy_close(db);
        }
    }

    #[test]
    fn test_ffi_guard_returns_fallback_on_panic() {
        let result = ffi_guard(MATCHY_ERROR_INTERNAL, || -> i32 {
            panic!("simulated FFI boundary panic");
        });

        assert_eq!(result, MATCHY_ERROR_INTERNAL);
    }

    #[test]
    fn test_matchy_open_buffer_copies_input_buffer() {
        let mut bytes = build_test_db_bytes();

        // SAFETY: The test passes a valid buffer pointer and closes the returned handle once.
        unsafe {
            let db = matchy_open_buffer(bytes.as_ptr(), bytes.len());
            assert!(!db.is_null(), "test database should open through C API");

            bytes.fill(0);

            let query = CString::new("1.1.1.1").unwrap();
            let result = matchy_query(db, query.as_ptr());
            assert!(
                result.found,
                "database should remain usable after caller mutates the source buffer"
            );

            matchy_close(db);
        }
    }

    #[test]
    fn test_c_api_error_codes_are_unique() {
        let error_codes = [
            MATCHY_ERROR_FILE_NOT_FOUND,
            MATCHY_ERROR_INVALID_FORMAT,
            MATCHY_ERROR_CORRUPT_DATA,
            MATCHY_ERROR_OUT_OF_MEMORY,
            MATCHY_ERROR_INVALID_PARAM,
            MATCHY_ERROR_IO,
            MATCHY_ERROR_SCHEMA_VALIDATION,
            MATCHY_ERROR_UNKNOWN_SCHEMA,
            MATCHY_ERROR_INTERNAL,
            MATCHY_ERROR_LOOKUP_PATH_INVALID,
            MATCHY_ERROR_NO_DATA,
            MATCHY_ERROR_DATA_PARSE,
        ];

        for (idx, code) in error_codes.iter().enumerate() {
            assert!(
                !error_codes[..idx].contains(code),
                "duplicate C API error code: {code}"
            );
        }
    }
}
