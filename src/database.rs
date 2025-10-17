//! Unified Database API
//!
//! Provides a single interface for querying databases that contain:
//! - IP address data (using binary search tree)
//! - Pattern data (using Aho-Corasick automaton)
//! - Combined databases with both IP and pattern data
//!
//! The database format is automatically detected and the appropriate
//! lookup method is used transparently.

use crate::data_section::DataValue;
use crate::literal_hash::LiteralHash;
use crate::mmdb::{MmdbError, MmdbHeader, SearchTree};
use crate::paraglob_offset::Paraglob;
use lru::LruCache;
use memmap2::Mmap;
use std::cell::RefCell;
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

/// Statistics for database queries and cache performance
#[derive(Debug, Clone, Copy, Default)]
pub struct DatabaseStats {
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

impl DatabaseStats {
    /// Calculate cache hit rate (0.0 to 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_ops = self.cache_hits + self.cache_misses;
        if total_cache_ops == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total_cache_ops as f64
        }
    }

    /// Calculate match rate (0.0 to 1.0)
    pub fn match_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.queries_with_match as f64 / self.total_queries as f64
        }
    }
}

/// Query result from a database lookup
#[derive(Debug, Clone)]
pub enum QueryResult {
    /// IP address lookup result
    Ip {
        /// The data associated with this IP
        data: DataValue,
        /// Network prefix length (CIDR)
        prefix_len: u8,
    },
    /// Pattern match result
    Pattern {
        /// Pattern IDs that matched
        pattern_ids: Vec<u32>,
        /// Optional data for matched patterns
        data: Vec<Option<DataValue>>,
    },
    /// Not found
    NotFound,
}

/// Database format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseFormat {
    /// Pure IP database (tree-based)
    IpOnly,
    /// Pure pattern database (.pgb)
    PatternOnly,
    /// Combined IP + pattern database
    Combined,
}

/// Unified database for IP and pattern lookups
///
/// This is the primary public API for querying threat intelligence,
/// GeoIP, or any IP/domain-based data. The database automatically
/// handles both IP addresses and domain patterns.
///
/// # Examples
///
/// ```no_run
/// use matchy::Database;
///
/// let db = Database::open("threats.db")?;
///
/// // IP lookup
/// if let Some(result) = db.lookup("1.2.3.4")? {
///     println!("Found threat data: {:?}", result);
/// }
///
/// // Pattern lookup
/// if let Some(result) = db.lookup("evil.com")? {
///     println!("Domain matches patterns: {:?}", result);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// Storage for database data - either owned or memory-mapped
enum DatabaseStorage {
    Owned(Vec<u8>),
    Mmap(Mmap),
}

impl DatabaseStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            DatabaseStorage::Owned(v) => v.as_slice(),
            DatabaseStorage::Mmap(m) => &m[..],
        }
    }
}

/// Lazy pattern data mappings for O(1) load time
/// Stores offset range instead of parsing all mappings eagerly
struct PatternDataMappings {
    /// Offset to start of mapping data (after pattern_count u32)
    mappings_offset: usize,
    /// Number of patterns (and thus offsets)
    pattern_count: usize,
}

impl PatternDataMappings {
    /// Get data offset for a specific pattern_id by parsing only that entry
    fn get_offset(&self, pattern_id: u32, data: &[u8]) -> Option<u32> {
        if pattern_id as usize >= self.pattern_count {
            return None;
        }

        let offset_pos = self.mappings_offset + (pattern_id as usize * 4);
        if offset_pos + 4 > data.len() {
            return None;
        }

        Some(u32::from_le_bytes([
            data[offset_pos],
            data[offset_pos + 1],
            data[offset_pos + 2],
            data[offset_pos + 3],
        ]))
    }
}

/// Default LRU cache size for query results
/// ~1-5 MB memory usage depending on result sizes
const DEFAULT_QUERY_CACHE_SIZE: usize = 10_000;

/// Options for opening a database
#[derive(Debug, Clone)]
pub struct DatabaseOptions {
    /// Path to the database file (optional for from_bytes)
    pub path: PathBuf,

    /// Skip validation checks (faster but less safe)
    pub trusted: bool,

    /// LRU cache capacity (None = use default, Some(0) = disable)
    pub cache_capacity: Option<usize>,

    /// Optional in-memory bytes (for from_bytes builder)
    pub bytes: Option<Vec<u8>>,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            trusted: false,
            cache_capacity: Some(DEFAULT_QUERY_CACHE_SIZE),
            bytes: None,
        }
    }
}

/// Builder for opening databases with custom configuration
///
/// Created via `Database::from(path)`. Use the fluent API to configure
/// options like caching and validation, then call `.open()` to load the database.
///
/// # Examples
///
/// ```no_run
/// use matchy::Database;
///
/// // Simple case with defaults
/// let db = Database::from("threats.mxy").open()?;
///
/// // Custom configuration
/// let db = Database::from("threats.mxy")
///     .trusted()
///     .cache_capacity(100_000)
///     .open()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DatabaseOpener {
    options: DatabaseOptions,
}

impl DatabaseOpener {
    /// Create a new database opener for the given path
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            options: DatabaseOptions {
                path: path.into(),
                ..Default::default()
            },
        }
    }

    /// Skip validation checks (faster, for trusted databases)
    ///
    /// # Security Warning
    ///
    /// Only use this for databases from trusted sources. Skips UTF-8
    /// validation and other safety checks for ~15-20% performance improvement.
    pub fn trusted(mut self) -> Self {
        self.options.trusted = true;
        self
    }

    /// Set LRU cache capacity
    ///
    /// The cache dramatically improves performance for workloads with
    /// repeated queries (80-95% hit rates typical in log analysis).
    ///
    /// Default: 10,000 entries (~1-5 MB memory)
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.options.cache_capacity = Some(capacity);
        self
    }

    /// Disable caching entirely
    ///
    /// Use this for workloads where queries are never repeated
    /// (e.g., sequential IP scans). Saves memory at cost of performance.
    pub fn no_cache(mut self) -> Self {
        self.options.cache_capacity = Some(0);
        self
    }

    /// Open the database with configured options
    pub fn open(self) -> Result<Database, DatabaseError> {
        Database::open_with_options(self.options)
    }

    /// Create a database opener from bytes (for testing/benchmarking)
    ///
    /// This allows you to configure cache settings before loading.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db_bytes = vec![/* ... */];
    ///
    /// // With cache disabled
    /// let db = Database::from_bytes_builder(db_bytes.clone())
    ///     .no_cache()
    ///     .open()?;
    ///
    /// // With custom cache
    /// let db = Database::from_bytes_builder(db_bytes)
    ///     .cache_capacity(50000)
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes_builder(bytes: Vec<u8>) -> DatabaseOpener {
        DatabaseOpener {
            options: DatabaseOptions {
                bytes: Some(bytes),
                ..Default::default()
            },
        }
    }
}

/// Unified database for IP and pattern lookups
pub struct Database {
    data: DatabaseStorage,
    format: DatabaseFormat,
    ip_header: Option<MmdbHeader>,
    /// Literal hash table for O(1) exact string lookups
    literal_hash: Option<LiteralHash<'static>>,
    /// Pattern matcher for glob patterns (Combined or PatternOnly databases)
    /// Uses RefCell for interior mutability since find_all needs &mut self
    pattern_matcher: Option<RefCell<Paraglob>>,
    /// For combined databases: lazy mapping from pattern_id -> data offset in MMDB data section
    /// None for pattern-only databases (which use Paraglob's internal data)
    pattern_data_mappings: Option<PatternDataMappings>,
    /// LRU query cache for recent lookups (IP, string, pattern)
    /// Uses RefCell for interior mutability on lookups
    /// Uses FxHasher (same as literal hash table) for fast non-cryptographic hashing
    /// Significantly improves performance for repeated queries (80-95% hit rate typical)
    pub(crate) query_cache:
        RefCell<LruCache<String, QueryResult, BuildHasherDefault<rustc_hash::FxHasher>>>,
    /// Whether caching is enabled (false = skip cache operations entirely)
    cache_enabled: bool,
    /// Query statistics (uses RefCell for interior mutability)
    stats: RefCell<DatabaseStats>,
}

impl Database {
    /// Create a database opener with fluent builder API
    ///
    /// This is the recommended way to open databases, providing clean
    /// configuration of cache size, validation, and future options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// // Defaults (cache enabled, validation on)
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Performance mode
    /// let db = Database::from("threats.mxy")
    ///     .trusted()
    ///     .cache_capacity(100_000)
    ///     .open()?;
    ///
    /// // No cache
    /// let db = Database::from("threats.mxy")
    ///     .no_cache()
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from(path: impl Into<PathBuf>) -> DatabaseOpener {
        DatabaseOpener::new(path)
    }

    /// Create a database builder from raw bytes
    ///
    /// Allows configuration of cache settings before loading from memory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db_bytes = vec![/* ... */];
    ///
    /// // With cache disabled for benchmarking
    /// let db = Database::from_bytes_builder(db_bytes.clone())
    ///     .no_cache()
    ///     .open()?;
    ///
    /// // With custom cache size
    /// let db = Database::from_bytes_builder(db_bytes)
    ///     .cache_capacity(50000)
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes_builder(bytes: Vec<u8>) -> DatabaseOpener {
        DatabaseOpener::from_bytes_builder(bytes)
    }

    /// Clear the query cache
    ///
    /// Removes all cached query results. Useful for benchmarking or
    /// when you want to force fresh lookups.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Do some queries (fills cache)
    /// db.lookup("example.com")?;
    ///
    /// // Clear cache to force fresh lookups
    /// db.clear_cache();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn clear_cache(&self) {
        self.query_cache.borrow_mut().clear();
    }

    /// Get database statistics
    ///
    /// Returns statistics about query performance, cache effectiveness,
    /// and query distribution.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Do some queries
    /// db.lookup("1.2.3.4")?;
    /// db.lookup("example.com")?;
    ///
    /// // Check stats
    /// let stats = db.stats();
    /// println!("Total queries: {}", stats.total_queries);
    /// println!("Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);
    /// println!("Match rate: {:.1}%", stats.match_rate() * 100.0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn stats(&self) -> DatabaseStats {
        *self.stats.borrow()
    }

    /// Open database with custom options (lower-level API)
    ///
    /// Most users should use `Database::from()` builder instead.
    pub fn open_with_options(options: DatabaseOptions) -> Result<Self, DatabaseError> {
        let trusted = options.trusted;
        let cache_capacity = options.cache_capacity;

        // Open the database - either from bytes or from file
        let mut db = if let Some(bytes) = options.bytes {
            // Load from bytes
            Self::from_storage_with_trust(DatabaseStorage::Owned(bytes), trusted)?
        } else {
            // Load from file
            Self::open_with_trust_internal(
                options
                    .path
                    .to_str()
                    .ok_or_else(|| DatabaseError::Io("Invalid path encoding".to_string()))?,
                trusted,
            )?
        };

        // Configure cache size (0 means disable, None means use default)
        if let Some(capacity) = cache_capacity {
            if capacity == 0 {
                // Disable cache completely - skip all cache operations
                db.cache_enabled = false;
            } else if capacity != DEFAULT_QUERY_CACHE_SIZE {
                // Resize cache (use FxHasher for speed)
                db.query_cache = std::cell::RefCell::new(lru::LruCache::with_hasher(
                    std::num::NonZeroUsize::new(capacity).unwrap(),
                    BuildHasherDefault::<rustc_hash::FxHasher>::default(),
                ));
                db.cache_enabled = true;
            }
            // else: keep default size and enabled
        }

        Ok(db)
    }
    /// Open a database file using memory mapping - SAFE mode (validates UTF-8)
    ///
    /// This uses mmap for zero-copy file access, which is much faster than
    /// loading the entire file into memory, especially for large databases.
    ///
    /// Validates UTF-8 on pattern string reads. Use for untrusted databases.
    ///
    /// Automatically detects the database format and initializes
    /// the appropriate lookup structures. Uses default cache settings.
    ///
    /// # Deprecation
    ///
    /// Use `Database::from(path).open()` for the new builder API with configurable options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matchy::Database;
    /// // Old way (still works)
    /// let db = Database::open("threats.mxy")?;
    ///
    /// // New way (recommended)
    /// let db = Database::from("threats.mxy").open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[deprecated(
        since = "1.1.0",
        note = "Use `Database::from(path).open()` instead for configurable options"
    )]
    pub fn open(path: &str) -> Result<Self, DatabaseError> {
        // Delegate to new builder API
        Self::from(path).open()
    }

    /// Open a database file using memory mapping - TRUSTED mode (skips UTF-8 validation)
    ///
    /// **SECURITY WARNING**: Only use for databases from trusted sources!
    /// Skips UTF-8 validation for ~15-20% performance improvement.
    ///
    /// This uses mmap for zero-copy file access, which is much faster than
    /// loading the entire file into memory, especially for large databases.
    ///
    /// # Deprecation
    ///
    /// Use `Database::from(path).trusted().open()` for the new builder API.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matchy::Database;
    /// // Old way (still works)
    /// let db = Database::open_trusted("threats.mxy")?;
    ///
    /// // New way (recommended)
    /// let db = Database::from("threats.mxy").trusted().open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[deprecated(
        since = "1.1.0",
        note = "Use `Database::from(path).trusted().open()` instead"
    )]
    pub fn open_trusted(path: &str) -> Result<Self, DatabaseError> {
        // Delegate to new builder API
        Self::from(path).trusted().open()
    }

    /// Internal: Open database with explicit trust mode
    /// Used by database_opener to bypass deprecated API
    pub(crate) fn open_with_trust_internal(
        path: &str,
        trusted: bool,
    ) -> Result<Self, DatabaseError> {
        let file = File::open(path)
            .map_err(|e| DatabaseError::Io(format!("Failed to open {}: {}", path, e)))?;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| DatabaseError::Io(format!("Failed to mmap {}: {}", path, e)))?;

        Self::from_storage_with_trust(DatabaseStorage::Mmap(mmap), trusted)
    }

    /// Create database from raw bytes (for testing)
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DatabaseError> {
        Self::from_storage(DatabaseStorage::Owned(data))
    }

    /// Internal: Create database from storage (safe mode - validates UTF-8)
    fn from_storage(storage: DatabaseStorage) -> Result<Self, DatabaseError> {
        Self::from_storage_with_trust(storage, false)
    }

    /// Internal: Create database from storage with explicit trust mode
    fn from_storage_with_trust(
        storage: DatabaseStorage,
        trusted: bool,
    ) -> Result<Self, DatabaseError> {
        // First, create the struct with minimal initialization
        let mut db = Self {
            data: storage,
            format: DatabaseFormat::IpOnly, // Temporary, will be set below
            ip_header: None,
            literal_hash: None,
            pattern_matcher: None,
            pattern_data_mappings: None,
            query_cache: RefCell::new(LruCache::with_hasher(
                NonZeroUsize::new(DEFAULT_QUERY_CACHE_SIZE).unwrap(),
                BuildHasherDefault::<rustc_hash::FxHasher>::default(),
            )),
            cache_enabled: true, // Default: cache enabled
            stats: RefCell::new(DatabaseStats::default()),
        };

        // Now we can safely get 'static reference since db owns the data
        let data: &'static [u8] = unsafe { std::mem::transmute(db.data.as_slice()) };

        // Detect format
        db.format = Self::detect_format(data)?;

        // Parse based on format
        match db.format {
            DatabaseFormat::IpOnly => {
                db.ip_header = Some(MmdbHeader::from_file(data).map_err(DatabaseError::Format)?);
            }
            DatabaseFormat::PatternOnly => {
                // Pattern-only: load from start of file
                let pg = Self::load_pattern_section(data, 0, trusted).map_err(|e| {
                    DatabaseError::Unsupported(format!("Failed to load pattern section: {}", e))
                })?;
                db.pattern_matcher = Some(RefCell::new(pg));
            }
            DatabaseFormat::Combined => {
                // Parse IP header first
                db.ip_header = Some(MmdbHeader::from_file(data).map_err(DatabaseError::Format)?);

                // Find and load pattern section after MMDB_PATTERN separator
                if let Some(offset) = Self::find_pattern_section_fast(data) {
                    let (pg, map) = Self::load_combined_pattern_section(data, offset, trusted)
                        .map_err(|e| {
                            DatabaseError::Unsupported(format!(
                                "Failed to load pattern section: {}",
                                e
                            ))
                        })?;
                    db.pattern_matcher = Some(RefCell::new(pg));
                    db.pattern_data_mappings = Some(map);
                }
            }
        }

        // Load literal hash section if present (MMDB_LITERAL marker)
        if let Some(offset) = Self::find_literal_section_fast(data) {
            // Skip the 16-byte marker
            let literal_data = &data[offset + 16..];
            // Read match mode from metadata
            let match_mode = Self::read_match_mode_from_metadata(data);
            db.literal_hash = Some(LiteralHash::from_buffer(literal_data, match_mode).map_err(
                |e| DatabaseError::Unsupported(format!("Failed to load literal hash: {}", e)),
            )?);
        }

        Ok(db)
    }

    /// Look up a query string (IP address or string pattern)
    ///
    /// Automatically determines if the query is an IP address or string
    /// and uses the appropriate lookup method.
    ///
    /// Queries are cached using an LRU cache. Repeated queries return
    /// cached results without re-parsing or re-searching. Cache hit rates
    /// of 80-95% are typical in log processing workloads.
    ///
    /// Returns `Ok(Some(result))` if found, `Ok(None)` if not found.
    pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // Check cache first (only if caching is enabled)
        if self.cache_enabled {
            if let Some(cached_result) = self.query_cache.borrow_mut().get(query) {
                // Cache hit - update stats in single borrow
                let mut stats = self.stats.borrow_mut();
                stats.total_queries += 1;
                stats.cache_hits += 1;
                drop(stats);
                return Ok(Some(cached_result.clone()));
            }
        }

        // Cache miss (or cache disabled) - perform actual lookup
        let result = if let Ok(addr) = query.parse::<IpAddr>() {
            self.lookup_ip_uncached(addr)?
        } else {
            self.lookup_string_uncached(query)?
        };

        // Update all stats in single borrow to minimize overhead
        {
            let mut stats = self.stats.borrow_mut();
            stats.total_queries += 1;

            // Track query type based on result
            match &result {
                Some(QueryResult::Ip { .. }) => stats.ip_queries += 1,
                Some(QueryResult::Pattern { .. }) | Some(QueryResult::NotFound) | None => {
                    stats.string_queries += 1
                }
            }

            // Track cache miss if caching enabled
            if self.cache_enabled {
                stats.cache_misses += 1;
            }

            // Track match/no-match
            if result.is_some() {
                stats.queries_with_match += 1;
            } else {
                stats.queries_without_match += 1;
            }
        }

        // Store in cache if result was found AND caching is enabled
        if self.cache_enabled {
            if let Some(ref res) = result {
                self.query_cache
                    .borrow_mut()
                    .put(query.to_string(), res.clone());
            }
        }

        Ok(result)
    }

    /// Look up an IP address (uncached internal method)
    ///
    /// Returns data associated with the IP address if found.
    /// This is the internal uncached version used by `lookup()`.
    fn lookup_ip_uncached(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
        let header = match &self.ip_header {
            Some(h) => h,
            None => return Ok(None), // No IP data in this database
        };

        // Traverse tree
        let tree = SearchTree::new(self.data.as_slice(), header);
        let tree_result = tree.lookup(addr).map_err(DatabaseError::Format)?;

        let tree_result = match tree_result {
            Some(r) => r,
            None => return Ok(Some(QueryResult::NotFound)),
        };

        // Decode data
        let data = self.decode_ip_data(header, tree_result.data_offset)?;

        Ok(Some(QueryResult::Ip {
            data,
            prefix_len: tree_result.prefix_len,
        }))
    }

    /// Look up an IP address (public API, uses cache)
    ///
    /// Returns data associated with the IP address if found.
    pub fn lookup_ip(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
        // Convert to string for cache key
        let query = addr.to_string();

        // Check cache first
        if let Some(cached_result) = self.query_cache.borrow_mut().get(&query) {
            return Ok(Some(cached_result.clone()));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_ip_uncached(addr)?;

        // Store in cache if found
        if let Some(ref res) = result {
            self.query_cache.borrow_mut().put(query, res.clone());
        }

        Ok(result)
    }

    /// Look up a string (literal or glob pattern) - uncached internal method
    ///
    /// Returns matching pattern IDs and associated data.
    /// Checks both:
    /// 1. Literal hash table for O(1) exact matches
    /// 2. Glob patterns for wildcard matches
    ///
    /// A query can match both a literal AND a glob pattern simultaneously.
    fn lookup_string_uncached(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
        let mut all_pattern_ids = Vec::new();
        let mut all_data_values = Vec::new();

        // 1. Try literal hash table first (O(1) lookup)
        if let Some(literal_hash) = &self.literal_hash {
            if let Some(pattern_id) = literal_hash.lookup(pattern) {
                // Found an exact match!
                if let Some(data_offset) = literal_hash.get_data_offset(pattern_id) {
                    let header = self.ip_header.as_ref().ok_or_else(|| {
                        DatabaseError::Format(MmdbError::InvalidFormat(
                            "Literal hash present but no IP header".to_string(),
                        ))
                    })?;
                    let data = self.decode_ip_data(header, data_offset)?;
                    all_pattern_ids.push(pattern_id);
                    all_data_values.push(Some(data));
                }
            }
        }

        // 2. Check glob patterns (for wildcard matches)
        if let Some(pg_cell) = &self.pattern_matcher {
            let pg = pg_cell.borrow();
            let glob_pattern_ids = pg.find_all(pattern);

            // Add glob matches
            for &pattern_id in &glob_pattern_ids {
                // For combined databases, use mappings to decode from MMDB data section
                // For pattern-only databases, use Paraglob's internal data cache
                let data = if let Some(mappings) = &self.pattern_data_mappings {
                    // Combined database: decode from MMDB data section using lazy lookup
                    if let Some(data_offset) = mappings.get_offset(pattern_id, self.data.as_slice())
                    {
                        let header = self.ip_header.as_ref().unwrap();
                        Some(self.decode_ip_data(header, data_offset)?)
                    } else {
                        None
                    }
                } else {
                    // Pattern-only database: use Paraglob's lazy data lookup
                    pg.get_pattern_data(pattern_id)
                };
                all_pattern_ids.push(pattern_id);
                all_data_values.push(data);
            }
        }

        // Return results
        if all_pattern_ids.is_empty() {
            // Only return NotFound if we actually have some pattern data
            if self.literal_hash.is_some() || self.pattern_matcher.is_some() {
                Ok(Some(QueryResult::NotFound))
            } else {
                Ok(None) // No pattern data in this database
            }
        } else {
            Ok(Some(QueryResult::Pattern {
                pattern_ids: all_pattern_ids,
                data: all_data_values,
            }))
        }
    }

    /// Look up a string (literal or glob pattern) - public API, uses cache
    ///
    /// Returns matching pattern IDs and associated data.
    pub fn lookup_string(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // Check cache first
        if let Some(cached_result) = self.query_cache.borrow_mut().get(pattern) {
            return Ok(Some(cached_result.clone()));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_string_uncached(pattern)?;

        // Store in cache if found
        if let Some(ref res) = result {
            self.query_cache
                .borrow_mut()
                .put(pattern.to_string(), res.clone());
        }

        Ok(result)
    }

    /// Decode IP data at a given offset
    /// Decode IP data at a given offset
    fn decode_ip_data(&self, header: &MmdbHeader, offset: u32) -> Result<DataValue, DatabaseError> {
        use crate::data_section::DataDecoder;

        // Offsets from the tree are relative to the start of the data section (after the 16-byte separator)
        // So we slice the buffer to start at tree_size + 16
        let data_section_start = header.tree_size + 16;
        let data_section = &self.data.as_slice()[data_section_start..];

        // Offsets from tree are relative to data_section, which we've sliced
        // So base_offset is 0 (the decoder will resolve pointers relative to the buffer start)
        let decoder = DataDecoder::new(data_section, 0);

        decoder
            .decode(offset)
            .map_err(|e| DatabaseError::Format(MmdbError::DecodeError(e.to_string())))
    }

    /// Detect database format (optimized to avoid full file scan)
    fn detect_format(data: &[u8]) -> Result<DatabaseFormat, DatabaseError> {
        // Check for paraglob magic at start (pattern-only format)
        let has_paraglob_start = data.len() >= 8 && &data[0..8] == b"PARAGLOB";
        if has_paraglob_start {
            return Ok(DatabaseFormat::PatternOnly);
        }

        // Check for MMDB metadata marker (searches last 128KB only)
        let has_mmdb = crate::mmdb::find_metadata_marker(data).is_ok();
        if !has_mmdb {
            return Err(DatabaseError::Format(MmdbError::InvalidFormat(
                "Unknown database format (no MMDB or PARAGLOB marker)".to_string(),
            )));
        }

        // Fast path: Check metadata for section offsets (new format)
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                // If pattern_section_offset exists in metadata, use it to determine format
                if let Some(DataValue::Uint32(pattern_offset)) = map.get("pattern_section_offset") {
                    // New format with metadata offsets
                    let has_patterns = *pattern_offset != 0;
                    if let Some(DataValue::Uint32(literal_offset)) =
                        map.get("literal_section_offset")
                    {
                        let has_literals = *literal_offset != 0;
                        if has_patterns || has_literals {
                            return Ok(DatabaseFormat::Combined);
                        } else {
                            return Ok(DatabaseFormat::IpOnly);
                        }
                    }
                }
            }
        }

        // Slow path: Old format without metadata offsets - need to scan
        // Check for MMDB_PATTERN separator (combined format)
        let pattern_separator = b"MMDB_PATTERN\x00\x00\x00\x00";
        let has_pattern_section = data.windows(16).any(|window| window == pattern_separator);

        if has_pattern_section {
            Ok(DatabaseFormat::Combined)
        } else {
            Ok(DatabaseFormat::IpOnly)
        }
    }

    /// Get database format
    pub fn format(&self) -> &str {
        match self.format {
            DatabaseFormat::IpOnly => "IP database",
            DatabaseFormat::PatternOnly => "Pattern database",
            DatabaseFormat::Combined => "Combined IP+Pattern database",
        }
    }

    /// Check if database supports IP lookups
    pub fn has_ip_data(&self) -> bool {
        self.ip_header.is_some()
    }

    /// Check if database supports string lookups (literals or patterns)
    pub fn has_string_data(&self) -> bool {
        self.literal_hash.is_some() || self.pattern_matcher.is_some()
    }

    /// Check if database supports literal (exact string) lookups
    pub fn has_literal_data(&self) -> bool {
        self.literal_hash.is_some()
    }

    /// Check if database supports glob pattern lookups
    pub fn has_glob_data(&self) -> bool {
        self.pattern_matcher.is_some()
    }

    /// Check if database supports pattern lookups (deprecated, use has_literal_data or has_glob_data)
    #[deprecated(
        since = "0.5.0",
        note = "Use has_literal_data or has_glob_data instead"
    )]
    pub fn has_pattern_data(&self) -> bool {
        self.has_string_data()
    }

    /// Get MMDB metadata if available
    ///
    /// Returns the full metadata as a DataValue map, or None if this is not
    /// an MMDB-format database or if metadata cannot be parsed.
    pub fn metadata(&self) -> Option<DataValue> {
        if !self.has_ip_data() {
            return None;
        }

        use crate::mmdb::MmdbMetadata;
        let metadata = MmdbMetadata::from_file(self.data.as_slice()).ok()?;
        metadata.as_value().ok()
    }

    /// Get pattern string by ID
    ///
    /// Returns the pattern string for a given pattern ID.
    /// Returns None if the database has no pattern data or pattern ID is invalid.
    pub fn get_pattern_string(&self, pattern_id: u32) -> Option<String> {
        let pg_cell = self.pattern_matcher.as_ref()?;
        let pg = pg_cell.borrow();
        pg.get_pattern(pattern_id)
    }

    /// Get total number of glob patterns
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no pattern data.
    pub fn pattern_count(&self) -> usize {
        match &self.pattern_matcher {
            Some(pg_cell) => {
                let pg = pg_cell.borrow();
                pg.pattern_count()
            }
            None => 0,
        }
    }

    /// Get number of glob patterns (alias for pattern_count)
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no glob pattern data.
    pub fn glob_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("glob_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // Fallback to pattern_count
        self.pattern_count()
    }

    /// Get number of literal patterns
    ///
    /// Returns the number of literal (exact-match) patterns in the database.
    /// Returns 0 if the database has no literal pattern data.
    pub fn literal_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("literal_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // Fallback to literal_hash entry count
        match &self.literal_hash {
            Some(lh) => lh.entry_count() as usize,
            None => 0,
        }
    }

    /// Get number of IP address entries
    ///
    /// Returns the number of IP entries in the database.
    /// Returns 0 if the database has no IP data.
    pub fn ip_count(&self) -> usize {
        // Try to get from metadata first (most accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("ip_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // No accurate fallback for IP count
        0
    }

    /// Helper to extract unsigned integer from DataValue
    fn extract_uint_from_datavalue(value: &DataValue) -> Option<u64> {
        match value {
            DataValue::Uint16(v) => Some(*v as u64),
            DataValue::Uint32(v) => Some(*v as u64),
            DataValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    /// Find the pattern section using fast metadata lookup with fallback to scanning
    /// Returns the offset to the start of pattern data (after MMDB_PATTERN marker)
    fn find_pattern_section_fast(data: &[u8]) -> Option<usize> {
        // Fast path: Try to read offset from metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint32(offset)) = map.get("pattern_section_offset") {
                    let offset_val = *offset as usize;
                    // 0 means no pattern section (fast negative result)
                    if offset_val == 0 {
                        return None;
                    }
                    return Some(offset_val);
                }
            }
        }

        // Slow path: Scan for separator (backwards compatibility)
        eprintln!("Warning: Database lacks section offset metadata, falling back to full file scan (slower load time)");
        Self::find_pattern_section_slow(data)
    }

    /// Find the pattern section by scanning (slow, for backwards compatibility)
    /// Returns the offset to the start of pattern data (after MMDB_PATTERN marker)
    fn find_pattern_section_slow(data: &[u8]) -> Option<usize> {
        let separator = b"MMDB_PATTERN\x00\x00\x00\x00";

        // Search for the separator
        for i in 0..data.len().saturating_sub(16) {
            if &data[i..i + 16] == separator {
                // Pattern section starts after the 16-byte separator
                return Some(i + 16);
            }
        }
        None
    }

    /// Find the literal section using fast metadata lookup with fallback to scanning
    /// Returns the offset to the start of MMDB_LITERAL marker
    fn find_literal_section_fast(data: &[u8]) -> Option<usize> {
        // Fast path: Try to read offset from metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint32(offset)) = map.get("literal_section_offset") {
                    let offset_val = *offset as usize;
                    // 0 means no literal section (fast negative result)
                    if offset_val == 0 {
                        return None;
                    }
                    // Metadata stores offset to start of data, but we need offset to marker
                    // So subtract 16 bytes for the "MMDB_LITERAL" marker
                    return Some(offset_val - 16);
                }
            }
        }

        // Slow path: Scan for separator (backwards compatibility)
        if data.len() > 1024 * 1024 {
            // Only warn for files > 1MB
            eprintln!("Warning: Database lacks section offset metadata, falling back to full file scan (slower load time)");
        }
        Self::find_literal_section_slow(data)
    }

    /// Find the literal hash section by scanning (slow, for backwards compatibility)
    /// Returns the offset to the start of MMDB_LITERAL marker
    fn find_literal_section_slow(data: &[u8]) -> Option<usize> {
        let separator = b"MMDB_LITERAL\x00\x00\x00\x00";

        // Search for the separator
        (0..data.len().saturating_sub(16)).find(|&i| &data[i..i + 16] == separator)
    }

    /// Load pattern section from data at given offset (for pattern-only databases)
    /// The format at offset is: PARAGLOB magic + data
    /// Uses zero-copy from_mmap for O(1) loading
    fn load_pattern_section(
        data: &'static [u8],
        offset: usize,
        trusted: bool,
    ) -> Result<Paraglob, String> {
        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // Try to read match mode from metadata
        let match_mode = Self::read_match_mode_from_metadata(data);

        // For pattern-only databases, data starts with PARAGLOB magic
        if offset == 0 && data.len() >= 8 && &data[0..8] == b"PARAGLOB" {
            // Standard .pgb format - load with zero-copy
            // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
            let result = if trusted {
                unsafe { Paraglob::from_mmap_trusted(data, match_mode) }
            } else {
                unsafe { Paraglob::from_mmap(data, match_mode) }
            };
            return result.map_err(|e| format!("Failed to parse pattern-only database: {}", e));
        }

        Err("Invalid pattern-only database format".to_string())
    }

    /// Load combined pattern section from data at given offset
    /// The format at offset is: `[total_size][paraglob_size][PARAGLOB data][pattern_count][data_offsets...]`
    /// Returns (Paraglob matcher, lazy PatternDataMappings)
    /// Uses zero-copy and deferred parsing for O(1) load time
    fn load_combined_pattern_section(
        data: &'static [u8],
        offset: usize,
        trusted: bool,
    ) -> Result<(Paraglob, PatternDataMappings), String> {
        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // Try to read match mode from metadata
        let match_mode = Self::read_match_mode_from_metadata(data);

        // Read section header
        if offset + 8 > data.len() {
            return Err("Pattern section header truncated".to_string());
        }

        // Read sizes (little-endian u32)
        let _total_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let paraglob_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        // Paraglob data starts at offset + 8
        let paraglob_start = offset + 8;
        let paraglob_end = paraglob_start + paraglob_size;

        if paraglob_end > data.len() {
            return Err(format!(
                "Paraglob section extends beyond file (start={}, size={}, file_len={})",
                paraglob_start,
                paraglob_size,
                data.len()
            ));
        }

        // Extract and load paraglob data with zero-copy
        let paraglob_data = &data[paraglob_start..paraglob_end];
        // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
        let paraglob = if trusted {
            unsafe { Paraglob::from_mmap_trusted(paraglob_data, match_mode) }
        } else {
            unsafe { Paraglob::from_mmap(paraglob_data, match_mode) }
        };
        let paraglob = paraglob.map_err(|e| format!("Failed to parse paraglob section: {}", e))?;

        // Store mapping metadata WITHOUT parsing all offsets (O(1) instead of O(n))
        let mappings_start = paraglob_end;
        if mappings_start + 4 > data.len() {
            return Err("Pattern mappings section truncated".to_string());
        }

        let pattern_count = u32::from_le_bytes([
            data[mappings_start],
            data[mappings_start + 1],
            data[mappings_start + 2],
            data[mappings_start + 3],
        ]) as usize;

        let offsets_start = mappings_start + 4;

        // Validate the mapping section exists, but don't parse it
        let total_mapping_bytes = pattern_count * 4;
        if offsets_start + total_mapping_bytes > data.len() {
            return Err(format!(
                "Pattern mappings section out of bounds (need {} bytes)",
                total_mapping_bytes
            ));
        }

        let mappings = PatternDataMappings {
            mappings_offset: offsets_start,
            pattern_count,
        };

        Ok((paraglob, mappings))
    }

    /// Read match mode from database metadata
    /// Returns CaseSensitive as default if not found or on error
    fn read_match_mode_from_metadata(data: &[u8]) -> crate::glob::MatchMode {
        use crate::glob::MatchMode;

        // Try to read metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint16(mode_val)) = map.get("match_mode") {
                    return match *mode_val {
                        1 => MatchMode::CaseInsensitive,
                        _ => MatchMode::CaseSensitive, // 0 or unknown = CaseSensitive (default)
                    };
                }
            }
        }

        // Default to case-sensitive for backward compatibility with old databases
        MatchMode::CaseSensitive
    }
}

/// Database error type
#[derive(Debug)]
pub enum DatabaseError {
    /// I/O error
    Io(String),
    /// Format error
    Format(MmdbError),
    /// Unsupported operation
    Unsupported(String),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::Io(msg) => write!(f, "I/O error: {}", msg),
            DatabaseError::Format(err) => write!(f, "Format error: {}", err),
            DatabaseError::Unsupported(msg) => write!(f, "Unsupported: {}", msg),
        }
    }
}

impl std::error::Error for DatabaseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ip_database() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();
        assert_eq!(db.format, DatabaseFormat::IpOnly);
        assert!(db.has_ip_data());
        assert!(!db.has_string_data());
    }

    #[test]
    fn test_lookup_ip_address() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        // Test IP lookup
        let result = db.lookup("1.1.1.1").unwrap();
        assert!(result.is_some());

        if let Some(QueryResult::Ip { data, prefix_len }) = result {
            assert!(prefix_len > 0);
            assert!(prefix_len <= 32);

            // Should have map data
            match data {
                DataValue::Map(map) => {
                    assert!(!map.is_empty());
                }
                _ => panic!("Expected map data"),
            }
        } else {
            panic!("Expected IP result");
        }
    }

    #[test]
    fn test_lookup_ipv6() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let result = db.lookup("2001:4860:4860::8888").unwrap();
        assert!(result.is_some());

        if let Some(QueryResult::Ip { prefix_len, .. }) = result {
            assert!(prefix_len > 0);
            assert!(prefix_len <= 128);
        }
    }

    #[test]
    fn test_lookup_not_found() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let result = db.lookup("127.0.0.1").unwrap();
        assert!(matches!(result, Some(QueryResult::NotFound)));
    }

    #[test]
    fn test_auto_detect_query_type() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        // Should auto-detect as IP
        let result = db.lookup("8.8.8.8").unwrap();
        assert!(matches!(result, Some(QueryResult::Ip { .. })));

        // Should auto-detect as pattern (but no pattern data in this DB)
        let result = db.lookup("example.com").unwrap();
        assert!(result.is_none() || matches!(result, Some(QueryResult::NotFound)));
    }
}
