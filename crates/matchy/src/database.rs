//! Unified Database API
//!
//! Provides a single interface for querying databases that contain:
//! - IP address data (using binary search tree)
//! - Pattern data (using Aho-Corasick automaton)
//! - Combined databases with both IP and pattern data
//!
//! The database format is automatically detected and the appropriate
//! lookup method is used transparently.

use crate::mmdb::{MmdbError, MmdbHeader, SearchTree};
use lru::LruCache;
use matchy_data_format::{DataDecoder, DataValue, DecodeBudget};
use matchy_literal_hash::LiteralHash;
use matchy_paraglob::{error::ParaglobError, offset_format::ParaglobHeader, Paraglob};
use std::cell::RefCell;
use std::hash::BuildHasherDefault;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::ops::{Deref, Range};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zerocopy::FromBytes;

#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

#[cfg(not(target_family = "wasm"))]
use crate::updater::{LiveOptions, LiveState};

#[cfg(not(target_family = "wasm"))]
use memmap2::Mmap;
#[cfg(not(target_family = "wasm"))]
use std::fs::File;

#[cfg(not(target_family = "wasm"))]
pub use crate::updater::{
    FallbackCallback, FallbackEvent, ReloadCallback, ReloadEvent, ReloadSource,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheQueryKind {
    Ip,
    String,
}

#[derive(Debug, Clone)]
enum CachedQueryValue {
    Owned(QueryResult),
    Reference(LookupRef),
}

#[derive(Debug, Clone)]
struct CachedQueryResult {
    kind: CacheQueryKind,
    value: CachedQueryValue,
}

type QueryCacheEntries =
    LruCache<String, CachedQueryResult, BuildHasherDefault<rustc_hash::FxHasher>>;

/// Maximum estimated result heap retained by all database caches in one thread.
const QUERY_CACHE_HEAP_BUDGET: usize = 64 * 1024 * 1024;
const MAX_QUERY_CACHE_NAMESPACES: usize = 16;
const QUERY_CACHE_COMPACTION_MIN_HIGH_WATER: usize = 64;
const MAX_STRING_QUERY_MATCHES: usize = 65_536;
const MAX_STRING_QUERY_MATCHING_WORK: usize = 1_000_000;

/// A result cache bounded by both entry count and estimated retained heap.
struct QueryCacheInner {
    entries: QueryCacheEntries,
    entry_limit: usize,
    entry_high_water_len: usize,
    retained_heap_bytes: usize,
    heap_budget: usize,
    #[cfg(test)]
    compaction_count: usize,
}

impl QueryCacheInner {
    fn empty_entries() -> QueryCacheEntries {
        LruCache::unbounded_with_hasher(BuildHasherDefault::<rustc_hash::FxHasher>::default())
    }

    fn new(capacity: NonZeroUsize, heap_budget: usize) -> Self {
        Self {
            // The bounded constructor preallocates for the full capacity. Use
            // incremental storage and enforce the configured entry limit below
            // so an enormous user-supplied limit cannot allocate up front.
            entries: Self::empty_entries(),
            entry_limit: capacity.get(),
            entry_high_water_len: 0,
            retained_heap_bytes: 0,
            heap_budget,
            #[cfg(test)]
            compaction_count: 0,
        }
    }

    fn get(&mut self, key: &str, kind: CacheQueryKind) -> Option<&QueryResult> {
        let cached = self.entries.get(key)?;
        if cached.kind != kind {
            return None;
        }
        match &cached.value {
            CachedQueryValue::Owned(result) => Some(result),
            CachedQueryValue::Reference(_) => None,
        }
    }

    fn get_ref(
        &mut self,
        key: &str,
        kind: CacheQueryKind,
        format: DatabaseFormat,
    ) -> Option<LookupRef> {
        let cached = self.entries.get(key)?;
        if cached.kind != kind {
            return None;
        }
        Some(match &cached.value {
            CachedQueryValue::Owned(result) => lookup_ref_from_query_result(result, format),
            CachedQueryValue::Reference(lookup) => *lookup,
        })
    }

    fn can_cache(&self, key: &str, value: &QueryResult) -> bool {
        estimated_cache_entry_heap(key.len(), value) <= self.heap_budget
    }

    fn put_borrowed(&mut self, key: &str, kind: CacheQueryKind, value: &QueryResult) {
        if let Some((old_key, old_value)) = self.entries.pop_entry(key) {
            self.retained_heap_bytes =
                self.retained_heap_bytes
                    .saturating_sub(estimated_cached_entry_heap(
                        old_key.capacity(),
                        &old_value.value,
                    ));
        }

        // Check the borrowed inputs before allocating either an owned key or a
        // cloned result. Oversized entries are never materialized for caching.
        if !self.can_cache(key, value) {
            self.maybe_compact_entries();
            return;
        }

        let key = key.to_string();
        let new_weight = estimated_cache_entry_heap(key.capacity(), value);
        if new_weight > self.heap_budget {
            self.maybe_compact_entries();
            return;
        }

        // Evict before cloning so the cache never transiently grows beyond its
        // configured entry or heap bounds. A one-for-one full-cache eviction
        // leaves the live set unchanged, so its bucket capacity remains useful.
        while self.entries.len() >= self.entry_limit
            || self.retained_heap_bytes.saturating_add(new_weight) > self.heap_budget
        {
            if !self.pop_lru_accounted() {
                self.retained_heap_bytes = 0;
                break;
            }
        }

        let value = CachedQueryResult {
            kind,
            value: CachedQueryValue::Owned(value.clone()),
        };
        self.retained_heap_bytes = self.retained_heap_bytes.saturating_add(new_weight);
        if let Some((old_key, old_value)) = self.entries.push(key, value) {
            self.retained_heap_bytes =
                self.retained_heap_bytes
                    .saturating_sub(estimated_cached_entry_heap(
                        old_key.capacity(),
                        &old_value.value,
                    ));
        }

        self.entry_high_water_len = self.entry_high_water_len.max(self.entries.len());
        self.maybe_compact_entries();
    }

    fn put_ref(&mut self, key: &str, kind: CacheQueryKind, lookup: LookupRef) {
        if let Some((old_key, old_value)) = self.entries.pop_entry(key) {
            self.retained_heap_bytes =
                self.retained_heap_bytes
                    .saturating_sub(estimated_cached_entry_heap(
                        old_key.capacity(),
                        &old_value.value,
                    ));
        }

        let borrowed_weight = estimated_reference_cache_entry_heap(key.len());
        if borrowed_weight > self.heap_budget {
            self.maybe_compact_entries();
            return;
        }

        let key = key.to_string();
        let new_weight = estimated_reference_cache_entry_heap(key.capacity());
        if new_weight > self.heap_budget {
            self.maybe_compact_entries();
            return;
        }

        while self.entries.len() >= self.entry_limit
            || self.retained_heap_bytes.saturating_add(new_weight) > self.heap_budget
        {
            if !self.pop_lru_accounted() {
                self.retained_heap_bytes = 0;
                break;
            }
        }

        let value = CachedQueryResult {
            kind,
            value: CachedQueryValue::Reference(lookup),
        };
        self.retained_heap_bytes = self.retained_heap_bytes.saturating_add(new_weight);
        if let Some((old_key, old_value)) = self.entries.push(key, value) {
            self.retained_heap_bytes =
                self.retained_heap_bytes
                    .saturating_sub(estimated_cached_entry_heap(
                        old_key.capacity(),
                        &old_value.value,
                    ));
        }

        self.entry_high_water_len = self.entry_high_water_len.max(self.entries.len());
        self.maybe_compact_entries();
    }

    fn pop_lru_accounted(&mut self) -> bool {
        let Some((key, value)) = self.entries.pop_lru() else {
            return false;
        };
        self.retained_heap_bytes = self
            .retained_heap_bytes
            .saturating_sub(estimated_cached_entry_heap(key.capacity(), &value.value));
        true
    }

    fn compact_entries(&mut self) {
        let mut compacted = Self::empty_entries();
        while let Some((key, value)) = self.entries.pop_lru() {
            let _ = compacted.push(key, value);
        }
        self.entries = compacted;
        self.entry_high_water_len = self.entries.len();
        #[cfg(test)]
        {
            self.compaction_count = self.compaction_count.saturating_add(1);
        }
    }

    fn maybe_compact_entries(&mut self) {
        let live_len = self.entries.len();
        let shrank_materially = self.entry_high_water_len >= QUERY_CACHE_COMPACTION_MIN_HIGH_WATER
            && live_len <= self.entry_high_water_len / 2;
        if (live_len == 0 && self.entry_high_water_len != 0) || shrank_materially {
            self.compact_entries();
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn estimated_cache_entry_heap(key_capacity: usize, value: &QueryResult) -> usize {
    estimated_cache_entry_heap_with_value(key_capacity, estimated_query_result_heap(value))
}

fn estimated_reference_cache_entry_heap(key_capacity: usize) -> usize {
    estimated_cache_entry_heap_with_value(key_capacity, 0)
}

fn estimated_cached_entry_heap(key_capacity: usize, value: &CachedQueryValue) -> usize {
    let value_heap = match value {
        CachedQueryValue::Owned(result) => estimated_query_result_heap(result),
        CachedQueryValue::Reference(_) => 0,
    };
    estimated_cache_entry_heap_with_value(key_capacity, value_heap)
}

fn estimated_cache_entry_heap_with_value(key_capacity: usize, value_heap: usize) -> usize {
    std::mem::size_of::<String>()
        .saturating_add(std::mem::size_of::<CachedQueryResult>())
        .saturating_add(4 * std::mem::size_of::<usize>())
        .saturating_add(key_capacity)
        .saturating_add(value_heap)
}

fn estimated_query_result_heap(value: &QueryResult) -> usize {
    match value {
        QueryResult::Ip { data, .. } => estimated_data_value_heap(data),
        QueryResult::Pattern {
            pattern_ids,
            data,
            data_offsets,
        } => pattern_ids
            .capacity()
            .saturating_mul(std::mem::size_of::<u32>())
            .saturating_add(
                data.capacity()
                    .saturating_mul(std::mem::size_of::<Option<DataValue>>()),
            )
            .saturating_add(
                data_offsets
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(data.iter().flatten().fold(0usize, |total, value| {
                total.saturating_add(estimated_data_value_heap(value))
            })),
        QueryResult::NotFound => 0,
    }
}

fn estimated_data_value_heap(value: &DataValue) -> usize {
    match value {
        DataValue::String(value) => value.capacity(),
        DataValue::Bytes(value) => value.capacity(),
        DataValue::Map(values) => values
            .capacity()
            .saturating_mul(std::mem::size_of::<(String, DataValue)>().saturating_add(1))
            .saturating_mul(2)
            .saturating_add(values.iter().fold(0usize, |total, (key, value)| {
                total
                    .saturating_add(key.capacity())
                    .saturating_add(estimated_data_value_heap(value))
            })),
        DataValue::Array(values) => values
            .capacity()
            .saturating_mul(std::mem::size_of::<DataValue>())
            .saturating_add(values.iter().fold(0usize, |total, value| {
                total.saturating_add(estimated_data_value_heap(value))
            })),
        DataValue::Pointer(_)
        | DataValue::Double(_)
        | DataValue::Uint16(_)
        | DataValue::Uint32(_)
        | DataValue::Int32(_)
        | DataValue::Uint64(_)
        | DataValue::Uint128(_)
        | DataValue::Bool(_)
        | DataValue::Float(_)
        | DataValue::Timestamp(_) => 0,
    }
}

fn is_decoder_resource_error(error: &str) -> bool {
    matches!(
        error,
        "Decoded value exceeds work limit"
            | "Decoded value exceeds allocation limit"
            | "String allocation failed"
            | "Bytes allocation failed"
            | "Map allocation failed"
            | "Array allocation failed"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheNamespace {
    generation: u64,
    instance: u64,
}

impl CacheNamespace {
    const fn new(generation: u64, instance: u64) -> Self {
        Self {
            generation,
            instance,
        }
    }
}

type QueryCacheNamespaces =
    LruCache<CacheNamespace, QueryCacheInner, BuildHasherDefault<rustc_hash::FxHasher>>;

/// Per-thread manager that bounds both stale generations and aggregate heap.
struct QueryCacheManager {
    namespaces: QueryCacheNamespaces,
    heap_budget: usize,
}

impl QueryCacheManager {
    fn new(max_generations: NonZeroUsize, heap_budget: usize) -> Self {
        Self {
            namespaces: LruCache::with_hasher(
                max_generations,
                BuildHasherDefault::<rustc_hash::FxHasher>::default(),
            ),
            heap_budget,
        }
    }

    fn with_namespace<F, R>(
        &mut self,
        namespace: CacheNamespace,
        entry_capacity: NonZeroUsize,
        operation: F,
    ) -> R
    where
        F: FnOnce(&mut QueryCacheInner) -> R,
    {
        let result = {
            let heap_budget = self.heap_budget;
            let cache = self.namespaces.get_or_insert_mut(namespace, || {
                QueryCacheInner::new(entry_capacity, heap_budget)
            });
            operation(cache)
        };
        self.enforce_heap_budget();
        result
    }

    fn remove_namespace(&mut self, namespace: CacheNamespace) {
        self.namespaces.pop(&namespace);
    }

    fn remove_generation(&mut self, generation: u64) {
        while let Some(namespace) = self
            .namespaces
            .iter()
            .find_map(|(namespace, _)| (namespace.generation == generation).then_some(*namespace))
        {
            self.namespaces.pop(&namespace);
        }
    }

    fn namespace_size(&mut self, namespace: CacheNamespace) -> usize {
        let size = self
            .namespaces
            .get(&namespace)
            .map_or(0, QueryCacheInner::len);
        self.enforce_heap_budget();
        size
    }

    fn retained_heap_bytes(&self) -> usize {
        self.namespaces.iter().fold(0usize, |total, (_, cache)| {
            total.saturating_add(cache.retained_heap_bytes)
        })
    }

    fn enforce_heap_budget(&mut self) {
        while self.retained_heap_bytes() > self.heap_budget {
            if self.namespaces.pop_lru().is_none() {
                break;
            }
        }
    }
}

// Thread-local cache storage bounded across database namespaces. This keeps
// lock-free locality without allowing reloads or dropped databases to retain
// an unbounded number of independent caches.
thread_local! {
    static QUERY_CACHES: RefCell<QueryCacheManager> = RefCell::new(QueryCacheManager::new(
        NonZeroUsize::new(MAX_QUERY_CACHE_NAMESPACES)
            .expect("query cache namespace limit is non-zero"),
        QUERY_CACHE_HEAP_BUDGET,
    ));
}

/// Global counter for generating unique cache generation IDs.
/// Each Database instance gets a unique ID to prevent cache collisions
/// between different databases.
static NEXT_CACHE_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Generate a unique cache generation ID for a new database instance
pub(crate) fn next_cache_generation() -> u64 {
    NEXT_CACHE_GENERATION.fetch_add(1, Ordering::Relaxed)
}

/// Monotonic private database-instance IDs make a caller-supplied generation
/// safe to reuse across independently opened databases. Refuse to wrap instead
/// of ever reusing an instance ID while an older database could still be live.
static NEXT_CACHE_INSTANCE: AtomicU64 = AtomicU64::new(1);

fn next_cache_instance() -> u64 {
    NEXT_CACHE_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .expect("database cache instance ID space exhausted")
}

/// Statistics for database queries and cache performance
/// Uses atomic counters for thread-safe access across all threads
#[derive(Debug, Default)]
pub struct DatabaseStats {
    /// Total number of queries executed
    pub total_queries: AtomicU64,
    /// Queries that found a match
    pub queries_with_match: AtomicU64,
    /// Queries that found no match
    pub queries_without_match: AtomicU64,
    /// Cache hits (query served from cache)
    pub cache_hits: AtomicU64,
    /// Cache misses (query required lookup)
    pub cache_misses: AtomicU64,
    /// Number of IP address queries
    pub ip_queries: AtomicU64,
    /// Number of string queries (literal or pattern)
    pub string_queries: AtomicU64,
}

/// Snapshot of database statistics at a point in time
#[derive(Debug, Clone, Copy, Default)]
pub struct DatabaseStatsSnapshot {
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
    /// Take a snapshot of current statistics
    pub fn snapshot(&self) -> DatabaseStatsSnapshot {
        DatabaseStatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            queries_with_match: self.queries_with_match.load(Ordering::Relaxed),
            queries_without_match: self.queries_without_match.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            ip_queries: self.ip_queries.load(Ordering::Relaxed),
            string_queries: self.string_queries.load(Ordering::Relaxed),
        }
    }
}

impl DatabaseStatsSnapshot {
    /// Calculate cache hit rate (0.0 to 1.0)
    #[must_use]
    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_ops = self.cache_hits + self.cache_misses;
        if total_cache_ops == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total_cache_ops as f64
        }
    }

    /// Calculate match rate (0.0 to 1.0)
    #[must_use]
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
        /// Offset to data in MMDB data section (for C API)
        data_offset: u32,
    },
    /// Pattern match result
    Pattern {
        /// Pattern IDs that matched
        pattern_ids: Vec<u32>,
        /// Optional data for matched patterns
        data: Vec<Option<DataValue>>,
        /// Offsets to data in MMDB data section (for C API)
        data_offsets: Vec<u32>,
    },
    /// Not found
    NotFound,
}

/// Offset-only lookup result for the C API.
///
/// The result itself owns no decoded data. A cold string lookup may still grow
/// bounded thread-local matcher scratch; steady-state lookups reuse it.
#[derive(Debug, Clone, Copy)]
pub struct LookupRef {
    /// Whether a match was found
    pub found: bool,
    /// Data token for [`Database::decode_at_offset`]. This is an MMDB data-section
    /// offset for IP/combined databases and a pattern ID for pattern-only files.
    /// It is 0 when not found or when a combined match has no mapped data.
    pub data_offset: u32,
    /// Network prefix length (for IP results, 0 for patterns)
    pub prefix_len: u8,
    /// Result type: 0=not found, 1=ip, 2=pattern
    pub result_type: u8,
}

impl LookupRef {
    /// Create a not-found result
    #[inline]
    #[must_use]
    pub const fn not_found() -> Self {
        Self {
            found: false,
            data_offset: 0,
            prefix_len: 0,
            result_type: 0,
        }
    }

    /// Create an IP lookup result
    #[inline]
    #[must_use]
    pub const fn ip(data_offset: u32, prefix_len: u8) -> Self {
        Self {
            found: true,
            data_offset,
            prefix_len,
            result_type: 1,
        }
    }

    /// Create a pattern lookup result
    #[inline]
    #[must_use]
    pub const fn pattern(data_offset: u32) -> Self {
        Self {
            found: true,
            data_offset,
            prefix_len: 0,
            result_type: 2,
        }
    }
}

#[inline]
fn lookup_ref_from_query_result(result: &QueryResult, format: DatabaseFormat) -> LookupRef {
    match result {
        QueryResult::Ip {
            prefix_len,
            data_offset,
            ..
        } => LookupRef::ip(*data_offset, *prefix_len),
        QueryResult::Pattern {
            pattern_ids,
            data_offsets,
            ..
        } => LookupRef::pattern(if matches!(format, DatabaseFormat::PatternOnly) {
            pattern_ids.first().copied().unwrap_or(0)
        } else {
            data_offsets.first().copied().unwrap_or(0)
        }),
        QueryResult::NotFound => LookupRef::not_found(),
    }
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

const PATTERN_SECTION_MARKER: &[u8; 16] = b"MMDB_PATTERN\x00\x00\x00\x00";
const LITERAL_SECTION_MARKER: &[u8; 16] = b"MMDB_LITERAL\x00\x00\x00\x00";

#[derive(Debug, Clone, Copy)]
pub(crate) struct EmbeddedSections {
    pattern_data_offset: Option<usize>,
    literal_marker_offset: Option<usize>,
    opaque_data_offset: Option<usize>,
    metadata_offset: usize,
}

impl EmbeddedSections {
    const fn pattern_only(file_len: usize) -> Self {
        Self {
            pattern_data_offset: None,
            literal_marker_offset: None,
            opaque_data_offset: None,
            metadata_offset: file_len,
        }
    }

    pub(crate) fn data_section_end(self) -> Option<usize> {
        let pattern_marker_offset = self
            .pattern_data_offset
            .and_then(|offset| offset.checked_sub(PATTERN_SECTION_MARKER.len()));
        [
            Some(self.metadata_offset),
            pattern_marker_offset,
            self.literal_marker_offset,
            self.opaque_data_offset,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) const fn pattern_data_offset(self) -> Option<usize> {
        self.pattern_data_offset
    }

    pub(crate) fn literal_data_offset(self) -> Option<usize> {
        self.literal_marker_offset
            .and_then(|offset| offset.checked_add(LITERAL_SECTION_MARKER.len()))
    }

    pub(crate) fn literal_data_end(self) -> usize {
        self.metadata_offset
    }

    fn validate_after_mmdb_separator(self, data_section_start: usize) -> Result<(), String> {
        let pattern_marker_offset = match self.pattern_data_offset {
            Some(offset) => Some(
                offset
                    .checked_sub(PATTERN_SECTION_MARKER.len())
                    .ok_or_else(|| "Pattern data offset precedes its section marker".to_string())?,
            ),
            None => None,
        };

        for (section_name, marker_offset) in [
            ("Pattern", pattern_marker_offset),
            ("Literal", self.literal_marker_offset),
            ("Opaque", self.opaque_data_offset),
        ] {
            if let Some(marker_offset) = marker_offset {
                if marker_offset < data_section_start {
                    return Err(format!(
                        "{section_name} section marker at {marker_offset} overlaps the MMDB tree or 16-byte separator ending at {data_section_start}"
                    ));
                }
            }
        }

        Ok(())
    }
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
/// use matchy::{Database, QueryResult};
///
/// let db = Database::from("threats.db").open()?;
///
/// // IP lookup
/// if let Some(result @ QueryResult::Ip { .. }) = db.lookup("1.2.3.4")? {
///     println!("Found threat data: {:?}", result);
/// }
///
/// // Pattern lookup
/// if let Some(result @ QueryResult::Pattern { .. }) = db.lookup("evil.com")? {
///     println!("Domain matches patterns: {:?}", result);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// Storage for database data - either owned or memory-mapped
enum DatabaseStorage {
    Owned(Vec<u8>),
    #[cfg(not(target_family = "wasm"))]
    Mmap(Mmap),
}

impl DatabaseStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v.as_slice(),
            #[cfg(not(target_family = "wasm"))]
            Self::Mmap(m) => &m[..],
        }
    }
}

#[derive(Debug, Clone)]
struct EmbeddedSectionLocation {
    name: String,
    format: String,
    range: Range<usize>,
    alignment: usize,
}

/// An owned view of an opaque section embedded in a Matchy database.
///
/// Cloning this handle is inexpensive. It keeps the complete database storage
/// alive, so the returned byte address remains stable even after the originating
/// [`Database`] is dropped or a live database swaps to a newer generation.
#[derive(Clone)]
pub struct DatabaseSection {
    storage: Arc<DatabaseStorage>,
    location: EmbeddedSectionLocation,
}

impl DatabaseSection {
    /// Return the logical section name recorded in database metadata.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.location.name
    }

    /// Return the independently versioned format identifier for this section.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.location.format
    }

    /// Return the section's database-relative byte offset.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.location.range.start
    }

    /// Return the section's declared database-relative alignment.
    ///
    /// This is also the in-memory address alignment for a file-backed mapping,
    /// whose base address is page-aligned. Owned byte buffers only guarantee
    /// the relative layout and should be consumed through byte-safe readers.
    #[must_use]
    pub fn alignment(&self) -> usize {
        self.location.alignment
    }

    /// Whether this section is retained in a file-backed memory map.
    #[must_use]
    pub fn is_memory_mapped(&self) -> bool {
        #[cfg(not(target_family = "wasm"))]
        {
            matches!(self.storage.as_ref(), DatabaseStorage::Mmap(_))
        }
        #[cfg(target_family = "wasm")]
        {
            false
        }
    }

    /// Return the validated section bytes without copying them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage.as_slice()[self.location.range.clone()]
    }
}

impl Deref for DatabaseSection {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl std::fmt::Debug for DatabaseSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseSection")
            .field("name", &self.name())
            .field("format", &self.format())
            .field("offset", &self.offset())
            .field("length", &self.len())
            .field("alignment", &self.alignment())
            .finish()
    }
}

/// Lazy pattern data mappings for O(1) load time
/// Stores offset range instead of parsing all mappings eagerly
#[derive(Clone)]
struct PatternDataMappings {
    /// Offset to start of mapping data (after pattern_count u32)
    mappings_offset: usize,
    /// Number of patterns (and thus offsets)
    pattern_count: usize,
}

impl PatternDataMappings {
    /// Get data offset for a specific pattern_id by parsing only that entry
    fn get_offset(&self, pattern_id: u32, data: &[u8]) -> Option<u32> {
        let pattern_index = usize::try_from(pattern_id).ok()?;
        if pattern_index >= self.pattern_count {
            return None;
        }

        let relative_offset = pattern_index.checked_mul(std::mem::size_of::<u32>())?;
        let offset_pos = self.mappings_offset.checked_add(relative_offset)?;
        let offset_end = offset_pos.checked_add(std::mem::size_of::<u32>())?;
        let bytes = data.get(offset_pos..offset_end)?;

        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }
}

/// Default LRU entry ceiling for query results.
///
/// Retained result heap is also capped by a 64 MiB aggregate budget.
const DEFAULT_QUERY_CACHE_SIZE: usize = 10_000;

/// Options for opening a database
#[derive(Clone, Default)]
pub struct DatabaseOptions {
    /// Path to the database file (optional for from_bytes)
    pub path: PathBuf,

    /// LRU entry ceiling (`None` = default, `Some(0)` = disabled).
    ///
    /// The estimated retained heap has a separate fixed 64 MiB aggregate
    /// ceiling per calling thread across at most 16 recent database namespaces.
    pub cache_capacity: Option<usize>,

    /// Optional in-memory bytes (for from_bytes builder)
    pub bytes: Option<Vec<u8>>,

    /// Optional logical cache generation, primarily for live-update internals.
    ///
    /// A private per-database discriminator prevents two databases with the
    /// same value from sharing results. Leave this as `None` unless coordinated
    /// generation-wide clearing via [`Database::clear_cache_generation`] is
    /// required.
    pub cache_generation: Option<u64>,
}

/// Builder for opening databases with custom configuration
///
/// Created via `Database::from(path)`. Use the fluent API to configure
/// options like caching and live updates, then call `.open()` to load the database.
pub struct DatabaseOpener {
    options: DatabaseOptions,
    #[cfg(not(target_family = "wasm"))]
    live: LiveOptions,
}

impl DatabaseOpener {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            options: DatabaseOptions {
                path: path.into(),
                ..Default::default()
            },
            #[cfg(not(target_family = "wasm"))]
            live: LiveOptions::default(),
        }
    }

    /// Set the LRU entry ceiling. Default: 10,000 entries.
    ///
    /// Increasing this value does not increase the separate 64 MiB aggregate
    /// estimated-retained-heap ceiling per calling thread. Each thread retains
    /// caches for at most 16 recent database namespaces.
    #[must_use]
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.options.cache_capacity = Some(capacity);
        self
    }

    /// Disable caching entirely.
    #[must_use]
    pub fn no_cache(mut self) -> Self {
        self.options.cache_capacity = Some(0);
        self
    }

    /// Enable automatic file watching and hot-reload.
    /// Database will reload when file changes are detected.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy")
    ///     .watch()
    ///     .on_reload(|event| {
    ///         println!("Database reloaded: {:?}", event.path);
    ///     })
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn watch(mut self) -> Self {
        self.live.enabled = true;
        self
    }

    /// Enable automatic updates from the database's embedded update URL.
    ///
    /// The database must have an update URL embedded in its metadata (set during build
    /// with `DatabaseBuilder::with_update_url()`). If the database has no embedded URL,
    /// `open()` will return an error.
    ///
    /// Updates are downloaded to a cache directory (configurable via `cache_dir()`),
    /// leaving the original file untouched.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use matchy::Database;
    /// use std::time::Duration;
    ///
    /// let db = Database::from("threats.mxy")
    ///     .auto_update()
    ///     .update_interval(Duration::from_secs(3600))
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(all(not(target_family = "wasm"), feature = "auto-update"))]
    #[must_use]
    pub fn auto_update(mut self) -> Self {
        self.live.enabled = true;
        self.live.auto_update_enabled = true;
        if self.live.update_interval.is_none() {
            self.live.update_interval = Some(Duration::from_secs(
                crate::updater::DEFAULT_UPDATE_INTERVAL_SECS,
            ));
        }
        self
    }

    /// Set how often to check for remote updates. Default: 1 hour.
    #[cfg(all(not(target_family = "wasm"), feature = "auto-update"))]
    #[must_use]
    pub fn update_interval(mut self, interval: Duration) -> Self {
        self.live.update_interval = Some(interval);
        self
    }

    /// Set the cache directory for downloaded updates.
    ///
    /// Default: `~/.cache/matchy/` on Unix, `%LOCALAPPDATA%\matchy\` on Windows,
    /// or system temp directory as fallback.
    #[cfg(all(not(target_family = "wasm"), feature = "auto-update"))]
    #[must_use]
    pub fn cache_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.live.cache_dir = Some(path.into());
        self
    }

    /// Set how often to check for local file changes. Default: 1 second.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.live.poll_interval = Some(interval);
        self
    }

    /// Set callback for reload notifications.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn on_reload<F>(mut self, callback: F) -> Self
    where
        F: Fn(ReloadEvent) + Send + Sync + 'static,
    {
        self.live.reload_callback = Some(Arc::new(callback));
        self
    }

    /// Set callback for fallback notifications (when current database has errors
    /// and we fall back to the previous version).
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn on_fallback<F>(mut self, callback: F) -> Self
    where
        F: Fn(FallbackEvent) + Send + Sync + 'static,
    {
        self.live.fallback_callback = Some(Arc::new(callback));
        self
    }

    /// Open the database with configured options.
    ///
    /// On native platforms the file is memory-mapped. Keep the mapped inode
    /// immutable for the lifetime of the returned database: do not truncate or
    /// rewrite it in place. Publish updates by writing a new file and atomically
    /// replacing the path.
    #[cfg(not(target_family = "wasm"))]
    pub fn open(self) -> Result<Database, DatabaseError> {
        let db = Database::open_with_options(self.options.clone())?;

        #[cfg(feature = "auto-update")]
        if self.live.auto_update_enabled && db.update_url().is_none() {
            return Err(DatabaseError::Config(
                "auto_update() requires database with embedded update URL".to_string(),
            ));
        }

        if self.live.enabled {
            let live_state =
                self.live
                    .start_updater(&self.options.path, db, self.options.cache_capacity);
            Ok(Database::with_live_state(live_state))
        } else {
            Ok(db)
        }
    }

    /// Open the database with configured options.
    #[cfg(target_family = "wasm")]
    pub fn open(self) -> Result<Database, DatabaseError> {
        Database::open_with_options(self.options)
    }

    /// Create a `DatabaseOpener` from raw bytes.
    #[must_use]
    pub fn from_bytes_builder(bytes: Vec<u8>) -> Self {
        Self {
            options: DatabaseOptions {
                bytes: Some(bytes),
                ..Default::default()
            },
            #[cfg(not(target_family = "wasm"))]
            live: LiveOptions::default(),
        }
    }
}

/// Unified database for IP and pattern lookups.
/// Supports optional live-reloading when opened with `.watch()` or `.auto_update()`.
pub struct Database {
    data: Arc<DatabaseStorage>,
    format: DatabaseFormat,
    ip_header: Option<MmdbHeader>,
    /// Exclusive end of the MMDB data section, before extensions/metadata.
    data_section_end: Option<usize>,
    literal_hash: Option<LiteralHash<'static>>,
    pattern_matcher: Option<Paraglob>,
    pattern_data_mappings: Option<PatternDataMappings>,
    embedded_sections: Vec<EmbeddedSectionLocation>,
    cache_capacity: usize,
    cache_enabled: bool,
    stats: Arc<DatabaseStats>,
    cache_generation: u64,
    cache_instance: u64,
    #[cfg(not(target_family = "wasm"))]
    live: Option<Box<LiveState>>,
}

// SAFETY: Database is Send + Sync because:
// - All fields are either Send+Sync types (Arc, Vec, Option of Send+Sync types)
// - LiteralHash<'static> and Paraglob contain references transmuted to 'static lifetime
//   that point into `data` (DatabaseStorage). This is safe because:
//   1. Database owns both the data and the structures referencing it
//   2. They are created together and destroyed together (no dangling references)
//   3. The data is read-only after construction (no mutation races)
// - The 'static lifetime trick is a common pattern for self-referential structs
//   when the referenced data is owned and outlives all references
unsafe impl Send for Database {}
// SAFETY: See above
unsafe impl Sync for Database {}

impl Database {
    /// Helper: Access thread-local cache for this database, initializing if needed
    ///
    /// Each database instance has its own cache namespace, combining the public
    /// generation with a private per-instance discriminator,
    /// stored per-thread for lock-free access. This allows multiple databases
    /// to coexist safely even when callers assign the same generation.
    #[inline]
    fn with_cache<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut QueryCacheInner) -> R,
    {
        if !self.cache_enabled {
            return None;
        }

        QUERY_CACHES.with(|caches| {
            Some(
                caches.borrow_mut().with_namespace(
                    self.cache_namespace(),
                    NonZeroUsize::new(self.cache_capacity)
                        .expect("cache_capacity > 0 when cache_enabled is true"),
                    f,
                ),
            )
        })
    }

    #[inline]
    const fn cache_namespace(&self) -> CacheNamespace {
        CacheNamespace::new(self.cache_generation, self.cache_instance)
    }

    /// Create a database opener with fluent builder API
    ///
    /// This is the recommended way to open databases, providing clean
    /// configuration of cache size, live reloads, and future options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// // Defaults (cache enabled)
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Custom cache size
    /// let db = Database::from("threats.mxy")
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
    #[must_use]
    pub fn from_bytes_builder(bytes: Vec<u8>) -> DatabaseOpener {
        DatabaseOpener::from_bytes_builder(bytes)
    }

    /// Clear the thread-local query cache
    ///
    /// Clears the cache for the current thread only. Useful for benchmarking or
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
        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            Self::resolve_live_db(live).clear_cache();
            return;
        }

        if self.cache_enabled {
            QUERY_CACHES.with(|caches| {
                caches.borrow_mut().remove_namespace(self.cache_namespace());
            });
        }
    }

    /// Clear cache entries for a specific generation (used by WatchingDatabase)
    pub fn clear_cache_generation(generation: u64) {
        QUERY_CACHES.with(|caches| {
            caches.borrow_mut().remove_generation(generation);
        });
    }

    /// Get current thread-local cache size (number of entries)
    ///
    /// Returns the number of query results currently cached in this thread
    /// for this specific database.
    /// Useful for monitoring cache usage.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Do some queries
    /// db.lookup("example.com")?;
    /// println!("Cache size: {}", db.cache_size());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn cache_size(&self) -> usize {
        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return Self::resolve_live_db(live).cache_size();
        }

        if !self.cache_enabled {
            return 0;
        }
        QUERY_CACHES.with(|caches| caches.borrow_mut().namespace_size(self.cache_namespace()))
    }

    /// Get database statistics snapshot
    ///
    /// Returns a point-in-time snapshot of query statistics aggregated
    /// across all threads. Uses atomic counters for thread-safe access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    /// use std::sync::Arc;
    ///
    /// let db = Arc::new(Database::from("threats.mxy").open()?);
    ///
    /// // Query from multiple threads...
    ///
    /// // Get aggregated stats
    /// let stats = db.stats();
    /// println!("Total queries: {}", stats.total_queries);
    /// println!("Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn stats(&self) -> DatabaseStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get the match mode of the database (case-sensitive or case-insensitive)
    ///
    /// Returns the MatchMode for this database, which determines how pattern
    /// matching is performed. Used to optimize query processing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::{Database, MatchMode};
    ///
    /// let db = Database::from("threats.mxy").open()?;
    /// if db.mode() == MatchMode::CaseInsensitive {
    ///     println!("Database uses case-insensitive matching");
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn mode(&self) -> matchy_match_mode::MatchMode {
        // If there's a pattern matcher, use its mode
        if let Some(ref pm) = self.pattern_matcher {
            return pm.mode();
        }
        // If there's a literal hash, use its mode
        if let Some(ref lh) = self.literal_hash {
            return lh.mode();
        }
        // Default to case-sensitive for IP-only databases
        matchy_match_mode::MatchMode::CaseSensitive
    }

    /// Open database with custom options (lower-level API)
    ///
    /// Most users should use `Database::from()` builder instead.
    pub fn open_with_options(options: DatabaseOptions) -> Result<Self, DatabaseError> {
        // Open the database - either from bytes or from file
        let mut db = if let Some(bytes) = options.bytes {
            // Load from bytes
            Self::from_storage(DatabaseStorage::Owned(bytes))?
        } else {
            // Load from file
            Self::open_internal(
                options
                    .path
                    .to_str()
                    .ok_or_else(|| DatabaseError::Io("Invalid path encoding".to_string()))?,
            )?
        };

        // Configure cache size (0 means disable, None means use default)
        if let Some(capacity) = options.cache_capacity {
            if capacity == 0 {
                // Disable cache completely - skip all cache operations
                db.cache_enabled = false;
            } else {
                db.cache_capacity = capacity;
                db.cache_enabled = true;
            }
        }

        // Set cache generation if provided (for WatchingDatabase)
        if let Some(generation) = options.cache_generation {
            db.cache_generation = generation;
        }

        Ok(db)
    }

    /// Internal: Open database from file
    /// Uses memory-mapping on native platforms for performance.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn open_internal(path: &str) -> Result<Self, DatabaseError> {
        let file = File::open(path)
            .map_err(|e| DatabaseError::Io(format!("Failed to open {path}: {e}")))?;

        // SAFETY: Mmap::map is unsafe because the file could be modified externally
        // while mapped, causing undefined behavior. We accept this risk because:
        // - Database files are expected to be stable after creation
        // - Live-reload creates a new mmap rather than modifying in-place
        // - This is standard practice for read-only database files
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| DatabaseError::Io(format!("Failed to mmap {path}: {e}")))?;

        Self::from_storage(DatabaseStorage::Mmap(mmap))
    }

    /// Internal: Open database from file
    /// Reads entire file into memory on WASM (no mmap available).
    #[cfg(target_family = "wasm")]
    pub(crate) fn open_internal(path: &str) -> Result<Self, DatabaseError> {
        let bytes = std::fs::read(path)
            .map_err(|e| DatabaseError::Io(format!("Failed to read {}: {}", path, e)))?;

        Self::from_storage(DatabaseStorage::Owned(bytes))
    }

    /// Create database from raw bytes (for testing)
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DatabaseError> {
        Self::from_storage(DatabaseStorage::Owned(data))
    }

    #[cfg(not(target_family = "wasm"))]
    fn with_live_state(live_state: LiveState) -> Self {
        let snapshot = live_state.current.load_full();
        Self {
            data: Arc::new(DatabaseStorage::Owned(vec![])),
            format: snapshot.format,
            ip_header: None,
            data_section_end: None,
            literal_hash: None,
            pattern_matcher: None,
            pattern_data_mappings: None,
            embedded_sections: Vec::new(),
            cache_capacity: snapshot.cache_capacity,
            cache_enabled: snapshot.cache_enabled,
            stats: snapshot.stats.clone(),
            cache_generation: live_state.generation.load(Ordering::Acquire),
            cache_instance: snapshot.cache_instance,
            live: Some(Box::new(live_state)),
        }
    }

    /// Resolve the current live database, using a thread-local cache to avoid
    /// reloading the Arc on every call within the same generation.
    #[cfg(not(target_family = "wasm"))]
    fn resolve_live_db(live: &LiveState) -> Arc<Self> {
        use crate::updater::LOCAL_DB;

        let current_gen = live.generation.load(Ordering::Acquire);
        LOCAL_DB.with(|local| {
            let mut local_ref = local.borrow_mut();
            match &*local_ref {
                Some((gen, db)) if *gen == current_gen => db.clone(),
                _ => {
                    let new_db = live.current.load_full();
                    *local_ref = Some((current_gen, new_db.clone()));
                    new_db
                }
            }
        })
    }

    #[cfg(not(target_family = "wasm"))]
    fn lookup_live(
        &self,
        query: &str,
        live: &LiveState,
    ) -> Result<Option<QueryResult>, DatabaseError> {
        use crate::updater::{FallbackEvent, LOCAL_DB};

        let db = Self::resolve_live_db(live);

        match db.lookup(query) {
            Ok(result) => Ok(result),
            Err(e) if e.is_data_error() => {
                if let Some(prev_db) = live.previous.load_full().as_ref() {
                    match prev_db.lookup(query) {
                        Ok(result) => {
                            live.current.store(prev_db.clone());
                            live.previous.store(Arc::new(None));

                            LOCAL_DB.with(|local| {
                                *local.borrow_mut() = None;
                            });

                            if let Some(ref callback) = live.fallback_callback {
                                callback(FallbackEvent {
                                    error: e.to_string(),
                                    generation: live.generation.load(Ordering::Acquire),
                                });
                            }

                            Ok(result)
                        }
                        Err(_) => Err(e),
                    }
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn from_storage(storage: DatabaseStorage) -> Result<Self, DatabaseError> {
        let storage = Arc::new(storage);
        let mut db = Self {
            data: storage,
            format: DatabaseFormat::IpOnly,
            ip_header: None,
            data_section_end: None,
            literal_hash: None,
            pattern_matcher: None,
            pattern_data_mappings: None,
            embedded_sections: Vec::new(),
            cache_capacity: DEFAULT_QUERY_CACHE_SIZE,
            cache_enabled: true,
            stats: Arc::new(DatabaseStats::default()),
            cache_generation: next_cache_generation(),
            cache_instance: next_cache_instance(),
            #[cfg(not(target_family = "wasm"))]
            live: None,
        };

        // SAFETY: This transmute extends the lifetime of `db.data.as_slice()` to 'static.
        //
        // This is a "self-referential struct" pattern and is sound because:
        // 1. `db.data` is owned by this Database instance (either Vec<u8> or Mmap)
        // 2. The resulting 'static references are stored in fields also owned by Database
        //    (ip_header, literal_hash, pattern_matcher, pattern_data_mappings)
        // 3. Database ensures `data` cannot be dropped while any references exist
        // 4. All references become invalid when Database drops, and Rust's ownership
        //    prevents them from escaping (they're private fields)
        //
        // The key invariant: Database owns BOTH the backing data AND all structures
        // that reference it. They are created and destroyed together.
        //
        // Alternative approaches (ouroboros, self_cell crates) were considered but
        // add dependency complexity. This pattern is well-contained within Database
        // initialization and the invariant is straightforward to maintain.
        let data: &'static [u8] = unsafe { std::mem::transmute(db.data.as_slice()) };

        // Detect the format and locate any embedded pattern sections in one metadata
        // pass. Keeping the validated locations together prevents later loaders from
        // trusting the same untrusted offsets differently.
        let (format, sections) = Self::detect_format_and_sections(data)?;
        db.format = format;
        if db.format != DatabaseFormat::PatternOnly {
            db.embedded_sections = Self::parse_opaque_sections(data, sections.metadata_offset)
                .map_err(|error| DatabaseError::Format(MmdbError::InvalidFormat(error)))?;
        }
        if db.format != DatabaseFormat::PatternOnly {
            db.data_section_end = sections.data_section_end();
        }

        // Parse based on format
        match db.format {
            DatabaseFormat::IpOnly => {
                let header = MmdbHeader::from_file(data).map_err(DatabaseError::Format)?;
                Self::validate_embedded_sections_for_header(&header, sections)?;
                db.ip_header = Some(header);
            }
            DatabaseFormat::PatternOnly => {
                // Pattern-only: load from start of file
                let pg = Self::load_pattern_section(data, 0).map_err(|e| {
                    DatabaseError::Unsupported(format!("Failed to load pattern section: {e}"))
                })?;
                db.pattern_matcher = Some(pg);
            }
            DatabaseFormat::Combined => {
                // Parse IP header first
                let header = MmdbHeader::from_file(data).map_err(DatabaseError::Format)?;
                Self::validate_embedded_sections_for_header(&header, sections)?;
                db.ip_header = Some(header);

                // Find and load pattern section after MMDB_PATTERN separator
                if let Some(offset) = sections.pattern_data_offset {
                    let section_limit = sections
                        .literal_marker_offset
                        .filter(|literal_offset| *literal_offset >= offset)
                        .into_iter()
                        .chain(
                            sections
                                .opaque_data_offset
                                .filter(|opaque| *opaque >= offset),
                        )
                        .min()
                        .unwrap_or(sections.metadata_offset);
                    let (pg, map) = Self::load_combined_pattern_section(
                        data,
                        offset,
                        section_limit,
                    )
                    .map_err(|e| {
                        DatabaseError::Unsupported(format!("Failed to load pattern section: {e}"))
                    })?;
                    db.pattern_matcher = Some(pg);
                    db.pattern_data_mappings = Some(map);
                }
            }
        }

        // Load literal hash section if present (MMDB_LITERAL marker)
        if let Some(marker_offset) = sections.literal_marker_offset {
            let literal_start = marker_offset
                .checked_add(LITERAL_SECTION_MARKER.len())
                .ok_or_else(|| {
                    DatabaseError::Unsupported(
                        "Literal section start offset overflowed usize".to_string(),
                    )
                })?;
            let literal_data = data
                .get(literal_start..sections.literal_data_end())
                .ok_or_else(|| {
                    DatabaseError::Unsupported(format!(
                        "Literal section range [{literal_start}, {}) is invalid for file length {}",
                        sections.literal_data_end(),
                        data.len()
                    ))
                })?;
            // Read match mode from metadata
            let match_mode = Self::read_match_mode_from_metadata(data);
            db.literal_hash = Some(LiteralHash::from_buffer(literal_data, match_mode).map_err(
                |e| DatabaseError::Unsupported(format!("Failed to load literal hash: {e}")),
            )?);
        }

        Ok(db)
    }

    fn validate_embedded_sections_for_header(
        header: &MmdbHeader,
        sections: EmbeddedSections,
    ) -> Result<(), DatabaseError> {
        let data_section_start = header.tree_size.checked_add(16).ok_or_else(|| {
            DatabaseError::Format(MmdbError::InvalidFormat(
                "Tree size overflows data section offset".to_string(),
            ))
        })?;
        sections
            .validate_after_mmdb_separator(data_section_start)
            .map_err(|error| DatabaseError::Format(MmdbError::InvalidFormat(error)))
    }

    /// Get the current generation counter. Increments on each reload.
    /// Returns 0 for static (non-watching) databases.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn generation(&self) -> u64 {
        match &self.live {
            Some(live) => live.generation.load(Ordering::Acquire),
            None => 0,
        }
    }

    /// Returns the current database generation (always 0 for WASM).
    #[cfg(target_family = "wasm")]
    pub fn generation(&self) -> u64 {
        0
    }

    fn ensure_string_query_within_limit(query: &str) -> Result<(), DatabaseError> {
        if query.len() > MAX_STRING_QUERY_MATCHING_WORK {
            return Err(DatabaseError::Config(format!(
                "String query is {} bytes; the maximum is {MAX_STRING_QUERY_MATCHING_WORK}",
                query.len()
            )));
        }
        Ok(())
    }

    fn record_query_stats(
        &self,
        kind: CacheQueryKind,
        result: Option<&QueryResult>,
        cache_hit: bool,
    ) {
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);
        if cache_hit {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else if self.cache_enabled {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        match kind {
            CacheQueryKind::Ip => {
                self.stats.ip_queries.fetch_add(1, Ordering::Relaxed);
            }
            CacheQueryKind::String => {
                self.stats.string_queries.fetch_add(1, Ordering::Relaxed);
            }
        }

        if matches!(
            result,
            Some(QueryResult::Ip { .. } | QueryResult::Pattern { .. })
        ) {
            self.stats
                .queries_with_match
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats
                .queries_without_match
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Look up a query string (IP address or string pattern).
    ///
    /// Returns [`QueryResult::NotFound`] when an applicable lookup table exists
    /// but has no match. `Ok(None)` means this database has no applicable table
    /// for the query type.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Format`] for malformed database data and
    /// [`DatabaseError::Config`] when a string query exceeds a runtime resource
    /// limit.
    pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError> {
        Self::ensure_string_query_within_limit(query)?;

        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return self.lookup_live(query, live);
        }

        let parsed_address = query.parse::<IpAddr>().ok();
        let kind = if parsed_address.is_some() {
            CacheQueryKind::Ip
        } else {
            CacheQueryKind::String
        };

        if let Some(Some(result)) = self.with_cache(|cache| cache.get(query, kind).cloned()) {
            self.record_query_stats(kind, Some(&result), true);
            return Ok(Some(result));
        }

        // Cache miss (or cache disabled) - perform actual lookup
        let result = if let Some(addr) = parsed_address {
            self.lookup_ip_uncached(addr)?
        } else {
            self.lookup_string_uncached(query)?
        };
        self.record_query_stats(kind, result.as_ref(), false);

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put_borrowed(query, kind, res));
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

        let data = self.decode_ip_data(header, tree_result.data_offset)?;

        Ok(Some(QueryResult::Ip {
            data,
            prefix_len: tree_result.prefix_len,
            data_offset: tree_result.data_offset,
        }))
    }

    /// Look up an IP address (public API, uses thread-local cache)
    ///
    /// Returns [`QueryResult::Ip`] when found, [`QueryResult::NotFound`] when an
    /// IP index exists but has no match, and `None` when the database has no IP
    /// index.
    pub fn lookup_ip(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return Self::resolve_live_db(live).lookup_ip(addr);
        }

        // Convert to string for cache key
        let query = addr.to_string();

        // Check thread-local cache first
        if let Some(Some(result)) =
            self.with_cache(|cache| cache.get(&query, CacheQueryKind::Ip).cloned())
        {
            self.record_query_stats(CacheQueryKind::Ip, Some(&result), true);
            return Ok(Some(result));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_ip_uncached(addr)?;
        self.record_query_stats(CacheQueryKind::Ip, result.as_ref(), false);

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put_borrowed(&query, CacheQueryKind::Ip, res));
        }

        Ok(result)
    }

    /// Look up an extracted item using the most efficient path
    ///
    /// This method handles the type differences in `ExtractedItem` automatically,
    /// using the optimal lookup strategy for each variant:
    /// - IP addresses use `lookup_ip()` (avoids string parsing)
    /// - Everything else uses `lookup()` (string-based)
    ///
    /// This is the recommended way to query databases after extraction,
    /// as it avoids boilerplate match statements and ensures maximum performance.
    ///
    /// # Arguments
    ///
    /// * `item` - The extracted match to look up
    /// * `input` - The original input buffer (needed to extract string slices)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::{Database, QueryResult, extractor::Extractor};
    ///
    /// let db = Database::from("threats.mxy").open()?;
    /// let extractor = Extractor::new()?;
    ///
    /// let log_line = b"Connection from 192.168.1.1 to evil.com";
    ///
    /// for item in extractor.extract_from_line(log_line) {
    ///     if let Some(result @ (QueryResult::Ip { .. } | QueryResult::Pattern { .. })) =
    ///         db.lookup_extracted(&item, log_line)?
    ///     {
    ///         println!("Match: {} -> {:?}", item.as_str(log_line), result);
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lookup_extracted(
        &self,
        item: &crate::extractor::Match,
        input: &[u8],
    ) -> Result<Option<QueryResult>, DatabaseError> {
        use crate::extractor::ExtractedItem;

        match &item.item {
            ExtractedItem::Ipv4(ip) => self.lookup_ip(IpAddr::V4(*ip)),
            ExtractedItem::Ipv6(ip) => self.lookup_ip(IpAddr::V6(*ip)),
            _ => self.lookup(item.as_str(input)),
        }
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
        let mut all_data_offsets = Vec::new();
        let data_decoder = if self.literal_hash.is_some() || self.pattern_data_mappings.is_some() {
            let header = self.ip_header.as_ref().ok_or_else(|| {
                DatabaseError::Format(MmdbError::InvalidFormat(
                    "String data mappings present but no IP header".to_string(),
                ))
            })?;
            Some(DataDecoder::new(self.bounded_data_section(header)?, 0))
        } else {
            None
        };
        let mut decode_budget = data_decoder.as_ref().map(DataDecoder::new_budget);

        // 1. Try literal hash table first (O(1) lookup)
        if let Some(literal_hash) = &self.literal_hash {
            if let Some(pattern_id) = literal_hash.lookup(pattern) {
                if let Some(data_offset) = literal_hash.get_data_offset(pattern_id) {
                    if all_pattern_ids.len() >= MAX_STRING_QUERY_MATCHES {
                        return Err(DatabaseError::Config(format!(
                            "String query exceeded the maximum of {MAX_STRING_QUERY_MATCHES} matches"
                        )));
                    }
                    let decoder = data_decoder.as_ref().ok_or_else(|| {
                        DatabaseError::Format(MmdbError::InvalidFormat(
                            "Literal hash present but no data decoder".to_string(),
                        ))
                    })?;
                    let budget = decode_budget.as_mut().ok_or_else(|| {
                        DatabaseError::Format(MmdbError::InvalidFormat(
                            "Literal hash present but no decode budget".to_string(),
                        ))
                    })?;
                    let data = Self::decode_data_with_budget(decoder, budget, data_offset)?;
                    all_pattern_ids.push(pattern_id);
                    all_data_values.push(Some(data));
                    all_data_offsets.push(data_offset);
                }
            }
        }

        // 2. Check glob patterns (for wildcard matches)
        if let Some(ref pg) = self.pattern_matcher {
            let remaining_matches = MAX_STRING_QUERY_MATCHES
                .checked_sub(all_pattern_ids.len())
                .ok_or_else(|| {
                    DatabaseError::Config(format!(
                        "String query exceeded the maximum of {MAX_STRING_QUERY_MATCHES} matches"
                    ))
                })?;
            let glob_pattern_ids = pg
                .try_find_all_bounded(pattern, remaining_matches, MAX_STRING_QUERY_MATCHING_WORK)
                .map_err(|error| {
                    Self::map_paraglob_query_error("Pattern matching failed", error)
                })?;
            if glob_pattern_ids.len() > remaining_matches {
                return Err(DatabaseError::Config(format!(
                    "String query exceeded the maximum of {MAX_STRING_QUERY_MATCHES} matches"
                )));
            }

            match (&self.pattern_data_mappings, &self.ip_header) {
                (Some(mappings), Some(_)) => {
                    for &pattern_id in &glob_pattern_ids {
                        if let Some(data_offset) =
                            mappings.get_offset(pattern_id, self.data.as_slice())
                        {
                            let decoder = data_decoder.as_ref().ok_or_else(|| {
                                DatabaseError::Format(MmdbError::InvalidFormat(
                                    "Pattern mappings present but no data decoder".to_string(),
                                ))
                            })?;
                            let budget = decode_budget.as_mut().ok_or_else(|| {
                                DatabaseError::Format(MmdbError::InvalidFormat(
                                    "Pattern mappings present but no decode budget".to_string(),
                                ))
                            })?;
                            all_pattern_ids.push(pattern_id);
                            all_data_values.push(Some(Self::decode_data_with_budget(
                                decoder,
                                budget,
                                data_offset,
                            )?));
                            all_data_offsets.push(data_offset);
                        } else {
                            all_pattern_ids.push(pattern_id);
                            all_data_values.push(None);
                            all_data_offsets.push(0);
                        }
                    }
                }
                (Some(_), None) => {
                    unreachable!(
                        "pattern_data_mappings present without ip_header - invalid database state"
                    )
                }
                (None, _) => {
                    // Pattern-only databases store data inside the Paraglob
                    // section, so decode every match under one aggregate budget.
                    let data =
                        pg.try_get_pattern_data_many(&glob_pattern_ids)
                            .map_err(|error| {
                                Self::map_paraglob_query_error(
                                    "Failed to decode data for matched patterns",
                                    error,
                                )
                            })?;
                    if data.len() != glob_pattern_ids.len() {
                        return Err(DatabaseError::Format(MmdbError::InvalidFormat(
                            "Pattern data batch length does not match the matched pattern count"
                                .to_string(),
                        )));
                    }
                    all_pattern_ids.extend_from_slice(&glob_pattern_ids);
                    all_data_offsets.resize(all_data_offsets.len() + data.len(), 0);
                    all_data_values.extend(data);
                }
            }
        }

        if all_pattern_ids.is_empty() {
            if self.literal_hash.is_some() || self.pattern_matcher.is_some() {
                Ok(Some(QueryResult::NotFound))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(QueryResult::Pattern {
                pattern_ids: all_pattern_ids,
                data: all_data_values,
                data_offsets: all_data_offsets,
            }))
        }
    }

    /// Look up a string (literal or glob pattern) - public API, uses thread-local cache.
    ///
    /// Returns [`QueryResult::Pattern`] when one or more strings match,
    /// [`QueryResult::NotFound`] when a string index exists but none match, and
    /// `None` when the database has no string index. All decoded values in
    /// one query share an aggregate decoder budget. Queries that exceed 65,536
    /// matches, one million units in any bounded matching-work dimension (query
    /// bytes, unique literal hits, or raw candidates plus wildcard checks), the
    /// derived 64-million-unit shared matching CPU allowance, or the decoder
    /// work/allocation limits return [`DatabaseError::Config`] instead of
    /// allocating unbounded intermediate or result storage.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Format`] for malformed database data and
    /// [`DatabaseError::Config`] when a query exceeds a runtime resource limit.
    pub fn lookup_string(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
        Self::ensure_string_query_within_limit(pattern)?;

        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return Self::resolve_live_db(live).lookup_string(pattern);
        }

        // Check thread-local cache first
        if let Some(Some(result)) =
            self.with_cache(|cache| cache.get(pattern, CacheQueryKind::String).cloned())
        {
            self.record_query_stats(CacheQueryKind::String, Some(&result), true);
            return Ok(Some(result));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_string_uncached(pattern)?;
        self.record_query_stats(CacheQueryKind::String, result.as_ref(), false);

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put_borrowed(pattern, CacheQueryKind::String, res));
        }

        Ok(result)
    }

    fn bounded_data_section(&self, header: &MmdbHeader) -> Result<&[u8], DatabaseError> {
        let data_section_start = header.tree_size.checked_add(16).ok_or_else(|| {
            DatabaseError::Format(MmdbError::InvalidFormat(
                "Tree size overflows data section offset".to_string(),
            ))
        })?;
        let data_section_end = self.data_section_end.ok_or_else(|| {
            DatabaseError::Format(MmdbError::InvalidFormat(
                "MMDB data section boundary is unavailable".to_string(),
            ))
        })?;
        let data = self.data.as_slice();
        data.get(data_section_start..data_section_end).ok_or_else(|| {
            DatabaseError::Format(MmdbError::InvalidFormat(format!(
                "Data section range [{data_section_start}, {data_section_end}) is invalid for file length {}",
                data.len(),
            )))
        })
    }

    fn validate_data_offset(&self, header: &MmdbHeader, offset: u32) -> Result<(), DatabaseError> {
        let data_section = self.bounded_data_section(header)?;
        let offset = usize::try_from(offset).map_err(|_| {
            DatabaseError::Format(MmdbError::InvalidFormat(
                "Data offset is not addressable on this platform".to_string(),
            ))
        })?;
        if offset >= data_section.len() {
            return Err(DatabaseError::Format(MmdbError::InvalidFormat(format!(
                "Data offset {offset} exceeds bounded data section ({} bytes)",
                data_section.len()
            ))));
        }
        Ok(())
    }

    fn decode_data_with_budget(
        decoder: &DataDecoder<'_>,
        budget: &mut DecodeBudget,
        offset: u32,
    ) -> Result<DataValue, DatabaseError> {
        decoder.decode_with_budget(offset, budget).map_err(|error| {
            if is_decoder_resource_error(error) {
                DatabaseError::Config(format!(
                    "String query data at offset {offset} hit a decode resource limit: {error}"
                ))
            } else {
                DatabaseError::Format(MmdbError::DecodeError(error.to_string()))
            }
        })
    }

    fn map_paraglob_query_error(context: &str, error: ParaglobError) -> DatabaseError {
        match error {
            ParaglobError::ResourceLimitExceeded(message) => {
                DatabaseError::Config(format!("{context}: {message}"))
            }
            error => DatabaseError::Format(MmdbError::DecodeError(format!("{context}: {error}"))),
        }
    }

    /// Decode IP data at a given offset.
    fn decode_ip_data(&self, header: &MmdbHeader, offset: u32) -> Result<DataValue, DatabaseError> {
        // Tree, literal, and pattern mappings store offsets relative to this
        // bounded MMDB data section. Extension sections and metadata are not
        // valid decoder input.
        let data_section = self.bounded_data_section(header)?;

        // Offsets from tree are relative to data_section, which we've sliced
        // So base_offset is 0 (the decoder will resolve pointers relative to the buffer start)
        let decoder = DataDecoder::new(data_section, 0);

        decoder
            .decode(offset)
            .map_err(|e| DatabaseError::Format(MmdbError::DecodeError(e.to_string())))
    }

    /// Offset-only lookup that returns references as offsets instead of decoded data.
    ///
    /// This is designed for the C API where the returned result should not own
    /// decoded values. Cold string queries may allocate bounded thread-local
    /// matcher scratch; repeated queries reuse that capacity. Data can be
    /// decoded on demand via `decode_at_offset()`.
    ///
    /// For a live-reloading database, the token is not bound to a generation.
    /// A reload between this call and [`Self::decode_at_offset`] can make the
    /// token refer to different bytes. Applications that need snapshot-stable
    /// deferred decoding should use a non-watching `Database` snapshot.
    ///
    /// # Arguments
    /// * `query` - IP address or string to look up
    ///
    /// # Returns
    /// `LookupRef` containing:
    /// - `found`: whether a match was found
    /// - `data_offset`: format-specific data token (use only with `decode_at_offset()`)
    /// - `prefix_len`: network prefix length (for IP results)
    /// - `result_type`: 0=not found, 1=ip, 2=pattern
    pub fn lookup_ref(&self, query: &str) -> Result<LookupRef, DatabaseError> {
        Self::ensure_string_query_within_limit(query)?;

        // Delegate to live database if auto-reload is enabled
        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return Self::resolve_live_db(live).lookup_ref(query);
        }

        let parsed_address = query.parse::<IpAddr>().ok();
        let kind = if parsed_address.is_some() {
            CacheQueryKind::Ip
        } else {
            CacheQueryKind::String
        };

        // An owned full result and a lightweight offset-only result share one
        // cache slot. The latter avoids decoding and retaining DataValue trees
        // solely to warm the C-facing lookup path.
        if let Some(Some(lookup)) = self.with_cache(|cache| cache.get_ref(query, kind, self.format))
        {
            self.record_lookup_ref_stats(kind, lookup, true);
            return Ok(lookup);
        }

        let lookup = if let Some(addr) = parsed_address {
            self.lookup_ip_ref(addr)
        } else {
            self.lookup_string_ref(query)
        }?;
        self.record_lookup_ref_stats(kind, lookup, false);
        self.with_cache(|cache| cache.put_ref(query, kind, lookup));
        Ok(lookup)
    }

    fn record_lookup_ref_stats(&self, kind: CacheQueryKind, lookup: LookupRef, cache_hit: bool) {
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);

        if cache_hit {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else if self.cache_enabled {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        match kind {
            CacheQueryKind::Ip => {
                self.stats.ip_queries.fetch_add(1, Ordering::Relaxed);
            }
            CacheQueryKind::String => {
                self.stats.string_queries.fetch_add(1, Ordering::Relaxed);
            }
        }
        if lookup.found {
            self.stats
                .queries_with_match
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats
                .queries_without_match
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Offset-only IP lookup that returns an offset instead of decoded data.
    fn lookup_ip_ref(&self, addr: IpAddr) -> Result<LookupRef, DatabaseError> {
        let header = match &self.ip_header {
            Some(h) => h,
            None => return Ok(LookupRef::not_found()),
        };

        let tree = SearchTree::new(self.data.as_slice(), header);
        let tree_result = tree.lookup(addr).map_err(DatabaseError::Format)?;

        match tree_result {
            Some(r) => {
                self.validate_data_offset(header, r.data_offset)?;
                Ok(LookupRef::ip(r.data_offset, r.prefix_len))
            }
            None => Ok(LookupRef::not_found()),
        }
    }

    /// Offset-only string lookup that returns an offset instead of decoded data.
    fn lookup_string_ref(&self, pattern: &str) -> Result<LookupRef, DatabaseError> {
        // 1. Try literal hash table first (O(1) lookup)
        if let Some(literal_hash) = &self.literal_hash {
            if let Some(pattern_id) = literal_hash.lookup(pattern) {
                if let Some(data_offset) = literal_hash.get_data_offset(pattern_id) {
                    let header = self.ip_header.as_ref().ok_or_else(|| {
                        DatabaseError::Format(MmdbError::InvalidFormat(
                            "Literal hash has no MMDB header".to_string(),
                        ))
                    })?;
                    self.validate_data_offset(header, data_offset)?;
                    return Ok(LookupRef::pattern(data_offset));
                }
            }
        }

        // 2. Check glob patterns (for wildcard matches)
        if let Some(ref pg) = self.pattern_matcher {
            let pattern_id = pg
                .try_find_first_bounded(pattern, MAX_STRING_QUERY_MATCHING_WORK)
                .map_err(|error| {
                    Self::map_paraglob_query_error("Pattern matching failed", error)
                })?;
            if let Some(pattern_id) = pattern_id {
                // For combined databases, use mappings to get offset
                if let Some(mappings) = &self.pattern_data_mappings {
                    if let Some(data_offset) = mappings.get_offset(pattern_id, self.data.as_slice())
                    {
                        let header = self.ip_header.as_ref().ok_or_else(|| {
                            DatabaseError::Format(MmdbError::InvalidFormat(
                                "Pattern mappings have no MMDB header".to_string(),
                            ))
                        })?;
                        self.validate_data_offset(header, data_offset)?;
                        return Ok(LookupRef::pattern(data_offset));
                    }
                } else {
                    // Pattern-only files keep their data inside the Paraglob
                    // section. Use the pattern ID as the opaque decode token.
                    return Ok(LookupRef::pattern(pattern_id));
                }
            }
        }

        Ok(LookupRef::not_found())
    }

    /// Decode data selected by a [`LookupRef`] data token.
    ///
    /// This is the companion to `lookup_ref()` - use it to decode data on-demand
    /// after getting an offset from an offset-only lookup.
    /// On a live-reloading database, see [`Self::lookup_ref`] for the generation
    /// limitation of deferred tokens.
    ///
    /// # Arguments
    /// * `offset` - The format-specific token from [`LookupRef::data_offset`]
    ///
    /// # Returns
    /// The decoded `DataValue` or an error if the offset is invalid.
    ///
    /// # Example
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    /// let lookup = db.lookup_ref("1.2.3.4")?;
    /// if lookup.found {
    ///     let data = db.decode_at_offset(lookup.data_offset)?;
    ///     println!("Data: {:?}", data);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn decode_at_offset(&self, offset: u32) -> Result<DataValue, DatabaseError> {
        // Delegate to live database if auto-reload is enabled
        #[cfg(not(target_family = "wasm"))]
        if let Some(ref live) = self.live {
            return Self::resolve_live_db(live).decode_at_offset(offset);
        }

        match self.format {
            DatabaseFormat::PatternOnly => {
                let matcher = self.pattern_matcher.as_ref().ok_or_else(|| {
                    DatabaseError::Format(MmdbError::InvalidFormat(
                        "Pattern-only database has no pattern matcher".to_string(),
                    ))
                })?;
                matcher
                    .try_get_pattern_data(offset)
                    .map_err(|error| {
                        Self::map_paraglob_query_error("Pattern data decoding failed", error)
                    })?
                    .ok_or_else(|| {
                        DatabaseError::Unsupported(format!(
                            "Pattern {offset} has no associated data"
                        ))
                    })
            }
            DatabaseFormat::IpOnly | DatabaseFormat::Combined => {
                let header = self.ip_header.as_ref().ok_or_else(|| {
                    DatabaseError::Format(MmdbError::InvalidFormat(
                        "MMDB-backed database has no IP header".to_string(),
                    ))
                })?;
                self.decode_ip_data(header, offset)
            }
        }
    }

    /// Detect database format and validate embedded-section locations.
    fn detect_format_and_sections(
        data: &[u8],
    ) -> Result<(DatabaseFormat, EmbeddedSections), DatabaseError> {
        // Check for paraglob magic at start (pattern-only format)
        let has_paraglob_start = data.len() >= 8 && &data[0..8] == b"PARAGLOB";
        if has_paraglob_start {
            return Ok((
                DatabaseFormat::PatternOnly,
                EmbeddedSections::pattern_only(data.len()),
            ));
        }

        let metadata_offset = crate::mmdb::find_metadata_marker(data).map_err(|_| {
            DatabaseError::Format(MmdbError::InvalidFormat(
                "Unknown database format (no MMDB or PARAGLOB marker)".to_string(),
            ))
        })?;
        let sections = Self::locate_embedded_sections(data, metadata_offset)
            .map_err(|error| DatabaseError::Format(MmdbError::InvalidFormat(error)))?;

        let format =
            if sections.pattern_data_offset.is_some() || sections.literal_marker_offset.is_some() {
                DatabaseFormat::Combined
            } else {
                DatabaseFormat::IpOnly
            };

        Ok((format, sections))
    }

    /// Get database format
    #[must_use]
    pub fn format(&self) -> &str {
        match self.format {
            DatabaseFormat::IpOnly => "IP database",
            DatabaseFormat::PatternOnly => "Pattern database",
            DatabaseFormat::Combined => "Combined IP+Pattern database",
        }
    }

    /// Check if database supports IP lookups
    #[must_use]
    pub fn has_ip_data(&self) -> bool {
        self.ip_header.is_some()
    }

    /// Check if database supports string lookups (literals or patterns)
    #[must_use]
    pub fn has_string_data(&self) -> bool {
        self.literal_hash.is_some() || self.pattern_matcher.is_some()
    }

    /// Check if database supports literal (exact string) lookups
    #[must_use]
    pub fn has_literal_data(&self) -> bool {
        self.literal_hash.is_some()
    }

    /// Check if database supports glob pattern lookups
    #[must_use]
    pub fn has_glob_data(&self) -> bool {
        self.pattern_matcher.is_some()
    }

    /// Return the names of opaque sections embedded in this database image.
    #[must_use]
    pub fn embedded_section_names(&self) -> Vec<String> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(live) = &self.live {
            return Self::resolve_live_db(live).embedded_section_names();
        }

        self.embedded_sections
            .iter()
            .map(|section| section.name.clone())
            .collect()
    }

    /// Open an opaque embedded section by its logical name without copying it.
    ///
    /// The returned handle owns the backing database storage and remains valid
    /// independently of this [`Database`]. For a watched database, it refers to
    /// the generation current when this method is called.
    #[must_use]
    pub fn embedded_section(&self, name: &str) -> Option<DatabaseSection> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(live) = &self.live {
            return Self::resolve_live_db(live).embedded_section(name);
        }

        let location = self
            .embedded_sections
            .iter()
            .find(|section| section.name == name)?
            .clone();
        Some(DatabaseSection {
            storage: self.data.clone(),
            location,
        })
    }

    /// Check if database supports pattern lookups (deprecated, use has_literal_data or has_glob_data)
    #[deprecated(
        since = "0.5.0",
        note = "Use has_literal_data or has_glob_data instead"
    )]
    #[must_use]
    pub fn has_pattern_data(&self) -> bool {
        self.has_string_data()
    }

    /// Get MMDB metadata if available
    ///
    /// Returns the full metadata as a DataValue map, or None if this is not
    /// an MMDB-format database or if metadata cannot be parsed.
    #[must_use]
    pub fn metadata(&self) -> Option<DataValue> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(live) = &self.live {
            return live.current.load().metadata();
        }

        if !self.has_ip_data() {
            return None;
        }

        use crate::mmdb::MmdbMetadata;
        let metadata = MmdbMetadata::from_file(self.data.as_slice()).ok()?;
        metadata.as_value().ok()
    }

    /// Get the update URL from database metadata, if set during build.
    ///
    /// Returns `None` if no update URL was set or if metadata is unavailable.
    #[must_use]
    pub fn update_url(&self) -> Option<String> {
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(DataValue::String(url)) = map.get("update_url") {
                return Some(url.clone());
            }
        }
        None
    }

    /// Get pattern string by ID
    ///
    /// Returns the pattern string for a given pattern ID.
    /// Returns None if the database has no pattern data or pattern ID is invalid.
    #[must_use]
    pub fn get_pattern_string(&self, pattern_id: u32) -> Option<String> {
        let pg = self.pattern_matcher.as_ref()?;
        pg.get_pattern(pattern_id)
    }

    /// Get total number of glob patterns
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no pattern data.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        match &self.pattern_matcher {
            Some(pg) => pg.pattern_count(),
            None => 0,
        }
    }

    /// Get number of glob patterns (alias for pattern_count)
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no glob pattern data.
    #[must_use]
    pub fn glob_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("glob_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return usize::try_from(val).unwrap_or(usize::MAX);
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
    #[must_use]
    pub fn literal_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("literal_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return usize::try_from(val).unwrap_or(usize::MAX);
                }
            }
        }
        // Fallback to literal_hash entry count
        match &self.literal_hash {
            Some(lh) => lh.entry_count() as usize,
            None => 0,
        }
    }

    /// Get number of IP/CIDR entries
    ///
    /// Returns the number of IP or CIDR entries in the database.
    /// Returns 0 if the database has no IP data.
    ///
    /// For databases built with matchy, this returns the exact entry count from `ip_entry_count`.
    /// For standard MMDB files (like MaxMind GeoLite2), it falls back to `node_count` which
    /// represents the search tree size (a reasonable proxy for entry count).
    #[must_use]
    pub fn ip_count(&self) -> usize {
        if let Some(DataValue::Map(map)) = self.metadata() {
            // Try exact count first (matchy-built databases)
            if let Some(count) = map.get("ip_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return usize::try_from(val).unwrap_or(usize::MAX);
                }
            }
            // Fall back to node_count (standard MMDB files like MaxMind)
            if let Some(count) = map.get("node_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return usize::try_from(val).unwrap_or(usize::MAX);
                }
            }
        }
        0
    }

    /// Helper to extract unsigned integer from DataValue
    fn extract_uint_from_datavalue(value: &DataValue) -> Option<u64> {
        match value {
            DataValue::Uint16(v) => Some(u64::from(*v)),
            DataValue::Uint32(v) => Some(u64::from(*v)),
            DataValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    fn parse_opaque_sections(
        data: &[u8],
        metadata_offset: usize,
    ) -> Result<Vec<EmbeddedSectionLocation>, String> {
        let metadata = crate::mmdb::MmdbMetadata::from_file(data)
            .map_err(|error| format!("Could not read embedded section metadata: {error}"))?
            .as_value()
            .map_err(|error| format!("Could not decode embedded section metadata: {error}"))?;
        let DataValue::Map(metadata) = metadata else {
            return Err("MMDB metadata is not a map".to_string());
        };
        let Some(directory) = metadata.get("embedded_sections") else {
            return Ok(Vec::new());
        };
        let version = metadata
            .get("embedded_section_directory_version")
            .and_then(Self::extract_uint_from_datavalue)
            .ok_or_else(|| "Embedded section directory has no numeric version".to_string())?;
        if version != 1 {
            return Err(format!(
                "Unsupported embedded section directory version {version}"
            ));
        }
        let DataValue::Map(directory) = directory else {
            return Err("embedded_sections metadata is not a map".to_string());
        };

        let mut sections = Vec::with_capacity(directory.len());
        for (name, descriptor) in directory {
            if name.is_empty() {
                return Err("Embedded section name cannot be empty".to_string());
            }
            let DataValue::Map(descriptor) = descriptor else {
                return Err(format!("Embedded section {name:?} descriptor is not a map"));
            };
            let format = match descriptor.get("format") {
                Some(DataValue::String(format)) if !format.is_empty() => format.clone(),
                _ => {
                    return Err(format!("Embedded section {name:?} has no non-empty format"));
                }
            };
            let numeric = |field: &str| {
                descriptor
                    .get(field)
                    .and_then(Self::extract_uint_from_datavalue)
                    .ok_or_else(|| format!("Embedded section {name:?} has no numeric {field}"))
            };
            let offset = usize::try_from(numeric("offset")?)
                .map_err(|_| format!("Embedded section {name:?} offset exceeds usize"))?;
            let length = usize::try_from(numeric("length")?)
                .map_err(|_| format!("Embedded section {name:?} length exceeds usize"))?;
            let alignment = usize::try_from(numeric("alignment")?)
                .map_err(|_| format!("Embedded section {name:?} alignment exceeds usize"))?;
            if alignment == 0 || !alignment.is_power_of_two() || alignment > 64 * 1024 {
                return Err(format!(
                    "Embedded section {name:?} alignment must be a power of two no greater than 65536"
                ));
            }
            if offset % alignment != 0 {
                return Err(format!(
                    "Embedded section {name:?} offset {offset} is not aligned to {alignment}"
                ));
            }
            let end = offset
                .checked_add(length)
                .ok_or_else(|| format!("Embedded section {name:?} range overflows usize"))?;
            if end > metadata_offset {
                return Err(format!(
                    "Embedded section {name:?} range [{offset}, {end}) crosses metadata at {metadata_offset}"
                ));
            }
            sections.push(EmbeddedSectionLocation {
                name: name.clone(),
                format,
                range: offset..end,
                alignment,
            });
        }

        sections.sort_unstable_by(|left, right| {
            left.range
                .start
                .cmp(&right.range.start)
                .then_with(|| left.name.cmp(&right.name))
        });
        for pair in sections.windows(2) {
            if pair[0].range.end > pair[1].range.start {
                return Err(format!(
                    "Embedded sections {:?} and {:?} overlap",
                    pair[0].name, pair[1].name
                ));
            }
        }
        Ok(sections)
    }

    /// Locate embedded pattern and literal sections. Metadata offsets are the
    /// fast path, but each non-zero offset must point immediately after the
    /// corresponding marker and remain before MMDB metadata. Older databases
    /// without usable offset fields fall back to one bounded scan.
    pub(crate) fn locate_embedded_sections(
        data: &[u8],
        metadata_offset: usize,
    ) -> Result<EmbeddedSections, String> {
        let searchable = data.get(..metadata_offset).ok_or_else(|| {
            format!(
                "Metadata offset {metadata_offset} exceeds file length {}",
                data.len()
            )
        })?;

        let mut pattern_data_offset = None;
        let mut literal_marker_offset = None;
        let mut scan_for_pattern = true;
        let mut scan_for_literal = true;
        let mut invalid_pattern_offset = None;
        let mut invalid_literal_offset = None;

        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint32(offset)) = map.get("pattern_section_offset") {
                    if *offset == 0 {
                        scan_for_pattern = false;
                    } else if let Some(marker_offset) = Self::validated_marker_before_offset(
                        data,
                        metadata_offset,
                        *offset,
                        PATTERN_SECTION_MARKER,
                    ) {
                        pattern_data_offset =
                            marker_offset.checked_add(PATTERN_SECTION_MARKER.len());
                        scan_for_pattern = false;
                    } else {
                        invalid_pattern_offset = Some(*offset);
                    }
                }

                if let Some(DataValue::Uint32(offset)) = map.get("literal_section_offset") {
                    if *offset == 0 {
                        scan_for_literal = false;
                    } else if let Some(marker_offset) = Self::validated_marker_before_offset(
                        data,
                        metadata_offset,
                        *offset,
                        LITERAL_SECTION_MARKER,
                    ) {
                        literal_marker_offset = Some(marker_offset);
                        scan_for_literal = false;
                    } else {
                        invalid_literal_offset = Some(*offset);
                    }
                }
            }
        }

        if scan_for_pattern {
            pattern_data_offset = searchable
                .windows(PATTERN_SECTION_MARKER.len())
                .position(|window| window == PATTERN_SECTION_MARKER)
                .and_then(|marker_offset| marker_offset.checked_add(PATTERN_SECTION_MARKER.len()));
            if pattern_data_offset.is_none() {
                if let Some(offset) = invalid_pattern_offset {
                    return Err(format!(
                        "pattern_section_offset {offset} is invalid and no legacy marker was found"
                    ));
                }
            }
        }

        if scan_for_literal {
            literal_marker_offset = searchable
                .windows(LITERAL_SECTION_MARKER.len())
                .position(|window| window == LITERAL_SECTION_MARKER);
            if literal_marker_offset.is_none() {
                if let Some(offset) = invalid_literal_offset {
                    return Err(format!(
                        "literal_section_offset {offset} is invalid and no legacy marker was found"
                    ));
                }
            }
        }

        if let (Some(pattern_offset), Some(literal_offset)) =
            (pattern_data_offset, literal_marker_offset)
        {
            if literal_offset < pattern_offset {
                return Err(format!(
                    "Literal section at {literal_offset} precedes pattern data at {pattern_offset}"
                ));
            }
        }

        let opaque_data_offset = Self::parse_opaque_sections(data, metadata_offset)?
            .first()
            .map(|section| section.range.start);

        Ok(EmbeddedSections {
            pattern_data_offset,
            literal_marker_offset,
            opaque_data_offset,
            metadata_offset,
        })
    }

    fn validated_marker_before_offset(
        data: &[u8],
        metadata_offset: usize,
        data_offset: u32,
        marker: &[u8; 16],
    ) -> Option<usize> {
        let data_offset = usize::try_from(data_offset).ok()?;
        if data_offset > metadata_offset {
            return None;
        }
        let marker_offset = data_offset.checked_sub(marker.len())?;
        let marker_end = marker_offset.checked_add(marker.len())?;
        if marker_end != data_offset {
            return None;
        }
        (data.get(marker_offset..marker_end)? == marker).then_some(marker_offset)
    }

    fn read_match_mode_from_paraglob_header(
        data: &[u8],
    ) -> Result<matchy_match_mode::MatchMode, String> {
        use matchy_match_mode::MatchMode;

        let (header, _) = ParaglobHeader::read_from_prefix(data)
            .map_err(|_| "Paraglob header is truncated".to_string())?;
        match header.match_mode {
            0 => Ok(MatchMode::CaseSensitive),
            1 => Ok(MatchMode::CaseInsensitive),
            value => Err(format!(
                "Invalid Paraglob match_mode value {value}; expected 0 or 1"
            )),
        }
    }

    /// Load pattern section from data at given offset (for pattern-only databases)
    /// The format at offset is: PARAGLOB magic + data
    /// Uses zero-copy from_mmap for O(1) loading
    fn load_pattern_section(data: &'static [u8], offset: usize) -> Result<Paraglob, String> {
        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // For pattern-only databases, data starts with PARAGLOB magic
        if offset == 0 && data.len() >= 8 && &data[0..8] == b"PARAGLOB" {
            let match_mode = Self::read_match_mode_from_paraglob_header(data)?;
            // Standard .pgb format - load with zero-copy
            // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
            let result = unsafe { Paraglob::from_mmap(data, match_mode) };
            return result.map_err(|e| format!("Failed to parse pattern-only database: {e}"));
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
        section_limit: usize,
    ) -> Result<(Paraglob, PatternDataMappings), String> {
        if section_limit > data.len() || offset > section_limit {
            return Err(format!(
                "Pattern section range [{offset}, {section_limit}) is invalid for file length {}",
                data.len()
            ));
        }

        // Try to read match mode from metadata
        let match_mode = Self::read_match_mode_from_metadata(data);

        // Read section header
        let header_end = offset
            .checked_add(2 * std::mem::size_of::<u32>())
            .ok_or_else(|| "Pattern section header offset overflow".to_string())?;
        let header = data
            .get(offset..header_end)
            .filter(|_| header_end <= section_limit)
            .ok_or_else(|| "Pattern section header truncated".to_string())?;

        // Read sizes (little-endian u32)
        let total_size = usize::try_from(u32::from_le_bytes(
            header[..4]
                .try_into()
                .expect("section size slice has exact length"),
        ))
        .map_err(|_| "Pattern section size does not fit usize".to_string())?;
        let paraglob_size = usize::try_from(u32::from_le_bytes(
            header[4..8]
                .try_into()
                .expect("paraglob size slice has exact length"),
        ))
        .map_err(|_| "Paraglob size does not fit usize".to_string())?;

        let section_end = offset
            .checked_add(total_size)
            .ok_or_else(|| "Pattern section end offset overflow".to_string())?;
        if section_end > section_limit {
            return Err(format!(
                "Pattern section ends at {section_end}, beyond containing section limit {section_limit}"
            ));
        }
        if section_end < header_end {
            return Err(format!(
                "Pattern total_size {total_size} is smaller than its header"
            ));
        }

        // Paraglob data starts at offset + 8
        let paraglob_start = header_end;
        let paraglob_end = paraglob_start
            .checked_add(paraglob_size)
            .ok_or_else(|| "Paraglob section end offset overflow".to_string())?;

        if paraglob_end > section_end {
            return Err(format!(
                "Paraglob range [{paraglob_start}, {paraglob_end}) exceeds declared pattern section ending at {section_end}"
            ));
        }

        // Extract and load paraglob data with zero-copy
        let paraglob_data = data
            .get(paraglob_start..paraglob_end)
            .ok_or_else(|| "Paraglob range is outside the file".to_string())?;
        let serialized_match_mode = Self::read_match_mode_from_paraglob_header(paraglob_data)?;
        if serialized_match_mode != match_mode {
            return Err(format!(
                "Paraglob match mode {serialized_match_mode:?} disagrees with MMDB metadata mode {match_mode:?}"
            ));
        }
        // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
        let paraglob = unsafe { Paraglob::from_mmap(paraglob_data, serialized_match_mode) };
        let paraglob = paraglob.map_err(|e| format!("Failed to parse paraglob section: {e}"))?;

        // Store mapping metadata WITHOUT parsing all offsets (O(1) instead of O(n))
        let mappings_start = paraglob_end;
        let offsets_start = mappings_start
            .checked_add(std::mem::size_of::<u32>())
            .ok_or_else(|| "Pattern mapping count offset overflow".to_string())?;
        let count_bytes = data
            .get(mappings_start..offsets_start)
            .filter(|_| offsets_start <= section_end)
            .ok_or_else(|| "Pattern mappings section truncated".to_string())?;
        let pattern_count = usize::try_from(u32::from_le_bytes(
            count_bytes
                .try_into()
                .expect("pattern count slice has exact length"),
        ))
        .map_err(|_| "Pattern mapping count does not fit usize".to_string())?;
        if pattern_count < paraglob.pattern_count() {
            return Err(format!(
                "Pattern mapping count {pattern_count} is smaller than Paraglob pattern count {}",
                paraglob.pattern_count()
            ));
        }

        // Validate the mapping section exists, but don't parse it
        let total_mapping_bytes = pattern_count
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| "Pattern mapping table size overflow".to_string())?;
        let mappings_end = offsets_start
            .checked_add(total_mapping_bytes)
            .ok_or_else(|| "Pattern mapping table end offset overflow".to_string())?;
        if mappings_end != section_end {
            return Err(format!(
                "Pattern mappings end at {mappings_end}, but declared pattern section ends at {section_end}"
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
    fn read_match_mode_from_metadata(data: &[u8]) -> matchy_match_mode::MatchMode {
        use matchy_match_mode::MatchMode;

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
    /// Configuration or runtime resource-policy error
    Config(String),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Format(err) => write!(f, "Format error: {err}"),
            Self::Unsupported(msg) => write!(f, "Unsupported: {msg}"),
            Self::Config(msg) => write!(f, "Configuration or resource error: {msg}"),
        }
    }
}

impl std::error::Error for DatabaseError {}

impl DatabaseError {
    /// Returns true if this error indicates data corruption that should trigger fallback.
    #[must_use]
    pub fn is_data_error(&self) -> bool {
        matches!(self, Self::Format(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matchy_data_format::DataEncoder;
    use matchy_format::DatabaseBuilder;
    use matchy_match_mode::MatchMode;
    use std::collections::HashMap;

    const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

    fn build_database(keys: &[&str]) -> Vec<u8> {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        for (index, key) in keys.iter().enumerate() {
            let mut value = HashMap::new();
            value.insert(
                "index".to_string(),
                DataValue::Uint32(u32::try_from(index).unwrap()),
            );
            builder.add_entry(key, value).unwrap();
        }
        builder.build().unwrap()
    }

    fn expanding_data_value(fill: char) -> DataValue {
        let repeated = DataValue::String(fill.to_string().repeat(1024));
        let row = DataValue::Array(vec![repeated; 24]);
        DataValue::Array(vec![row; 24])
    }

    fn expanding_record(fill: char) -> HashMap<String, DataValue> {
        HashMap::from([("matrix".to_string(), expanding_data_value(fill))])
    }

    fn rewrite_section_offset(bytes: &[u8], field: &str, value: u32) -> Vec<u8> {
        let metadata = crate::mmdb::MmdbMetadata::from_file(bytes)
            .unwrap()
            .as_value()
            .unwrap();
        let DataValue::Map(mut map) = metadata else {
            panic!("test database metadata must be a map");
        };
        map.insert(field.to_string(), DataValue::Uint32(value));

        let metadata_offset = crate::mmdb::find_metadata_marker(bytes).unwrap();
        let mut rewritten = bytes[..metadata_offset].to_vec();
        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::Map(map));
        rewritten.extend_from_slice(METADATA_MARKER);
        rewritten.extend_from_slice(&encoder.into_bytes());
        rewritten
    }

    fn rewrite_opaque_section_field(
        bytes: &[u8],
        section_name: &str,
        field: &str,
        value: DataValue,
    ) -> Vec<u8> {
        let metadata = crate::mmdb::MmdbMetadata::from_file(bytes)
            .unwrap()
            .as_value()
            .unwrap();
        let DataValue::Map(mut metadata) = metadata else {
            panic!("test database metadata must be a map");
        };
        let Some(DataValue::Map(directory)) = metadata.get_mut("embedded_sections") else {
            panic!("test database lacks an embedded section directory");
        };
        let Some(DataValue::Map(descriptor)) = directory.get_mut(section_name) else {
            panic!("test database lacks embedded section {section_name:?}");
        };
        descriptor.insert(field.to_string(), value);

        let metadata_offset = crate::mmdb::find_metadata_marker(bytes).unwrap();
        let mut rewritten = bytes[..metadata_offset].to_vec();
        rewritten.extend_from_slice(METADATA_MARKER);
        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::Map(metadata));
        rewritten.extend_from_slice(&encoder.into_bytes());
        rewritten
    }

    fn metadata_u32(bytes: &[u8], field: &str) -> u32 {
        let metadata = crate::mmdb::MmdbMetadata::from_file(bytes)
            .unwrap()
            .as_value()
            .unwrap();
        let DataValue::Map(map) = metadata else {
            panic!("test database metadata must be a map");
        };
        let Some(DataValue::Uint32(value)) = map.get(field) else {
            panic!("test database metadata lacks {field}");
        };
        *value
    }

    fn rewrite_offset_to_eof(bytes: &[u8], field: &str) -> Vec<u8> {
        let mut offset = u32::try_from(bytes.len()).unwrap();
        for _ in 0..4 {
            let rewritten = rewrite_section_offset(bytes, field, offset);
            let next_offset = u32::try_from(rewritten.len()).unwrap();
            if next_offset == offset {
                return rewritten;
            }
            offset = next_offset;
        }
        panic!("metadata length did not stabilize");
    }

    fn assert_database_rejected(bytes: Vec<u8>, case: &str) {
        assert!(
            Database::from_bytes(bytes).is_err(),
            "{case}: malformed database was accepted"
        );
    }

    fn result_index(result: &QueryResult) -> Option<u32> {
        let data = match result {
            QueryResult::Ip { data, .. } => data,
            QueryResult::Pattern { data, .. } => data.first()?.as_ref()?,
            QueryResult::NotFound => return None,
        };
        let DataValue::Map(map) = data else {
            return None;
        };
        let DataValue::Uint32(index) = map.get("index")? else {
            return None;
        };
        Some(*index)
    }

    #[test]
    fn typed_lookup_cache_entries_do_not_cross_contaminate() {
        let db = Database::from_bytes(build_database(&["192.0.2.1", "literal:192.0.2.1"])).unwrap();

        let string_result = db.lookup_string("192.0.2.1").unwrap().unwrap();
        assert!(matches!(string_result, QueryResult::Pattern { .. }));
        assert_eq!(result_index(&string_result), Some(1));

        let ip_result = db.lookup("192.0.2.1").unwrap().unwrap();
        assert!(matches!(ip_result, QueryResult::Ip { .. }));
        assert_eq!(result_index(&ip_result), Some(0));

        let string_result_again = db.lookup_string("192.0.2.1").unwrap().unwrap();
        assert!(matches!(string_result_again, QueryResult::Pattern { .. }));
        assert_eq!(result_index(&string_result_again), Some(1));
    }

    #[test]
    fn reused_public_generation_does_not_share_cache_between_databases() {
        let first = Database::open_with_options(DatabaseOptions {
            bytes: Some(build_database(&["shared.test"])),
            cache_generation: Some(7),
            ..Default::default()
        })
        .unwrap();
        let second = Database::open_with_options(DatabaseOptions {
            bytes: Some(build_database(&["filler.test", "shared.test"])),
            cache_generation: Some(7),
            ..Default::default()
        })
        .unwrap();

        let first_result = first.lookup_string("shared.test").unwrap().unwrap();
        let second_result = second.lookup_string("shared.test").unwrap().unwrap();
        assert_eq!(result_index(&first_result), Some(0));
        assert_eq!(result_index(&second_result), Some(1));
        assert_ne!(first.cache_namespace(), second.cache_namespace());
    }

    #[test]
    fn lookup_ref_warms_lightweight_cache_and_interoperates_with_owned_results() {
        let db = Database::from_bytes(build_database(&["literal.test"])).unwrap();

        let first = db.lookup_ref("literal.test").unwrap();
        assert!(first.found);
        assert_eq!(db.cache_size(), 1);
        let second = db.lookup_ref("literal.test").unwrap();
        assert_eq!(second.data_offset, first.data_offset);

        let stats = db.stats();
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hits, 1);

        // A full lookup cannot use the offset-only cache entry, so it replaces
        // that slot with an owned result. A later ref lookup derives its token
        // from the owned result without decoding again.
        assert!(matches!(
            db.lookup_string("literal.test").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));
        assert_eq!(db.cache_size(), 1);
        let third = db.lookup_ref("literal.test").unwrap();
        assert_eq!(third.data_offset, first.data_offset);

        let stats = db.stats();
        assert_eq!(stats.cache_misses, 2);
        assert_eq!(stats.cache_hits, 2);
    }

    #[test]
    fn typed_lookup_methods_record_consistent_stats() {
        let db = Database::from_bytes(build_database(&["192.0.2.1", "literal.test"])).unwrap();

        for _ in 0..2 {
            let _ = db.lookup_ip("192.0.2.1".parse().unwrap()).unwrap();
            let _ = db.lookup_ip("192.0.2.2".parse().unwrap()).unwrap();
            let _ = db.lookup_string("literal.test").unwrap();
            let _ = db.lookup_string("absent.test").unwrap();
        }

        let stats = db.stats();
        assert_eq!(stats.total_queries, 8);
        assert_eq!(stats.ip_queries, 4);
        assert_eq!(stats.string_queries, 4);
        assert_eq!(stats.queries_with_match, 4);
        assert_eq!(stats.queries_without_match, 4);
        assert_eq!(stats.cache_hits, 4);
        assert_eq!(stats.cache_misses, 4);
    }

    #[test]
    fn pattern_only_lookup_ref_token_decodes_inline_data() {
        let mut first_metadata = HashMap::new();
        first_metadata.insert("kind".to_string(), DataValue::String("first".to_string()));
        let mut metadata = HashMap::new();
        metadata.insert("kind".to_string(), DataValue::String("inline".to_string()));
        let paraglob = Paraglob::build_from_patterns_with_data(
            &["first.pattern.test", "*.pattern.test"],
            Some(&[
                Some(DataValue::Map(first_metadata)),
                Some(DataValue::Map(metadata.clone())),
            ]),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        let db = Database::from_bytes(paraglob.buffer().to_vec()).unwrap();

        // Populate the full-result cache first. Pattern-only data tokens are
        // pattern IDs, not the zero placeholders in `data_offsets`.
        assert!(matches!(
            db.lookup("value.pattern.test").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));
        let lookup = db.lookup_ref("value.pattern.test").unwrap();
        assert!(lookup.found);
        assert_eq!(lookup.result_type, 2);
        assert_eq!(lookup.data_offset, 1);
        assert_eq!(
            db.decode_at_offset(lookup.data_offset).unwrap(),
            DataValue::Map(metadata)
        );
    }

    #[test]
    fn oversized_literal_only_query_is_rejected_before_hashing() {
        let db = Database::from_bytes(build_database(&["literal.test"])).unwrap();
        let query = "x".repeat(MAX_STRING_QUERY_MATCHING_WORK + 1);
        assert!(matches!(
            db.lookup_string(&query),
            Err(DatabaseError::Config(_))
        ));
        assert!(matches!(
            db.lookup_ref(&query),
            Err(DatabaseError::Config(_))
        ));
    }

    #[test]
    fn query_cache_enforces_heap_budget_and_lru_order() {
        let result = QueryResult::Ip {
            data: DataValue::Array(vec![DataValue::String("x".repeat(256))]),
            prefix_len: 32,
            data_offset: 0,
        };
        let entry_weight = estimated_cache_entry_heap("first1".len(), &result);
        let mut cache = QueryCacheInner::new(NonZeroUsize::new(10).unwrap(), entry_weight * 2);

        cache.put_borrowed("first1", CacheQueryKind::String, &result);
        cache.put_borrowed("second", CacheQueryKind::String, &result);
        assert!(cache.get("first1", CacheQueryKind::String).is_some());
        cache.put_borrowed("third3", CacheQueryKind::String, &result);

        assert_eq!(cache.len(), 2);
        assert!(cache.get("first1", CacheQueryKind::String).is_some());
        assert!(cache.get("second", CacheQueryKind::String).is_none());
        assert!(cache.get("third3", CacheQueryKind::String).is_some());
        assert!(cache.retained_heap_bytes <= cache.heap_budget);

        let mut too_small = QueryCacheInner::new(
            NonZeroUsize::new(10).unwrap(),
            entry_weight.saturating_sub(1),
        );
        too_small.put_borrowed("first1", CacheQueryKind::String, &result);
        assert_eq!(too_small.len(), 0);
        assert_eq!(too_small.retained_heap_bytes, 0);
    }

    #[test]
    fn query_cache_entry_limit_is_incremental_and_evicts_lru() {
        let result = QueryResult::NotFound;
        let mut cache = QueryCacheInner::new(NonZeroUsize::new(2).unwrap(), usize::MAX);
        cache.put_borrowed("first", CacheQueryKind::String, &result);
        cache.put_borrowed("second", CacheQueryKind::String, &result);
        assert!(cache.get("first", CacheQueryKind::String).is_some());
        cache.put_borrowed("third", CacheQueryKind::String, &result);

        assert_eq!(cache.len(), 2);
        assert!(cache.get("first", CacheQueryKind::String).is_some());
        assert!(cache.get("second", CacheQueryKind::String).is_none());
        assert!(cache.get("third", CacheQueryKind::String).is_some());

        let mut huge_limit =
            QueryCacheInner::new(NonZeroUsize::new(usize::MAX).unwrap(), usize::MAX);
        assert_eq!(huge_limit.len(), 0);
        huge_limit.put_borrowed("one", CacheQueryKind::String, &result);
        assert_eq!(huge_limit.len(), 1);
        assert_eq!(huge_limit.entry_limit, usize::MAX);
    }

    #[test]
    fn query_cache_compacts_after_live_set_shrinks_and_preserves_lru() {
        let result = QueryResult::NotFound;
        let entry_weight = estimated_cache_entry_heap("key000".len(), &result);
        let mut cache = QueryCacheInner::new(NonZeroUsize::new(512).unwrap(), usize::MAX);
        for index in 0..256 {
            cache.put_borrowed(&format!("key{index:03}"), CacheQueryKind::String, &result);
        }
        assert!(cache.get("key000", CacheQueryKind::String).is_some());

        cache.heap_budget = entry_weight.saturating_mul(2);
        let compactions_before = cache.compaction_count;
        cache.put_borrowed("newkey", CacheQueryKind::String, &result);

        assert_eq!(cache.compaction_count, compactions_before + 1);
        assert_eq!(cache.len(), 2);
        assert!(cache.entries.peek("key000").is_some());
        assert!(cache.entries.peek("newkey").is_some());

        // `key000` was touched before the shrink and remains the older of the
        // two survivors. A subsequent eviction proves rebuilding kept that LRU
        // order instead of reversing it.
        cache.put_borrowed("last00", CacheQueryKind::String, &result);
        assert!(cache.entries.peek("key000").is_none());
        assert!(cache.entries.peek("newkey").is_some());
        assert!(cache.entries.peek("last00").is_some());
    }

    #[test]
    fn query_cache_compacts_gradual_shrink_without_thrashing() {
        let small = QueryResult::NotFound;
        let entry_weight = estimated_cache_entry_heap("key000".len(), &small);
        let heap_budget = entry_weight.saturating_mul(512);
        let oversized = QueryResult::Ip {
            data: DataValue::String("x".repeat(heap_budget)),
            prefix_len: 32,
            data_offset: 0,
        };
        let mut cache = QueryCacheInner::new(NonZeroUsize::new(512).unwrap(), heap_budget);
        for index in 0..256 {
            cache.put_borrowed(&format!("key{index:03}"), CacheQueryKind::String, &small);
        }

        let compactions_before = cache.compaction_count;
        cache.put_borrowed("key000", CacheQueryKind::String, &oversized);
        assert_eq!(cache.compaction_count, compactions_before);
        assert_eq!(cache.len(), 255);

        for index in 1..128 {
            cache.put_borrowed(
                &format!("key{index:03}"),
                CacheQueryKind::String,
                &oversized,
            );
        }
        assert_eq!(cache.compaction_count, compactions_before + 1);
        assert_eq!(cache.len(), 128);
        assert_eq!(cache.entry_high_water_len, 128);

        // The remaining keys retain their original order across compaction.
        cache.entry_limit = 128;
        cache.put_borrowed("newkey", CacheQueryKind::String, &small);
        assert!(cache.entries.peek("key128").is_none());
        assert!(cache.entries.peek("key255").is_some());
        assert!(cache.entries.peek("newkey").is_some());
    }

    #[test]
    fn query_cache_manager_caps_retained_namespaces() {
        let mut manager = QueryCacheManager::new(NonZeroUsize::new(3).unwrap(), usize::MAX);
        let entry_capacity = NonZeroUsize::new(1).unwrap();
        let result = QueryResult::NotFound;

        for generation in 1..=4 {
            let namespace = CacheNamespace::new(generation, generation + 100);
            manager.with_namespace(namespace, entry_capacity, |cache| {
                cache.put_borrowed("query", CacheQueryKind::String, &result);
            });
        }

        assert_eq!(manager.namespaces.len(), 3);
        assert!(manager
            .namespaces
            .peek(&CacheNamespace::new(1, 101))
            .is_none());
        for generation in 2..=4 {
            assert!(manager
                .namespaces
                .peek(&CacheNamespace::new(generation, generation + 100))
                .is_some());
        }
    }

    #[test]
    fn query_cache_manager_enforces_aggregate_heap_budget() {
        let result = QueryResult::Ip {
            data: DataValue::String("x".repeat(256)),
            prefix_len: 32,
            data_offset: 0,
        };
        let entry_weight = estimated_cache_entry_heap("query".len(), &result);
        let mut manager = QueryCacheManager::new(
            NonZeroUsize::new(4).unwrap(),
            entry_weight.saturating_mul(2),
        );
        let entry_capacity = NonZeroUsize::new(1).unwrap();

        for generation in 1..=2 {
            manager.with_namespace(
                CacheNamespace::new(generation, generation),
                entry_capacity,
                |cache| {
                    cache.put_borrowed("query", CacheQueryKind::String, &result);
                },
            );
        }
        manager.with_namespace(CacheNamespace::new(1, 1), entry_capacity, |cache| {
            assert!(cache.get("query", CacheQueryKind::String).is_some());
        });
        manager.with_namespace(CacheNamespace::new(3, 3), entry_capacity, |cache| {
            cache.put_borrowed("query", CacheQueryKind::String, &result);
        });

        assert!(manager.retained_heap_bytes() <= manager.heap_budget);
        assert!(manager
            .namespaces
            .peek(&CacheNamespace::new(1, 1))
            .is_some());
        assert!(manager
            .namespaces
            .peek(&CacheNamespace::new(2, 2))
            .is_none());
        assert!(manager
            .namespaces
            .peek(&CacheNamespace::new(3, 3))
            .is_some());
    }

    #[test]
    fn decoder_allocation_failures_are_resource_errors() {
        for error in [
            "Decoded value exceeds work limit",
            "Decoded value exceeds allocation limit",
            "String allocation failed",
            "Bytes allocation failed",
            "Map allocation failed",
            "Array allocation failed",
        ] {
            assert!(is_decoder_resource_error(error), "{error}");
        }
        assert!(!is_decoder_resource_error("Invalid UTF-8"));
    }

    #[test]
    fn string_query_shares_one_aggregate_decode_budget() {
        let query = "payload.aggregate.test";
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder.add_entry(query, expanding_record('a')).unwrap();
        builder
            .add_entry("*.aggregate.test", expanding_record('b'))
            .unwrap();
        let db = Database::from_bytes(builder.build().unwrap()).unwrap();

        let literal_hash = db.literal_hash.as_ref().unwrap();
        let literal_id = literal_hash.lookup(query).unwrap();
        let literal_offset = literal_hash.get_data_offset(literal_id).unwrap();
        let paraglob = db.pattern_matcher.as_ref().unwrap();
        let glob_id = paraglob.find_first(query).unwrap();
        let glob_offset = db
            .pattern_data_mappings
            .as_ref()
            .unwrap()
            .get_offset(glob_id, db.data.as_slice())
            .unwrap();

        assert!(db.decode_at_offset(literal_offset).is_ok());
        assert!(db.decode_at_offset(glob_offset).is_ok());

        let error = db
            .lookup_string_uncached(query)
            .expect_err("related decodes must not each receive a fresh allocation budget");
        assert!(matches!(error, DatabaseError::Config(_)));
        assert!(
            error.to_string().contains("allocation limit"),
            "unexpected aggregate decode error: {error}"
        );
    }

    #[test]
    fn pattern_only_query_batch_shares_one_decode_budget() {
        let pattern_data = [
            Some(expanding_data_value('a')),
            Some(expanding_data_value('b')),
        ];
        let paraglob = Paraglob::build_from_patterns_with_data(
            &["*.batch.test", "payload.*"],
            Some(&pattern_data),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        assert!(paraglob.try_get_pattern_data(0).is_ok());
        assert!(paraglob.try_get_pattern_data(1).is_ok());

        let db = Database::from_bytes(paraglob.buffer().to_vec()).unwrap();
        let error = db
            .lookup_string_uncached("payload.batch.test")
            .expect_err("pattern-only matches must share one aggregate decode budget");
        assert!(matches!(error, DatabaseError::Config(_)));
        assert!(
            error.to_string().contains("allocation limit"),
            "unexpected aggregate decode error: {error}"
        );
    }

    #[test]
    fn builder_generated_combined_sections_remain_compatible() {
        let bytes = build_database(&["192.0.2.1", "literal.example", "*.malware.test"]);
        let db = Database::from_bytes(bytes).unwrap();

        assert!(matches!(
            db.lookup("192.0.2.1").unwrap(),
            Some(QueryResult::Ip { .. })
        ));
        assert!(matches!(
            db.lookup("literal.example").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));
        assert!(matches!(
            db.lookup("payload.malware.test").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));

        // DatabaseBuilder currently retains one mapping per submitted glob even
        // when Paraglob deduplicates identical patterns. That is valid existing
        // output, so extra fully-bounded mappings remain compatible.
        let duplicate_globs = build_database(&["*.duplicate.test", "*.duplicate.test"]);
        let duplicate_db = Database::from_bytes(duplicate_globs).unwrap();
        assert!(matches!(
            duplicate_db.lookup("payload.duplicate.test").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));

        let duplicate_literals = build_database(&["literal.duplicate", "literal.duplicate"]);
        let duplicate_db = Database::from_bytes(duplicate_literals).unwrap();
        assert!(matches!(
            duplicate_db.lookup("literal.duplicate").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));
    }

    #[test]
    fn stale_fast_offsets_fall_back_to_legacy_markers() {
        let valid = build_database(&["literal.example", "*.malware.test"]);
        let pattern_offset = metadata_u32(&valid, "pattern_section_offset");
        let literal_offset = metadata_u32(&valid, "literal_section_offset");

        for (stale_pattern, stale_literal) in [
            (1, 15),
            (pattern_offset + 1, literal_offset + 1),
            (u32::MAX, u32::MAX),
        ] {
            let bytes = rewrite_section_offset(&valid, "pattern_section_offset", stale_pattern);
            let bytes = rewrite_section_offset(&bytes, "literal_section_offset", stale_literal);
            let db = Database::from_bytes(bytes).unwrap();

            assert!(matches!(
                db.lookup("literal.example").unwrap(),
                Some(QueryResult::Pattern { .. })
            ));
            assert!(matches!(
                db.lookup("payload.malware.test").unwrap(),
                Some(QueryResult::Pattern { .. })
            ));
        }
    }

    #[test]
    fn invalid_fast_offsets_without_legacy_markers_are_rejected() {
        let ip_only = build_database(&["192.0.2.1"]);

        for field in ["pattern_section_offset", "literal_section_offset"] {
            for offset in [1, 15, 16, u32::MAX] {
                assert_database_rejected(
                    rewrite_section_offset(&ip_only, field, offset),
                    &format!("{field}={offset}"),
                );
            }

            assert_database_rejected(
                rewrite_offset_to_eof(&ip_only, field),
                &format!("{field}=EOF"),
            );
        }
    }

    #[test]
    fn embedded_section_markers_cannot_overlap_mmdb_tree() {
        let original = build_database(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]);
        let header = MmdbHeader::from_file(&original).unwrap();

        for (field, marker) in [
            ("pattern_section_offset", PATTERN_SECTION_MARKER),
            ("literal_section_offset", LITERAL_SECTION_MARKER),
        ] {
            let marker_offset = header
                .tree_size
                .checked_sub(marker.len())
                .expect("test database tree must fit an extension marker");
            let mut bytes = original.clone();
            bytes[marker_offset..marker_offset + marker.len()].copy_from_slice(marker);
            let section_data_offset = u32::try_from(marker_offset + marker.len()).unwrap();
            let bytes = rewrite_section_offset(&bytes, field, section_data_offset);

            let error = Database::from_bytes(bytes)
                .err()
                .expect("extension marker overlapping the MMDB tree must be rejected");
            assert!(
                error.to_string().contains("overlaps the MMDB tree"),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn marked_sections_without_payloads_are_rejected_at_metadata_boundary() {
        let ip_only = build_database(&["192.0.2.1"]);
        let metadata_offset = crate::mmdb::find_metadata_marker(&ip_only).unwrap();

        for (field, marker) in [
            ("pattern_section_offset", PATTERN_SECTION_MARKER.as_slice()),
            ("literal_section_offset", LITERAL_SECTION_MARKER.as_slice()),
        ] {
            let mut with_empty_section = ip_only[..metadata_offset].to_vec();
            with_empty_section.extend_from_slice(marker);
            with_empty_section.extend_from_slice(&ip_only[metadata_offset..]);
            let section_data_offset = u32::try_from(metadata_offset + marker.len()).unwrap();
            let with_empty_section =
                rewrite_section_offset(&with_empty_section, field, section_data_offset);
            assert_database_rejected(with_empty_section, field);
        }
    }

    #[test]
    fn malformed_combined_pattern_envelopes_are_rejected() {
        let valid = build_database(&["*.malware.test"]);
        let pattern_start =
            usize::try_from(metadata_u32(&valid, "pattern_section_offset")).unwrap();
        let total_size =
            u32::from_le_bytes(valid[pattern_start..pattern_start + 4].try_into().unwrap());
        let paraglob_size = usize::try_from(u32::from_le_bytes(
            valid[pattern_start + 4..pattern_start + 8]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let pattern_count_offset = pattern_start + 8 + paraglob_size;

        let mut zero_total_size = valid.clone();
        zero_total_size[pattern_start..pattern_start + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_database_rejected(zero_total_size, "zero pattern total_size");

        let mut oversized_total = valid.clone();
        oversized_total[pattern_start..pattern_start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_database_rejected(oversized_total, "oversized pattern total_size");

        let mut short_total = valid.clone();
        short_total[pattern_start..pattern_start + 4]
            .copy_from_slice(&(total_size - 1).to_le_bytes());
        assert_database_rejected(short_total, "truncated declared mapping range");

        let mut oversized_paraglob = valid.clone();
        oversized_paraglob[pattern_start + 4..pattern_start + 8]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_database_rejected(oversized_paraglob, "oversized paraglob range");

        let mut inconsistent_match_mode = valid.clone();
        let match_mode_offset =
            pattern_start + 8 + std::mem::offset_of!(ParaglobHeader, match_mode);
        inconsistent_match_mode[match_mode_offset..match_mode_offset + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        assert_database_rejected(
            inconsistent_match_mode,
            "Paraglob match mode inconsistent with metadata",
        );

        let mut mismatched_count = valid.clone();
        mismatched_count[pattern_count_offset..pattern_count_offset + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        assert_database_rejected(mismatched_count, "mismatched pattern mapping count");

        let mut missing_mapping = valid.clone();
        missing_mapping[pattern_start..pattern_start + 4]
            .copy_from_slice(&(total_size - 4).to_le_bytes());
        missing_mapping[pattern_count_offset..pattern_count_offset + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        assert_database_rejected(missing_mapping, "missing pattern mapping");

        let mut physically_truncated = valid;
        let metadata_offset = crate::mmdb::find_metadata_marker(&physically_truncated).unwrap();
        physically_truncated.remove(metadata_offset - 1);
        assert_database_rejected(
            physically_truncated,
            "physically truncated pattern mappings",
        );
    }

    #[test]
    fn pattern_mapping_offsets_fail_closed_on_arithmetic_and_bounds_errors() {
        let mappings = PatternDataMappings {
            mappings_offset: usize::MAX,
            pattern_count: usize::MAX,
        };
        assert_eq!(mappings.get_offset(0, &[0; 4]), None);
        assert_eq!(mappings.get_offset(u32::MAX, &[0; 4]), None);

        let mappings = PatternDataMappings {
            mappings_offset: 1,
            pattern_count: 1,
        };
        assert_eq!(mappings.get_offset(0, &[0; 4]), None);
        assert_eq!(mappings.get_offset(1, &[0; 4]), None);
    }

    #[test]
    fn decoder_cannot_cross_into_extensions_or_metadata() {
        for keys in [
            vec!["192.0.2.1"],
            vec!["192.0.2.1", "literal.example", "*.malware.test"],
        ] {
            let bytes = build_database(&keys);
            let header = MmdbHeader::from_file(&bytes).unwrap();
            let (_, sections) = Database::detect_format_and_sections(&bytes).unwrap();
            let data_start = header.tree_size + 16;
            let data_end = sections.data_section_end().unwrap();
            let first_invalid_offset = u32::try_from(data_end - data_start).unwrap();
            let db = Database::from_bytes(bytes).unwrap();

            assert!(
                db.decode_at_offset(first_invalid_offset).is_err(),
                "decoder accepted the first byte after the bounded data section"
            );
        }
    }

    #[test]
    fn lookup_ref_rejects_mapping_offsets_outside_data_section() {
        let mut bytes = build_database(&["*.malware.test"]);
        let header = MmdbHeader::from_file(&bytes).unwrap();
        let pattern_start =
            usize::try_from(metadata_u32(&bytes, "pattern_section_offset")).unwrap();
        let paraglob_size = usize::try_from(u32::from_le_bytes(
            bytes[pattern_start + 4..pattern_start + 8]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let first_mapping = pattern_start + 8 + paraglob_size + 4;
        let invalid_offset = u32::try_from(pattern_start - PATTERN_SECTION_MARKER.len())
            .unwrap()
            .checked_sub(u32::try_from(header.tree_size + 16).unwrap())
            .unwrap();
        bytes[first_mapping..first_mapping + 4].copy_from_slice(&invalid_offset.to_le_bytes());

        let db = Database::from_bytes(bytes).unwrap();
        assert!(db.lookup_ref("payload.malware.test").is_err());
        assert!(db.lookup("payload.malware.test").is_err());
    }

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

        if let Some(QueryResult::Ip {
            data, prefix_len, ..
        }) = result
        {
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

    #[test]
    fn test_lookup_extracted() {
        use crate::extractor::Extractor;

        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();
        let extractor = Extractor::new().unwrap();

        // Test with IP addresses (should use efficient typed lookup)
        let log_line = b"Connection from 8.8.8.8 and 2001:4860:4860::8888";
        let matches: Vec<_> = extractor.extract_from_line(log_line).collect();

        assert_eq!(matches.len(), 2, "Should extract 2 IP addresses");

        // First match: IPv4
        let result = db.lookup_extracted(&matches[0], log_line).unwrap();
        assert!(
            matches!(result, Some(QueryResult::Ip { .. })),
            "IPv4 should match via lookup_extracted"
        );

        // Second match: IPv6
        let result = db.lookup_extracted(&matches[1], log_line).unwrap();
        assert!(
            matches!(result, Some(QueryResult::Ip { .. })),
            "IPv6 should match via lookup_extracted"
        );

        // Test with domain (should use string-based lookup)
        let log_line = b"Visit example.com for more info";
        let matches: Vec<_> = extractor.extract_from_line(log_line).collect();

        assert_eq!(matches.len(), 1, "Should extract 1 domain");

        // Domain lookup (no pattern data in this DB, so expect None or NotFound)
        let result = db.lookup_extracted(&matches[0], log_line).unwrap();
        assert!(
            result.is_none() || matches!(result, Some(QueryResult::NotFound)),
            "Domain should not match in IP-only database"
        );
    }

    #[test]
    fn test_ip_count_returns_node_count_for_standard_mmdb() {
        // Standard MMDB files (like MaxMind) have node_count but not ip_entry_count
        // ip_count() should fall back to node_count for these
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let count = db.ip_count();

        // Should return node_count (which is > 0 for a real database)
        assert!(
            count > 0,
            "ip_count() should return node_count for standard MMDB"
        );

        // The GeoLite2-Country.mmdb has ~1.6 million nodes
        assert!(
            count > 1_000_000,
            "GeoLite2-Country should have > 1M nodes, got {count}"
        );
    }

    #[test]
    fn test_ip_count_prefers_ip_entry_count_when_available() {
        // Build a database with matchy (which sets ip_entry_count)
        use matchy_format::DatabaseBuilder;
        use matchy_match_mode::MatchMode;
        use std::collections::HashMap;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test.mxy");

        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

        let mut data1 = HashMap::new();
        data1.insert("test".to_string(), DataValue::String("value1".to_string()));
        builder.add_entry("10.0.0.0/8", data1).unwrap();

        let mut data2 = HashMap::new();
        data2.insert("test".to_string(), DataValue::String("value2".to_string()));
        builder.add_entry("192.168.0.0/16", data2).unwrap();

        let mut data3 = HashMap::new();
        data3.insert("test".to_string(), DataValue::String("value3".to_string()));
        builder.add_entry("172.16.0.0/12", data3).unwrap();

        let db_data = builder.build().unwrap();
        std::fs::write(&output_path, &db_data).unwrap();

        let db = Database::from(output_path.to_str().unwrap())
            .open()
            .unwrap();

        // Matchy-built databases have ip_entry_count which should be preferred
        // Note: node_count will be larger than ip_entry_count due to tree structure
        let count = db.ip_count();

        // We added 3 IP/CIDR entries
        assert_eq!(
            count, 3,
            "ip_count() should return ip_entry_count (3) for matchy-built DB"
        );
    }

    #[test]
    fn test_lookup_ref_finds_pattern_only_matches() {
        let paraglob = Paraglob::build_from_patterns(
            &["*.evil.com"],
            matchy_match_mode::MatchMode::CaseSensitive,
        )
        .unwrap();
        let db = Database::from_bytes(paraglob.buffer().to_vec()).unwrap();

        let lookup = db.lookup_ref("sub.evil.com").unwrap();

        assert!(
            lookup.found,
            "lookup_ref should report pattern-only matches"
        );
        assert_eq!(lookup.result_type, 2, "result_type should be 2 (pattern)");
        assert_eq!(
            lookup.data_offset, 0,
            "pattern-only matches have no MMDB offset"
        );
    }

    #[test]
    fn pattern_only_reload_uses_serialized_case_insensitive_mode() {
        let paraglob =
            Paraglob::build_from_patterns(&["*.MiXeD.Example"], MatchMode::CaseInsensitive)
                .unwrap();
        let db = Database::from_bytes(paraglob.buffer().to_vec()).unwrap();

        assert_eq!(db.mode(), MatchMode::CaseInsensitive);
        assert!(matches!(
            db.lookup("PAYLOAD.mixed.EXAMPLE").unwrap(),
            Some(QueryResult::Pattern { .. })
        ));
    }

    #[test]
    fn pattern_only_reload_rejects_invalid_serialized_match_mode() {
        let paraglob =
            Paraglob::build_from_patterns(&["*.example"], MatchMode::CaseSensitive).unwrap();
        let mut bytes = paraglob.buffer().to_vec();
        let match_mode_offset = std::mem::offset_of!(ParaglobHeader, match_mode);
        bytes[match_mode_offset..match_mode_offset + 4].copy_from_slice(&2u32.to_le_bytes());

        let error = Database::from_bytes(bytes)
            .err()
            .expect("unknown serialized match modes must be rejected");
        assert!(
            error.to_string().contains("expected 0 or 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn pattern_only_lookup_propagates_corrupt_matched_data() {
        let pattern_data = [Some(DataValue::String("ok".to_string()))];
        let paraglob = Paraglob::build_from_patterns_with_data(
            &["*.corrupt.test"],
            Some(&pattern_data),
            MatchMode::CaseSensitive,
        )
        .unwrap();
        let mut bytes = paraglob.buffer().to_vec();
        let data_offset_field = std::mem::offset_of!(
            matchy_paraglob::offset_format::ParaglobHeader,
            data_section_offset
        );
        let data_start = usize::try_from(u32::from_le_bytes(
            bytes[data_offset_field..data_offset_field + std::mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        ))
        .unwrap();

        // Payload 31 requires three additional size bytes, but this data
        // section contains only the original two-byte string payload.
        bytes[data_start] = 0x5f;

        let db = Database::from_bytes(bytes).unwrap();
        let error = db
            .lookup("payload.corrupt.test")
            .expect_err("matched corrupt data must not be reported as absent");

        assert!(matches!(
            error,
            DatabaseError::Format(MmdbError::DecodeError(_))
        ));
    }

    #[test]
    fn test_lookup_ref_updates_query_stats() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let lookup = db.lookup_ref("1.1.1.1").unwrap();

        assert!(lookup.found);
        let stats = db.stats();
        assert_eq!(stats.total_queries, 1);
        assert_eq!(stats.ip_queries, 1);
        assert_eq!(stats.queries_with_match, 1);
    }

    #[test]
    fn test_decode_at_offset_returns_error_for_truncated_data_section() {
        use matchy_data_format::DataEncoder;
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        metadata.insert("node_count".to_string(), DataValue::Uint32(100));
        metadata.insert("record_size".to_string(), DataValue::Uint16(24));
        metadata.insert("ip_version".to_string(), DataValue::Uint16(4));

        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::Map(metadata));

        // Supply the complete tree and separator envelope claimed by metadata,
        // but no data value at offset zero.
        let mut bytes = vec![0u8; 100 * 6];
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        bytes.extend_from_slice(&encoder.into_bytes());

        let db = Database::from_bytes(bytes).unwrap();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| db.decode_at_offset(0)));

        assert!(
            result.is_ok(),
            "decode_at_offset should return an error instead of panicking"
        );
        assert!(result.unwrap().is_err());
    }

    /// Regression test: lookup_ref and decode_at_offset must delegate to the live
    /// database when auto-reload is enabled. Previously they operated on the shell
    /// database (which has empty data/no ip_header), returning not-found or errors.
    #[test]
    fn test_lookup_ref_with_auto_reload() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .watch()
            .open()
            .unwrap();

        // lookup_ref should find known IPs via the live database
        let lookup = db.lookup_ref("1.1.1.1").unwrap();
        assert!(
            lookup.found,
            "lookup_ref should find 1.1.1.1 with auto-reload enabled"
        );
        assert_eq!(lookup.result_type, 1, "result_type should be 1 (IP)");
        assert!(lookup.prefix_len > 0);

        // decode_at_offset should be able to decode the data the ref points to
        let data = db.decode_at_offset(lookup.data_offset).unwrap();
        match data {
            DataValue::Map(map) => assert!(!map.is_empty(), "decoded data should not be empty"),
            _ => panic!("Expected map data from decode_at_offset"),
        }

        // Verify consistency: lookup_ref + decode_at_offset should produce the
        // same data as the full lookup() path
        let full_result = db.lookup("1.1.1.1").unwrap();
        if let Some(QueryResult::Ip {
            data: full_data,
            prefix_len,
            ..
        }) = full_result
        {
            assert_eq!(prefix_len, lookup.prefix_len);
            let ref_data = db.decode_at_offset(lookup.data_offset).unwrap();
            assert_eq!(full_data, ref_data, "lookup_ref+decode should match lookup");
        } else {
            panic!("Full lookup should also find 1.1.1.1");
        }
    }

    #[test]
    fn embedded_sections_round_trip_without_copying() {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder
            .add_entry(
                "indicator.example",
                HashMap::from([("kind".to_string(), DataValue::String("ioc".to_string()))]),
            )
            .unwrap();
        builder
            .add_entry(
                "*.evil.example",
                HashMap::from([("kind".to_string(), DataValue::String("glob".to_string()))]),
            )
            .unwrap();
        builder
            .add_embedded_section(
                "network-program",
                "matchy-detection-network/v1",
                64,
                b"compiled rules".to_vec(),
            )
            .unwrap();
        builder
            .add_embedded_section(
                "ioc-dataset",
                "matchy-ioc/v1",
                4096,
                b"co-located indicators".to_vec(),
            )
            .unwrap();
        let bytes = builder.build().unwrap();

        let metadata = crate::mmdb::MmdbMetadata::from_file(&bytes)
            .unwrap()
            .as_value()
            .unwrap();
        let DataValue::Map(metadata) = metadata else {
            panic!("metadata must be a map");
        };
        let Some(DataValue::Map(directory)) = metadata.get("embedded_sections") else {
            panic!("metadata must contain the embedded section directory");
        };
        for (name, expected_alignment) in [("network-program", 64_u64), ("ioc-dataset", 4096_u64)] {
            let Some(DataValue::Map(descriptor)) = directory.get(name) else {
                panic!("missing descriptor for {name}");
            };
            let offset = Database::extract_uint_from_datavalue(&descriptor["offset"]).unwrap();
            assert_eq!(offset % expected_alignment, 0);
        }
        let opaque_end = directory
            .values()
            .map(|descriptor| {
                let DataValue::Map(descriptor) = descriptor else {
                    panic!("section descriptor must be a map");
                };
                Database::extract_uint_from_datavalue(&descriptor["offset"]).unwrap()
                    + Database::extract_uint_from_datavalue(&descriptor["length"]).unwrap()
            })
            .max()
            .unwrap();
        let pattern_data_offset =
            Database::extract_uint_from_datavalue(&metadata["pattern_section_offset"]).unwrap();
        assert!(
            opaque_end <= pattern_data_offset - PATTERN_SECTION_MARKER.len() as u64,
            "opaque sections must precede the legacy pattern marker"
        );

        let db = Database::from_bytes(bytes.clone()).unwrap();
        assert!(db.lookup("indicator.example").unwrap().is_some());
        assert!(db.lookup("host.evil.example").unwrap().is_some());
        assert_eq!(
            db.embedded_section_names(),
            vec!["network-program".to_string(), "ioc-dataset".to_string()]
        );
        let program = db.embedded_section("network-program").unwrap();
        assert_eq!(program.format(), "matchy-detection-network/v1");
        assert_eq!(program.alignment(), 64);
        assert_eq!(program.as_bytes(), b"compiled rules");
        drop(db);
        assert_eq!(program.as_bytes(), b"compiled rules");

        let temp_dir = tempfile::TempDir::new().unwrap();
        let path = temp_dir.path().join("embedded.mxy");
        std::fs::write(&path, bytes).unwrap();
        let validation =
            crate::validation::validate_database(&path, crate::validation::ValidationLevel::Strict)
                .unwrap();
        assert!(validation.is_valid(), "{:?}", validation.errors);
        let mapped = Database::from(path.to_str().unwrap()).open().unwrap();
        let dataset = mapped.embedded_section("ioc-dataset").unwrap();
        assert_eq!(dataset.as_bytes(), b"co-located indicators");
        assert_eq!((dataset.as_ptr() as usize) % dataset.alignment(), 0);
    }

    #[test]
    fn malformed_embedded_section_ranges_are_rejected() {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder
            .add_embedded_section("first", "test/v1", 8, vec![1, 2, 3, 4])
            .unwrap();
        builder
            .add_embedded_section("second", "test/v1", 8, vec![5, 6, 7, 8])
            .unwrap();
        let valid = builder.build().unwrap();
        let first = Database::from_bytes(valid.clone())
            .unwrap()
            .embedded_section("first")
            .unwrap();

        let overlapping = rewrite_opaque_section_field(
            &valid,
            "second",
            "offset",
            DataValue::Uint64(u64::try_from(first.offset()).unwrap()),
        );
        assert!(Database::from_bytes(overlapping).is_err());

        let crosses_metadata =
            rewrite_opaque_section_field(&valid, "first", "length", DataValue::Uint64(u64::MAX));
        assert!(Database::from_bytes(crosses_metadata).is_err());

        let misaligned = rewrite_opaque_section_field(
            &valid,
            "first",
            "offset",
            DataValue::Uint64(u64::try_from(first.offset() + 1).unwrap()),
        );
        assert!(Database::from_bytes(misaligned).is_err());
    }
}
