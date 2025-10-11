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
use memmap2::Mmap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;

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
    /// For combined databases: mapping from pattern_id -> data offset in MMDB data section
    /// None for pattern-only databases (which use Paraglob's internal data)
    pattern_data_mappings: Option<HashMap<u32, u32>>,
}

impl Database {
    /// Open a database file using memory mapping for optimal performance
    ///
    /// This uses mmap for zero-copy file access, which is much faster than
    /// loading the entire file into memory, especially for large databases.
    ///
    /// Automatically detects the database format and initializes
    /// the appropriate lookup structures.
    pub fn open(path: &str) -> Result<Self, DatabaseError> {
        let file = File::open(path)
            .map_err(|e| DatabaseError::Io(format!("Failed to open {}: {}", path, e)))?;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| DatabaseError::Io(format!("Failed to mmap {}: {}", path, e)))?;

        Self::from_storage(DatabaseStorage::Mmap(mmap))
    }

    /// Create database from raw bytes (for testing)
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DatabaseError> {
        Self::from_storage(DatabaseStorage::Owned(data))
    }

    /// Internal: Create database from storage
    fn from_storage(storage: DatabaseStorage) -> Result<Self, DatabaseError> {
        let data = storage.as_slice();
        // Detect format
        let format = Self::detect_format(data)?;

        // Parse based on format
        let (ip_header, pattern_matcher, pattern_data_mappings) = match format {
            DatabaseFormat::IpOnly => {
                let header = MmdbHeader::from_file(data).map_err(DatabaseError::Format)?;
                (Some(header), None, None)
            }
            DatabaseFormat::PatternOnly => {
                // Pattern-only: load from start of file
                let pg = Self::load_pattern_section(data, 0).map_err(|e| {
                    DatabaseError::Unsupported(format!("Failed to load pattern section: {}", e))
                })?;
                (None, Some(RefCell::new(pg)), None)
            }
            DatabaseFormat::Combined => {
                // Parse IP header first
                let header = MmdbHeader::from_file(data).map_err(DatabaseError::Format)?;

                // Find and load pattern section after MMDB_PATTERN separator
                let (pattern_matcher, mappings) =
                    if let Some(offset) = Self::find_pattern_section(data) {
                        let (pg, map) =
                            Self::load_combined_pattern_section(data, offset).map_err(|e| {
                                DatabaseError::Unsupported(format!(
                                    "Failed to load pattern section: {}",
                                    e
                                ))
                            })?;
                        (Some(RefCell::new(pg)), Some(map))
                    } else {
                        (None, None)
                    };
                (Some(header), pattern_matcher, mappings)
            }
        };

        // Load literal hash section if present (MMDB_LITERAL marker)
        let literal_hash = if let Some(offset) = Self::find_literal_section(data) {
            // Skip the 16-byte marker
            let literal_data = &data[offset + 16..];
            // SAFETY: We're extending the lifetime to 'static because the data is either:
            // 1. In a mmap which lives as long as the Database struct
            // 2. In owned Vec<u8> which also lives as long as Database
            // The LiteralHash only holds a reference, so it won't outlive the data
            let literal_data_static: &'static [u8] = unsafe { std::mem::transmute(literal_data) };
            Some(LiteralHash::from_buffer(literal_data_static).map_err(|e| {
                DatabaseError::Unsupported(format!("Failed to load literal hash: {}", e))
            })?)
        } else {
            None
        };

        Ok(Self {
            data: storage,
            format,
            ip_header,
            literal_hash,
            pattern_matcher,
            pattern_data_mappings,
        })
    }

    /// Look up a query string (IP address or string pattern)
    ///
    /// Automatically determines if the query is an IP address or string
    /// and uses the appropriate lookup method.
    ///
    /// Returns `Ok(Some(result))` if found, `Ok(None)` if not found.
    pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // Try parsing as IP address first
        if let Ok(addr) = query.parse::<IpAddr>() {
            return self.lookup_ip(addr);
        }

        // Otherwise, treat as string (literal or glob)
        self.lookup_string(query)
    }

    /// Look up an IP address
    ///
    /// Returns data associated with the IP address if found.
    pub fn lookup_ip(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
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

    /// Look up a string (literal or glob pattern)
    ///
    /// Returns matching pattern IDs and associated data.
    /// Checks both:
    /// 1. Literal hash table for O(1) exact matches
    /// 2. Glob patterns for wildcard matches
    ///
    /// A query can match both a literal AND a glob pattern simultaneously.
    pub fn lookup_string(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
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
            let mut pg = pg_cell.borrow_mut();
            let glob_pattern_ids = pg.find_all(pattern);

            // Add glob matches
            for &pattern_id in &glob_pattern_ids {
                // For combined databases, use mappings to decode from MMDB data section
                // For pattern-only databases, use Paraglob's internal data cache
                let data = if let Some(mappings) = &self.pattern_data_mappings {
                    // Combined database: decode from MMDB data section
                    if let Some(&data_offset) = mappings.get(&pattern_id) {
                        let header = self.ip_header.as_ref().unwrap();
                        Some(self.decode_ip_data(header, data_offset)?)
                    } else {
                        None
                    }
                } else {
                    // Pattern-only database: use Paraglob's cache
                    pg.get_pattern_data(pattern_id).cloned()
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

    /// Detect database format
    fn detect_format(data: &[u8]) -> Result<DatabaseFormat, DatabaseError> {
        // Check for MMDB metadata marker
        let has_mmdb = crate::mmdb::find_metadata_marker(data).is_ok();

        // Check for paraglob magic at start (pattern-only format)
        let has_paraglob_start = data.len() >= 8 && &data[0..8] == b"PARAGLOB";

        // Check for MMDB_PATTERN separator (combined format)
        // Pattern section separator: "MMDB_PATTERN\x00\x00\x00" (16 bytes)
        let pattern_separator = b"MMDB_PATTERN\x00\x00\x00\x00";
        let has_pattern_section = data.windows(16).any(|window| window == pattern_separator);

        match (has_mmdb, has_paraglob_start, has_pattern_section) {
            (true, false, false) => Ok(DatabaseFormat::IpOnly),
            (false, true, false) => Ok(DatabaseFormat::PatternOnly),
            (true, false, true) => Ok(DatabaseFormat::Combined), // MMDB + pattern separator
            (true, true, _) => Ok(DatabaseFormat::Combined),     // Both markers
            (false, false, false) => Err(DatabaseError::Format(MmdbError::InvalidFormat(
                "Unknown database format".to_string(),
            ))),
            _ => Ok(DatabaseFormat::Combined), // Any other combination, assume combined
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

    /// Find the pattern section in a combined database
    /// Returns the offset to the start of MMDB_PATTERN marker
    fn find_pattern_section(data: &[u8]) -> Option<usize> {
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

    /// Find the literal hash section in a combined database
    /// Returns the offset to the start of MMDB_LITERAL marker
    fn find_literal_section(data: &[u8]) -> Option<usize> {
        let separator = b"MMDB_LITERAL\x00\x00\x00\x00";

        // Search for the separator
        (0..data.len().saturating_sub(16)).find(|&i| &data[i..i + 16] == separator)
    }

    /// Load pattern section from data at given offset (for pattern-only databases)
    /// The format at offset is: PARAGLOB magic + data
    fn load_pattern_section(data: &[u8], offset: usize) -> Result<Paraglob, String> {
        use crate::glob::MatchMode;
        use crate::serialization::from_bytes;

        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // For pattern-only databases, data starts with PARAGLOB magic
        if offset == 0 && data.len() >= 8 && &data[0..8] == b"PARAGLOB" {
            // Standard .pgb format - load directly
            return from_bytes(data, MatchMode::CaseSensitive)
                .map_err(|e| format!("Failed to parse pattern-only database: {}", e));
        }

        Err("Invalid pattern-only database format".to_string())
    }

    /// Load combined pattern section from data at given offset
    /// The format at offset is: `[total_size][paraglob_size][PARAGLOB data][pattern_count][data_offsets...]`
    /// Returns (Paraglob matcher, HashMap of pattern_id -> data_offset)
    fn load_combined_pattern_section(
        data: &[u8],
        offset: usize,
    ) -> Result<(Paraglob, HashMap<u32, u32>), String> {
        use crate::glob::MatchMode;
        use crate::serialization::from_bytes;

        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

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

        // Extract and load paraglob data
        let paraglob_data = &data[paraglob_start..paraglob_end];
        let paraglob = from_bytes(paraglob_data, MatchMode::CaseSensitive)
            .map_err(|e| format!("Failed to parse paraglob section: {}", e))?;

        // Load mappings: [pattern_count][offset1][offset2]...
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

        let mut mappings = HashMap::new();
        let offsets_start = mappings_start + 4;

        for i in 0..pattern_count {
            let offset_pos = offsets_start + (i * 4);
            if offset_pos + 4 > data.len() {
                return Err(format!("Pattern mapping {} out of bounds", i));
            }

            let data_offset = u32::from_le_bytes([
                data[offset_pos],
                data[offset_pos + 1],
                data[offset_pos + 2],
                data[offset_pos + 3],
            ]);

            mappings.insert(i as u32, data_offset);
        }

        Ok((paraglob, mappings))
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
        let db = Database::open("tests/data/GeoLite2-Country.mmdb").unwrap();
        assert_eq!(db.format, DatabaseFormat::IpOnly);
        assert!(db.has_ip_data());
        assert!(!db.has_string_data());
    }

    #[test]
    fn test_lookup_ip_address() {
        let db = Database::open("tests/data/GeoLite2-Country.mmdb").unwrap();

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
        let db = Database::open("tests/data/GeoLite2-Country.mmdb").unwrap();

        let result = db.lookup("2001:4860:4860::8888").unwrap();
        assert!(result.is_some());

        if let Some(QueryResult::Ip { prefix_len, .. }) = result {
            assert!(prefix_len > 0);
            assert!(prefix_len <= 128);
        }
    }

    #[test]
    fn test_lookup_not_found() {
        let db = Database::open("tests/data/GeoLite2-Country.mmdb").unwrap();

        let result = db.lookup("127.0.0.1").unwrap();
        assert!(matches!(result, Some(QueryResult::NotFound)));
    }

    #[test]
    fn test_auto_detect_query_type() {
        let db = Database::open("tests/data/GeoLite2-Country.mmdb").unwrap();

        // Should auto-detect as IP
        let result = db.lookup("8.8.8.8").unwrap();
        assert!(matches!(result, Some(QueryResult::Ip { .. })));

        // Should auto-detect as pattern (but no pattern data in this DB)
        let result = db.lookup("example.com").unwrap();
        assert!(result.is_none() || matches!(result, Some(QueryResult::NotFound)));
    }
}
