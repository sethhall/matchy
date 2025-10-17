//! Literal String Minimal Perfect Hash for O(1) Lookups with Minimal Space
//!
//! This module provides a memory-mapped minimal perfect hash table optimized for exact string matching.
//! Uses boomphf for ~2.5 bits/key space overhead (vs 10+ bytes/key for traditional hash tables).
//!
//! # Format
//!
//! The MPH table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header]
//!   magic: [u8; 4]           // "LMPH"
//!   version: u32              // 1
//!   entry_count: u32          // Number of literal patterns
//!   mphf_offset: u32          // Offset to MPHF data
//!   mphf_size: u32            // Size of MPHF data
//!   strings_offset: u32       // Offset to string pool
//!   strings_size: u32         // Size of string pool
//!   index_offset: u32         // Offset to index mapping
//!
//! [MPHF Data]
//!   Serialized boomphf structure (~2.5 bits per key)
//!
//! [String Pool]
//!   Strings stored as: [length: u16][bytes...]
//!   Indexed by MPHF output
//!
//! [Index Mapping]
//!   pattern_ids: [u32; entry_count]  // pattern_id for each MPHF index
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```
//!
use crate::error::ParaglobError;
use crate::glob::MatchMode;
use boomphf::Mphf;
use rayon::prelude::*;
use std::hash::{Hash, Hasher};
use std::panic;

/// Magic bytes for literal MPH section
pub const LITERAL_MPH_MAGIC: &[u8; 4] = b"LMPH";

/// Current version of the literal MPH format
pub const LITERAL_MPH_VERSION: u32 = 1;

/// MPH table header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiteralMphHeader {
    /// Magic bytes "LMPH"
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Number of literal patterns
    pub entry_count: u32,
    /// Offset to MPHF data
    pub mphf_offset: u32,
    /// Size of MPHF data
    pub mphf_size: u32,
    /// Offset to string pool
    pub strings_offset: u32,
    /// Size of string pool
    pub strings_size: u32,
    /// Offset to index→pattern_id mapping
    pub index_offset: u32,
}

/// Pattern ID to data offset mapping
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PatternMapping {
    /// Pattern identifier
    pub pattern_id: u32,
    /// Offset to data section
    pub data_offset: u32,
}

/// Wrapper for String to implement Hash with custom hasher
/// boomphf requires keys to implement Hash
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct StringKey(String);

impl Hash for StringKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

/// Builder for literal minimal perfect hash table
pub struct LiteralMphBuilder {
    patterns: Vec<(String, u32)>, // (pattern, pattern_id)
    mode: MatchMode,
}

impl LiteralMphBuilder {
    /// Create a new builder
    pub fn new(mode: MatchMode) -> Self {
        Self {
            patterns: Vec::new(),
            mode,
        }
    }

    /// Add a literal pattern
    pub fn add_pattern(&mut self, pattern: &str, pattern_id: u32) {
        // Normalize pattern based on match mode
        let normalized = match self.mode {
            MatchMode::CaseSensitive => pattern.to_string(),
            MatchMode::CaseInsensitive => pattern.to_lowercase(),
        };
        self.patterns.push((normalized, pattern_id));
    }

    /// Build the minimal perfect hash table
    ///
    /// Returns serialized MPH table bytes
    pub fn build(
        self,
        pattern_data_offsets: &[(u32, u32)], // (pattern_id, data_offset)
    ) -> Result<Vec<u8>, ParaglobError> {
        if self.patterns.is_empty() {
            return Ok(Vec::new());
        }

        let start = std::time::Instant::now();
        eprintln!("[LiteralMPH] Building minimal perfect hash for {} patterns...", self.patterns.len());

        // Build MPHF
        let keys: Vec<StringKey> = self.patterns.iter()
            .map(|(s, _)| StringKey(s.clone()))
            .collect();

        eprintln!("[LiteralMPH] Constructing MPHF with {} threads...", rayon::current_num_threads());
        let gamma = 2.0; // Space/time tradeoff (1.0 = slower build, 2.5 bits/key; 2.0 = faster, still ~2.5 bits/key)
        let mphf = Mphf::new_parallel(
            gamma,
            &keys,
            None, // Let boomphf choose thread count
        );
        eprintln!("[LiteralMPH] MPHF constructed ({:?})", start.elapsed());

        // Serialize MPHF
        let mphf_bytes = bincode::serialize(&mphf)
            .map_err(|e| ParaglobError::InvalidPattern(format!("Failed to serialize MPHF: {}", e)))?;
        eprintln!("[LiteralMPH] MPHF size: {} bytes ({:.2} bits/key)", 
                  mphf_bytes.len(), 
                  (mphf_bytes.len() * 8) as f64 / self.patterns.len() as f64);

        // Build string pool and index mapping
        // MPHF gives us index 0..n-1 for our n keys
        // We need to store: strings[mphf(key)] = key, pattern_ids[mphf(key)] = pattern_id
        
        let mut strings = vec![String::new(); self.patterns.len()];
        let mut pattern_ids = vec![0u32; self.patterns.len()];
        
        for (pattern, pattern_id) in &self.patterns {
            let key = StringKey(pattern.clone());
            let idx = mphf.hash(&key) as usize;
            if idx >= self.patterns.len() {
                return Err(ParaglobError::InvalidPattern(
                    format!("MPHF produced invalid index: {}", idx)
                ));
            }
            strings[idx] = pattern.clone();
            pattern_ids[idx] = *pattern_id;
        }

        // Serialize string pool
        let mut string_pool = Vec::new();
        for s in &strings {
            if s.len() > u16::MAX as usize {
                return Err(ParaglobError::InvalidPattern(
                    format!("String too long: {} bytes", s.len())
                ));
            }
            string_pool.extend_from_slice(&(s.len() as u16).to_le_bytes());
            string_pool.extend_from_slice(s.as_bytes());
        }

        // Build header
        let header_size = std::mem::size_of::<LiteralMphHeader>();
        let mphf_offset = header_size as u32;
        let strings_offset = mphf_offset + mphf_bytes.len() as u32;
        let index_offset = strings_offset + string_pool.len() as u32;

        let header = LiteralMphHeader {
            magic: *LITERAL_MPH_MAGIC,
            version: LITERAL_MPH_VERSION,
            entry_count: self.patterns.len() as u32,
            mphf_offset,
            mphf_size: mphf_bytes.len() as u32,
            strings_offset,
            strings_size: string_pool.len() as u32,
            index_offset,
        };

        // Assemble buffer
        let mut buffer = Vec::new();
        
        // Header
        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.mphf_offset.to_le_bytes());
        buffer.extend_from_slice(&header.mphf_size.to_le_bytes());
        buffer.extend_from_slice(&header.strings_offset.to_le_bytes());
        buffer.extend_from_slice(&header.strings_size.to_le_bytes());
        buffer.extend_from_slice(&header.index_offset.to_le_bytes());

        // MPHF data
        buffer.extend_from_slice(&mphf_bytes);

        // String pool
        buffer.extend_from_slice(&string_pool);

        // Index mapping (pattern_ids)
        for pid in pattern_ids {
            buffer.extend_from_slice(&pid.to_le_bytes());
        }

        // Pattern mappings
        buffer.extend_from_slice(&(pattern_data_offsets.len() as u32).to_le_bytes());
        for (pattern_id, data_offset) in pattern_data_offsets {
            buffer.extend_from_slice(&pattern_id.to_le_bytes());
            buffer.extend_from_slice(&data_offset.to_le_bytes());
        }

        eprintln!("[LiteralMPH] Total build time: {:?}", start.elapsed());
        eprintln!("[LiteralMPH] Total size: {} bytes ({:.2} MB)", 
                  buffer.len(), 
                  buffer.len() as f64 / 1_048_576.0);
        
        Ok(buffer)
    }

    /// Get number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for LiteralMphBuilder {
    fn default() -> Self {
        Self::new(MatchMode::CaseSensitive)
    }
}

/// Memory-mapped literal MPH table for lookups
pub struct LiteralMph {
    mphf: Mphf<StringKey>,
    strings: Vec<String>,
    pattern_ids: Vec<u32>,
    mode: MatchMode,
}

impl LiteralMph {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &[u8], mode: MatchMode) -> Result<Self, ParaglobError> {
        const HEADER_SIZE: usize = 32; // 4 bytes magic + 7 u32s
        if buffer.len() < HEADER_SIZE {
            return Err(ParaglobError::InvalidPattern(
                "Buffer too small for literal MPH header".to_string(),
            ));
        }

        // Parse header
        let magic = &buffer[0..4];
        if magic != LITERAL_MPH_MAGIC {
            return Err(ParaglobError::InvalidPattern(format!(
                "Invalid literal MPH magic: expected {:?}, got {:?}",
                LITERAL_MPH_MAGIC, magic
            )));
        }

        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if version != LITERAL_MPH_VERSION {
            return Err(ParaglobError::InvalidPattern(format!(
                "Unsupported literal MPH version: {}",
                version
            )));
        }

        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap()) as usize;
        let mphf_offset = u32::from_le_bytes(buffer[12..16].try_into().unwrap()) as usize;
        let mphf_size = u32::from_le_bytes(buffer[16..20].try_into().unwrap()) as usize;
        let strings_offset = u32::from_le_bytes(buffer[20..24].try_into().unwrap()) as usize;
        let strings_size = u32::from_le_bytes(buffer[24..28].try_into().unwrap()) as usize;
        let index_offset = u32::from_le_bytes(buffer[28..32].try_into().unwrap()) as usize;

        // Deserialize MPHF
        let mphf_data = &buffer[mphf_offset..mphf_offset + mphf_size];
        let mphf: Mphf<StringKey> = bincode::deserialize(mphf_data)
            .map_err(|e| ParaglobError::InvalidPattern(format!("Failed to deserialize MPHF: {}", e)))?;

        // Parse string pool
        let mut strings = Vec::with_capacity(entry_count);
        let mut pos = strings_offset;
        let strings_end = strings_offset + strings_size;
        
        while pos < strings_end {
            if pos + 2 > buffer.len() {
                return Err(ParaglobError::InvalidPattern("String pool truncated".to_string()));
            }
            let len = u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            
            if pos + len > buffer.len() {
                return Err(ParaglobError::InvalidPattern("String data truncated".to_string()));
            }
            
            let s = String::from_utf8(buffer[pos..pos + len].to_vec())
                .map_err(|e| ParaglobError::InvalidPattern(format!("Invalid UTF-8 in string pool: {}", e)))?;
            strings.push(s);
            pos += len;
        }

        if strings.len() != entry_count {
            return Err(ParaglobError::InvalidPattern(format!(
                "String count mismatch: expected {}, got {}",
                entry_count, strings.len()
            )));
        }

        // Parse index mapping
        let mut pattern_ids = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let offset = index_offset + i * 4;
            if offset + 4 > buffer.len() {
                return Err(ParaglobError::InvalidPattern("Index mapping truncated".to_string()));
            }
            pattern_ids.push(u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()));
        }

        Ok(Self {
            mphf,
            strings,
            pattern_ids,
            mode,
        })
    }

    /// Lookup a literal string using minimal perfect hash
    ///
    /// Returns the pattern ID if found, None otherwise
    pub fn lookup(&self, query: &str) -> Option<u32> {
        // Normalize query based on match mode
        let normalized_query = match self.mode {
            MatchMode::CaseSensitive => query.to_string(),
            MatchMode::CaseInsensitive => query.to_lowercase(),
        };

        let key = StringKey(normalized_query.clone());
        
        // MPHF may panic for keys not in the original set
        // Catch the panic and treat as not found
        let idx = match panic::catch_unwind(panic::AssertUnwindSafe(|| self.mphf.hash(&key))) {
            Ok(i) => i as usize,
            Err(_) => return None,  // Key not in original set
        };

        // Bounds check
        if idx >= self.strings.len() {
            return None;
        }

        // Verify the string matches (MPHF is minimal perfect for original set only)
        if self.strings[idx] == normalized_query {
            Some(self.pattern_ids[idx])
        } else {
            None
        }
    }

    /// Get data offset for a pattern ID
    pub fn get_data_offset(&self, _pattern_id: u32, buffer: &[u8]) -> Option<u32> {
        // Pattern mappings are stored after index mapping
        // We can compute this from header offsets
        const HEADER_SIZE: usize = 32;
        if buffer.len() < HEADER_SIZE + 4 {
            return None;
        }
        
        // Read index_offset from header
        let index_offset = u32::from_le_bytes(buffer[28..32].try_into().unwrap()) as usize;
        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap()) as usize;
        
        // Pattern mappings start after index mapping
        let mappings_pos = index_offset + entry_count * 4;
        
        if mappings_pos + 4 > buffer.len() {
            return None;
        }

        let count = u32::from_le_bytes(buffer[mappings_pos..mappings_pos + 4].try_into().unwrap()) as usize;
        let mappings_start = mappings_pos + 4;

        // Linear search through mappings
        for i in 0..count {
            let offset = mappings_start + i * 8;
            if offset + 8 > buffer.len() {
                return None;
            }
            let pid = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap());
            if pid == _pattern_id {
                return Some(u32::from_le_bytes(buffer[offset + 4..offset + 8].try_into().unwrap()));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mph_basic() {
        let mut builder = LiteralMphBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("hello", 1);
        builder.add_pattern("world", 2);
        builder.add_pattern("foo", 3);

        let pattern_data = vec![(1, 100), (2, 200), (3, 300)];
        let buffer = builder.build(&pattern_data).unwrap();

        let mph = LiteralMph::from_buffer(&buffer, MatchMode::CaseSensitive).unwrap();
        
        assert_eq!(mph.lookup("hello"), Some(1));
        assert_eq!(mph.lookup("world"), Some(2));
        assert_eq!(mph.lookup("foo"), Some(3));
        assert_eq!(mph.lookup("bar"), None);
    }

    #[test]
    fn test_mph_case_insensitive() {
        let mut builder = LiteralMphBuilder::new(MatchMode::CaseInsensitive);
        builder.add_pattern("Hello", 1);
        builder.add_pattern("WORLD", 2);

        let pattern_data = vec![(1, 100), (2, 200)];
        let buffer = builder.build(&pattern_data).unwrap();

        let mph = LiteralMph::from_buffer(&buffer, MatchMode::CaseInsensitive).unwrap();
        
        assert_eq!(mph.lookup("hello"), Some(1));
        assert_eq!(mph.lookup("HELLO"), Some(1));
        assert_eq!(mph.lookup("world"), Some(2));
        assert_eq!(mph.lookup("World"), Some(2));
    }
}
