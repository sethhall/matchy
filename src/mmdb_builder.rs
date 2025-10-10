//! Unified MMDB Database Builder
//!
//! Builds MMDB-format databases containing both IP address data and pattern matching data.
//! Automatically detects whether input rows are IP addresses (including CIDRs) or patterns.

use crate::data_section::{DataEncoder, DataValue};
use crate::error::ParaglobError;
use crate::glob::MatchMode;
use crate::ip_tree_builder::IpTreeBuilder;
use crate::mmdb::types::RecordSize;
use crate::paraglob_offset::ParaglobBuilder;
use std::collections::HashMap;
use std::net::IpAddr;

/// Entry type auto-detected from input
#[derive(Debug, Clone)]
pub enum EntryType {
    /// IP address or CIDR block with prefix length
    IpAddress {
        /// IP address
        addr: IpAddr,
        /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
        prefix_len: u8,
    },
    /// Glob pattern
    Pattern(String),
}

/// Single row of input data
#[derive(Debug, Clone)]
pub struct DataEntry {
    /// The original key (IP/CIDR or pattern)
    pub key: String,
    /// Detected entry type
    pub entry_type: EntryType,
    /// Associated data values
    pub data: HashMap<String, DataValue>,
}

/// Unified database builder
pub struct MmdbBuilder {
    entries: Vec<DataEntry>,
    match_mode: MatchMode,
    /// Optional custom database type name
    database_type: Option<String>,
    /// Optional custom description (language -> text)
    description: HashMap<String, String>,
}

impl MmdbBuilder {
    /// Create a new builder
    pub fn new(match_mode: MatchMode) -> Self {
        Self {
            entries: Vec::new(),
            match_mode,
            database_type: None,
            description: HashMap::new(),
        }
    }

    /// Set a custom database type name
    ///
    /// If not set, defaults to "Paraglob-Combined-IP-Pattern" or "Paraglob-IP"
    ///
    /// # Example
    /// ```
    /// use paraglob_rs::mmdb_builder::MmdbBuilder;
    /// use paraglob_rs::glob::MatchMode;
    ///
    /// let builder = MmdbBuilder::new(MatchMode::CaseSensitive)
    ///     .with_database_type("MyCompany-ThreatIntel");
    /// ```
    pub fn with_database_type(mut self, db_type: impl Into<String>) -> Self {
        self.database_type = Some(db_type.into());
        self
    }

    /// Add a description in a specific language
    ///
    /// Can be called multiple times for different languages.
    /// If not called, defaults to English description.
    ///
    /// # Example
    /// ```
    /// use paraglob_rs::mmdb_builder::MmdbBuilder;
    /// use paraglob_rs::glob::MatchMode;
    ///
    /// let builder = MmdbBuilder::new(MatchMode::CaseSensitive)
    ///     .with_description("en", "My custom threat database")
    ///     .with_description("es", "Mi base de datos de amenazas personalizada");
    /// ```
    pub fn with_description(
        mut self,
        language: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        self.description.insert(language.into(), text.into());
        self
    }

    /// Add an entry with auto-detection
    pub fn add_entry(
        &mut self,
        key: &str,
        data: HashMap<String, DataValue>,
    ) -> Result<(), ParaglobError> {
        let entry_type = Self::detect_entry_type(key)?;

        self.entries.push(DataEntry {
            key: key.to_string(),
            entry_type,
            data,
        });

        Ok(())
    }

    /// Auto-detect if key is an IP/CIDR or pattern
    fn detect_entry_type(key: &str) -> Result<EntryType, ParaglobError> {
        // Try parsing as plain IP address first (most conservative)
        if let Ok(addr) = key.parse::<IpAddr>() {
            let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
            return Ok(EntryType::IpAddress { addr, prefix_len });
        }

        // Check for CIDR notation (contains '/' and valid format)
        if let Some(slash_pos) = key.find('/') {
            let addr_str = &key[..slash_pos];
            let prefix_str = &key[slash_pos + 1..];

            // Only try CIDR parsing if the prefix part looks numeric and address part looks like IP
            if let (Ok(addr), Ok(prefix_len)) =
                (addr_str.parse::<IpAddr>(), prefix_str.parse::<u8>())
            {
                // Validate prefix length
                let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
                if prefix_len <= max_prefix {
                    return Ok(EntryType::IpAddress { addr, prefix_len });
                }
            }
            // If CIDR parsing fails, fall through to pattern handling
        }

        // Check for glob pattern characters
        if key.contains('*') || key.contains('?') || key.contains('[') {
            return Ok(EntryType::Pattern(key.to_string()));
        }

        // Otherwise, treat as literal string pattern
        Ok(EntryType::Pattern(key.to_string()))
    }

    /// Build the unified MMDB database
    pub fn build(&self) -> Result<Vec<u8>, ParaglobError> {
        // Separate IP and pattern entries
        let mut ip_entries = Vec::new();
        let mut pattern_entries = Vec::new();

        for entry in &self.entries {
            match &entry.entry_type {
                EntryType::IpAddress { addr, prefix_len } => {
                    ip_entries.push((addr, *prefix_len, &entry.data));
                }
                EntryType::Pattern(pattern) => {
                    pattern_entries.push((pattern.as_str(), &entry.data));
                }
            }
        }

        // Build data section with all data
        let mut data_encoder = DataEncoder::new();
        let mut data_offsets = HashMap::new();

        // Encode data for both IPs and patterns (deduplicated)
        for entry in &self.entries {
            let data_value = DataValue::Map(entry.data.clone());
            let offset = data_encoder.encode(&data_value);
            data_offsets.insert(entry.key.clone(), offset);
        }

        let data_section = data_encoder.into_bytes();

        // Always build IP tree structure (even if empty) to maintain MMDB format
        // This ensures pattern-only databases still work with the Database API
        let (ip_tree_bytes, node_count, record_size, ip_version) = if !ip_entries.is_empty() {
            // Determine IP version needed
            let needs_v6 = ip_entries.iter().any(|(addr, _, _)| addr.is_ipv6());

            // Use 24-bit records (most common, balances size and performance)
            let record_size = RecordSize::Bits24;

            let mut tree_builder = if needs_v6 {
                IpTreeBuilder::new_v6(record_size)
            } else {
                IpTreeBuilder::new_v4(record_size)
            };

            // Insert all IP entries
            for entry in &self.entries {
                if let EntryType::IpAddress { addr, prefix_len } = &entry.entry_type {
                    let data_offset = data_offsets[&entry.key];
                    tree_builder.insert(*addr, *prefix_len, data_offset)?;
                }
            }

            // Build the tree
            let (tree_bytes, node_cnt) = tree_builder.build()?;

            let ip_ver = if needs_v6 { 6 } else { 4 };
            (tree_bytes, node_cnt, record_size, ip_ver)
        } else {
            // Empty IP tree - create minimal valid tree
            let record_size = RecordSize::Bits24;
            let tree_builder = IpTreeBuilder::new_v4(record_size);
            let (tree_bytes, node_cnt) = tree_builder.build()?;
            (tree_bytes, node_cnt, record_size, 4)
        };

        // Build pattern section if we have pattern entries
        let (has_patterns, pattern_section_bytes) = if !pattern_entries.is_empty() {
            let mut pattern_builder = ParaglobBuilder::new(self.match_mode);
            let mut pattern_data = Vec::new();

            for (pattern, _data) in &pattern_entries {
                let pattern_id = pattern_builder.add_pattern(pattern)?;
                let data_offset = data_offsets[*pattern];
                pattern_data.push((pattern_id, data_offset));
            }

            let paraglob = pattern_builder.build()?;
            let paraglob_bytes = paraglob.buffer().to_vec();

            // Build complete pattern section: [total_size][paraglob_size][paraglob_data][mappings]
            let mut section = Vec::new();

            // Will fill in sizes at the end
            let size_placeholder = vec![0u8; 8]; // 2 u32s
            section.extend_from_slice(&size_placeholder);

            // Paraglob data
            section.extend_from_slice(&paraglob_bytes);

            // Mappings: pattern_count + data offsets
            let pattern_count = pattern_data.len() as u32;
            section.extend_from_slice(&pattern_count.to_le_bytes());
            for (_pattern_id, data_offset) in pattern_data {
                section.extend_from_slice(&data_offset.to_le_bytes());
            }

            // Fill in sizes
            let total_size = section.len() as u32;
            let paraglob_size = paraglob_bytes.len() as u32;
            section[0..4].copy_from_slice(&total_size.to_le_bytes());
            section[4..8].copy_from_slice(&paraglob_size.to_le_bytes());

            (true, section)
        } else {
            (false, Vec::new())
        };

        // Assemble final database - always use MMDB format
        let mut database = Vec::new();

        // IP tree (empty or populated)
        database.extend_from_slice(&ip_tree_bytes);
        database
            .extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // 16-byte separator

        // Data section
        database.extend_from_slice(&data_section);

        // Add MMDB metadata section (always present)
        {
            // Build metadata map
            let mut metadata = HashMap::new();
            metadata.insert(
                "binary_format_major_version".to_string(),
                DataValue::Uint16(2),
            );
            metadata.insert(
                "binary_format_minor_version".to_string(),
                DataValue::Uint16(0),
            );
            metadata.insert(
                "build_epoch".to_string(),
                DataValue::Uint64(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
            );
            // Database type - use custom if provided, otherwise auto-generate
            let db_type = self.database_type.clone().unwrap_or_else(|| {
                if has_patterns {
                    if !ip_entries.is_empty() {
                        "Paraglob-Combined-IP-Pattern".to_string()
                    } else {
                        "Paraglob-Pattern".to_string()
                    }
                } else {
                    "Paraglob-IP".to_string()
                }
            });
            metadata.insert("database_type".to_string(), DataValue::String(db_type));

            // Description - use custom if provided, otherwise use default
            let description_map = if self.description.is_empty() {
                let mut desc = HashMap::new();
                desc.insert(
                    "en".to_string(),
                    DataValue::String(
                        "Paraglob unified database with IP and pattern matching".to_string(),
                    ),
                );
                desc
            } else {
                self.description
                    .iter()
                    .map(|(k, v)| (k.clone(), DataValue::String(v.clone())))
                    .collect()
            };
            metadata.insert("description".to_string(), DataValue::Map(description_map));
            metadata.insert(
                "languages".to_string(),
                DataValue::Array(vec![DataValue::String("en".to_string())]),
            );
            metadata.insert(
                "ip_version".to_string(),
                DataValue::Uint16(ip_version as u16),
            );
            metadata.insert("node_count".to_string(), DataValue::Uint32(node_count));
            metadata.insert(
                "record_size".to_string(),
                DataValue::Uint16(match record_size {
                    RecordSize::Bits24 => 24,
                    RecordSize::Bits28 => 28,
                    RecordSize::Bits32 => 32,
                }),
            );

            // Encode metadata
            let mut meta_encoder = DataEncoder::new();
            let metadata_value = DataValue::Map(metadata);
            meta_encoder.encode(&metadata_value);
            let metadata_bytes = meta_encoder.into_bytes();

            // Save metadata for end of file (will be added after pattern section)
            // This ensures it's in the last 128KB for the metadata marker search

            // Add MMDB_PATTERN separator before patterns (if any)
            if has_patterns {
                database.extend_from_slice(b"MMDB_PATTERN\x00\x00\x00\x00");
                database.extend_from_slice(&pattern_section_bytes);
            }

            // Add metadata at the END of the file so it's within the 128KB search window
            database.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
            database.extend_from_slice(&metadata_bytes);
        }

        Ok(database)
    }

    /// Get statistics about the builder
    pub fn stats(&self) -> BuilderStats {
        let mut ip_count = 0;
        let mut pattern_count = 0;

        for entry in &self.entries {
            match &entry.entry_type {
                EntryType::IpAddress { .. } => ip_count += 1,
                EntryType::Pattern(_) => pattern_count += 1,
            }
        }

        BuilderStats {
            total_entries: self.entries.len(),
            ip_entries: ip_count,
            pattern_entries: pattern_count,
        }
    }
}

/// Builder statistics
#[derive(Debug, Clone)]
pub struct BuilderStats {
    /// Total number of entries added
    pub total_entries: usize,
    /// Number of IP address/CIDR entries
    pub ip_entries: usize,
    /// Number of pattern entries
    pub pattern_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ip_address() {
        let result = MmdbBuilder::detect_entry_type("8.8.8.8").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "8.8.8.8");
                assert_eq!(prefix_len, 32);
            }
            _ => panic!("Expected IP address"),
        }
    }

    #[test]
    fn test_detect_cidr() {
        let result = MmdbBuilder::detect_entry_type("192.168.0.0/16").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "192.168.0.0");
                assert_eq!(prefix_len, 16);
            }
            _ => panic!("Expected CIDR"),
        }
    }

    #[test]
    fn test_detect_ipv6() {
        let result = MmdbBuilder::detect_entry_type("2001:4860:4860::8888").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert!(addr.is_ipv6());
                assert_eq!(prefix_len, 128);
            }
            _ => panic!("Expected IPv6"),
        }
    }

    #[test]
    fn test_detect_pattern_wildcard() {
        let result = MmdbBuilder::detect_entry_type("*.evil.com").unwrap();
        match result {
            EntryType::Pattern(p) => assert_eq!(p, "*.evil.com"),
            _ => panic!("Expected pattern"),
        }
    }

    #[test]
    fn test_detect_pattern_literal() {
        let result = MmdbBuilder::detect_entry_type("evil.com").unwrap();
        match result {
            EntryType::Pattern(p) => assert_eq!(p, "evil.com"),
            _ => panic!("Expected pattern"),
        }
    }
}
