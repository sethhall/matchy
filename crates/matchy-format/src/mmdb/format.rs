//! MMDB Binary Format Parsing
//!
//! This module handles parsing the MMDB binary format with minimal heap allocation.
//! Only essential header information is extracted; everything else stays in mmap.
//!
//! Design:
//! - Find metadata marker (slice search, no allocation)
//! - Extract only: node_count, record_size, ip_version (~16 bytes on heap)
//! - Tree traversal works with pure offsets (zero allocation)
//! - Data decoding only allocates when returning results to users

use super::types::{record_size_from_bits, IpVersion, MmdbError, RecordSize, METADATA_MARKER};
use matchy_data_format::{DataDecoder, DataValue};

/// MMDB file header - minimal heap usage
///
/// Contains only the essential information needed for IP lookups.
/// Total heap usage: ~16 bytes.
#[derive(Debug, Clone, Copy)]
pub struct MmdbHeader {
    /// Number of nodes in the search tree
    pub node_count: u32,
    /// Record size in bits (24, 28, or 32)
    pub record_size: RecordSize,
    /// IP version (4 or 6)
    pub ip_version: IpVersion,
    /// Size of the search tree in bytes
    pub tree_size: usize,
}

impl MmdbHeader {
    /// Parse MMDB file and extract minimal header information
    ///
    /// Only extracts fields needed for IP lookups. Metadata stays in mmap.
    pub fn from_file(data: &[u8]) -> Result<Self, MmdbError> {
        // Find metadata marker
        let marker_offset = find_metadata_marker(data)?;

        // Metadata comes AFTER the marker (verified from libmaxminddb source)
        // The metadata section starts right after the marker bytes
        let metadata_offset = marker_offset + METADATA_MARKER.len();
        let metadata_bytes = &data[metadata_offset..];

        // Decode metadata as MMDB data starting at offset 0
        let decoder = DataDecoder::new(metadata_bytes, 0);
        let metadata_value = decoder
            .decode(0)
            .map_err(|e| MmdbError::InvalidMetadata(format!("Failed to decode metadata: {e}")))?;

        // Extract required fields (temporary allocation during parsing)
        let (node_count, record_size_bits, ip_version_num) = match metadata_value {
            DataValue::Map(ref map) => {
                let node_count = extract_uint(map, "node_count")?;
                let record_size = u16::try_from(extract_uint(map, "record_size")?)
                    .map_err(|_| MmdbError::InvalidMetadata("record_size too large".to_string()))?;
                let ip_version = extract_uint(map, "ip_version")?;
                (node_count, record_size, ip_version)
            }
            _ => {
                return Err(MmdbError::InvalidMetadata(
                    "Metadata is not a map".to_string(),
                ))
            }
        };

        let record_size = record_size_from_bits(record_size_bits)?;

        let ip_version = match ip_version_num {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => {
                return Err(MmdbError::InvalidMetadata(format!(
                    "Invalid IP version: {ip_version_num}"
                )))
            }
        };

        // Calculate tree size
        let node_count_u32 = u32::try_from(node_count)
            .map_err(|_| MmdbError::InvalidMetadata("node_count exceeds u32::MAX".to_string()))?;
        let tree_size = usize::try_from(node_count)
            .map_err(|_| MmdbError::InvalidMetadata("node_count exceeds usize".to_string()))?
            .checked_mul(record_size.node_bytes())
            .ok_or_else(|| {
                MmdbError::InvalidFormat("Search tree size overflows address space".to_string())
            })?;

        // An MMDB file stores a 16-byte zero separator immediately after the
        // search tree. Both must end before the metadata marker. Checking this
        // envelope at load time keeps later tree reads from trusting a
        // metadata-provided size that the actual file cannot satisfy.
        let data_section_start = tree_size.checked_add(16).ok_or_else(|| {
            MmdbError::InvalidFormat("Data section offset overflows address space".to_string())
        })?;
        if data_section_start > marker_offset {
            return Err(MmdbError::InvalidFormat(format!(
                "Search tree ({tree_size} bytes) and separator extend past metadata marker at {marker_offset}"
            )));
        }

        let separator = data.get(tree_size..data_section_start).ok_or_else(|| {
            MmdbError::InvalidFormat("MMDB data section separator is truncated".to_string())
        })?;
        if separator.iter().any(|&byte| byte != 0) {
            return Err(MmdbError::InvalidFormat(
                "MMDB data section separator must contain 16 zero bytes".to_string(),
            ));
        }

        Ok(Self {
            node_count: node_count_u32,
            record_size,
            ip_version,
            tree_size,
        })
    }
}

/// Optional metadata access (zero-copy, parses on-demand)
///
/// This provides access to non-essential metadata fields without
/// allocating until actually requested.
pub struct MmdbMetadata<'a> {
    raw_data: &'a [u8],
    metadata_offset: usize,
}

impl<'a> MmdbMetadata<'a> {
    /// Create metadata accessor from mmap'd data
    pub fn from_file(data: &'a [u8]) -> Result<Self, MmdbError> {
        let metadata_start = find_metadata_marker(data)?;
        let metadata_offset = metadata_start + METADATA_MARKER.len();

        Ok(MmdbMetadata {
            raw_data: data,
            metadata_offset,
        })
    }

    /// Get full metadata as DataValue (allocates on-demand)
    pub fn as_value(&self) -> Result<DataValue, MmdbError> {
        let decoder = DataDecoder::new(&self.raw_data[self.metadata_offset..], 0);
        decoder
            .decode(0)
            .map_err(|e| MmdbError::InvalidMetadata(e.to_string()))
    }
}

/// Find the metadata marker in MMDB file (zero allocation)
///
/// The marker "\xAB\xCD\xEFMaxMind.com" appears somewhere in the last 128KB
/// of the file. The metadata comes AFTER the marker.
///
/// Note: If there are multiple markers (unlikely but possible), we want the LAST one.
pub fn find_metadata_marker(data: &[u8]) -> Result<usize, MmdbError> {
    const SEARCH_SIZE: usize = 128 * 1024; // 128KB

    if data.len() < METADATA_MARKER.len() {
        return Err(MmdbError::MetadataNotFound);
    }

    // Start searching from the end, but only within the last 128KB
    let search_start = if data.len() > SEARCH_SIZE {
        data.len() - SEARCH_SIZE
    } else {
        0
    };

    // Search for the marker, keeping track of the LAST occurrence
    // (libmaxminddb does this to handle files with multiple markers)
    let mut last_marker = None;
    for i in search_start..=(data.len() - METADATA_MARKER.len()) {
        if &data[i..i + METADATA_MARKER.len()] == METADATA_MARKER {
            last_marker = Some(i);
        }
    }

    last_marker.ok_or(MmdbError::MetadataNotFound)
}

// Helper functions to extract values from metadata map (temporary during parsing)

fn extract_uint(
    map: &std::collections::HashMap<String, DataValue>,
    key: &str,
) -> Result<u64, MmdbError> {
    match map.get(key) {
        Some(DataValue::Uint16(n)) => Ok(u64::from(*n)),
        Some(DataValue::Uint32(n)) => Ok(u64::from(*n)),
        Some(DataValue::Uint64(n)) => Ok(*n),
        Some(_) => Err(MmdbError::InvalidMetadata(format!(
            "Field '{key}' is not an unsigned integer"
        ))),
        None => Err(MmdbError::InvalidMetadata(format!(
            "Required field '{key}' not found"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matchy_data_format::DataEncoder;
    use std::collections::HashMap;

    fn synthetic_mmdb(
        node_count: u32,
        record_size: u16,
        ip_version: u16,
        tree: &[u8],
        separator: &[u8],
    ) -> Vec<u8> {
        let mut metadata = HashMap::new();
        metadata.insert("node_count".to_string(), DataValue::Uint32(node_count));
        metadata.insert("record_size".to_string(), DataValue::Uint16(record_size));
        metadata.insert("ip_version".to_string(), DataValue::Uint16(ip_version));

        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::Map(metadata));

        let mut data = Vec::new();
        data.extend_from_slice(tree);
        data.extend_from_slice(separator);
        data.extend_from_slice(METADATA_MARKER);
        data.extend_from_slice(&encoder.into_bytes());
        data
    }

    #[test]
    fn test_find_metadata_marker() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let marker_offset = find_metadata_marker(data);
        assert!(marker_offset.is_ok(), "Should find metadata marker");

        let offset = marker_offset.unwrap();
        println!("Total file size: {} bytes", data.len());
        println!("Marker found at offset: {offset}");
        println!(
            "Marker: {:?}",
            &data[offset..offset + METADATA_MARKER.len()]
        );

        assert!(offset > 0, "Marker should not be at start of file");
        assert_eq!(
            &data[offset..offset + METADATA_MARKER.len()],
            METADATA_MARKER
        );

        // Check what's around the marker
        let after_marker = offset + METADATA_MARKER.len();
        let before_marker = offset.saturating_sub(20);
        println!(
            "20 bytes before marker: {:02x?}",
            &data[before_marker..offset]
        );
        println!(
            "Bytes after marker: {} bytes remaining",
            data.len() - after_marker
        );
        if data.len() > after_marker {
            println!(
                "First 20 bytes after marker: {:02x?}",
                &data[after_marker..after_marker.min(data.len())]
            );
        }
    }

    #[test]
    fn test_parse_header_minimal() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let header = MmdbHeader::from_file(data);
        if let Err(ref e) = header {
            println!("Error parsing header: {e}");
        }
        assert!(header.is_ok(), "Should parse header successfully");

        let header = header.unwrap();
        assert!(header.node_count > 0, "Should have nodes");
        assert!(header.tree_size > 0, "Tree should have size");

        // Record size should be valid
        match header.record_size {
            RecordSize::Bits24 | RecordSize::Bits28 | RecordSize::Bits32 => {}
        }

        // IP version should be valid
        match header.ip_version {
            IpVersion::V4 | IpVersion::V6 => {}
        }

        println!("Header: {header:?}");
        println!("Heap usage: ~{} bytes", std::mem::size_of_val(&header));
    }

    #[test]
    fn test_metadata_on_demand() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let metadata = MmdbMetadata::from_file(data);
        assert!(metadata.is_ok(), "Should create metadata accessor");

        let metadata = metadata.unwrap();

        // Parse on-demand from mmap using as_value()
        let metadata_value = metadata.as_value();
        assert!(metadata_value.is_ok());

        if let DataValue::Map(ref map) = metadata_value.unwrap() {
            // Check database_type
            if let Some(DataValue::String(db_type)) = map.get("database_type") {
                assert_eq!(db_type, "GeoLite2-Country");
            }

            // Check build_epoch
            if let Some(epoch_value) = map.get("build_epoch") {
                let epoch_num = match epoch_value {
                    DataValue::Uint32(n) => u64::from(*n),
                    DataValue::Uint64(n) => *n,
                    _ => panic!("build_epoch has unexpected type"),
                };
                println!("Build epoch: {epoch_num}");
                assert!(epoch_num > 0);
            }
        } else {
            panic!("Metadata should be a map");
        }
    }

    #[test]
    fn test_metadata_not_found() {
        let data = b"not a valid mmdb file";
        let result = find_metadata_marker(data);
        assert!(result.is_err());
        assert!(matches!(result, Err(MmdbError::MetadataNotFound)));
    }

    #[test]
    fn test_parse_header_accepts_valid_synthetic_tree_and_separator() {
        let tree = [0, 0, 1, 0, 0, 1];
        let data = synthetic_mmdb(1, 24, 4, &tree, &[0; 16]);

        let header = MmdbHeader::from_file(&data).unwrap();

        assert_eq!(header.node_count, 1);
        assert_eq!(header.record_size, RecordSize::Bits24);
        assert_eq!(header.ip_version, IpVersion::V4);
        assert_eq!(header.tree_size, tree.len());
    }

    #[test]
    fn test_parse_header_rejects_tree_truncated_before_metadata() {
        for (record_size, node_bytes) in [(24, 6), (28, 7), (32, 8)] {
            // Metadata claims two nodes, but only one node is present before
            // the separator and metadata marker.
            let tree = vec![0; node_bytes];
            let data = synthetic_mmdb(2, record_size, 4, &tree, &[0; 16]);

            let result = MmdbHeader::from_file(&data);
            assert!(
                matches!(result, Err(MmdbError::InvalidFormat(_))),
                "record size {record_size} unexpectedly accepted: {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_header_rejects_truncated_separator() {
        let tree = [0, 0, 1, 0, 0, 1];
        let data = synthetic_mmdb(1, 24, 4, &tree, &[0; 15]);

        assert!(matches!(
            MmdbHeader::from_file(&data),
            Err(MmdbError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_parse_header_rejects_nonzero_separator() {
        let tree = [0, 0, 1, 0, 0, 1];
        let mut separator = [0; 16];
        separator[7] = 1;
        let data = synthetic_mmdb(1, 24, 4, &tree, &separator);

        assert!(matches!(
            MmdbHeader::from_file(&data),
            Err(MmdbError::InvalidFormat(_))
        ));
    }
}
