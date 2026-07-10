//! MMDB Search Tree Traversal
//!
//! Implements binary search tree traversal for IP address lookups.
//! The tree uses a compact binary representation where each node contains
//! two records (left and right) that point to either:
//! - Another node (continue traversal)
//! - A data section offset (found)
//! - A "not found" marker

use super::format::MmdbHeader;
use super::types::{IpVersion, MmdbError, RecordSize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of an IP lookup
#[derive(Debug, Clone, PartialEq)]
pub struct LookupResult {
    /// Offset into the data section (relative to data section start)
    pub data_offset: u32,
    /// Network prefix length (netmask)
    pub prefix_len: u8,
}

/// Result of walking the IPv4-compatible prefix in an IPv6 tree.
enum Ipv4Start {
    /// Continue with the 32 IPv4 address bits from this node.
    Node(u32),
    /// The prefix walk reached a data record before reaching a node at depth 96.
    Data(LookupResult),
    /// The IPv6 tree contains no IPv4-compatible address space.
    NotFound,
}

/// Search tree for IP address lookups
pub struct SearchTree<'a> {
    /// The bounded search-tree prefix of the file.
    data: &'a [u8],
    /// Parsed header information
    header: &'a MmdbHeader,
}

impl<'a> SearchTree<'a> {
    /// Create a new search tree
    #[must_use]
    pub fn new(data: &'a [u8], header: &'a MmdbHeader) -> Self {
        // Keep reads inside both the declared tree and the actual input. A
        // hand-constructed inconsistent header therefore remains safe without
        // repeating two bounds comparisons at every traversed bit.
        let tree_len = header.tree_size.min(data.len());
        Self {
            data: &data[..tree_len],
            header,
        }
    }

    /// Look up an IP address
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<LookupResult>, MmdbError> {
        match ip {
            IpAddr::V4(addr) => self.lookup_v4(addr),
            IpAddr::V6(addr) => self.lookup_v6(addr),
        }
    }

    /// Look up an IPv4 address
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> Result<Option<LookupResult>, MmdbError> {
        // Check if this is an IPv6 tree
        let (mut node, mut depth) = if self.header.ip_version == IpVersion::V6 {
            // IPv4 addresses in IPv6 trees require finding the IPv4 start node first.
            // Per the MMDB specification, the address is represented as 96 zero
            // bits followed by its 32 IPv4 bits (not as an IPv4-mapped ::ffff
            // address).
            match self.find_ipv4_start_node()? {
                Ipv4Start::Node(node) => (node, 96),
                Ipv4Start::Data(result) => return Ok(Some(result)),
                Ipv4Start::NotFound => return Ok(None),
            }
        } else {
            // Pure IPv4 tree - start at root
            (0u32, 0u8)
        };

        // Now traverse the IPv4 address bits
        let bits = ipv4_to_bits(addr);

        for bit_index in 0..32 {
            let bit = ((bits >> (31 - bit_index)) & 1) as u8;
            let record = self.read_record(node as usize, bit)?;

            if record == self.header.node_count {
                return Ok(None);
            } else if record < self.header.node_count {
                node = record;
                depth += 1;
            } else {
                let data_offset = self.calculate_data_offset(record)?;
                // For IPv4 lookups, report the prefix as IPv4 prefix length
                // (depth includes the 96 bits traversed for IPv6 tree, so subtract them)
                let ipv4_prefix = if depth >= 96 {
                    depth - 96 + 1
                } else {
                    depth + 1
                };
                return Ok(Some(LookupResult {
                    data_offset,
                    prefix_len: ipv4_prefix,
                }));
            }
        }

        Ok(None)
    }

    /// Look up an IPv6 address
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> Result<Option<LookupResult>, MmdbError> {
        // The MMDB API treats an IPv6 query against an IPv4-only database as a
        // successful lookup with no entry. In particular, an IPv4-mapped IPv6
        // address is still an IPv6 query and is not silently remapped.
        if self.header.ip_version == IpVersion::V4 {
            return Ok(None);
        }

        // Convert IPv6 to bits
        let bits = ipv6_to_bits(addr);

        let mut node = 0u32;
        let mut depth = 0u8;
        let max_depth = 128;

        for bit_index in 0..max_depth {
            // Extract bit from 128-bit value
            let bit: u8 = if bit_index < 64 {
                if ((bits.0 >> (63 - bit_index)) & 1) == 0 {
                    0
                } else {
                    1
                }
            } else if ((bits.1 >> (127 - bit_index)) & 1) == 0 {
                0
            } else {
                1
            };

            let record = self.read_record(node as usize, bit)?;

            if record == self.header.node_count {
                return Ok(None);
            } else if record < self.header.node_count {
                node = record;
                depth = bit_index + 1;
            } else {
                let data_offset = self.calculate_data_offset(record)?;
                return Ok(Some(LookupResult {
                    data_offset,
                    prefix_len: depth + 1,
                }));
            }
        }

        Ok(None)
    }

    /// Read a record from a node
    ///
    /// Each node contains two records. `side` determines which:
    /// - 0 = left record (for IP bit 0)
    /// - 1 = right record (for IP bit 1)
    fn read_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        if side > 1 {
            return Err(MmdbError::InvalidFormat(format!(
                "Invalid tree record side {side}; expected 0 or 1"
            )));
        }

        if node >= usize::try_from(self.header.node_count).unwrap_or(usize::MAX) {
            return Err(MmdbError::InvalidFormat(format!(
                "Node index {} exceeds node count {}",
                node, self.header.node_count
            )));
        }

        match self.header.record_size {
            RecordSize::Bits24 => self.read_24bit_record(node, side),
            RecordSize::Bits28 => self.read_28bit_record(node, side),
            RecordSize::Bits32 => self.read_32bit_record(node, side),
        }
    }

    /// Return one complete node from the already bounded tree prefix.
    #[inline]
    fn node_bytes(&self, node: usize, width: usize) -> Result<&'a [u8], MmdbError> {
        let offset = node.checked_mul(width).ok_or_else(|| {
            MmdbError::InvalidFormat(format!("Tree node offset overflows for node {node}"))
        })?;
        let end = offset.checked_add(width).ok_or_else(|| {
            MmdbError::InvalidFormat(format!("Tree node end overflows for node {node}"))
        })?;
        self.data.get(offset..end).ok_or_else(|| {
            MmdbError::InvalidFormat(format!(
                "Tree node range [{offset}, {end}) exceeds bounded tree bytes {}",
                self.data.len()
            ))
        })
    }

    /// Read a 24-bit record (3 bytes per record, 6 bytes per node)
    fn read_24bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let node_bytes = self.node_bytes(node, 6)?;
        let offset = usize::from(side) * 3;
        let bytes = &node_bytes[offset..offset + 3];

        // Read 3 bytes in big-endian order
        let b0 = u32::from(bytes[0]);
        let b1 = u32::from(bytes[1]);
        let b2 = u32::from(bytes[2]);

        Ok((b0 << 16) | (b1 << 8) | b2)
    }

    /// Read a 28-bit record (3.5 bytes per record, 7 bytes per node)
    ///
    /// Layout: [Left 24 bits][Middle 8 bits][Right 24 bits]
    /// Middle byte contains 4 high bits of left + 4 high bits of right
    fn read_28bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let bytes = self.node_bytes(node, 7)?;

        if side == 0 {
            // Left record: bytes[0..3] with 4 high bits from middle byte
            let high_bits = u32::from((bytes[3] >> 4) & 0x0F);
            let low_bits =
                (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
            Ok((high_bits << 24) | low_bits)
        } else {
            // Right record: bytes[4..7] with 4 low bits from middle byte
            let high_bits = u32::from(bytes[3] & 0x0F);
            let low_bits =
                (u32::from(bytes[4]) << 16) | (u32::from(bytes[5]) << 8) | u32::from(bytes[6]);
            Ok((high_bits << 24) | low_bits)
        }
    }

    /// Read a 32-bit record (4 bytes per record, 8 bytes per node)
    fn read_32bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let node_bytes = self.node_bytes(node, 8)?;
        let offset = usize::from(side) * 4;
        let bytes = &node_bytes[offset..offset + 4];

        // Read 4 bytes in big-endian order
        let b0 = u32::from(bytes[0]);
        let b1 = u32::from(bytes[1]);
        let b2 = u32::from(bytes[2]);
        let b3 = u32::from(bytes[3]);

        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }

    /// Calculate data section offset from record value
    ///
    /// Per MMDB spec:
    /// - Record value > node_count means it points to data
    /// - Formula: data_offset = (record_value - node_count) - 16
    /// - The 16 is the data section separator size
    fn calculate_data_offset(&self, record: u32) -> Result<u32, MmdbError> {
        if record <= self.header.node_count {
            return Err(MmdbError::InvalidFormat(format!(
                "Record {} is not a data pointer (node_count = {})",
                record, self.header.node_count
            )));
        }

        // Per spec: subtract node count, then subtract 16 for separator
        let offset_before_separator =
            record.checked_sub(self.header.node_count).ok_or_else(|| {
                MmdbError::InvalidFormat(format!(
                    "Record {} - node_count {} underflow",
                    record, self.header.node_count
                ))
            })?;

        let offset = offset_before_separator.checked_sub(16).ok_or_else(|| {
            MmdbError::InvalidFormat(format!(
                "Data pointer {} - 16 underflow (record={}, node_count={})",
                offset_before_separator, record, self.header.node_count
            ))
        })?;

        Ok(offset)
    }

    /// Find the IPv4 start node in an IPv6 tree
    ///
    /// Per the MMDB specification, IPv4 addresses in IPv6 trees are accessed
    /// through a 96-zero-bit prefix. A terminal record before depth 96 applies
    /// to the IPv4-compatible address space and must be returned directly.
    fn find_ipv4_start_node(&self) -> Result<Ipv4Start, MmdbError> {
        let mut node = 0u32;

        // Traverse 96 zero bits (left record each time)
        for depth in 1..=96u8 {
            let record = self.read_record(node as usize, 0)?;

            if record == self.header.node_count {
                // IPv4 space not found in this tree
                return Ok(Ipv4Start::NotFound);
            } else if record < self.header.node_count {
                node = record;
            } else {
                let data_offset = self.calculate_data_offset(record)?;
                return Ok(Ipv4Start::Data(LookupResult {
                    data_offset,
                    // A prefix terminating at or before the 96-bit IPv4
                    // boundary covers the complete IPv4 address space.
                    prefix_len: depth.saturating_sub(96),
                }));
            }
        }

        Ok(Ipv4Start::Node(node))
    }
}

/// Convert IPv4 address to 32-bit integer
fn ipv4_to_bits(addr: Ipv4Addr) -> u32 {
    let octets = addr.octets();
    (u32::from(octets[0]) << 24)
        | (u32::from(octets[1]) << 16)
        | (u32::from(octets[2]) << 8)
        | u32::from(octets[3])
}

/// Convert IPv6 address to 128-bit integer (as two u64s)
fn ipv6_to_bits(addr: Ipv6Addr) -> (u64, u64) {
    let segments = addr.segments();
    let high = (u64::from(segments[0]) << 48)
        | (u64::from(segments[1]) << 32)
        | (u64::from(segments[2]) << 16)
        | u64::from(segments[3]);
    let low = (u64::from(segments[4]) << 48)
        | (u64::from(segments[5]) << 32)
        | (u64::from(segments[6]) << 16)
        | u64::from(segments[7]);
    (high, low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_bits() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let bits = ipv4_to_bits(addr);
        assert_eq!(bits, 0xC0A80101);
    }

    #[test]
    fn test_ipv6_to_bits() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let (high, low) = ipv6_to_bits(addr);
        assert_eq!(high, 0x20010db800000000);
        assert_eq!(low, 0x0000000000000001);
    }

    #[test]
    fn test_read_24bit_record() {
        // Create a small test tree with 24-bit records
        // Node 0: left=1, right=2
        let mut data = vec![0u8; 1000];
        data[0] = 0x00; // left record high byte
        data[1] = 0x00;
        data[2] = 0x01; // left = 1
        data[3] = 0x00; // right record high byte
        data[4] = 0x00;
        data[5] = 0x02; // right = 2

        let header = MmdbHeader {
            node_count: 10,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: 60, // 10 nodes * 6 bytes
        };

        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.read_24bit_record(0, 0).unwrap(), 1);
        assert_eq!(tree.read_24bit_record(0, 1).unwrap(), 2);
    }

    #[test]
    fn test_read_28bit_record() {
        // Create test data for 28-bit records
        let mut data = vec![0u8; 1000];
        // Node 0 with 28-bit records
        // Left: 0x1000001, Right: 0x2000002
        data[0] = 0x00; // left low 24 bits
        data[1] = 0x00;
        data[2] = 0x01;
        data[3] = 0x12; // middle byte: 0x1 for left high, 0x2 for right high
        data[4] = 0x00; // right low 24 bits
        data[5] = 0x00;
        data[6] = 0x02;

        let header = MmdbHeader {
            node_count: 10,
            record_size: RecordSize::Bits28,
            ip_version: IpVersion::V6,
            tree_size: 70, // 10 nodes * 7 bytes
        };

        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.read_28bit_record(0, 0).unwrap(), 0x1000001);
        assert_eq!(tree.read_28bit_record(0, 1).unwrap(), 0x2000002);
    }

    #[test]
    fn test_read_32bit_record() {
        let data = [0x01, 0x02, 0x03, 0x04, 0xA0, 0xB0, 0xC0, 0xD0];
        let header = MmdbHeader {
            node_count: 1,
            record_size: RecordSize::Bits32,
            ip_version: IpVersion::V6,
            tree_size: data.len(),
        };
        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.read_32bit_record(0, 0).unwrap(), 0x0102_0304);
        assert_eq!(tree.read_32bit_record(0, 1).unwrap(), 0xA0B0_C0D0);
    }

    #[test]
    fn test_record_reads_reject_actual_buffer_truncation_for_every_width() {
        for (record_size, node_bytes) in [
            (RecordSize::Bits24, 6),
            (RecordSize::Bits28, 7),
            (RecordSize::Bits32, 8),
        ] {
            let data = vec![0; node_bytes - 1];
            let header = MmdbHeader {
                node_count: 1,
                record_size,
                ip_version: IpVersion::V6,
                tree_size: node_bytes,
            };
            let tree = SearchTree::new(&data, &header);

            assert!(
                tree.read_record(0, 1).is_err(),
                "{record_size:?} reader trusted declared size over actual bytes"
            );
        }
    }

    #[test]
    fn test_record_read_rejects_invalid_side() {
        let data = [0; 6];
        let header = MmdbHeader {
            node_count: 1,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V4,
            tree_size: data.len(),
        };
        let tree = SearchTree::new(&data, &header);

        assert!(matches!(
            tree.read_record(0, 2),
            Err(MmdbError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_calculate_data_offset() {
        let header = MmdbHeader {
            node_count: 100,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: 600,
        };

        let tree = SearchTree::new(&[], &header);

        // Record 116 -> data offset 0
        // (116 - 100 - 16 = 0)
        assert_eq!(tree.calculate_data_offset(116).unwrap(), 0);

        // Record 200 -> data offset 84
        // (200 - 100 - 16 = 84)
        assert_eq!(tree.calculate_data_offset(200).unwrap(), 84);
    }

    #[test]
    fn test_ipv4_lookup_stops_when_ipv6_tree_has_no_ipv4_subtree() {
        // At the first zero bit the tree says "not found". The right edge is
        // deliberately a valid data pointer: the old implementation returned
        // to the root and could falsely follow this edge using the IPv4 bits.
        let data = [0, 0, 1, 0, 0, 17];
        let header = MmdbHeader {
            node_count: 1,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: data.len(),
        };
        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.lookup_v4(Ipv4Addr::new(192, 0, 2, 1)).unwrap(), None);
    }

    #[test]
    fn test_ipv4_lookup_returns_data_reached_before_ipv4_subtree() {
        // Record 17 means data offset 0 for node_count 1. A data record on the
        // zero-prefix walk covers the entire IPv4-compatible address space.
        let data = [0, 0, 17, 0, 0, 1];
        let header = MmdbHeader {
            node_count: 1,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: data.len(),
        };
        let tree = SearchTree::new(&data, &header);

        assert_eq!(
            tree.lookup_v4(Ipv4Addr::new(203, 0, 113, 7)).unwrap(),
            Some(LookupResult {
                data_offset: 0,
                prefix_len: 0,
            })
        );
    }

    #[test]
    fn test_ipv6_lookup_in_ipv4_database_is_not_found() {
        // Both records point to data, so traversing this as a 128-bit tree would
        // incorrectly return a match. MMDB specifies a successful not-found
        // result for IPv6 queries against IPv4-only databases.
        let data = [0, 0, 17, 0, 0, 17];
        let header = MmdbHeader {
            node_count: 1,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V4,
            tree_size: data.len(),
        };
        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.lookup_v6(Ipv6Addr::LOCALHOST).unwrap(), None);
        assert_eq!(
            tree.lookup_v6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped())
                .unwrap(),
            None
        );
    }

    #[test]
    fn test_lookup_with_real_database() {
        // This test uses the actual GeoLite2-Country.mmdb file
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");

        // Parse header
        let header = MmdbHeader::from_file(data).unwrap();
        let tree = SearchTree::new(data, &header);

        // Test a known IP (1.1.1.1 - Cloudflare, should be in database)
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let result = tree.lookup_v4(ip).unwrap();

        // Should find something for this well-known IP
        assert!(result.is_some(), "Should find data for 1.1.1.1");

        if let Some(lookup_result) = result {
            assert!(
                lookup_result.data_offset > 0,
                "Data offset should be non-zero"
            );
            assert!(
                lookup_result.prefix_len > 0,
                "Prefix length should be positive"
            );
            assert!(
                lookup_result.prefix_len <= 32,
                "IPv4 prefix should be <= 32"
            );
        }

        // Test another well-known IP
        let ip2 = Ipv4Addr::new(8, 8, 8, 8);
        let result2 = tree.lookup_v4(ip2).unwrap();
        assert!(result2.is_some(), "Should find data for 8.8.8.8");
    }
}
