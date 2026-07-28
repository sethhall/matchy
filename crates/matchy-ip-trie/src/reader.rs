//! Borrowed lookup view over a serialized IP tree.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{IpVersion, RecordSize};

/// Result of an IP lookup.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct IpLookup {
    /// Offset into the caller-owned data section.
    pub data_offset: u32,
    /// Network prefix length, expressed in the queried address family.
    pub prefix_len: u8,
}

/// Error returned when serialized tree bytes are malformed.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IpTreeLookupError {
    message: String,
}

impl IpTreeLookupError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IpTreeLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IpTreeLookupError {}

/// Result of walking the IPv4-compatible prefix in an IPv6 tree.
enum Ipv4Start {
    /// Continue with the 32 IPv4 address bits from this node.
    Node(u32),
    /// The prefix walk reached a data record before depth 96.
    Data(IpLookup),
    /// The tree contains no IPv4-compatible address space.
    NotFound,
}

/// Zero-copy lookup view over serialized IP tree bytes.
///
/// The view stores only a bounded byte slice and scalar metadata, making it
/// suitable for tree data borrowed directly from a memory-mapped artifact.
pub struct IpTree<'a> {
    data: &'a [u8],
    node_count: u32,
    record_size: RecordSize,
    ip_version: IpVersion,
}

impl<'a> IpTree<'a> {
    /// Create a borrowed view over a serialized tree section.
    ///
    /// Bytes beyond the exact node array are ignored. A truncated section is
    /// retained as-is and fails safely when a lookup reaches missing bytes.
    #[must_use]
    pub fn new(
        data: &'a [u8],
        node_count: u32,
        record_size: RecordSize,
        ip_version: IpVersion,
    ) -> Self {
        let expected_len = usize::try_from(node_count)
            .ok()
            .and_then(|count| count.checked_mul(record_size.node_bytes()))
            .unwrap_or(usize::MAX);
        let tree_len = expected_len.min(data.len());
        Self {
            data: &data[..tree_len],
            node_count,
            record_size,
            ip_version,
        }
    }

    /// Look up an IP address.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<IpLookup>, IpTreeLookupError> {
        match ip {
            IpAddr::V4(addr) => self.lookup_v4(addr),
            IpAddr::V6(addr) => self.lookup_v6(addr),
        }
    }

    /// Look up an IPv4 address.
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> Result<Option<IpLookup>, IpTreeLookupError> {
        let (mut node, mut depth) = if self.ip_version == IpVersion::V6 {
            match self.find_ipv4_start_node()? {
                Ipv4Start::Node(node) => (node, 96),
                Ipv4Start::Data(result) => return Ok(Some(result)),
                Ipv4Start::NotFound => return Ok(None),
            }
        } else {
            (0_u32, 0_u8)
        };

        let bits = u32::from(addr);
        for bit_index in 0..32 {
            let bit = ((bits >> (31 - bit_index)) & 1) as u8;
            let record = self.read_record(node as usize, bit)?;
            if record == self.node_count {
                return Ok(None);
            }
            if record < self.node_count {
                node = record;
                depth += 1;
                continue;
            }

            let data_offset = self.calculate_data_offset(record)?;
            let prefix_len = if depth >= 96 {
                depth - 96 + 1
            } else {
                depth + 1
            };
            return Ok(Some(IpLookup {
                data_offset,
                prefix_len,
            }));
        }

        Ok(None)
    }

    /// Look up an IPv6 address.
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> Result<Option<IpLookup>, IpTreeLookupError> {
        if self.ip_version == IpVersion::V4 {
            return Ok(None);
        }

        let bits = u128::from(addr);
        let mut node = 0_u32;
        let mut depth = 0_u8;
        for bit_index in 0..128 {
            let bit = ((bits >> (127 - bit_index)) & 1) as u8;
            let record = self.read_record(node as usize, bit)?;
            if record == self.node_count {
                return Ok(None);
            }
            if record < self.node_count {
                node = record;
                depth = bit_index + 1;
                continue;
            }

            return Ok(Some(IpLookup {
                data_offset: self.calculate_data_offset(record)?,
                prefix_len: depth + 1,
            }));
        }

        Ok(None)
    }

    fn read_record(&self, node: usize, side: u8) -> Result<u32, IpTreeLookupError> {
        if side > 1 {
            return Err(IpTreeLookupError::invalid(format!(
                "invalid tree record side {side}; expected 0 or 1"
            )));
        }
        if node >= usize::try_from(self.node_count).unwrap_or(usize::MAX) {
            return Err(IpTreeLookupError::invalid(format!(
                "node index {node} exceeds node count {}",
                self.node_count
            )));
        }

        match self.record_size {
            RecordSize::Bits24 => self.read_24bit_record(node, side),
            RecordSize::Bits28 => self.read_28bit_record(node, side),
            RecordSize::Bits32 => self.read_32bit_record(node, side),
        }
    }

    fn node_bytes(&self, node: usize, width: usize) -> Result<&'a [u8], IpTreeLookupError> {
        let offset = node.checked_mul(width).ok_or_else(|| {
            IpTreeLookupError::invalid(format!("tree node offset overflows for node {node}"))
        })?;
        let end = offset.checked_add(width).ok_or_else(|| {
            IpTreeLookupError::invalid(format!("tree node end overflows for node {node}"))
        })?;
        self.data.get(offset..end).ok_or_else(|| {
            IpTreeLookupError::invalid(format!(
                "tree node range [{offset}, {end}) exceeds bounded tree bytes {}",
                self.data.len()
            ))
        })
    }

    fn read_24bit_record(&self, node: usize, side: u8) -> Result<u32, IpTreeLookupError> {
        let node_bytes = self.node_bytes(node, 6)?;
        let offset = usize::from(side) * 3;
        Ok((u32::from(node_bytes[offset]) << 16)
            | (u32::from(node_bytes[offset + 1]) << 8)
            | u32::from(node_bytes[offset + 2]))
    }

    fn read_28bit_record(&self, node: usize, side: u8) -> Result<u32, IpTreeLookupError> {
        let bytes = self.node_bytes(node, 7)?;
        if side == 0 {
            let high = u32::from((bytes[3] >> 4) & 0x0f);
            let low =
                (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
            Ok((high << 24) | low)
        } else {
            let high = u32::from(bytes[3] & 0x0f);
            let low =
                (u32::from(bytes[4]) << 16) | (u32::from(bytes[5]) << 8) | u32::from(bytes[6]);
            Ok((high << 24) | low)
        }
    }

    fn read_32bit_record(&self, node: usize, side: u8) -> Result<u32, IpTreeLookupError> {
        let bytes = self.node_bytes(node, 8)?;
        let offset = usize::from(side) * 4;
        Ok(u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("bounded four-byte record"),
        ))
    }

    fn calculate_data_offset(&self, record: u32) -> Result<u32, IpTreeLookupError> {
        if record <= self.node_count {
            return Err(IpTreeLookupError::invalid(format!(
                "record {record} is not a data pointer (node count = {})",
                self.node_count
            )));
        }
        record
            .checked_sub(self.node_count)
            .and_then(|offset| offset.checked_sub(16))
            .ok_or_else(|| {
                IpTreeLookupError::invalid(format!(
                    "data pointer underflows (record={record}, node count={})",
                    self.node_count
                ))
            })
    }

    fn find_ipv4_start_node(&self) -> Result<Ipv4Start, IpTreeLookupError> {
        let mut node = 0_u32;
        for depth in 1..=96_u8 {
            let record = self.read_record(node as usize, 0)?;
            if record == self.node_count {
                return Ok(Ipv4Start::NotFound);
            }
            if record < self.node_count {
                node = record;
                continue;
            }

            return Ok(Ipv4Start::Data(IpLookup {
                data_offset: self.calculate_data_offset(record)?,
                prefix_len: depth.saturating_sub(96),
            }));
        }
        Ok(Ipv4Start::Node(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        node_count: u32,
        record_size: RecordSize,
        ip_version: IpVersion,
        data: &[u8],
    ) -> IpTree<'_> {
        IpTree::new(data, node_count, record_size, ip_version)
    }

    #[test]
    fn reads_every_record_width() {
        let bits24 = [0x00, 0x00, 0x01, 0x00, 0x00, 0x02];
        assert_eq!(
            header(1, RecordSize::Bits24, IpVersion::V4, &bits24)
                .read_record(0, 1)
                .unwrap(),
            2
        );

        let bits28 = [0x00, 0x00, 0x01, 0x12, 0x00, 0x00, 0x02];
        let tree = header(1, RecordSize::Bits28, IpVersion::V4, &bits28);
        assert_eq!(tree.read_record(0, 0).unwrap(), 0x0100_0001);
        assert_eq!(tree.read_record(0, 1).unwrap(), 0x0200_0002);

        let bits32 = [0x01, 0x02, 0x03, 0x04, 0xa0, 0xb0, 0xc0, 0xd0];
        assert_eq!(
            header(1, RecordSize::Bits32, IpVersion::V4, &bits32)
                .read_record(0, 1)
                .unwrap(),
            0xa0b0_c0d0
        );
    }

    #[test]
    fn truncated_nodes_fail_safely_for_every_width() {
        for record_size in [RecordSize::Bits24, RecordSize::Bits28, RecordSize::Bits32] {
            let data = vec![0; record_size.node_bytes() - 1];
            assert!(header(1, record_size, IpVersion::V4, &data)
                .lookup_v4(Ipv4Addr::LOCALHOST)
                .is_err());
        }
    }

    #[test]
    fn ipv4_lookup_stops_when_ipv6_tree_has_no_ipv4_subtree() {
        let data = [0, 0, 1, 0, 0, 17];
        let tree = header(1, RecordSize::Bits24, IpVersion::V6, &data);
        assert_eq!(tree.lookup_v4(Ipv4Addr::new(192, 0, 2, 1)).unwrap(), None);
    }

    #[test]
    fn ipv4_lookup_returns_data_before_ipv4_subtree() {
        let data = [0, 0, 17, 0, 0, 1];
        let tree = header(1, RecordSize::Bits24, IpVersion::V6, &data);
        assert_eq!(
            tree.lookup_v4(Ipv4Addr::new(203, 0, 113, 7)).unwrap(),
            Some(IpLookup {
                data_offset: 0,
                prefix_len: 0,
            })
        );
    }

    #[test]
    fn ipv6_lookup_in_ipv4_tree_is_not_found() {
        let data = [0, 0, 17, 0, 0, 17];
        let tree = header(1, RecordSize::Bits24, IpVersion::V4, &data);
        assert_eq!(tree.lookup_v6(Ipv6Addr::LOCALHOST).unwrap(), None);
    }
}
