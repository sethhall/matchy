//! MMDB search-tree compatibility wrapper.
//!
//! Binary traversal is owned by `matchy-ip-trie`; this module only adapts
//! parsed MMDB metadata to that crate's bounded borrowed view.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use matchy_ip_trie::IpLookup as LookupResult;
use matchy_ip_trie::IpTree;

use super::format::MmdbHeader;
use super::types::MmdbError;

/// Search tree for IP address lookups in an MMDB file.
pub struct SearchTree<'a> {
    tree: IpTree<'a>,
}

impl<'a> SearchTree<'a> {
    /// Create a borrowed search-tree view.
    #[must_use]
    pub fn new(data: &'a [u8], header: &MmdbHeader) -> Self {
        let tree_len = header.tree_size.min(data.len());
        Self {
            tree: IpTree::new(
                &data[..tree_len],
                header.node_count,
                header.record_size,
                header.ip_version,
            ),
        }
    }

    /// Look up an IP address.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<LookupResult>, MmdbError> {
        self.tree
            .lookup(ip)
            .map_err(|error| map_lookup_error(&error))
    }

    /// Look up an IPv4 address.
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> Result<Option<LookupResult>, MmdbError> {
        self.tree
            .lookup_v4(addr)
            .map_err(|error| map_lookup_error(&error))
    }

    /// Look up an IPv6 address.
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> Result<Option<LookupResult>, MmdbError> {
        self.tree
            .lookup_v6(addr)
            .map_err(|error| map_lookup_error(&error))
    }
}

fn map_lookup_error(error: &matchy_ip_trie::IpTreeLookupError) -> MmdbError {
    MmdbError::InvalidFormat(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmdb::types::{IpVersion, RecordSize};

    #[test]
    fn ipv4_lookup_stops_when_ipv6_tree_has_no_ipv4_subtree() {
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
    fn ipv4_lookup_returns_data_reached_before_ipv4_subtree() {
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
    fn ipv6_lookup_in_ipv4_database_is_not_found() {
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
    fn lookup_rejects_actual_buffer_truncation_for_every_width() {
        for (record_size, node_bytes) in [
            (RecordSize::Bits24, 6),
            (RecordSize::Bits28, 7),
            (RecordSize::Bits32, 8),
        ] {
            let data = vec![0; node_bytes - 1];
            let header = MmdbHeader {
                node_count: 1,
                record_size,
                ip_version: IpVersion::V4,
                tree_size: node_bytes,
            };
            let tree = SearchTree::new(&data, &header);

            assert!(
                tree.lookup_v4(Ipv4Addr::LOCALHOST).is_err(),
                "{record_size:?} reader trusted declared size over actual bytes"
            );
        }
    }

    #[test]
    fn lookup_with_real_database() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let header = MmdbHeader::from_file(data).unwrap();
        let tree = SearchTree::new(data, &header);

        for ip in [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)] {
            let result = tree.lookup_v4(ip).unwrap();
            assert!(result.is_some(), "should find data for {ip}");
            let result = result.unwrap();
            assert!(result.data_offset > 0);
            assert!((1..=32).contains(&result.prefix_len));
        }
    }
}
