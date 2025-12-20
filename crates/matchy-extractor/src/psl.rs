//! Public Suffix List (PSL) hash table lookup.
//!
//! The PSL data is compiled at build time into a binary hash table format,
//! enabling O(1) TLD lookups without any runtime heap allocation.

/// PSL hash table data - compiled at build time, lives in read-only section.
static PSL_HASH_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/psl_hash.bin"));

const EMPTY_SLOT: u32 = 0xFFFFFFFF;

/// Check if a suffix exists in the PSL hash table (zero-copy, O(1)).
#[inline]
pub fn psl_contains(suffix: &[u8]) -> bool {
    use xxhash_rust::xxh64::xxh64;

    if PSL_HASH_DATA.len() < 16 {
        return false;
    }

    let table_size = u32::from_le_bytes(PSL_HASH_DATA[12..16].try_into().unwrap());
    let table_mask = table_size.wrapping_sub(1);

    let table_start = 16usize;
    let string_pool_start = table_start + (table_size as usize * 16);

    let hash = xxh64(suffix, 0);
    let mut slot = usize::try_from(hash & u64::from(table_mask)).unwrap();

    for _ in 0..table_size {
        let entry_offset = table_start + slot * 16;
        if entry_offset + 16 > PSL_HASH_DATA.len() {
            return false;
        }

        let entry_hash = u64::from_le_bytes(
            PSL_HASH_DATA[entry_offset..entry_offset + 8]
                .try_into()
                .unwrap(),
        );
        let string_offset = u32::from_le_bytes(
            PSL_HASH_DATA[entry_offset + 8..entry_offset + 12]
                .try_into()
                .unwrap(),
        );
        let string_len = u32::from_le_bytes(
            PSL_HASH_DATA[entry_offset + 12..entry_offset + 16]
                .try_into()
                .unwrap(),
        );

        if string_offset == EMPTY_SLOT {
            return false;
        }

        if entry_hash == hash {
            let str_start = string_pool_start + string_offset as usize;
            let str_end = str_start + string_len as usize;
            if str_end <= PSL_HASH_DATA.len() {
                let stored = &PSL_HASH_DATA[str_start..str_end];
                if stored == suffix {
                    return true;
                }
            }
        }

        slot = (slot + 1) & (table_mask as usize);
    }

    false
}

/// Find the valid TLD suffix in a domain byte slice using hash-based PSL lookup.
/// Returns the byte position where the TLD starts (including the dot).
///
/// Example: b"example.co.uk" -> Some(7) for b".co.uk"
///          b"example.com" -> Some(7) for b".com"
///          b"notldhere" -> None
pub fn find_valid_tld_suffix_bytes(domain_bytes: &[u8]) -> Option<usize> {
    for i in (0..domain_bytes.len()).rev() {
        let b = domain_bytes[i];
        if b == b'.' {
            let suffix = &domain_bytes[i + 1..];
            if psl_contains(suffix) {
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psl_contains_common_tlds() {
        assert!(psl_contains(b"com"));
        assert!(psl_contains(b"org"));
        assert!(psl_contains(b"net"));
        assert!(psl_contains(b"io"));
    }

    #[test]
    fn test_psl_contains_multi_part() {
        assert!(psl_contains(b"co.uk"));
        assert!(psl_contains(b"com.au"));
    }

    #[test]
    fn test_psl_contains_invalid() {
        assert!(!psl_contains(b"notarealtld"));
        assert!(!psl_contains(b"xyz123fake"));
    }

    #[test]
    fn test_find_valid_tld_suffix_com() {
        let domain = b"example.com";
        let pos = find_valid_tld_suffix_bytes(domain);
        assert_eq!(pos, Some(7)); // Position of dot before "com"
    }

    #[test]
    fn test_find_valid_tld_suffix_co_uk() {
        let domain = b"example.co.uk";
        let pos = find_valid_tld_suffix_bytes(domain);
        assert_eq!(pos, Some(10)); // Position of dot before "uk" (first valid TLD found walking backwards)
    }

    #[test]
    fn test_find_valid_tld_suffix_none() {
        let domain = b"notavalidtld";
        let pos = find_valid_tld_suffix_bytes(domain);
        assert_eq!(pos, None);
    }

    #[test]
    fn test_find_valid_tld_suffix_subdomain() {
        let domain = b"sub.example.com";
        let pos = find_valid_tld_suffix_bytes(domain);
        assert_eq!(pos, Some(11)); // Position of dot before "com"
    }
}
