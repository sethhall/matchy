//! Utility functions and lookup tables for fast character classification.

/// Compile-time boundary character lookup table for O(1) checking.
/// Marked as boundary: whitespace, punctuation commonly found in logs.
pub static BOUNDARY_LOOKUP: [bool; 256] = {
    let mut table = [false; 256];
    // Whitespace characters
    table[b' ' as usize] = true;
    table[b'\t' as usize] = true;
    table[b'\n' as usize] = true;
    table[b'\r' as usize] = true;
    // Punctuation and delimiters
    table[b'/' as usize] = true;
    table[b',' as usize] = true;
    table[b';' as usize] = true;
    table[b':' as usize] = true;
    table[b'(' as usize] = true;
    table[b')' as usize] = true;
    table[b'[' as usize] = true;
    table[b']' as usize] = true;
    table[b'{' as usize] = true;
    table[b'}' as usize] = true;
    table[b'<' as usize] = true;
    table[b'>' as usize] = true;
    table[b'"' as usize] = true;
    table[b'\'' as usize] = true;
    table[b'@' as usize] = true;
    table[b'=' as usize] = true;
    table
};

/// Domain character whitelist - alphanumeric, hyphen, dot, and high UTF-8 bytes.
pub static DOMAIN_CHAR_LOOKUP: [bool; 256] = {
    let mut table = [false; 256];
    // Digits: 0-9
    let mut i = b'0';
    while i <= b'9' {
        table[i as usize] = true;
        i += 1;
    }
    // Lowercase: a-z
    i = b'a';
    while i <= b'z' {
        table[i as usize] = true;
        i += 1;
    }
    // Uppercase: A-Z
    i = b'A';
    while i <= b'Z' {
        table[i as usize] = true;
        i += 1;
    }
    // Special chars
    table[b'-' as usize] = true;
    table[b'.' as usize] = true;

    // High bytes (0x80-0xFF) for IDN domains (UTF-8 continuation bytes)
    i = 0x80;
    while i < 0xFF {
        table[i as usize] = true;
        i += 1;
    }
    table[0xFF] = true;
    table
};

/// Hex character lookup table for hash validation. Valid: 0-9, a-f, A-F.
pub static HEX_CHAR_LOOKUP: [bool; 256] = {
    let mut table = [false; 256];
    // Digits 0-9
    let mut i = b'0';
    while i <= b'9' {
        table[i as usize] = true;
        i += 1;
    }
    // Lowercase a-f
    i = b'a';
    while i <= b'f' {
        table[i as usize] = true;
        i += 1;
    }
    // Uppercase A-F
    i = b'A';
    while i <= b'F' {
        table[i as usize] = true;
        i += 1;
    }
    table
};

/// Fast boundary check using lookup table (branch-free, O(1)).
#[inline(always)]
pub fn is_boundary_fast(b: u8) -> bool {
    BOUNDARY_LOOKUP[b as usize]
}

/// Character classification for domain names.
#[inline]
pub fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}

/// Fast domain character check using lookup table (branch-free, O(1)).
#[inline(always)]
pub fn is_domain_char_fast(b: u8) -> bool {
    DOMAIN_CHAR_LOOKUP[b as usize]
}

/// Character classification for email local part (simplified RFC 5322).
#[inline]
pub fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+')
}

/// Word boundary check (delegates to lookup table).
#[inline]
pub fn is_word_boundary(b: u8) -> bool {
    is_boundary_fast(b)
}

/// Fast hex character check using lookup table (branch-free, O(1)).
#[inline(always)]
pub fn is_hex_char_fast(b: u8) -> bool {
    HEX_CHAR_LOOKUP[b as usize]
}

/// SIMD-friendly hex validation using lookup table.
/// Returns true if ALL bytes are valid hex [0-9a-fA-F].
/// LLVM auto-vectorizes this into SIMD operations.
#[inline]
pub fn is_all_hex_simd(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| is_hex_char_fast(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_lookup() {
        assert!(is_boundary_fast(b' '));
        assert!(is_boundary_fast(b'\t'));
        assert!(is_boundary_fast(b'\n'));
        assert!(is_boundary_fast(b','));
        assert!(is_boundary_fast(b'@'));
        assert!(!is_boundary_fast(b'a'));
        assert!(!is_boundary_fast(b'0'));
    }

    #[test]
    fn test_domain_char() {
        assert!(is_domain_char(b'a'));
        assert!(is_domain_char(b'Z'));
        assert!(is_domain_char(b'0'));
        assert!(is_domain_char(b'-'));
        assert!(is_domain_char(b'.'));
        assert!(!is_domain_char(b'@'));
        assert!(!is_domain_char(b' '));
    }

    #[test]
    fn test_domain_char_fast() {
        assert!(is_domain_char_fast(b'a'));
        assert!(is_domain_char_fast(b'Z'));
        assert!(is_domain_char_fast(b'0'));
        assert!(is_domain_char_fast(b'-'));
        assert!(is_domain_char_fast(b'.'));
        assert!(is_domain_char_fast(0x80)); // UTF-8 continuation
        assert!(!is_domain_char_fast(b'@'));
        assert!(!is_domain_char_fast(b' '));
    }

    #[test]
    fn test_email_local_char() {
        assert!(is_email_local_char(b'a'));
        assert!(is_email_local_char(b'0'));
        assert!(is_email_local_char(b'.'));
        assert!(is_email_local_char(b'-'));
        assert!(is_email_local_char(b'_'));
        assert!(is_email_local_char(b'+'));
        assert!(!is_email_local_char(b'@'));
        assert!(!is_email_local_char(b' '));
    }

    #[test]
    fn test_hex_char() {
        assert!(is_hex_char_fast(b'0'));
        assert!(is_hex_char_fast(b'9'));
        assert!(is_hex_char_fast(b'a'));
        assert!(is_hex_char_fast(b'f'));
        assert!(is_hex_char_fast(b'A'));
        assert!(is_hex_char_fast(b'F'));
        assert!(!is_hex_char_fast(b'g'));
        assert!(!is_hex_char_fast(b'G'));
        assert!(!is_hex_char_fast(b' '));
    }

    #[test]
    fn test_is_all_hex_simd() {
        assert!(is_all_hex_simd(b"0123456789abcdef"));
        assert!(is_all_hex_simd(b"ABCDEF"));
        assert!(is_all_hex_simd(b"aAbBcC"));
        assert!(!is_all_hex_simd(b"0123456789abcdefg"));
        assert!(!is_all_hex_simd(b"hello"));
    }
}
