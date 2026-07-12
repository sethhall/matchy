//! Fast extraction of structured patterns from log lines and text data.
//!
//! This module provides high-speed extraction of domains, IP addresses (IPv4/IPv6),
//! emails, file hashes, and cryptocurrency addresses from arbitrary text.

mod error;
mod extractors;
mod finders;
mod iter;
mod psl;
mod types;
mod util;

pub use error::ExtractorError;
pub use iter::ExtractIter;
pub use types::{ExtractedItem, HashType, Match};

use extractors::{
    BitcoinExtractor, DomainExtractor, EmailExtractor, EthereumExtractor, ExtractorKind,
    HashExtractor, Ipv4Extractor, Ipv6Extractor, MoneroExtractor,
};
use finders::FinderResults;

#[derive(Clone, Copy)]
struct ExtractorConfig {
    extract_domains: bool,
    extract_emails: bool,
    extract_ipv4: bool,
    extract_ipv6: bool,
    extract_hashes: bool,
    extract_bitcoin: bool,
    extract_ethereum: bool,
    extract_monero: bool,
    min_domain_labels: usize,
    require_word_boundaries: bool,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            extract_domains: true,
            extract_emails: true,
            extract_ipv4: true,
            extract_ipv6: true,
            extract_hashes: true,
            extract_bitcoin: true,
            extract_ethereum: true,
            extract_monero: true,
            min_domain_labels: 2,
            require_word_boundaries: true,
        }
    }
}

/// Configures which indicator types an [`Extractor`] recognizes.
///
/// By default, all supported indicator types are enabled, domains require at
/// least two labels, and extractors enforce word boundaries where applicable.
pub struct ExtractorBuilder {
    config: ExtractorConfig,
}

impl ExtractorBuilder {
    /// Creates a builder with all supported indicator types enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ExtractorConfig::default(),
        }
    }

    /// Enables or disables domain extraction.
    #[must_use]
    pub fn extract_domains(mut self, enable: bool) -> Self {
        self.config.extract_domains = enable;
        self
    }

    /// Enables or disables email extraction.
    #[must_use]
    pub fn extract_emails(mut self, enable: bool) -> Self {
        self.config.extract_emails = enable;
        self
    }

    /// Enables or disables IPv4 extraction.
    #[must_use]
    pub fn extract_ipv4(mut self, enable: bool) -> Self {
        self.config.extract_ipv4 = enable;
        self
    }

    /// Enables or disables IPv6 extraction.
    #[must_use]
    pub fn extract_ipv6(mut self, enable: bool) -> Self {
        self.config.extract_ipv6 = enable;
        self
    }

    /// Enables or disables file-hash extraction.
    #[must_use]
    pub fn extract_hashes(mut self, enable: bool) -> Self {
        self.config.extract_hashes = enable;
        self
    }

    /// Enables or disables Bitcoin address extraction.
    #[must_use]
    pub fn extract_bitcoin(mut self, enable: bool) -> Self {
        self.config.extract_bitcoin = enable;
        self
    }

    /// Enables or disables Ethereum address extraction.
    #[must_use]
    pub fn extract_ethereum(mut self, enable: bool) -> Self {
        self.config.extract_ethereum = enable;
        self
    }

    /// Enables or disables Monero address extraction.
    #[must_use]
    pub fn extract_monero(mut self, enable: bool) -> Self {
        self.config.extract_monero = enable;
        self
    }

    /// Sets the minimum number of labels required for extracted domains.
    #[must_use]
    pub fn min_domain_labels(mut self, min: usize) -> Self {
        self.config.min_domain_labels = min;
        self
    }

    /// Controls whether applicable extractors require surrounding word boundaries.
    #[must_use]
    pub fn require_word_boundaries(mut self, require: bool) -> Self {
        self.config.require_word_boundaries = require;
        self
    }

    /// Builds an extractor with this configuration.
    pub fn build(self) -> Result<Extractor, ExtractorError> {
        let config = self.config;
        let mut enabled = Vec::new();

        if config.extract_domains {
            enabled.push(ExtractorKind::Domain(DomainExtractor::new(
                config.min_domain_labels,
                config.require_word_boundaries,
            )));
        }

        if config.extract_ipv4 {
            enabled.push(ExtractorKind::Ipv4(Ipv4Extractor::new(
                config.require_word_boundaries,
            )));
        }

        if config.extract_ipv6 {
            enabled.push(ExtractorKind::Ipv6(Box::<Ipv6Extractor>::default()));
        }

        if config.extract_emails {
            enabled.push(ExtractorKind::Email(EmailExtractor::new(
                config.require_word_boundaries,
            )));
        }

        if config.extract_hashes {
            enabled.push(ExtractorKind::Hash(HashExtractor::new()));
        }

        if config.extract_bitcoin {
            enabled.push(ExtractorKind::Bitcoin(BitcoinExtractor::new()));
        }

        if config.extract_ethereum {
            enabled.push(ExtractorKind::Ethereum(EthereumExtractor::new(
                config.require_word_boundaries,
            )));
        }

        if config.extract_monero {
            enabled.push(ExtractorKind::Monero(MoneroExtractor::new()));
        }

        Ok(Extractor { config, enabled })
    }
}

impl Default for ExtractorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts structured indicators from byte slices.
pub struct Extractor {
    config: ExtractorConfig,
    enabled: Vec<ExtractorKind>,
}

impl Extractor {
    /// Creates an extractor with the default configuration.
    pub fn new() -> Result<Self, ExtractorError> {
        Self::builder().build()
    }

    /// Creates a builder for configuring an extractor.
    #[must_use]
    pub fn builder() -> ExtractorBuilder {
        ExtractorBuilder::new()
    }

    /// Extracts indicators from one line.
    ///
    /// Extraction is performed eagerly when the returned iterator is created.
    #[must_use]
    pub fn extract_from_line<'a>(&'a self, line: &'a [u8]) -> ExtractIter<'a> {
        ExtractIter::new(&self.enabled, line)
    }

    /// Extracts all indicators from a byte slice.
    #[must_use]
    pub fn extract_from_chunk<'a>(&'a self, chunk: &'a [u8]) -> Vec<Match<'a>> {
        extract_matches(&self.enabled, chunk)
    }

    /// Returns whether domain extraction is enabled.
    #[must_use]
    pub fn extract_domains(&self) -> bool {
        self.config.extract_domains
    }

    /// Returns whether email extraction is enabled.
    #[must_use]
    pub fn extract_emails(&self) -> bool {
        self.config.extract_emails
    }

    /// Returns whether IPv4 extraction is enabled.
    #[must_use]
    pub fn extract_ipv4(&self) -> bool {
        self.config.extract_ipv4
    }

    /// Returns whether IPv6 extraction is enabled.
    #[must_use]
    pub fn extract_ipv6(&self) -> bool {
        self.config.extract_ipv6
    }

    /// Returns whether file-hash extraction is enabled.
    #[must_use]
    pub fn extract_hashes(&self) -> bool {
        self.config.extract_hashes
    }

    /// Returns whether Bitcoin address extraction is enabled.
    #[must_use]
    pub fn extract_bitcoin(&self) -> bool {
        self.config.extract_bitcoin
    }

    /// Returns whether Ethereum address extraction is enabled.
    #[must_use]
    pub fn extract_ethereum(&self) -> bool {
        self.config.extract_ethereum
    }

    /// Returns whether Monero address extraction is enabled.
    #[must_use]
    pub fn extract_monero(&self) -> bool {
        self.config.extract_monero
    }

    /// Returns the minimum label count required for extracted domains.
    #[must_use]
    pub fn min_domain_labels(&self) -> usize {
        self.config.min_domain_labels
    }
}

fn extract_matches<'a>(extractors: &[ExtractorKind], input: &'a [u8]) -> Vec<Match<'a>> {
    let mut results = FinderResults::new(input);

    for extractor in extractors {
        for finder in extractor.required_finders() {
            results.ensure(*finder);
        }
    }

    let mut matches = Vec::new();
    for extractor in extractors {
        extractor.extract(&results, &mut matches);
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_extractor_creation() {
        let extractor = Extractor::new().unwrap();
        assert!(extractor.extract_domains());
    }

    #[test]
    fn test_concurrent_extraction() {
        use std::sync::Arc;
        use std::thread;

        let extractor = Arc::new(Extractor::new().unwrap());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let ext = Arc::clone(&extractor);
                thread::spawn(move || {
                    let data = b"Check test@example.com and 192.168.1.1 and malware.evil.com";
                    let results = ext.extract_from_chunk(data);

                    assert!(results.len() >= 3, "Expected at least 3 matches");

                    let has_email = results
                        .iter()
                        .any(|m| matches!(m.item, ExtractedItem::Email(_)));
                    let has_ipv4 = results
                        .iter()
                        .any(|m| matches!(m.item, ExtractedItem::Ipv4(_)));
                    let has_domain = results
                        .iter()
                        .any(|m| matches!(m.item, ExtractedItem::Domain(_)));

                    assert!(has_email, "Should extract email");
                    assert!(has_ipv4, "Should extract IPv4");
                    assert!(has_domain, "Should extract domain");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_extracted_item_type_name() {
        let extractor = Extractor::new().unwrap();

        let line = b"Check example.com user@test.com 192.168.1.1 2001:db8::1 5d41402abc4b2a76b9719d911017c592";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        for m in &matches {
            let type_name = m.item.type_name();
            match &m.item {
                ExtractedItem::Domain(_) => assert_eq!(type_name, "Domain"),
                ExtractedItem::Email(_) => assert_eq!(type_name, "Email"),
                ExtractedItem::Ipv4(_) => assert_eq!(type_name, "IPv4"),
                ExtractedItem::Ipv6(_) => assert_eq!(type_name, "IPv6"),
                ExtractedItem::Hash(HashType::Md5, _) => assert_eq!(type_name, "MD5"),
                ExtractedItem::Hash(HashType::Sha1, _) => assert_eq!(type_name, "SHA1"),
                ExtractedItem::Hash(HashType::Sha256, _) => assert_eq!(type_name, "SHA256"),
                ExtractedItem::Hash(HashType::Sha384, _) => assert_eq!(type_name, "SHA384"),
                ExtractedItem::Hash(HashType::Sha512, _) => assert_eq!(type_name, "SHA512"),
                ExtractedItem::Bitcoin(_) => assert_eq!(type_name, "Bitcoin"),
                ExtractedItem::Ethereum(_) => assert_eq!(type_name, "Ethereum"),
                ExtractedItem::Monero(_) => assert_eq!(type_name, "Monero"),
            }
        }
    }

    #[test]
    fn test_extracted_item_as_value() {
        let extractor = Extractor::new().unwrap();

        let line = b"Check example.com and 192.168.1.1";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert!(matches.len() >= 2);

        let domain_match = matches
            .iter()
            .find(|m| matches!(m.item, ExtractedItem::Domain(_)));
        assert!(domain_match.is_some());
        assert_eq!(domain_match.unwrap().item.as_value(), "example.com");

        let ip_match = matches
            .iter()
            .find(|m| matches!(m.item, ExtractedItem::Ipv4(_)));
        assert!(ip_match.is_some());
        assert_eq!(ip_match.unwrap().item.as_value(), "192.168.1.1");
    }

    #[test]
    fn test_hash_type_name() {
        assert_eq!(HashType::Md5.type_name(), "MD5");
        assert_eq!(HashType::Sha1.type_name(), "SHA1");
        assert_eq!(HashType::Sha256.type_name(), "SHA256");
        assert_eq!(HashType::Sha384.type_name(), "SHA384");
        assert_eq!(HashType::Sha512.type_name(), "SHA512");
    }

    #[test]
    fn test_sha512_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"SHA512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e found";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<_> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(HashType::Sha512, h) => Some(h),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1, "Should extract SHA512 hash");
        assert_eq!(
            hashes[0],
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_builder() {
        let extractor = Extractor::builder()
            .extract_domains(true)
            .extract_emails(false)
            .min_domain_labels(3)
            .build()
            .unwrap();

        assert!(extractor.extract_domains());
        assert!(!extractor.extract_emails());
        assert_eq!(extractor.min_domain_labels(), 3);
    }

    #[test]
    fn test_character_classification() {
        use crate::util::{is_domain_char, is_email_local_char, is_word_boundary};

        assert!(is_domain_char(b'a'));
        assert!(is_domain_char(b'0'));
        assert!(is_domain_char(b'-'));
        assert!(is_domain_char(b'.'));
        assert!(!is_domain_char(b'@'));
        assert!(!is_domain_char(b' '));

        assert!(is_email_local_char(b'a'));
        assert!(is_email_local_char(b'+'));
        assert!(!is_email_local_char(b'@'));

        assert!(is_word_boundary(b' '));
        assert!(is_word_boundary(b','));
        assert!(!is_word_boundary(b'a'));
    }

    #[test]
    fn test_domain_extraction_basic() {
        let extractor = Extractor::new().unwrap();

        let line = b"Visit example.com for more info";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "example.com");
        match matches[0].item {
            ExtractedItem::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("Expected domain"),
        }
    }

    #[test]
    fn test_domain_extraction_multiple() {
        let extractor = Extractor::new().unwrap();

        let line = b"Check google.com and github.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].as_str(line), "google.com");
        assert_eq!(matches[1].as_str(line), "github.com");
    }

    #[test]
    fn test_domain_extraction_subdomain() {
        let extractor = Extractor::new().unwrap();

        let line = b"Visit api.example.com today";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "api.example.com");
    }

    #[test]
    fn test_domain_extraction_with_protocol() {
        let extractor = Extractor::new().unwrap();

        let line = b"Go to https://www.example.com/path";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "www.example.com");
    }

    #[test]
    fn test_domain_min_labels() {
        let extractor = Extractor::builder()
            .extract_domains(true)
            .min_domain_labels(3)
            .build()
            .unwrap();

        let line = b"Visit example.com and api.test.example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "api.test.example.com");
    }

    #[test]
    fn test_domain_extraction_log_line() {
        let extractor = Extractor::new().unwrap();

        let line =
            b"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - malware.badsite.org";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert!(matches.len() >= 2);
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(domains.contains(&"evil.example.com"));
        assert!(domains.contains(&"malware.badsite.org"));
    }

    #[test]
    fn test_ipv4_extraction_basic() {
        let extractor = Extractor::new().unwrap();

        let line = b"Server at 192.168.1.1 responded";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ipv4_extraction_multiple() {
        let extractor = Extractor::new().unwrap();

        let line = b"Traffic from 10.0.0.5 to 172.16.0.10";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.0.0.5");
        assert_eq!(ips[1].to_string(), "172.16.0.10");
    }

    #[test]
    fn test_ipv4_invalid() {
        let extractor = Extractor::new().unwrap();

        let line = b"Not IPs: 256.1.1.1 1.2.3.999 1.2.3";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn test_mixed_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"Request from 10.1.2.3 to api.example.com at 192.168.1.100";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "api.example.com");
    }

    #[test]
    fn test_email_extraction_basic() {
        let extractor = Extractor::new().unwrap();

        let line = b"Contact user@example.com for info";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "user@example.com");
    }

    #[test]
    fn test_email_extraction_multiple() {
        let extractor = Extractor::new().unwrap();

        let line = b"Email alice@test.com or bob@company.org";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0], "alice@test.com");
        assert_eq!(emails[1], "bob@company.org");
    }

    #[test]
    fn test_email_with_plus() {
        let extractor = Extractor::new().unwrap();

        let line = b"Send to user+tag@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "user+tag@example.com");
    }

    #[test]
    fn test_full_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"2024-01-15 user@example.com from 10.1.2.3 accessed api.test.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(ips.len(), 1);
        assert_eq!(domains.len(), 2);

        assert_eq!(emails[0], "user@example.com");
        assert_eq!(ips[0].to_string(), "10.1.2.3");
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"api.test.com"));
    }

    #[test]
    fn test_ipv6_extraction_basic() {
        let extractor = Extractor::new().unwrap();

        let line = b"Server at 2001:db8:85a3::8a2e:370:7334 responded";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_ipv6_extraction_compressed() {
        let extractor = Extractor::new().unwrap();

        let line = b"Connecting to 2001:db8::1";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
    }

    #[test]
    fn test_ipv6_extraction_multiple() {
        let extractor = Extractor::new().unwrap();

        let line = b"Traffic from 2001:db8::1 to 2001:db8::2";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
        assert_eq!(ips[1].to_string(), "2001:db8::2");
    }

    #[test]
    fn test_mixed_ipv4_ipv6_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"IPv4: 192.168.1.1 IPv6: 2001:db8::1";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ipv4s: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let ipv6s: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ipv4s.len(), 1);
        assert_eq!(ipv6s.len(), 1);
        assert_eq!(ipv4s[0].to_string(), "192.168.1.1");
        assert_eq!(ipv6s[0].to_string(), "2001:db8::1");
    }

    #[test]
    fn test_hash_extraction_md5() {
        let extractor = Extractor::new().unwrap();

        let line = b"File hash: 5d41402abc4b2a76b9719d911017c592 uploaded";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].1, HashType::Md5);
        assert_eq!(hashes[0].0, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_hash_extraction_sha1() {
        let extractor = Extractor::new().unwrap();

        let line = b"SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 verified";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].1, HashType::Sha1);
        assert_eq!(hashes[0].0, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }

    #[test]
    fn test_hash_extraction_sha256() {
        let extractor = Extractor::new().unwrap();

        let line =
            b"SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae detected";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].1, HashType::Sha256);
    }

    #[test]
    fn test_hash_builder_disable() {
        let extractor = Extractor::builder().extract_hashes(false).build().unwrap();

        assert!(!extractor.extract_hashes());

        let line = b"Hash: 5d41402abc4b2a76b9719d911017c592 should not extract";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 0, "Should not extract when disabled");
    }

    #[test]
    fn test_bitcoin_legacy_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for payment";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let btc: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Bitcoin(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(btc.len(), 1);
        assert_eq!(btc[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_bitcoin_bech32_extraction() {
        let extractor = Extractor::new().unwrap();

        let line = b"Withdraw to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let btc: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Bitcoin(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(btc.len(), 1);
        assert_eq!(btc[0], "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    }

    #[test]
    fn test_ethereum_extraction_lowercase() {
        let extractor = Extractor::new().unwrap();

        let line = b"Transfer to 0x5aeda56215b167893e80b4fe645ba6d5bab767de";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let eth: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ethereum(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(eth.len(), 1);
        assert_eq!(eth[0], "0x5aeda56215b167893e80b4fe645ba6d5bab767de");
    }

    #[test]
    fn test_crypto_builder_disable() {
        let extractor = Extractor::builder()
            .extract_bitcoin(false)
            .extract_ethereum(false)
            .extract_monero(false)
            .build()
            .unwrap();

        assert!(!extractor.extract_bitcoin());
        assert!(!extractor.extract_ethereum());
        assert!(!extractor.extract_monero());

        let line = b"Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 0x5aeda56215b167893e80b4fe645ba6d5bab767de";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let crypto: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Bitcoin(addr)
                | ExtractedItem::Ethereum(addr)
                | ExtractedItem::Monero(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(crypto.len(), 0, "Should not extract when disabled");
    }

    #[test]
    fn test_binary_log_with_ascii_domain() {
        let extractor = Extractor::new().unwrap();

        // Binary log line with non-UTF-8 bytes but ASCII domain
        let mut line = Vec::new();
        line.extend_from_slice(b"Log: ");
        line.push(0xFF); // Invalid UTF-8 byte
        line.push(0xFE); // Invalid UTF-8 byte
        line.extend_from_slice(b" evil.com ");
        line.push(0x80); // Invalid UTF-8 byte

        let matches: Vec<_> = extractor.extract_from_line(&line).collect();

        // Should still extract ASCII domain despite binary junk
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(
            domains.contains(&"evil.com"),
            "Should extract ASCII domain from binary log"
        );
    }

    #[test]
    fn test_invalid_utf8_in_domain_rejected() {
        let extractor = Extractor::new().unwrap();

        // Line with invalid UTF-8 sequence where domain would be
        let mut line = Vec::new();
        line.extend_from_slice(b"Visit ");
        line.push(0xFF); // Invalid UTF-8
        line.push(0xC0); // Invalid UTF-8
        line.extend_from_slice(b".com");

        let matches: Vec<_> = extractor.extract_from_line(&line).collect();

        // Should NOT extract domain with invalid UTF-8
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(
            domains.is_empty(),
            "Should not extract domain with invalid UTF-8 prefix"
        );
    }

    #[test]
    fn test_bitcoin_chunk_extraction() {
        let extractor = Extractor::new().unwrap();

        let chunk = b"Line1: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nLine2: 3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64\n";
        let matches = extractor.extract_from_chunk(chunk);

        let btc: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Bitcoin(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(btc.len(), 2);
        assert!(btc.contains(&"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(btc.contains(&"3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64"));
    }

    #[test]
    fn test_crypto_mixed_with_other_types() {
        let extractor = Extractor::new().unwrap();

        // Line with IP, domain, and crypto addresses
        let line = b"Transaction from 192.168.1.1 to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq via example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        let btc: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Bitcoin(addr) => Some(addr),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
        assert!(domains.contains(&"example.com"));
        assert_eq!(btc.len(), 1);
        assert_eq!(btc[0], "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    }

    #[test]
    fn test_hash_chunk_extraction() {
        let extractor = Extractor::new().unwrap();

        let chunk = b"Line1: 5d41402abc4b2a76b9719d911017c592\nLine2: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n";
        let matches = extractor.extract_from_chunk(chunk);

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].1, HashType::Md5);
        assert_eq!(hashes[1].1, HashType::Sha1);
    }

    #[test]
    fn test_hash_extraction_mixed_case() {
        let extractor = Extractor::new().unwrap();

        let line = b"Hash: 5d41402AbC4b2A76b9719D911017c592 mixed";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, "5d41402AbC4b2A76b9719D911017c592");
    }

    #[test]
    fn test_hash_realistic_log_line() {
        let extractor = Extractor::new().unwrap();

        let line = b"2024-01-15 malware.exe MD5=5d41402abc4b2a76b9719d911017c592 detected from 192.168.1.100";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract both hash and IP
        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].1, HashType::Md5);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.100");
    }

    #[test]
    fn test_hash_reject_uuid() {
        let extractor = Extractor::new().unwrap();

        // UUID format: 550e8400-e29b-41d4-a716-446655440000 (36 chars with dashes)
        let line = b"UUID: 550e8400-e29b-41d4-a716-446655440000 not a hash";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let hashes: Vec<(&str, HashType)> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Hash(ht, h) => Some((h, ht)),
                _ => None,
            })
            .collect();

        // Should not extract - dashes break the hex sequence
        assert_eq!(hashes.len(), 0, "Should not extract UUID as hash");
    }

    #[test]
    fn test_ipv6_extraction_realistic() {
        let extractor = Extractor::new().unwrap();

        // Use realistic global unicast addresses with :: compression (not loopback/link-local)
        let line = b"Address 2001:0db8::1 connects to 2606:2800:220:1::248";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        // Should extract both global unicast addresses
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
        assert_eq!(ips[1].to_string(), "2606:2800:220:1::248");
    }

    #[test]
    fn test_mixed_unicode_ascii_domains() {
        let extractor = Extractor::new().unwrap();

        // Line with both ASCII and Unicode domains
        let line = "Check café.fr and example.com".as_bytes();
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract both domains
        assert!(matches.len() >= 2);

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // ASCII domain should be extracted normally
        assert!(domains.iter().any(|d| d.contains("example.com")));
        // Unicode domain should be extracted (either as-is or punycode)
        assert!(
            domains
                .iter()
                .any(|d| d.contains("café") || d.contains("xn--")),
            "Should extract Unicode domain"
        );
    }

    #[test]
    fn test_reject_domain_with_percent_encoding() {
        let extractor = Extractor::new().unwrap();

        // "Kagi%20Assistant.app" (% is invalid in domain chars)
        let line = b"Invalid domain: Kagi%20Assistant.app";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // Should only extract "Assistant.app" after the %20, not the full string
        assert!(
            !domains.iter().any(|d| d.contains("Kagi")),
            "Should not include Kagi in domain due to percent encoding"
        );
    }

    #[test]
    fn test_reject_ipv4_with_octet_over_255() {
        let extractor = Extractor::new().unwrap();

        // "460.1.1.2" (3 digits but >255)
        let line = b"Invalid IP: 460.1.1.2";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with octet > 255");
    }

    #[test]
    fn test_reject_ipv6_with_8_digit_segment() {
        let extractor = Extractor::new().unwrap();

        // "7::31BD71E4" (8-digit segment)
        let line = b"Invalid IPv6: 7::31BD71E4";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(
            ips.len(),
            0,
            "Should reject IPv6 with segment > 4 hex digits"
        );
    }

    #[test]
    fn test_unicode_domain_extraction() {
        let extractor = Extractor::new().unwrap();

        // German domain with umlaut (münchen.de in UTF-8)
        let line = "Visit münchen.de for info".as_bytes();
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract the Unicode domain
        assert_eq!(matches.len(), 1);
        let domain = match matches[0].item {
            ExtractedItem::Domain(d) => d,
            _ => panic!("Expected domain"),
        };

        // Domain contains UTF-8 characters
        assert!(domain.contains("ünchen") || domain.contains("xn--"));
    }

    #[test]
    fn test_accept_email_with_uuid_in_local() {
        let extractor = Extractor::new().unwrap();

        // "34480FE2-5610-4973-AA09-3ABB60D38D55@" is OK
        let line = b"Valid email: 34480FE2-5610-4973-AA09-3ABB60D38D55@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(
            emails.len(),
            1,
            "Should accept email with UUID containing letters"
        );
        assert_eq!(
            emails[0],
            "34480FE2-5610-4973-AA09-3ABB60D38D55@example.com"
        );
    }

    #[test]
    fn test_reject_email_with_consecutive_dots_in_local() {
        let extractor = Extractor::new().unwrap();

        // "s...@" (consecutive dots in local part)
        let line = b"Invalid email: s...@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(
            emails.len(),
            0,
            "Should reject email with consecutive dots in local"
        );
    }

    #[test]
    fn test_reject_email_with_fake_tld() {
        let extractor = Extractor::new().unwrap();

        // "Uv3.peer" (fake TLD)
        let line = b"Invalid email: test@Uv3.peer";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email with fake TLD");
    }

    #[test]
    fn test_reject_email_with_ip_address_domain() {
        let extractor = Extractor::new().unwrap();

        // "192.168.1.222" (IP address as domain)
        let line = b"Invalid email: user@192.168.1.222";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email with IP domain");
    }

    #[test]
    fn test_reject_email_without_letter_in_local() {
        let extractor = Extractor::new().unwrap();

        // ".@.." (no letter in local part)
        let line = b"Invalid email: .@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(
            emails.len(),
            0,
            "Should reject email without letter in local"
        );
    }

    #[test]
    fn test_reject_ipv4_with_4_and_8_digit_octets() {
        let extractor = Extractor::new().unwrap();

        // "2025.36.0.72591908" (4 and 8 digit octets)
        let line = b"Invalid IP: 2025.36.0.72591908";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with 4 and 8 digit octets");
    }

    #[test]
    fn test_reject_ipv4_with_consecutive_dots() {
        let extractor = Extractor::new().unwrap();

        // "26.0..26.0" (consecutive dots)
        let line = b"Invalid IP: 26.0..26.0";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with consecutive dots");
    }

    #[test]
    fn test_reject_ipv6_with_12_digit_segment() {
        let extractor = Extractor::new().unwrap();

        // "FEC0050519FB::c" (12-digit segment)
        let line = b"Invalid IPv6: FEC0050519FB::c";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(
            ips.len(),
            0,
            "Should reject IPv6 with segment > 4 hex digits"
        );
    }

    #[test]
    fn test_reject_link_local_ipv6() {
        let extractor = Extractor::new().unwrap();

        // fe80::/10 link-local addresses
        let line = b"Link-local address: fe80::1 and fe80::dead:beef";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject link-local IPv6 addresses");
    }

    #[test]
    fn test_reject_tiny_ipv6_addresses() {
        let extractor = Extractor::new().unwrap();

        // "e::f" (4 bytes), "ce::A" (5 bytes), "e::add" (6 bytes)
        let test_cases = [
            b"Tiny IPv6: e::f" as &[u8],
            b"Tiny IPv6: ce::A" as &[u8],
            b"Tiny IPv6: e::add" as &[u8],
        ];

        for line in test_cases {
            let matches: Vec<_> = extractor.extract_from_line(line).collect();

            let ips: Vec<Ipv6Addr> = matches
                .iter()
                .filter_map(|m| match m.item {
                    ExtractedItem::Ipv6(ip) => Some(ip),
                    _ => None,
                })
                .collect();

            assert_eq!(ips.len(), 0, "Should reject tiny IPv6 addresses");
        }
    }
}
