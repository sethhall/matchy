//! Pattern extractor implementations.
//!
//! Each extractor declares which [`Finder`]s it needs via [`PatternExtractor::required_finders`],
//! and the core ensures each finder runs at most once per chunk.

pub mod bitcoin;
pub mod domain;
pub mod email;
pub mod ethereum;
pub mod hash;
pub mod ipv4;
pub mod ipv6;
pub mod monero;

use crate::finders::{Finder, FinderResults};
use crate::types::Match;

pub use bitcoin::BitcoinExtractor;
pub use domain::DomainExtractor;
pub use email::EmailExtractor;
pub use ethereum::EthereumExtractor;
pub use hash::HashExtractor;
pub use ipv4::Ipv4Extractor;
pub use ipv6::Ipv6Extractor;
pub use monero::MoneroExtractor;

/// Trait for pattern extractors.
///
/// Implementors declare their finder requirements and provide extraction logic.
/// The core orchestration ensures finders are computed at most once per chunk.
pub trait PatternExtractor: Send + Sync {
    /// Which finders does this extractor need pre-computed?
    fn required_finders(&self) -> &'static [Finder];

    /// Extract matches from chunk using pre-computed finder results.
    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>);
}

/// All extractors wrapped in an enum for static dispatch.
/// This avoids the overhead of dynamic dispatch (`dyn PatternExtractor`).
pub enum ExtractorKind {
    Domain(DomainExtractor),
    Ipv4(Ipv4Extractor),
    Ipv6(Box<Ipv6Extractor>),
    Email(EmailExtractor),
    Hash(HashExtractor),
    Bitcoin(BitcoinExtractor),
    Ethereum(EthereumExtractor),
    Monero(MoneroExtractor),
}

impl ExtractorKind {
    /// Get the finders this extractor requires.
    #[inline]
    pub fn required_finders(&self) -> &'static [Finder] {
        match self {
            Self::Domain(e) => e.required_finders(),
            Self::Ipv4(e) => e.required_finders(),
            Self::Ipv6(e) => e.required_finders(),
            Self::Email(e) => e.required_finders(),
            Self::Hash(e) => e.required_finders(),
            Self::Bitcoin(e) => e.required_finders(),
            Self::Ethereum(e) => e.required_finders(),
            Self::Monero(e) => e.required_finders(),
        }
    }

    /// Run extraction with pre-computed finder results.
    #[inline]
    pub fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        match self {
            Self::Domain(e) => e.extract(results, matches),
            Self::Ipv4(e) => e.extract(results, matches),
            Self::Ipv6(e) => e.extract(results, matches),
            Self::Email(e) => e.extract(results, matches),
            Self::Hash(e) => e.extract(results, matches),
            Self::Bitcoin(e) => e.extract(results, matches),
            Self::Ethereum(e) => e.extract(results, matches),
            Self::Monero(e) => e.extract(results, matches),
        }
    }
}
