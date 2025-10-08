//! Binary format serialization and deserialization

pub mod format;
pub mod validation;

// Re-export commonly used types
pub use format::{
    OffsetAcHeader, OffsetParaglobHeader, MAGIC_PARAGLOB,
};

pub use validation::{
    validate_ac_header, validate_paraglob_header,
};
