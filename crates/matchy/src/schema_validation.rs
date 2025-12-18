//! Schema validation for yield values
//!
//! Validates that database yield values conform to built-in schemas during building.
//! This ensures data consistency and enables consumers to rely on the structure
//! of yield values without runtime validation.
//!
//! # Example
//!
//! ```rust,ignore
//! use matchy::schema_validation::SchemaValidator;
//! use matchy::DataValue;
//! use std::collections::HashMap;
//!
//! // Create validator for ThreatDB schema
//! let validator = SchemaValidator::new("threatdb")?;
//!
//! // Validate a yield value
//! let mut data = HashMap::new();
//! data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
//! data.insert("category".to_string(), DataValue::String("malware".to_string()));
//! data.insert("source".to_string(), DataValue::String("abuse.ch".to_string()));
//!
//! validator.validate(&data)?; // Ok
//! ```

use crate::schemas::get_schema_info;
use matchy_data_format::DataValue;
use matchy_format::EntryValidator;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use thiserror::Error;

/// Error returned when schema validation fails
#[derive(Debug, Clone)]
pub struct SchemaValidationError {
    /// List of validation errors
    pub errors: Vec<ValidationErrorDetail>,
}

impl fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.len() == 1 {
            write!(f, "Schema validation failed: {}", self.errors[0])
        } else {
            writeln!(
                f,
                "Schema validation failed with {} errors:",
                self.errors.len()
            )?;
            for (i, err) in self.errors.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, err)?;
            }
            Ok(())
        }
    }
}

impl std::error::Error for SchemaValidationError {}

/// Detail about a single validation error
#[derive(Debug, Clone)]
pub struct ValidationErrorDetail {
    /// JSON path to the invalid field (e.g., "/threat_level" or "/confidence")
    pub path: String,
    /// Description of what's wrong
    pub message: String,
}

impl fmt::Display for ValidationErrorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() || self.path == "/" {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// Errors that can occur when creating or using a schema validator
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Unknown schema name
    #[error("Unknown database type: '{0}'. Known types with validation: {1}")]
    UnknownSchema(String, String),
}

/// Valid threat_level enum values
const VALID_THREAT_LEVELS: &[&str] = &["critical", "high", "medium", "low", "unknown"];

/// Valid TLP enum values
const VALID_TLP: &[&str] = &["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];

/// Validates yield values against a built-in schema
///
/// Currently supports the ThreatDB schema for threat intelligence databases.
/// Validation is performed directly in Rust for speed and simplicity.
pub struct SchemaValidator {
    schema_name: String,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaValidator")
            .field("schema_name", &self.schema_name)
            .finish_non_exhaustive()
    }
}

impl SchemaValidator {
    /// Create a new validator for a built-in database type
    ///
    /// # Arguments
    /// * `database_type` - Name of a built-in database type (e.g., "threatdb")
    ///
    /// # Returns
    /// A validator, or an error if the type is unknown
    ///
    /// # Example
    /// ```rust,ignore
    /// let validator = SchemaValidator::new("threatdb")?;
    /// ```
    pub fn new(database_type: &str) -> Result<Self, SchemaError> {
        let schema_name = if get_schema_info(database_type).is_some() {
            database_type.to_string()
        } else if let Some(short_name) =
            crate::schemas::detect_schema_from_database_type(database_type)
        {
            short_name.to_string()
        } else {
            let available: Vec<_> = crate::schemas::available_schemas().collect();
            return Err(SchemaError::UnknownSchema(
                database_type.to_string(),
                available.join(", "),
            ));
        };

        Ok(Self { schema_name })
    }

    /// Get the schema name
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Get the canonical database_type that should be set in metadata
    ///
    /// Returns None if this validator was created from custom JSON (not a built-in type)
    pub fn database_type(&self) -> Option<&'static str> {
        get_schema_info(&self.schema_name).map(|info| info.database_type)
    }

    /// Validate a yield value (HashMap of field name to DataValue)
    ///
    /// # Arguments
    /// * `data` - The yield value to validate
    ///
    /// # Returns
    /// Ok(()) if valid, or SchemaValidationError with details
    pub fn validate(&self, data: &HashMap<String, DataValue>) -> Result<(), SchemaValidationError> {
        let errors = self.validate_detailed(data);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SchemaValidationError { errors })
        }
    }

    /// Validate and return a detailed result (useful for collecting all errors)
    pub fn validate_detailed(
        &self,
        data: &HashMap<String, DataValue>,
    ) -> Vec<ValidationErrorDetail> {
        // Currently only ThreatDB schema is supported
        validate_threatdb(data)
    }
}

/// Hand-rolled ThreatDB schema validation
///
/// Validates:
/// - Required: threat_level (enum), category (non-empty string), source (non-empty string)
/// - Optional: confidence (integer 0-100), tlp (enum), tags (array of strings),
///   first_seen, last_seen, description, reference, indicator_type
/// - Additional properties are allowed
fn validate_threatdb(data: &HashMap<String, DataValue>) -> Vec<ValidationErrorDetail> {
    let mut errors = Vec::new();

    // Required: threat_level (enum)
    match data.get("threat_level") {
        None => errors.push(ValidationErrorDetail {
            path: String::new(),
            message: "\"threat_level\" is a required property".to_string(),
        }),
        Some(DataValue::String(s)) => {
            if !VALID_THREAT_LEVELS.contains(&s.as_str()) {
                errors.push(ValidationErrorDetail {
                    path: "/threat_level".to_string(),
                    message: format!(
                        "\"{}\" is not one of [\"critical\", \"high\", \"medium\", \"low\", \"unknown\"]",
                        s
                    ),
                });
            }
        }
        Some(_) => {
            errors.push(ValidationErrorDetail {
                path: "/threat_level".to_string(),
                message: "expected string type".to_string(),
            });
        }
    }

    // Required: category (non-empty string)
    match data.get("category") {
        None => errors.push(ValidationErrorDetail {
            path: String::new(),
            message: "\"category\" is a required property".to_string(),
        }),
        Some(DataValue::String(s)) => {
            if s.is_empty() {
                errors.push(ValidationErrorDetail {
                    path: "/category".to_string(),
                    message: "string length 0 is less than minLength 1".to_string(),
                });
            }
        }
        Some(_) => {
            errors.push(ValidationErrorDetail {
                path: "/category".to_string(),
                message: "expected string type".to_string(),
            });
        }
    }

    // Required: source (non-empty string)
    match data.get("source") {
        None => errors.push(ValidationErrorDetail {
            path: String::new(),
            message: "\"source\" is a required property".to_string(),
        }),
        Some(DataValue::String(s)) => {
            if s.is_empty() {
                errors.push(ValidationErrorDetail {
                    path: "/source".to_string(),
                    message: "string length 0 is less than minLength 1".to_string(),
                });
            }
        }
        Some(_) => {
            errors.push(ValidationErrorDetail {
                path: "/source".to_string(),
                message: "expected string type".to_string(),
            });
        }
    }

    // Optional: confidence (integer 0-100)
    if let Some(v) = data.get("confidence") {
        match v {
            DataValue::Uint32(n) => {
                if *n > 100 {
                    errors.push(ValidationErrorDetail {
                        path: "/confidence".to_string(),
                        message: format!("{} is greater than the maximum of 100", n),
                    });
                }
            }
            DataValue::Int32(n) => {
                if *n < 0 {
                    errors.push(ValidationErrorDetail {
                        path: "/confidence".to_string(),
                        message: format!("{} is less than the minimum of 0", n),
                    });
                } else if *n > 100 {
                    errors.push(ValidationErrorDetail {
                        path: "/confidence".to_string(),
                        message: format!("{} is greater than the maximum of 100", n),
                    });
                }
            }
            DataValue::Uint64(n) => {
                if *n > 100 {
                    errors.push(ValidationErrorDetail {
                        path: "/confidence".to_string(),
                        message: format!("{} is greater than the maximum of 100", n),
                    });
                }
            }
            DataValue::Uint16(n) => {
                if *n > 100 {
                    errors.push(ValidationErrorDetail {
                        path: "/confidence".to_string(),
                        message: format!("{} is greater than the maximum of 100", n),
                    });
                }
            }
            _ => {
                errors.push(ValidationErrorDetail {
                    path: "/confidence".to_string(),
                    message: "expected integer type".to_string(),
                });
            }
        }
    }

    // Optional: tlp (enum)
    if let Some(v) = data.get("tlp") {
        match v {
            DataValue::String(s) => {
                if !VALID_TLP.contains(&s.as_str()) {
                    errors.push(ValidationErrorDetail {
                        path: "/tlp".to_string(),
                        message: format!(
                            "\"{}\" is not one of [\"CLEAR\", \"GREEN\", \"AMBER\", \"AMBER+STRICT\", \"RED\"]",
                            s
                        ),
                    });
                }
            }
            _ => {
                errors.push(ValidationErrorDetail {
                    path: "/tlp".to_string(),
                    message: "expected string type".to_string(),
                });
            }
        }
    }

    // Optional: tags (array of strings)
    if let Some(v) = data.get("tags") {
        match v {
            DataValue::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    if !matches!(item, DataValue::String(_)) {
                        errors.push(ValidationErrorDetail {
                            path: format!("/tags/{}", i),
                            message: "expected string type".to_string(),
                        });
                    }
                }
            }
            _ => {
                errors.push(ValidationErrorDetail {
                    path: "/tags".to_string(),
                    message: "expected array type".to_string(),
                });
            }
        }
    }

    // Optional: indicator_type (non-empty string if present)
    if let Some(v) = data.get("indicator_type") {
        match v {
            DataValue::String(s) => {
                if s.is_empty() {
                    errors.push(ValidationErrorDetail {
                        path: "/indicator_type".to_string(),
                        message: "string length 0 is less than minLength 1".to_string(),
                    });
                }
            }
            _ => {
                errors.push(ValidationErrorDetail {
                    path: "/indicator_type".to_string(),
                    message: "expected string type".to_string(),
                });
            }
        }
    }

    // Optional string fields (no validation beyond type): description, first_seen, last_seen, reference
    for field in &["description", "first_seen", "last_seen", "reference"] {
        if let Some(v) = data.get(*field) {
            if !matches!(v, DataValue::String(_)) {
                errors.push(ValidationErrorDetail {
                    path: format!("/{}", field),
                    message: "expected string type".to_string(),
                });
            }
        }
    }

    // Additional properties are allowed - no validation needed

    errors
}

/// Implement EntryValidator trait for SchemaValidator
///
/// This allows SchemaValidator to be used with DatabaseBuilder::with_validator()
/// for automatic schema validation during database construction.
impl EntryValidator for SchemaValidator {
    fn validate(
        &self,
        key: &str,
        data: &HashMap<String, DataValue>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.validate(data).map_err(|e| {
            let error_msg = format!("Entry '{}': {}", key, e);
            Box::new(SchemaValidationError {
                errors: vec![ValidationErrorDetail {
                    path: String::new(),
                    message: error_msg,
                }],
            }) as Box<dyn Error + Send + Sync>
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_threatdb_data() -> HashMap<String, DataValue> {
        let mut data = HashMap::new();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        data.insert(
            "category".to_string(),
            DataValue::String("malware".to_string()),
        );
        data.insert(
            "source".to_string(),
            DataValue::String("abuse.ch".to_string()),
        );
        data
    }

    #[test]
    fn test_validator_creation() {
        let validator = SchemaValidator::new("threatdb").expect("should create validator");
        assert_eq!(validator.schema_name(), "threatdb");
        assert_eq!(validator.database_type(), Some("ThreatDB-v1"));
    }

    #[test]
    fn test_validator_creation_from_canonical_name() {
        let validator = SchemaValidator::new("ThreatDB-v1").expect("should create validator");
        assert_eq!(validator.schema_name(), "threatdb");
        assert_eq!(validator.database_type(), Some("ThreatDB-v1"));
    }

    #[test]
    fn test_unknown_schema() {
        let result = SchemaValidator::new("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SchemaError::UnknownSchema(_, _)));
    }

    #[test]
    fn test_valid_threatdb_record() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let data = valid_threatdb_data();
        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_valid_threatdb_with_optional_fields() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert("confidence".to_string(), DataValue::Uint32(85));
        data.insert(
            "description".to_string(),
            DataValue::String("Known malware C2".to_string()),
        );
        data.insert("tlp".to_string(), DataValue::String("AMBER".to_string()));
        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_missing_required_field() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = HashMap::new();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        // Missing category and source

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.errors.is_empty());
        // Should mention missing required properties
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("category") || error_text.contains("source"),
            "Error should mention missing field: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_enum_value() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("super-critical".to_string()), // Not a valid enum value
        );

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("threat_level"),
            "Error should mention invalid enum: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_confidence_range() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert("confidence".to_string(), DataValue::Uint32(150)); // > 100

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("confidence") || error_text.contains("maximum"),
            "Error should mention confidence range: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_tlp_value() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "tlp".to_string(),
            DataValue::String("purple".to_string()), // Not a valid TLP
        );

        let result = validator.validate(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_type_for_field() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "confidence".to_string(),
            DataValue::String("high".to_string()),
        ); // Should be integer

        let result = validator.validate(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_additional_properties_allowed() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        // Additional properties are allowed
        data.insert(
            "custom_field".to_string(),
            DataValue::String("custom value".to_string()),
        );

        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_tags_array() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "tags".to_string(),
            DataValue::Array(vec![
                DataValue::String("emotet".to_string()),
                DataValue::String("banking-trojan".to_string()),
            ]),
        );

        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_validate_detailed() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let data = HashMap::new(); // Empty - missing all required fields

        let errors = validator.validate_detailed(&data);
        assert!(!errors.is_empty());
        // Should have errors for missing threat_level, category, source
    }

    #[test]
    fn test_error_display() {
        let err = SchemaValidationError {
            errors: vec![
                ValidationErrorDetail {
                    path: "/threat_level".to_string(),
                    message: "value must be one of: critical, high, medium, low, unknown"
                        .to_string(),
                },
                ValidationErrorDetail {
                    path: "/confidence".to_string(),
                    message: "value must be <= 100".to_string(),
                },
            ],
        };

        let display = format!("{}", err);
        assert!(display.contains("2 errors"));
        assert!(display.contains("threat_level"));
        assert!(display.contains("confidence"));
    }
}
