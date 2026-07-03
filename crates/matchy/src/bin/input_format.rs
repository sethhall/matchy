use anyhow::{Context, Result};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    Text,
    Csv,
    Json,
    Misp,
}

impl InputFormat {
    pub fn from_extension(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(|extension| match extension.to_ascii_lowercase().as_str() {
                "txt" => Some(Self::Text),
                "csv" => Some(Self::Csv),
                "json" => Some(Self::Json),
                "misp" => Some(Self::Misp),
                _ => None,
            })
    }

    pub fn parse_explicit(value: &str) -> Result<Self> {
        match value {
            "text" => Ok(Self::Text),
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            "misp" => Ok(Self::Misp),
            _ => anyhow::bail!("Unknown format: {value}. Use 'text', 'csv', 'json', or 'misp'"),
        }
    }

    pub fn detect_file(path: &Path) -> Result<Self> {
        if let Some(format) = Self::from_extension(path) {
            return Ok(format);
        }

        let content = fs::read_to_string(path).with_context(|| {
            format!(
                "Failed to read input file for format auto-detection: {}",
                path.display()
            )
        })?;
        Ok(Self::detect_content(&content))
    }

    pub fn detect_consistent(inputs: &[PathBuf]) -> Result<Self> {
        let mut detected_format: Option<(&Path, Self)> = None;
        for input in inputs {
            let input_format = Self::detect_file(input)?;
            if let Some((first_input, first_format)) = detected_format {
                if first_format != input_format {
                    anyhow::bail!(
                        "Could not auto-detect a single input format: {} looks like {}, but {} looks like {}. \
                        Use --input-format to parse all inputs as one format.",
                        first_input.display(),
                        first_format,
                        input.display(),
                        input_format
                    );
                }
            } else {
                detected_format = Some((input.as_path(), input_format));
            }
        }

        Ok(detected_format
            .map(|(_, input_format)| input_format)
            .unwrap_or(Self::Text))
    }

    fn detect_content(content: &str) -> Self {
        let trimmed = content.trim_start_matches('\u{feff}').trim_start();

        if trimmed.starts_with('{') {
            if trimmed.contains("\"Event\"") {
                Self::Misp
            } else {
                Self::Json
            }
        } else if trimmed.starts_with('[') {
            Self::Json
        } else {
            let first_line = content
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("");
            if looks_like_csv_entry_header(first_line)
                || (first_line.contains(',') && first_line.split(',').count() > 1)
            {
                Self::Csv
            } else {
                Self::Text
            }
        }
    }
}

impl fmt::Display for InputFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Misp => "misp",
        })
    }
}

pub fn resolve_input_format(
    inputs: &[PathBuf],
    explicit_format: Option<&str>,
) -> Result<InputFormat> {
    if let Some(format) = explicit_format {
        InputFormat::parse_explicit(format)
    } else {
        InputFormat::detect_consistent(inputs)
    }
}

pub fn looks_like_csv_entry_header(first_line: &str) -> bool {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(first_line.as_bytes());

    let Some(Ok(record)) = reader.records().next() else {
        return false;
    };

    if record.len() < 2 {
        return false;
    }

    matches!(record.get(0).map(str::trim), Some("entry" | "key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parses_explicit_formats() {
        assert_eq!(
            InputFormat::parse_explicit("text").unwrap(),
            InputFormat::Text
        );
        assert_eq!(
            InputFormat::parse_explicit("csv").unwrap(),
            InputFormat::Csv
        );
        assert_eq!(
            InputFormat::parse_explicit("json").unwrap(),
            InputFormat::Json
        );
        assert_eq!(
            InputFormat::parse_explicit("misp").unwrap(),
            InputFormat::Misp
        );
    }

    #[test]
    fn rejects_unknown_explicit_format() {
        let error = InputFormat::parse_explicit("jsonl")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Unknown format"));
        assert!(error.contains("text"));
        assert!(error.contains("misp"));
    }

    #[test]
    fn detects_format_by_extension() {
        assert_eq!(
            InputFormat::from_extension(Path::new("indicators.TXT")),
            Some(InputFormat::Text)
        );
        assert_eq!(
            InputFormat::from_extension(Path::new("indicators.Csv")),
            Some(InputFormat::Csv)
        );
        assert_eq!(
            InputFormat::from_extension(Path::new("indicators.JSON")),
            Some(InputFormat::Json)
        );
        assert_eq!(
            InputFormat::from_extension(Path::new("indicators.MISP")),
            Some(InputFormat::Misp)
        );
        assert_eq!(
            InputFormat::from_extension(Path::new("indicators.feed")),
            None
        );

        assert_eq!(
            InputFormat::detect_file(Path::new("indicators.TXT")).unwrap(),
            InputFormat::Text
        );
        assert_eq!(
            InputFormat::detect_file(Path::new("indicators.Csv")).unwrap(),
            InputFormat::Csv
        );
        assert_eq!(
            InputFormat::detect_file(Path::new("indicators.JSON")).unwrap(),
            InputFormat::Json
        );
        assert_eq!(
            InputFormat::detect_file(Path::new("indicators.MISP")).unwrap(),
            InputFormat::Misp
        );
    }

    #[test]
    fn detects_json_by_content_for_unknown_extension() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("indicators.feed");
        fs::write(&input, r#"[{"key":"example.com"}]"#).unwrap();

        assert_eq!(InputFormat::detect_file(&input).unwrap(), InputFormat::Json);
    }

    #[test]
    fn detects_csv_by_content_for_unknown_extension() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("indicators.feed");
        fs::write(&input, "entry,category\nexample.com,malware\n").unwrap();

        assert_eq!(InputFormat::detect_file(&input).unwrap(), InputFormat::Csv);
    }

    #[test]
    fn rejects_inconsistent_auto_detected_inputs() {
        let temp_dir = TempDir::new().unwrap();
        let json_input = temp_dir.path().join("indicators.json");
        let csv_input = temp_dir.path().join("indicators.csv");
        fs::write(&json_input, r#"[{"key":"example.com"}]"#).unwrap();
        fs::write(&csv_input, "entry,category\nexample.com,malware\n").unwrap();

        let error = InputFormat::detect_consistent(&[json_input, csv_input])
            .unwrap_err()
            .to_string();
        assert!(error.contains("Could not auto-detect a single input format"));
        assert!(error.contains("--input-format"));
    }
}
