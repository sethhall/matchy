use anyhow::{Context, Result};
use chrono::DateTime;
use matchy::schemas::{get_schema_info, is_known_database_type};
use matchy::{DataValue, DatabaseBuilder, DatabaseBuilderExt, MatchMode};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use crate::cli_utils::{json_entry_key, json_to_data_map};
use crate::input_format::{looks_like_csv_entry_header, resolve_input_format, InputFormat};

#[allow(clippy::too_many_arguments)]
pub fn cmd_build(
    inputs: &[PathBuf],
    output: &Path,
    format: Option<&str>,
    database_type: Option<&str>,
    description: Option<&str>,
    desc_lang: &str,
    verbose: bool,
    debug: bool,
    case_insensitive: bool,
    update_url: Option<&str>,
) -> Result<()> {
    let format_was_explicit = format.is_some();
    let format = resolve_input_format(inputs, format)?;

    let match_mode = if case_insensitive {
        MatchMode::CaseInsensitive
    } else {
        MatchMode::CaseSensitive
    };

    if debug {
        println!("Building unified MMDB database (IP + patterns)...");
        println!("  Input files: {}", inputs.len());
        for input in inputs {
            println!("    - {}", input.display());
        }
        println!("  Output: {}", output.display());
        if format_was_explicit {
            println!("  Format: {format}");
        } else {
            println!("  Format: {format} (auto-detected)");
        }
        println!(
            "  Match mode: {}",
            if case_insensitive {
                "case-insensitive"
            } else {
                "case-sensitive"
            }
        );
        println!();
    }

    let mut builder = DatabaseBuilder::new(match_mode);

    // Check if database_type is a known schema type (enables validation)
    if let Some(db_type) = database_type {
        if is_known_database_type(db_type) {
            // Known schema type - enable validation via with_schema()
            // This automatically sets database_type and enables validation on add_entry()
            builder = builder
                .with_schema(db_type)
                .with_context(|| format!("Failed to load schema for '{db_type}'"))?;

            if verbose || debug {
                // Show the canonical database_type that will be stored in metadata
                let canonical_type = get_schema_info(db_type)
                    .map(|info| info.database_type)
                    .unwrap_or(db_type);
                println!("Schema validation: enabled ({canonical_type})");
            }
        } else {
            // Custom database type - no validation, just set metadata
            builder = builder.with_database_type(db_type.to_string());
        }
    }

    if let Some(desc) = description {
        builder = builder.with_description(desc_lang.to_string(), desc.to_string());
    }

    if let Some(url) = update_url {
        builder = builder.with_update_url(url);
        if verbose || debug {
            println!("Update URL: {url}");
        }
    }

    match format {
        InputFormat::Text => {
            // Read entries from text file(s) (one per line)
            // Auto-detects IP addresses/CIDRs vs patterns
            let mut total_count = 0;

            for input in inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                // Validate that the file doesn't look like JSON or CSV
                // (common user error: using wrong format flag)
                if format_was_explicit {
                    if let Ok(content) = fs::read_to_string(input) {
                        let trimmed = content.trim_start();
                        if trimmed.starts_with('{') || trimmed.starts_with('[') {
                            if trimmed.contains("\"Event\"") {
                                anyhow::bail!(
                                    "File {} appears to be MISP JSON format.\n\n\
                                    You specified --input-format text, but this looks like MISP JSON.\n\
                                    Try: --input-format misp",
                                    input.display()
                                );
                            } else {
                                eprintln!(
                                    "Warning: {} looks like JSON but you specified --input-format text.\n\
                                    If this is a JSON file, use --input-format json instead.",
                                    input.display()
                                );
                            }
                        }
                        // Check for CSV-like content
                        let first_line = content.lines().next().unwrap_or("");
                        if looks_like_csv_entry_header(first_line) {
                            anyhow::bail!(
                                "File {} appears to be CSV with an 'entry' or 'key' header.\n\n\
                                You specified --input-format text, but this looks like CSV.\n\
                                Try: --input-format csv",
                                input.display()
                            );
                        } else if first_line.contains(',') && first_line.split(',').count() > 1 {
                            eprintln!(
                                "Warning: {} looks like CSV but you specified --input-format text.\n\
                                If this is a CSV file, use --input-format csv instead.",
                                input.display()
                            );
                        }
                    }
                }

                let file = fs::File::open(input)
                    .with_context(|| format!("Failed to open input file: {}", input.display()))?;
                let reader = io::BufReader::new(file);

                let mut count = 0;
                for line in reader.lines() {
                    let line = line?;
                    let entry = line.trim();
                    if !entry.is_empty() && !entry.starts_with('#') {
                        let data = HashMap::new();
                        // Auto-detection: builder will determine if it's IP or pattern
                        // Schema validation happens automatically if with_schema() was used
                        builder.add_entry(entry, data).with_context(|| {
                            format!("Failed to add entry '{entry}'. Use a custom --database-type name if you don't want schema validation.")
                        })?;
                        count += 1;
                        total_count += 1;
                        if debug && total_count % 1000 == 0 {
                            println!("    Added {total_count} entries...");
                        }
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {count} entries from this file");
                }
            }

            if debug {
                println!("  Total: {total_count} entries");
            }
        }
        InputFormat::Csv => {
            // Read entries with data from CSV file(s)
            // First column must be named "entry" (or "key") containing IP/CIDR/pattern
            // Remaining columns become metadata fields
            let mut total_entries = 0;

            for input in inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let file = fs::File::open(input)
                    .with_context(|| format!("Failed to open CSV file: {}", input.display()))?;
                let mut reader = csv::Reader::from_reader(file);

                // Get headers
                let headers = reader.headers().context("Failed to read CSV headers")?;

                // Find the entry column (try "entry" or "key")
                let entry_col = headers
                    .iter()
                    .position(|h| h == "entry" || h == "key")
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "CSV must have an 'entry' or 'key' column. Found headers: {}",
                            headers.iter().collect::<Vec<_>>().join(", ")
                        )
                    })?;

                // Get other column names for metadata
                let data_cols: Vec<(usize, String)> = headers
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != entry_col)
                    .map(|(i, name)| (i, name.to_string()))
                    .collect();

                // Process each row
                for (row_num, result) in reader.records().enumerate() {
                    let record = result.context("Failed to read CSV record")?;

                    // Get the entry value
                    let entry = record.get(entry_col).ok_or_else(|| {
                        anyhow::anyhow!("Missing entry column at row {}", row_num + 2)
                    })?;

                    // Build data map from other columns
                    let mut data = HashMap::new();
                    for (col_idx, col_name) in &data_cols {
                        if let Some(value) = record.get(*col_idx) {
                            if !value.is_empty() {
                                let data_value = if let Ok(i) = value.parse::<i64>() {
                                    DataValue::Int32(i32::try_from(i).unwrap_or(if i < 0 {
                                        i32::MIN
                                    } else {
                                        i32::MAX
                                    }))
                                } else if let Ok(u) = value.parse::<u64>() {
                                    DataValue::Uint64(u)
                                } else if let Ok(f) = value.parse::<f64>() {
                                    DataValue::Double(f)
                                } else if value == "true" || value == "false" {
                                    DataValue::Bool(value == "true")
                                } else if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
                                    DataValue::Timestamp(dt.timestamp())
                                } else {
                                    DataValue::String(value.to_string())
                                };
                                data.insert(col_name.clone(), data_value);
                            }
                        }
                    }

                    // Schema validation happens automatically if with_schema() was used
                    builder.add_entry(entry, data).with_context(|| {
                        format!("Failed to add entry '{}' at row {}. Use a custom --database-type name if you don't want schema validation.", entry, row_num + 2)
                    })?;
                    total_entries += 1;

                    if debug && total_entries % 1000 == 0 {
                        println!("    Added {total_entries} entries...");
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {} entries from this file", reader.position().line());
                }
            }

            if debug {
                println!("  Total: {total_entries} entries");
            }
        }
        InputFormat::Json => {
            // Read entries with data from JSON file(s)
            // Format: [{"key": "192.168.0.0/16" or "*.example.com", "data": {...}}]
            // The entry field is also accepted for consistency with CSV.
            let mut total_entries = 0;

            for input in inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let content = fs::read_to_string(input)
                    .with_context(|| format!("Failed to read JSON file: {}", input.display()))?;
                let entries: Vec<serde_json::Value> =
                    serde_json::from_str(&content).context("Failed to parse JSON")?;

                for (i, item) in entries.iter().enumerate() {
                    let key = json_entry_key(item, i)?;

                    let data = if let Some(data_json) = item.get("data") {
                        json_to_data_map(data_json)?
                    } else {
                        HashMap::new()
                    };

                    // Schema validation happens automatically if with_schema() was used
                    builder.add_entry(key, data).with_context(|| {
                        format!("Failed to add entry '{key}' at index {i}. Use a custom --database-type name if you don't want schema validation.")
                    })?;
                    total_entries += 1;

                    if debug && total_entries % 1000 == 0 {
                        println!("    Added {total_entries} entries...");
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {} entries from this file", entries.len());
                }
            }

            if debug {
                println!("  Total: {total_entries} entries");
            }
        }
        InputFormat::Misp => {
            // Read MISP JSON threat intelligence file(s) with streaming (low memory)
            use matchy::misp_importer::MispImporter;

            if debug {
                println!("  Processing MISP JSON files (streaming mode)...");
            }

            // Convert Vec<PathBuf> to Vec<&Path> for build_from_files
            let input_refs: Vec<&PathBuf> = inputs.iter().collect();

            // Use streaming import to process one file at a time
            // This keeps memory usage low even for very large datasets
            builder = MispImporter::build_from_files(
                &input_refs,
                MatchMode::CaseSensitive,
                false, // Use full metadata
            )
            .context("Failed to process MISP JSON files")?;

            if debug {
                let stats = builder.stats();
                println!("  Total indicators: {}", stats.total_entries);
            }
        }
    }

    // Always show statistics
    let stats = builder.stats();
    if verbose || debug {
        println!("\nBuilding database:");
        println!("  Total entries:   {}", stats.total_entries);
        println!("  IP entries:      {}", stats.ip_entries);
        println!("  Literal entries: {}", stats.literal_entries);
        println!("  Glob entries:    {}", stats.glob_entries);
    }

    if debug {
        println!("\nSerializing...");
    }

    let database_bytes = builder.build().context("Failed to build database")?;

    if debug {
        println!("Writing to disk...");
    }

    let temp_path = output.with_extension("tmp");
    fs::write(&temp_path, &database_bytes)
        .with_context(|| format!("Failed to write temp file: {}", temp_path.display()))?;
    fs::rename(&temp_path, output)
        .with_context(|| format!("Failed to rename to: {}", output.display()))?;

    // Always show success message (always displayed)
    if verbose || debug {
        println!("\n✓ Database built successfully!");
        println!("  Output:        {}", output.display());
        println!(
            "  Database size: {:.2} MB ({} bytes)",
            database_bytes.len() as f64 / (1024.0 * 1024.0),
            database_bytes.len()
        );
    } else {
        println!("✓ Database built: {}", output.display());
    }

    if debug {
        println!("  Format:        MMDB (extended with patterns)");
    }

    Ok(())
}
