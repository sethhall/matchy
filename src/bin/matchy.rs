use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use matchy::DataValue;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "matchy")]
#[command(about = "Fast multi-pattern glob matching with optional data associations", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query a pattern database
    Query {
        /// Path to the pattern database (.pgb file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Query string to match against patterns
        #[arg(value_name = "QUERY")]
        query: String,

        /// Quiet mode - no output, only exit code (0 = found, 1 = not found)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Inspect a pattern database
    Inspect {
        /// Path to the pattern database (.pgb file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Output metadata as JSON
        #[arg(short, long)]
        json: bool,

        /// Show detailed statistics
        #[arg(short, long)]
        verbose: bool,
    },

    /// Build a unified database from patterns and/or IP addresses
    Build {
        /// Input files containing patterns, IP addresses, or MISP JSON (can specify multiple)
        #[arg(value_name = "INPUT", required = true)]
        inputs: Vec<PathBuf>,

        /// Output database file (.mmdb extension recommended)
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Input format: text, csv, json, or misp (for MISP JSON threat intel files)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Database type name (e.g., "MyCompany-ThreatIntel")
        #[arg(short = 't', long)]
        database_type: Option<String>,

        /// Description text (can be specified multiple times with --desc-lang)
        #[arg(short = 'd', long)]
        description: Option<String>,

        /// Language code for description (default: "en")
        #[arg(long, default_value = "en")]
        desc_lang: String,

        /// Verbose output during build
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Query {
            database,
            query,
            quiet,
        } => cmd_query(database, query, quiet),
        Commands::Inspect {
            database,
            json,
            verbose,
        } => cmd_inspect(database, json, verbose),
        Commands::Build {
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
        } => cmd_build(
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
        ),
    }
}

/// Helper function to format IP and prefix length as CIDR
fn format_cidr(ip_str: &str, prefix_len: u8) -> String {
    if let Ok(addr) = ip_str.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ipv4) => {
                let ip_int = u32::from(ipv4);
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let network_int = ip_int & mask;
                let network = std::net::Ipv4Addr::from(network_int);
                format!("{}/{}", network, prefix_len)
            }
            IpAddr::V6(ipv6) => {
                let ip_int = u128::from(ipv6);
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let network_int = ip_int & mask;
                let network = std::net::Ipv6Addr::from(network_int);
                format!("{}/{}", network, prefix_len)
            }
        }
    } else {
        format!("{}/{}", ip_str, prefix_len)
    }
}

fn cmd_query(database: PathBuf, query: String, quiet: bool) -> Result<()> {
    use matchy::{Database, QueryResult};

    // Load database using unified API (supports IP, pattern, and combined formats)
    let db = Database::open(database.to_str().unwrap())
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    // Perform the query (auto-detects IP vs pattern)
    let result = db
        .lookup(&query)
        .with_context(|| format!("Query failed for: {}", query))?;

    // Determine if match was found (for exit code)
    let found = matches!(result, Some(QueryResult::Pattern { ref pattern_ids, .. }) if !pattern_ids.is_empty())
        || matches!(result, Some(QueryResult::Ip { .. }));

    if quiet {
        // Quiet mode: no output, just exit code
        std::process::exit(if found { 0 } else { 1 });
    }

    // Default: JSON output with data - always return array for consistency
    match result {
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            if pattern_ids.is_empty() {
                // No matches - return empty array
                println!("[]");
            } else {
                // Build match results - only include data, not internal pattern IDs
                let mut results = Vec::new();
                for (i, &_pattern_id) in pattern_ids.iter().enumerate() {
                    // Always include data if available
                    if let Some(Some(ref d)) = data.get(i) {
                        results.push(data_value_to_json(d));
                    }
                }

                // Return array of matches (just the data)
                println!("{}", serde_json::to_string_pretty(&json!(results))?);
            }
        }
        Some(QueryResult::Ip { data, prefix_len }) => {
            let cidr = format_cidr(&query, prefix_len);
            let mut result = data_value_to_json(&data);

            // Add CIDR info to the data object
            if let serde_json::Value::Object(ref mut map) = result {
                map.insert("cidr".to_string(), json!(cidr));
                map.insert("prefix_len".to_string(), json!(prefix_len));
            }

            // Return as array with single element
            println!("{}", serde_json::to_string_pretty(&json!([result]))?);
        }
        Some(QueryResult::NotFound) | None => {
            // Not found - return empty array
            println!("[]");
        }
    }

    // Exit with appropriate code
    std::process::exit(if found { 0 } else { 1 });
}

fn cmd_inspect(database: PathBuf, json_output: bool, verbose: bool) -> Result<()> {
    use matchy::Database;

    // Load database using unified API
    let db = Database::open(database.to_str().unwrap())
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    let format_str = db.format();
    let has_ip = db.has_ip_data();
    let has_literals = db.has_literal_data();
    let has_globs = db.has_glob_data();
    let has_string = has_literals || has_globs;
    let ip_count = db.ip_count();
    let literal_count = db.literal_count();
    let glob_count = db.glob_count();
    let metadata = db.metadata();

    if json_output {
        let mut output = json!({
            "file": database.display().to_string(),
            "format": format_str,
            "has_ip_data": has_ip,
            "has_literal_data": has_literals,
            "has_glob_data": has_globs,
            "has_string_data": has_string,
            "ip_count": ip_count,
            "literal_count": literal_count,
            "glob_count": glob_count,
        });

        if let Some(meta) = metadata {
            output["metadata"] = data_value_to_json(&meta);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Database: {}", database.display());
        // Display format based on actual content
        let actual_format = if ip_count > 0 && (literal_count > 0 || glob_count > 0) {
            "Combined IP+String database"
        } else if ip_count > 0 {
            "IP database"
        } else if literal_count > 0 || glob_count > 0 {
            "String database"
        } else {
            "Empty database"
        };
        println!("Format:   {}", actual_format);
        println!();
        println!("Capabilities:");
        // Only show IP lookups as available if there are actual IP entries
        if ip_count > 0 {
            println!("  IP lookups:      ✓");
            println!("    Entries:       {}", ip_count);
        } else {
            println!("  IP lookups:      ✗");
        }
        println!("  String lookups:  {}", if has_string { "✓" } else { "✗" });
        if has_literals {
            println!("    Literals:      ✓ ({} strings)", literal_count);
        }
        if has_globs {
            println!("    Globs:         ✓ ({} patterns)", glob_count);
        }

        if let Some(meta) = metadata {
            if let DataValue::Map(map) = &meta {
                println!();
                println!("Metadata:");

                // Show database_type if present
                if let Some(DataValue::String(db_type)) = map.get("database_type") {
                    println!("  Database type:   {}", db_type);
                }

                // Show description if present
                if let Some(DataValue::Map(desc_map)) = map.get("description") {
                    println!("  Description:");
                    for (lang, desc_value) in desc_map {
                        if let DataValue::String(desc) = desc_value {
                            println!("    {}: {}", lang, desc);
                        }
                    }
                }

                // Show build epoch if present
                if let Some(build_epoch) = map.get("build_epoch") {
                    if let Some(epoch) = extract_uint_from_datavalue(build_epoch) {
                        let timestamp_str = format_unix_timestamp(epoch);
                        println!("  Build time:      {} ({})", timestamp_str, epoch);
                    }
                }

                // Show IP version if present
                if let Some(ip_version) = map.get("ip_version") {
                    if let Some(ver) = extract_uint_from_datavalue(ip_version) {
                        println!("  IP version:      IPv{}", ver);
                    }
                }

                // Show node count if present
                if let Some(node_count) = map.get("node_count") {
                    if let Some(count) = extract_uint_from_datavalue(node_count) {
                        println!("  Node count:      {}", count);
                    }
                }

                // Show record size if present
                if let Some(record_size) = map.get("record_size") {
                    if let Some(size) = extract_uint_from_datavalue(record_size) {
                        println!("  Record size:     {} bits", size);
                    }
                }

                if verbose {
                    println!();
                    println!("Full metadata:");
                    println!("{}", format_data_value(&meta, "  "));
                }
            }
        }
    }

    Ok(())
}

fn cmd_build(
    inputs: Vec<PathBuf>,
    output: PathBuf,
    format: String,
    database_type: Option<String>,
    description: Option<String>,
    desc_lang: String,
    verbose: bool,
) -> Result<()> {
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;

    if verbose {
        println!("Building unified MMDB database (IP + patterns)...");
        println!("  Input files: {}", inputs.len());
        for input in &inputs {
            println!("    - {}", input.display());
        }
        println!("  Output: {}", output.display());
        println!("  Format: {}", format);
        println!();
    }

    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

    // Apply metadata if provided
    if let Some(db_type) = database_type {
        builder = builder.with_database_type(db_type);
    }

    if let Some(desc) = description {
        builder = builder.with_description(desc_lang, desc);
    }

    match format.as_str() {
        "text" => {
            // Read entries from text file(s) (one per line)
            // Auto-detects IP addresses/CIDRs vs patterns
            let mut total_count = 0;

            for input in &inputs {
                if verbose && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let file = fs::File::open(input)
                    .with_context(|| format!("Failed to open input file: {}", input.display()))?;
                let reader = io::BufReader::new(file);

                let mut count = 0;
                for line in reader.lines() {
                    let line = line?;
                    let entry = line.trim();
                    if !entry.is_empty() && !entry.starts_with('#') {
                        // Auto-detection: builder will determine if it's IP or pattern
                        builder.add_entry(entry, HashMap::new())?;
                        count += 1;
                        total_count += 1;
                        if verbose && total_count % 1000 == 0 {
                            println!("    Added {} entries...", total_count);
                        }
                    }
                }

                if verbose && inputs.len() > 1 {
                    println!("    {} entries from this file", count);
                }
            }

            if verbose {
                println!("  Total: {} entries", total_count);
            }
        }
        "csv" => {
            // Read entries with data from CSV file(s)
            // First column must be named "entry" (or "key") containing IP/CIDR/pattern
            // Remaining columns become metadata fields
            let mut total_entries = 0;

            for input in &inputs {
                if verbose && inputs.len() > 1 {
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
                                // Try to parse as number, otherwise treat as string
                                let data_value = if let Ok(i) = value.parse::<i64>() {
                                    DataValue::Int32(i as i32)
                                } else if let Ok(u) = value.parse::<u64>() {
                                    DataValue::Uint64(u)
                                } else if let Ok(f) = value.parse::<f64>() {
                                    DataValue::Double(f)
                                } else if value == "true" || value == "false" {
                                    DataValue::Bool(value == "true")
                                } else {
                                    DataValue::String(value.to_string())
                                };
                                data.insert(col_name.clone(), data_value);
                            }
                        }
                    }

                    builder.add_entry(entry, data)?;
                    total_entries += 1;

                    if verbose && total_entries % 1000 == 0 {
                        println!("    Added {} entries...", total_entries);
                    }
                }

                if verbose && inputs.len() > 1 {
                    println!("    {} entries from this file", reader.position().line());
                }
            }

            if verbose {
                println!("  Total: {} entries", total_entries);
            }
        }
        "json" => {
            // Read entries with data from JSON file(s)
            // Format: [{"key": "192.168.0.0/16" or "*.example.com", "data": {...}}]
            let mut total_entries = 0;

            for input in &inputs {
                if verbose && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let content = fs::read_to_string(input)
                    .with_context(|| format!("Failed to read JSON file: {}", input.display()))?;
                let entries: Vec<serde_json::Value> =
                    serde_json::from_str(&content).context("Failed to parse JSON")?;

                for (i, item) in entries.iter().enumerate() {
                    let key = item
                        .get("key")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Missing 'key' field at index {}", i))?;

                    let data = if let Some(data_json) = item.get("data") {
                        json_to_data_map(data_json)?
                    } else {
                        HashMap::new()
                    };

                    builder.add_entry(key, data)?;
                    total_entries += 1;

                    if verbose && total_entries % 1000 == 0 {
                        println!("    Added {} entries...", total_entries);
                    }
                }

                if verbose && inputs.len() > 1 {
                    println!("    {} entries from this file", entries.len());
                }
            }

            if verbose {
                println!("  Total: {} entries", total_entries);
            }
        }
        "misp" => {
            // Read MISP JSON threat intelligence file(s) with streaming (low memory)
            use matchy::misp_importer::MispImporter;

            if verbose {
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

            if verbose {
                let stats = builder.stats();
                println!("  Total indicators: {}", stats.total_entries);
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {}. Use 'text', 'csv', 'json', or 'misp'",
                format
            );
        }
    }

    // Always show statistics
    let stats = builder.stats();
    println!("\nBuilding database:");
    println!("  Total entries:   {}", stats.total_entries);
    println!("  IP entries:      {}", stats.ip_entries);
    println!("  Literal entries: {}", stats.literal_entries);
    println!("  Glob entries:    {}", stats.glob_entries);

    if verbose {
        println!("\nSerializing...");
    }

    let database_bytes = builder.build().context("Failed to build database")?;

    if verbose {
        println!("Writing to disk...");
    }

    fs::write(&output, &database_bytes)
        .with_context(|| format!("Failed to save database: {}", output.display()))?;

    // Always show success message
    println!("\n✓ Database built successfully!");
    println!("  Output:        {}", output.display());
    println!(
        "  Database size: {:.2} MB ({} bytes)",
        database_bytes.len() as f64 / (1024.0 * 1024.0),
        database_bytes.len()
    );

    if verbose {
        println!("  Format:        MMDB (extended with patterns)");
    }

    Ok(())
}

// Helper functions for data value conversion

fn data_value_to_json(data: &DataValue) -> serde_json::Value {
    match data {
        DataValue::String(s) => json!(s),
        DataValue::Double(d) => json!(d),
        DataValue::Bytes(b) => json!(b),
        DataValue::Uint16(u) => json!(u),
        DataValue::Uint32(u) => json!(u),
        DataValue::Uint64(u) => json!(u),
        DataValue::Uint128(u) => json!(u.to_string()),
        DataValue::Int32(i) => json!(i),
        DataValue::Bool(b) => json!(b),
        DataValue::Float(f) => json!(f),
        DataValue::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                map.insert(k.clone(), data_value_to_json(v));
            }
            json!(map)
        }
        DataValue::Array(items) => {
            json!(items.iter().map(data_value_to_json).collect::<Vec<_>>())
        }
        DataValue::Pointer(_) => json!("<pointer>"),
    }
}

fn json_to_data_map(json: &serde_json::Value) -> Result<HashMap<String, DataValue>> {
    match json {
        serde_json::Value::Object(obj) => obj
            .iter()
            .map(|(k, v)| Ok((k.clone(), json_to_data_value(v)?)))
            .collect::<Result<HashMap<_, _>>>(),
        _ => anyhow::bail!("Expected JSON object for data field"),
    }
}

fn json_to_data_value(json: &serde_json::Value) -> Result<DataValue> {
    match json {
        serde_json::Value::Null => Ok(DataValue::Bytes(vec![])),
        serde_json::Value::Bool(b) => Ok(DataValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(DataValue::Int32(i as i32))
            } else if let Some(u) = n.as_u64() {
                Ok(DataValue::Uint64(u))
            } else if let Some(f) = n.as_f64() {
                Ok(DataValue::Double(f))
            } else {
                anyhow::bail!("Unsupported number type")
            }
        }
        serde_json::Value::String(s) => Ok(DataValue::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items = arr
                .iter()
                .map(json_to_data_value)
                .collect::<Result<Vec<_>>>()?;
            Ok(DataValue::Array(items))
        }
        serde_json::Value::Object(obj) => {
            let entries = obj
                .iter()
                .map(|(k, v)| Ok((k.clone(), json_to_data_value(v)?)))
                .collect::<Result<HashMap<_, _>>>()?;
            Ok(DataValue::Map(entries))
        }
    }
}

fn extract_uint_from_datavalue(data: &DataValue) -> Option<u64> {
    match data {
        DataValue::Uint16(u) => Some(*u as u64),
        DataValue::Uint32(u) => Some(*u as u64),
        DataValue::Uint64(u) => Some(*u),
        _ => None,
    }
}

fn format_unix_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let duration = Duration::from_secs(timestamp);
    let datetime = UNIX_EPOCH + duration;

    // Convert to a formatted string using the system's local time
    // We'll format it manually since we don't have external dependencies
    match datetime.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let total_secs = d.as_secs();
            let days = total_secs / 86400;
            let remaining = total_secs % 86400;
            let hours = remaining / 3600;
            let remaining = remaining % 3600;
            let minutes = remaining / 60;
            let seconds = remaining % 60;

            // Calculate date from days since epoch (1970-01-01)
            let (year, month, day) = days_to_ymd(days);

            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                year, month, day, hours, minutes, seconds
            )
        }
        Err(_) => format!("Invalid timestamp: {}", timestamp),
    }
}

// Convert days since Unix epoch to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;
    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn format_data_value(data: &DataValue, indent: &str) -> String {
    match data {
        DataValue::String(s) => format!("\"{}\"", s),
        DataValue::Double(d) => format!("{}", d),
        DataValue::Bytes(b) => format!("{:?}", b),
        DataValue::Uint16(u) => format!("{}", u),
        DataValue::Uint32(u) => format!("{}", u),
        DataValue::Uint64(u) => format!("{}", u),
        DataValue::Uint128(u) => format!("{}", u),
        DataValue::Int32(i) => format!("{}", i),
        DataValue::Bool(b) => format!("{}", b),
        DataValue::Float(f) => format!("{}", f),
        DataValue::Map(entries) => {
            if entries.is_empty() {
                "{}".to_string()
            } else {
                let mut result = "{\n".to_string();
                for (k, v) in entries {
                    result.push_str(&format!(
                        "{}  {}: {},\n",
                        indent,
                        k,
                        format_data_value(v, &format!("{}  ", indent))
                    ));
                }
                result.push_str(&format!("{}}}", indent));
                result
            }
        }
        DataValue::Array(items) => {
            if items.is_empty() {
                "[]".to_string()
            } else {
                let items_str: Vec<_> = items
                    .iter()
                    .map(|item| format_data_value(item, indent))
                    .collect();
                format!("[{}]", items_str.join(", "))
            }
        }
        DataValue::Pointer(_) => "<pointer>".to_string(),
    }
}
