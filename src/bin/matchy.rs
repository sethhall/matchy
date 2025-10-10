use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use matchy::DataValue;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "paraglob")]
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

        /// Output results as JSON
        #[arg(short, long)]
        json: bool,

        /// Show associated data for matched patterns (v2 databases)
        #[arg(short, long)]
        data: bool,
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

        /// Input format: text, json, or misp (for MISP JSON threat intel files)
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
            json,
            data,
        } => cmd_query(database, query, json, data),
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

fn cmd_query(database: PathBuf, query: String, json_output: bool, show_data: bool) -> Result<()> {
    use matchy::{Database, QueryResult};

    // Load database using unified API (supports IP, pattern, and combined formats)
    let db = Database::open(database.to_str().unwrap())
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    // Perform the query (auto-detects IP vs pattern)
    let result = db
        .lookup(&query)
        .with_context(|| format!("Query failed for: {}", query))?;

    if json_output {
        // JSON output
        match result {
            Some(QueryResult::Pattern { pattern_ids, data }) => {
                let mut results = Vec::new();
                for (i, &pattern_id) in pattern_ids.iter().enumerate() {
                    let mut entry = json!({
                        "pattern_id": pattern_id,
                        "type": "pattern",
                    });

                    if show_data {
                        if let Some(Some(ref d)) = data.get(i) {
                            entry["data"] = data_value_to_json(d);
                        }
                    }

                    results.push(entry);
                }

                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "query": query,
                        "type": "pattern",
                        "match_count": results.len(),
                        "matches": results,
                    }))?
                );
            }
            Some(QueryResult::Ip { data, prefix_len }) => {
                let mut result = json!({
                    "query": query,
                    "type": "ip",
                    "prefix_len": prefix_len,
                });

                if show_data {
                    result["data"] = data_value_to_json(&data);
                }

                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            Some(QueryResult::NotFound) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "query": query,
                        "found": false,
                    }))?
                );
            }
            None => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "query": query,
                        "error": "No result",
                    }))?
                );
            }
        }
    } else {
        // Human-readable output
        match result {
            Some(QueryResult::Pattern { pattern_ids, data }) => {
                if pattern_ids.is_empty() {
                    println!("No matches found for: {}", query);
                } else {
                    println!(
                        "Found {} pattern match(es) for: {}\n",
                        pattern_ids.len(),
                        query
                    );
                    for (i, &pattern_id) in pattern_ids.iter().enumerate() {
                        println!("  Pattern ID: {}", pattern_id);

                        if show_data {
                            if let Some(Some(ref d)) = data.get(i) {
                                println!(
                                    "  Data:       {}",
                                    format_data_value(d, "              ")
                                );
                            } else {
                                println!("  Data:       (none)");
                            }
                        }
                        println!();
                    }
                }
            }
            Some(QueryResult::Ip { data, prefix_len }) => {
                println!("IP address found: {}\n", query);
                println!("  Prefix:     /{}", prefix_len);
                if show_data {
                    println!(
                        "  Data:       {}",
                        format_data_value(&data, "              ")
                    );
                }
            }
            Some(QueryResult::NotFound) => {
                println!("Not found: {}", query);
            }
            None => {
                println!("No result for: {}", query);
            }
        }
    }

    Ok(())
}

fn cmd_inspect(database: PathBuf, json_output: bool, verbose: bool) -> Result<()> {
    use matchy::Database;

    // Load database using unified API
    let db = Database::open(database.to_str().unwrap())
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    let format_str = db.format();
    let has_ip = db.has_ip_data();
    let has_pattern = db.has_pattern_data();
    let metadata = db.metadata();

    if json_output {
        let mut output = json!({
            "file": database.display().to_string(),
            "format": format_str,
            "has_ip_data": has_ip,
            "has_pattern_data": has_pattern,
        });

        if let Some(meta) = metadata {
            output["metadata"] = data_value_to_json(&meta);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Database: {}", database.display());
        println!("Format:   {}", format_str);
        println!();
        println!("Capabilities:");
        println!("  IP lookups:      {}", if has_ip { "✓" } else { "✗" });
        println!("  Pattern lookups: {}", if has_pattern { "✓" } else { "✗" });

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
            // Read MISP JSON threat intelligence file(s)
            use matchy::misp_importer::MispImporter;

            if verbose {
                println!("  Loading MISP JSON files...");
            }

            // Convert Vec<PathBuf> to Vec<&Path> for from_files
            let input_refs: Vec<&PathBuf> = inputs.iter().collect();
            let importer =
                MispImporter::from_files(&input_refs).context("Failed to load MISP JSON files")?;

            if verbose {
                let stats = importer.stats();
                println!("  Events:          {}", stats.total_events);
                println!("  Attributes:      {}", stats.total_attributes);
                println!("  Objects:         {}", stats.total_objects);
                println!();
                println!("  Building MISP database...");
            }

            // Build the database using MISP importer
            // This will populate the builder with all indicators and metadata
            builder = importer
                .build_database(MatchMode::CaseSensitive)
                .context("Failed to build MISP database")?;

            if verbose {
                let stats = builder.stats();
                println!("  Total indicators: {}", stats.total_entries);
            }
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use 'text', 'json', or 'misp'", format);
        }
    }

    // Show statistics
    let stats = builder.stats();
    if verbose {
        println!("\nStatistics:");
        println!("  Total entries:   {}", stats.total_entries);
        println!("  IP entries:      {}", stats.ip_entries);
        println!("  Pattern entries: {}", stats.pattern_entries);
        println!("\nBuilding database...");
    }

    let database_bytes = builder.build().context("Failed to build database")?;

    if verbose {
        println!("Saving to disk...");
    }

    fs::write(&output, &database_bytes)
        .with_context(|| format!("Failed to save database: {}", output.display()))?;

    if verbose {
        println!("\n✓ Success!");
        println!("  Database size: {} bytes", database_bytes.len());
        println!("  Output:        {}", output.display());
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
