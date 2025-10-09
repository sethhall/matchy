use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use paraglob_rs::DataValue;
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

    /// Build a pattern database from patterns
    Build {
        /// Input file containing patterns (one per line)
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Output database file (.pgb)
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Input format: text (default) or json (for patterns with data)
        #[arg(short, long, default_value = "text")]
        format: String,

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
            input,
            output,
            format,
            verbose,
        } => cmd_build(input, output, format, verbose),
    }
}

fn cmd_query(database: PathBuf, query: String, json_output: bool, show_data: bool) -> Result<()> {
    // Load the database with case-sensitive mode (default)
    let mut pg_mmap = paraglob_rs::load(&database, paraglob_rs::MatchMode::CaseSensitive)
        .with_context(|| format!("Failed to load database: {}", database.display()))?;
    let pg = pg_mmap.paraglob_mut();

    // Perform the query
    let matches = pg.find_all(&query);

    if json_output {
        // JSON output
        let mut results = Vec::new();
        for &pattern_id in &matches {
            let pattern = pg
                .get_pattern(pattern_id)
                .ok_or_else(|| anyhow::anyhow!("Invalid pattern ID: {}", pattern_id))?;

            let mut entry = json!({
                "pattern_id": pattern_id,
                "pattern": pattern,
            });

            if show_data {
                if let Some(data) = pg.get_pattern_data(pattern_id) {
                    entry["data"] = data_value_to_json(&data);
                }
            }

            results.push(entry);
        }

        println!("{}", serde_json::to_string_pretty(&json!({
            "query": query,
            "match_count": results.len(),
            "matches": results,
        }))?);
    } else {
        // Human-readable output
        if matches.is_empty() {
            println!("No matches found for: {}", query);
        } else {
            println!("Found {} match(es) for: {}\n", matches.len(), query);
            for &pattern_id in &matches {
                let pattern = pg
                    .get_pattern(pattern_id)
                    .ok_or_else(|| anyhow::anyhow!("Invalid pattern ID: {}", pattern_id))?;

                println!("  Pattern ID: {}", pattern_id);
                println!("  Pattern:    {}", pattern);

                if show_data {
                    if let Some(data) = pg.get_pattern_data(pattern_id) {
                        println!("  Data:       {}", format_data_value(&data, "              "));
                    } else {
                        println!("  Data:       (none)");
                    }
                }
                println!();
            }
        }
    }

    Ok(())
}

fn cmd_inspect(database: PathBuf, json_output: bool, verbose: bool) -> Result<()> {
    // Load the database with case-sensitive mode (default)
    let mut pg_mmap = paraglob_rs::load(&database, paraglob_rs::MatchMode::CaseSensitive)
        .with_context(|| format!("Failed to load database: {}", database.display()))?;
    let pg = pg_mmap.paraglob_mut();

    let stats = pg.get_stats();
    let version = pg.version();
    let has_data = pg.has_data_section();

    if json_output {
        let mut metadata = json!({
            "file": database.display().to_string(),
            "version": version,
            "has_data_section": has_data,
            "pattern_count": stats.pattern_count,
            "node_count": stats.node_count,
            "edge_count": stats.edge_count,
        });

        if has_data {
            metadata["data_section_size"] = json!(stats.data_section_size);
            metadata["mapping_count"] = json!(stats.mapping_count);
        }

        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!("Database: {}", database.display());
        println!("Version:  v{}", version);
        println!("Format:   {}", if has_data { "v2 (with data)" } else { "v1 (patterns only)" });
        println!();
        println!("Statistics:");
        println!("  Patterns:     {}", stats.pattern_count);
        println!("  Nodes:        {}", stats.node_count);
        println!("  Edges:        {}", stats.edge_count);

        if has_data {
            println!("  Data section: {} bytes", stats.data_section_size);
            println!("  Mappings:     {}", stats.mapping_count);
        }

        if verbose {
            println!();
            println!("Patterns:");
            for i in 0..stats.pattern_count {
                if let Some(pattern) = pg.get_pattern(i as u32) {
                    print!("  [{:4}] {}", i, pattern);
                    if has_data {
                        if let Some(data) = pg.get_pattern_data(i as u32) {
                            print!(" => {}", format_data_value(&data, ""));
                        }
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn cmd_build(input: PathBuf, output: PathBuf, format: String, verbose: bool) -> Result<()> {
    if verbose {
        println!("Building pattern database...");
        println!("  Input:  {}", input.display());
        println!("  Output: {}", output.display());
        println!("  Format: {}", format);
        println!();
    }

    let mut builder = paraglob_rs::incremental_builder();

    match format.as_str() {
        "text" => {
            // Read patterns from text file (one per line)
            let file = fs::File::open(&input)
                .with_context(|| format!("Failed to open input file: {}", input.display()))?;
            let reader = io::BufReader::new(file);

            let mut count = 0;
            for line in reader.lines() {
                let line = line?;
                let pattern = line.trim();
                if !pattern.is_empty() && !pattern.starts_with('#') {
                    builder.add_pattern(pattern)?;
                    count += 1;
                    if verbose && count % 1000 == 0 {
                        println!("  Added {} patterns...", count);
                    }
                }
            }

            if verbose {
                println!("  Total: {} patterns", count);
            }
        }
        "json" => {
            // Read patterns with data from JSON file
            let content = fs::read_to_string(&input)
                .with_context(|| format!("Failed to read JSON file: {}", input.display()))?;
            let patterns: Vec<serde_json::Value> = serde_json::from_str(&content)
                .context("Failed to parse JSON")?;

            for (i, item) in patterns.iter().enumerate() {
                let pattern_str = item
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'pattern' field at index {}", i))?;

                if let Some(data_json) = item.get("data") {
                    let data = json_to_data_value(data_json)?;
                    builder.add_pattern_with_data(pattern_str, Some(data))?;
                } else {
                    builder.add_pattern(pattern_str)?;
                };
                if verbose && (i + 1) % 1000 == 0 {
                    println!("  Added {} patterns...", i + 1);
                }
            }

            if verbose {
                println!("  Total: {} patterns", patterns.len());
            }
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use 'text' or 'json'", format);
        }
    }

    if verbose {
        println!("\nBuilding automaton...");
    }

    let pg = builder.build()?;

    if verbose {
        println!("Saving to disk...");
    }

    paraglob_rs::save(&pg, &output)
        .with_context(|| format!("Failed to save database: {}", output.display()))?;

    if verbose {
        let file_size = fs::metadata(&output)?.len();
        println!("\nSuccess!");
        println!("  Database size: {} bytes", file_size);
        println!("  Output:        {}", output.display());
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
