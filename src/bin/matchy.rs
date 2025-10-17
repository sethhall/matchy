use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use matchy::DataValue;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Zero-copy line scanner using memchr for SIMD-accelerated scanning.
/// Reuses a provided buffer to avoid allocations. Handles partial lines at buffer boundaries.
struct LineScanner<R: io::BufRead> {
    reader: R,
    partial: Vec<u8>,
    eof: bool,
}

impl<R: io::BufRead> LineScanner<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            partial: Vec::new(),
            eof: false,
        }
    }

    /// Trim ASCII whitespace from both ends of a byte slice
    fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
        while !bytes.is_empty() && bytes[0].is_ascii_whitespace() {
            bytes = &bytes[1..];
        }
        while !bytes.is_empty() && bytes[bytes.len() - 1].is_ascii_whitespace() {
            bytes = &bytes[..bytes.len() - 1];
        }
        bytes
    }

    /// Read next line into the provided buffer (zero-copy when possible).
    /// Returns Ok(true) if a line was read, Ok(false) on EOF, Err on I/O error.
    fn read_line(&mut self, line_buf: &mut Vec<u8>) -> io::Result<bool> {
        line_buf.clear();

        loop {
            if self.eof {
                // Handle final partial line if any
                if !self.partial.is_empty() {
                    let trimmed = Self::trim_ascii(&self.partial);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                        self.partial.clear();
                        return Ok(true);
                    }
                    self.partial.clear();
                }
                return Ok(false);
            }

            let buffer = self.reader.fill_buf()?;

            if buffer.is_empty() {
                self.eof = true;
                continue;
            }

            // Scan for newline using memchr
            if let Some(newline_pos) = memchr::memchr(b'\n', buffer) {
                // Found complete line
                if self.partial.is_empty() {
                    // Fast path: line is entirely in buffer, no allocation
                    let trimmed = Self::trim_ascii(&buffer[..newline_pos]);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                        self.reader.consume(newline_pos + 1);
                        return Ok(true);
                    }
                } else {
                    // Append to partial line from previous chunk
                    self.partial.extend_from_slice(&buffer[..newline_pos]);
                    let trimmed = Self::trim_ascii(&self.partial);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                    }
                    self.partial.clear();
                    self.reader.consume(newline_pos + 1);
                    if !line_buf.is_empty() {
                        return Ok(true);
                    }
                }

                // Empty line, consume and continue
                self.reader.consume(newline_pos + 1);
            } else {
                // No newline in buffer - accumulate and continue
                self.partial.extend_from_slice(buffer);
                let consumed = buffer.len();
                self.reader.consume(consumed);
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "matchy")]
#[command(
    about = "Unified database for IP addresses, string literals, and glob patterns",
    long_about = "matchy - High-performance unified database for IP lookups, exact string matching, and glob pattern matching\n\n\
    Build and query databases containing IP addresses (CIDR ranges), exact string literals, \n\
    and glob patterns with wildcards. Uses memory-mapped files for fast, zero-copy queries.\n\n\
    Features:\n\
      • IP address lookups (IPv4/IPv6 with CIDR support)\n\
      • Exact string matching (hash-based)\n\
      • Multi-pattern glob matching (wildcards: *, ?, [abc], [!abc])\n\
      • Extended MMDB format with backward compatibility\n\
      • Zero-copy memory-mapped access\n\
      • Attach custom metadata to any entry\n\n\
    Examples:\n\
      matchy build patterns.txt -o threats.mxy\n\
      matchy query threats.mxy '192.168.1.1'\n\
      matchy query threats.mxy 'evil.example.com'\n\
      matchy inspect threats.mxy --verbose\n\
      matchy validate threats.mxy --level strict"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Match strings from file or stdin against database (operational testing)
    Match {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Input file with strings to test (one per line), or "-" for stdin
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Output format: json (default, NDJSON), or summary (statistics only)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,

        /// Show detailed statistics in stderr (extraction time, candidate breakdown, etc.)
        #[arg(short, long)]
        stats: bool,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,

        /// LRU cache capacity (default: 10000, use 0 to disable)
        #[arg(long, default_value = "10000")]
        cache_size: usize,
    },

    /// Query a pattern database
    Query {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Query string to match against patterns
        #[arg(value_name = "QUERY")]
        query: String,

        /// Quiet mode - no output, only exit code (0 = found, 1 = not found)
        #[arg(short, long)]
        quiet: bool,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,
    },

    /// Inspect a pattern database
    Inspect {
        /// Path to the matchy database (.mxy file)
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

        /// Output database file (.mxy extension)
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

        /// Use case-insensitive matching for patterns (default: case-sensitive)
        #[arg(short = 'i', long)]
        case_insensitive: bool,
    },

    /// Validate a database file for safety and correctness
    Validate {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Validation level: standard, strict (default), or audit
        #[arg(short, long, default_value = "strict")]
        level: String,

        /// Output results as JSON
        #[arg(short, long)]
        json: bool,

        /// Show detailed information (warnings and info messages)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Benchmark database performance (build, load, query)
    Bench {
        /// Type of database to benchmark: ip, literal, pattern, or combined
        #[arg(value_name = "TYPE", default_value = "ip")]
        db_type: String,

        /// Number of entries to test with
        #[arg(short = 'n', long, default_value = "1000000")]
        count: usize,

        /// Output file for the test database (temp file if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Keep the generated database file after benchmarking
        #[arg(short, long)]
        keep: bool,

        /// Number of load iterations to average (default: 3)
        #[arg(long, default_value = "3")]
        load_iterations: usize,

        /// Number of queries for batch benchmark (default: 100000)
        #[arg(long, default_value = "100000")]
        query_count: usize,

        /// Percentage of queries that should match (0-100, default: 10)
        #[arg(long, default_value = "10")]
        hit_rate: usize,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,

        /// LRU cache capacity (default: 10000, use 0 to disable)
        #[arg(long, default_value = "10000")]
        cache_size: usize,

        /// Simulated cache hit rate percentage (0-100, default: 0 - all unique queries)
        /// Set to 80-90 to simulate real-world log patterns where queries repeat
        #[arg(long, default_value = "0")]
        cache_hit_rate: usize,

        /// Pattern style for pattern benchmarks: prefix, suffix, mixed, or complex (default: complex)
        #[arg(long, default_value = "complex")]
        pattern_style: String,
    },
}

/// Set file permissions to read-only (0444 on Unix, read-only attribute on Windows)
fn set_readonly(path: &PathBuf) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for: {}", path.display()))?
        .permissions();

    #[cfg(unix)]
    {
        perms.set_mode(0o444); // r--r--r--
    }

    #[cfg(not(unix))]
    {
        // On Windows and other platforms, use the cross-platform read-only API
        perms.set_readonly(true);
    }

    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set read-only permissions: {}", path.display()))?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Match {
            database,
            input,
            format,
            stats,
            trusted,
            cache_size,
        } => cmd_match(database, input, format, stats, trusted, cache_size),
        Commands::Query {
            database,
            query,
            quiet,
            trusted,
        } => cmd_query(database, query, quiet, trusted),
        Commands::Inspect {
            database,
            json,
            verbose,
        } => cmd_inspect(database, json, verbose),
        Commands::Validate {
            database,
            level,
            json,
            verbose,
        } => cmd_validate(database, level, json, verbose),
        Commands::Build {
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
            case_insensitive,
        } => cmd_build(
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
            case_insensitive,
        ),
        Commands::Bench {
            db_type,
            count,
            output,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
            pattern_style,
        } => cmd_bench(
            db_type,
            count,
            output,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
            pattern_style,
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

fn cmd_match(
    database: PathBuf,
    input: PathBuf,
    format: String,
    show_stats: bool,
    trusted: bool,
    cache_size: usize,
) -> Result<()> {
    use matchy::extractor::PatternExtractor;
    use matchy::Database;

    // Load database
    let load_start = Instant::now();
    let mut opener = Database::from(database.to_str().unwrap());
    if trusted {
        opener = opener.trusted();
    }
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener
        .open()
        .with_context(|| format!("Failed to load database: {}", database.display()))?;
    let load_time = load_start.elapsed();

    // Info messages to stderr
    if show_stats {
        eprintln!("[INFO] Loaded database: {}", database.display());
        eprintln!("[INFO] Load time: {:.2}ms", load_time.as_millis());
        eprintln!(
            "[INFO] Cache: {}",
            if cache_size == 0 {
                "disabled".to_string()
            } else {
                format!("{} entries", cache_size)
            }
        );
    }

    // Configure extractor based on database capabilities
    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    // Build extractor optimized for what the database contains
    let mut builder = PatternExtractor::builder();

    if !has_ip {
        // No IP data - skip IP extraction entirely
        builder = builder.extract_ipv4(false).extract_ipv6(false);
    }

    if !has_strings {
        // No string data - skip all string extraction
        builder = builder
            .extract_domains(false)
            .extract_emails(false)
            .extract_urls(false);
    }

    let extractor = builder.build().context("Failed to create pattern extractor")?;

    if show_stats {
        let extracting: Vec<&str> = [
            if has_ip { Some("IPs") } else { None },
            if has_strings { Some("strings") } else { None },
        ]
        .iter()
        .filter_map(|&x| x)
        .collect();

        eprintln!("[INFO] Extractor configured for: {}", extracting.join(", "));
    }

    // Open input for streaming (file or stdin) with 128KB buffer
    const BUFFER_SIZE: usize = 128 * 1024; // 128KB - optimal for log file processing
    let reader: Box<dyn io::BufRead> = if input.to_str() == Some("-") {
        Box::new(io::BufReader::with_capacity(BUFFER_SIZE, io::stdin()))
    } else {
        Box::new(io::BufReader::with_capacity(
            BUFFER_SIZE,
            fs::File::open(&input)
                .with_context(|| format!("Failed to open input file: {}", input.display()))?,
        ))
    };

    let mut lines_processed = 0;
    let mut candidates_tested = 0;
    let mut lines_with_matches = 0;
    let mut total_matches = 0;
    let mut total_bytes = 0usize;
    let mut extraction_time = std::time::Duration::ZERO;
    let mut lookup_time = std::time::Duration::ZERO;
    let mut extraction_samples = 0usize;
    let mut lookup_samples = 0usize;

    // Detailed stats (only tracked if --stats flag is set)
    let mut ipv4_count = 0usize;
    let mut ipv6_count = 0usize;
    let mut domain_count = 0usize;
    let mut email_count = 0usize;
    let mut url_count = 0usize;

    let overall_start = Instant::now();
    let output_json = format == "json";

    // Get base timestamp once, use monotonic clock for offsets (avoids syscalls)
    // Resync periodically to handle clock adjustments in long-running processes
    let mut base_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut last_resync = overall_start;
    const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    // Sampling: Only measure timing every Nth line/candidate to reduce Instant::now() overhead
    const SAMPLE_INTERVAL: usize = 100;

    if show_stats {
        eprintln!("[INFO] Processing stdin...");
    }

    // Process lines using LineScanner (zero-copy streaming + memchr)
    let mut scanner = LineScanner::new(reader);
    let mut line_buf = Vec::new(); // Reusable buffer, grows once to max line size

    while scanner.read_line(&mut line_buf)? {
        lines_processed += 1;
        total_bytes += line_buf.len();

        // Calculate timestamp from monotonic clock offset (no syscall)
        let timestamp = if output_json {
            base_timestamp + overall_start.elapsed().as_secs_f64()
        } else {
            0.0 // Not used
        };

        // Extract candidates from the line
        let extract_start = if show_stats && lines_processed % SAMPLE_INTERVAL == 0 {
            Some(Instant::now())
        } else {
            None
        };

        // Resync wall clock every 60s for long-running processes (piggyback on sampling)
        // Check on every sampled line, or every 6000 lines if stats disabled
        let should_check_resync = extract_start.is_some() || lines_processed % 6000 == 0;
        if output_json && should_check_resync {
            let now = extract_start.unwrap_or_else(Instant::now);
            if now.duration_since(last_resync) >= RESYNC_INTERVAL {
                base_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()
                    - overall_start.elapsed().as_secs_f64();
                last_resync = now;
            }
        }

        let extracted = extractor.extract_from_line(&line_buf);
        if let Some(start) = extract_start {
            extraction_time += start.elapsed();
            extraction_samples += 1;
        }

        let mut line_had_match = false;

        // Test each candidate
        for item in extracted {
            candidates_tested += 1;

            // Track candidate types if stats enabled
            if show_stats {
                match &item.item {
                    matchy::extractor::ExtractedItem::Ipv4(_) => ipv4_count += 1,
                    matchy::extractor::ExtractedItem::Ipv6(_) => ipv6_count += 1,
                    matchy::extractor::ExtractedItem::Domain(_) => domain_count += 1,
                    matchy::extractor::ExtractedItem::Email(_) => email_count += 1,
                    matchy::extractor::ExtractedItem::Url(_) => url_count += 1,
                }
            }

            // Lookup candidate (use specialized IP lookup to avoid string conversion)
            let lookup_start = if show_stats && candidates_tested % SAMPLE_INTERVAL == 0 {
                Some(Instant::now())
            } else {
                None
            };
            let (result, candidate_str) = match item.item {
                // IP addresses: use direct lookup_ip (no string conversion needed)
                matchy::extractor::ExtractedItem::Ipv4(ip) => {
                    (db.lookup_ip(IpAddr::V4(ip))?, ip.to_string())
                }
                matchy::extractor::ExtractedItem::Ipv6(ip) => {
                    (db.lookup_ip(IpAddr::V6(ip))?, ip.to_string())
                }
                // String patterns: use regular lookup
                matchy::extractor::ExtractedItem::Domain(s) => (db.lookup(s)?, s.to_string()),
                matchy::extractor::ExtractedItem::Email(s) => (db.lookup(s)?, s.to_string()),
                matchy::extractor::ExtractedItem::Url(s) => (db.lookup(s)?, s.to_string()),
            };
            if let Some(start) = lookup_start {
                lookup_time += start.elapsed();
                lookup_samples += 1;
            }

            let is_match = match &result {
                Some(matchy::QueryResult::Pattern { pattern_ids, .. }) => !pattern_ids.is_empty(),
                Some(matchy::QueryResult::Ip { .. }) => true,
                _ => false,
            };

            if is_match {
                if !line_had_match {
                    lines_with_matches += 1; // Only count the line once
                    line_had_match = true;
                }
                total_matches += 1;

                // Output match to stdout as NDJSON
                if output_json {
                    let mut match_obj = json!({
                        "timestamp": format!("{:.3}", timestamp),
                        "line_number": lines_processed,
                        "matched_text": candidate_str,
                        "input_line": String::from_utf8_lossy(&line_buf),
                    });

                    // Add match-specific fields
                    match &result {
                        Some(matchy::QueryResult::Pattern { pattern_ids, data }) => {
                            match_obj["match_type"] = json!("pattern");
                            match_obj["pattern_count"] = json!(pattern_ids.len());
                            if !data.is_empty() {
                                let data_json: Vec<_> = data
                                    .iter()
                                    .filter_map(|d| d.as_ref().map(data_value_to_json))
                                    .collect();
                                if !data_json.is_empty() {
                                    match_obj["data"] = json!(data_json);
                                }
                            }
                        }
                        Some(matchy::QueryResult::Ip { data, prefix_len }) => {
                            match_obj["match_type"] = json!("ip");
                            match_obj["prefix_len"] = json!(prefix_len);
                            match_obj["cidr"] = json!(format_cidr(&candidate_str, *prefix_len));
                            match_obj["data"] = data_value_to_json(data);
                        }
                        _ => {}
                    }

                    // Write to stdout
                    println!("{}", serde_json::to_string(&match_obj)?);
                }
            }
        }
    }

    let overall_elapsed = overall_start.elapsed();

    // Output summary stats to stderr
    if show_stats {
        let db_stats = db.stats();

        eprintln!();
        eprintln!("[INFO] Processing complete");
        eprintln!("[INFO] Lines processed: {}", format_number(lines_processed));
        eprintln!(
            "[INFO] Lines with matches: {} ({:.1}%)",
            format_number(lines_with_matches),
            if lines_processed > 0 {
                (lines_with_matches as f64 / lines_processed as f64) * 100.0
            } else {
                0.0
            }
        );
        eprintln!("[INFO] Total matches: {}", format_number(total_matches));
        eprintln!(
            "[INFO] Candidates tested: {}",
            format_number(candidates_tested)
        );

        if ipv4_count > 0 {
            eprintln!("[INFO]   IPv4: {}", format_number(ipv4_count));
        }
        if ipv6_count > 0 {
            eprintln!("[INFO]   IPv6: {}", format_number(ipv6_count));
        }
        if domain_count > 0 {
            eprintln!("[INFO]   Domains: {}", format_number(domain_count));
        }
        if email_count > 0 {
            eprintln!("[INFO]   Emails: {}", format_number(email_count));
        }
        if url_count > 0 {
            eprintln!("[INFO]   URLs: {}", format_number(url_count));
        }

        eprintln!(
            "[INFO] Throughput: {:.2} MB/s",
            if overall_elapsed.as_secs_f64() > 0.0 {
                (total_bytes as f64 / 1_000_000.0) / overall_elapsed.as_secs_f64()
            } else {
                0.0
            }
        );
        eprintln!("[INFO] Total time: {:.2}s", overall_elapsed.as_secs_f64());
        eprintln!(
            "[INFO] Extraction time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            extraction_time.as_secs_f64(),
            if extraction_samples > 0 {
                extraction_time.as_nanos() as f64 / 1000.0 / extraction_samples as f64
            } else {
                0.0
            },
            format_number(extraction_samples)
        );
        eprintln!(
            "[INFO] Lookup time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            lookup_time.as_secs_f64(),
            if lookup_samples > 0 {
                lookup_time.as_nanos() as f64 / 1000.0 / lookup_samples as f64
            } else {
                0.0
            },
            format_number(lookup_samples)
        );
        eprintln!(
            "[INFO] Query rate: {} candidates/sec (overall)",
            format_qps(if overall_elapsed.as_secs_f64() > 0.0 {
                candidates_tested as f64 / overall_elapsed.as_secs_f64()
            } else {
                0.0
            })
        );

        if cache_size > 0 {
            eprintln!(
                "[INFO] Cache: {} entries ({:.1}% hit rate)",
                format_number(cache_size),
                db_stats.cache_hit_rate() * 100.0
            );
        }
    }

    Ok(())
}

fn cmd_query(database: PathBuf, query: String, quiet: bool, trusted: bool) -> Result<()> {
    use matchy::{Database, QueryResult};

    // Load database using fluent API
    let mut opener = Database::from(database.to_str().unwrap());

    if trusted {
        opener = opener.trusted();
    }

    let db = opener
        .open()
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

    // Load database using fluent API
    let db = Database::from(database.to_str().unwrap())
        .open()
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

fn cmd_validate(
    database: PathBuf,
    level_str: String,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    use matchy::validation::{validate_database, ValidationLevel};

    // Parse validation level
    let level = match level_str.to_lowercase().as_str() {
        "standard" => ValidationLevel::Standard,
        "strict" => ValidationLevel::Strict,
        "audit" => ValidationLevel::Audit,
        _ => {
            anyhow::bail!(
                "Invalid validation level: '{}'. Must be: standard, strict, or audit",
                level_str
            );
        }
    };

    // Validate the database
    let start = Instant::now();
    let report = validate_database(&database, level)
        .with_context(|| format!("Validation failed: {}", database.display()))?;
    let duration = start.elapsed();

    // Output results
    if json_output {
        let output = json!({
            "database": database.display().to_string(),
            "validation_level": level_str,
            "is_valid": report.is_valid(),
            "duration_ms": duration.as_millis(),
            "errors": report.errors,
            "warnings": report.warnings,
            "info": report.info,
            "stats": {
                "file_size": report.stats.file_size,
                "version": report.stats.version,
                "ac_node_count": report.stats.ac_node_count,
                "pattern_count": report.stats.pattern_count,
                "ip_entry_count": report.stats.ip_entry_count,
                "literal_count": report.stats.literal_count,
                "glob_count": report.stats.glob_count,
                "has_data_section": report.stats.has_data_section,
                "has_ac_literal_mapping": report.stats.has_ac_literal_mapping,
                "max_ac_depth": report.stats.max_ac_depth,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        println!("Validating: {}", database.display());
        println!("Level:      {}", level_str);
        println!();

        // Statistics
        println!("Statistics:");
        println!("  {}", report.stats.summary());
        println!("  Validation time: {:.2}ms", duration.as_millis());
        println!();

        // Errors
        if !report.errors.is_empty() {
            println!("❌ ERRORS ({}):", report.errors.len());
            for error in &report.errors {
                println!("  • {}", error);
            }
            println!();
        }

        // Warnings
        if !report.warnings.is_empty() && verbose {
            println!("⚠️  WARNINGS ({}):", report.warnings.len());
            for warning in &report.warnings {
                println!("  • {}", warning);
            }
            println!();
        } else if !report.warnings.is_empty() {
            println!(
                "⚠️  {} warning(s) (use --verbose to show)",
                report.warnings.len()
            );
            println!();
        }

        // Info messages
        if verbose && !report.info.is_empty() {
            println!("ℹ️  INFORMATION ({}):", report.info.len());
            for info in &report.info {
                println!("  • {}", info);
            }
            println!();
        }

        // Final verdict
        if report.is_valid() {
            println!("✅ VALIDATION PASSED");
            println!("   Database is safe to use.");
        } else {
            println!("❌ VALIDATION FAILED");
            println!("   Database has {} critical error(s).", report.errors.len());
            println!("   DO NOT use this database without fixing the errors.");
        }
    }

    // Exit with appropriate code
    if report.is_valid() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_build(
    inputs: Vec<PathBuf>,
    output: PathBuf,
    format: String,
    database_type: Option<String>,
    description: Option<String>,
    desc_lang: String,
    verbose: bool,
    case_insensitive: bool,
) -> Result<()> {
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;

    let match_mode = if case_insensitive {
        MatchMode::CaseInsensitive
    } else {
        MatchMode::CaseSensitive
    };

    if verbose {
        println!("Building unified MMDB database (IP + patterns)...");
        println!("  Input files: {}", inputs.len());
        for input in &inputs {
            println!("    - {}", input.display());
        }
        println!("  Output: {}", output.display());
        println!("  Format: {}", format);
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

    let mut builder = MmdbBuilder::new(match_mode);

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

    // Set file to read-only to protect mmap integrity
    set_readonly(&output).with_context(|| {
        format!(
            "Failed to set read-only permissions on: {}",
            output.display()
        )
    })?;

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

#[allow(clippy::too_many_arguments)]
fn cmd_bench(
    db_type: String,
    count: usize,
    output: Option<PathBuf>,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    hit_rate: usize,
    trusted: bool,
    cache_size: usize,
    cache_hit_rate: usize,
    pattern_style: String,
) -> Result<()> {
    println!("=== Matchy Database Benchmark ===\n");
    println!("Configuration:");
    println!("  Database type:     {}", db_type);
    println!("  Entry count:       {}", format_number(count));
    println!("  Load iterations:   {}", load_iterations);
    println!("  Query iterations:  {}", format_number(query_count));
    println!(
        "  Match rate:        {}% (queries that find entries)",
        hit_rate
    );
    println!(
        "  Cache size:        {}",
        if cache_size == 0 {
            "disabled".to_string()
        } else {
            format_number(cache_size)
        }
    );
    println!(
        "  Cache hit rate:    {}% (query repetition{})",
        cache_hit_rate,
        if cache_hit_rate == 0 {
            " - worst case"
        } else {
            ""
        }
    );
    if db_type == "pattern" {
        println!("  Pattern style:     {}", pattern_style);
    }
    if trusted {
        println!("  Trust mode:        TRUSTED (UTF-8 validation disabled)");
    }
    println!();

    // Determine output file
    let temp_file = output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/matchy_bench_{}_{}.mxy", db_type, count)));

    match db_type.as_str() {
        "ip" => bench_ip_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            cache_size,
            cache_hit_rate,
        ),
        "literal" => bench_literal_database(BenchConfig {
            count,
            temp_file: &temp_file,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
        }),
        "pattern" => bench_pattern_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
            &pattern_style,
        ),
        "combined" => bench_combined_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            cache_size,
            cache_hit_rate,
        ),
        _ => {
            anyhow::bail!(
                "Unknown database type: {}. Use 'ip', 'literal', 'pattern', or 'combined'",
                db_type
            );
        }
    }
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_qps(qps: f64) -> String {
    if qps >= 1_000_000.0 {
        format!("{:.2}M", qps / 1_000_000.0)
    } else if qps >= 1_000.0 {
        format!("{:.2}K", qps / 1_000.0)
    } else {
        format!("{:.2}", qps)
    }
}

fn bench_ip_database(
    count: usize,
    temp_file: &PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    cache_size: usize,
    cache_hit_rate: usize,
) -> Result<()> {
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;

    println!("--- Phase 1: Build IP Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-IP")
        .with_description("en", "IP database benchmark");

    let empty_data = HashMap::new();
    for i in 0..count {
        let ip_num = i as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip_str = format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4);
        builder.add_ip(&ip_str, empty_data.clone())?;

        if count > 100_000 && (i + 1) % 1_000_000 == 0 {
            println!(
                "  Progress: {}/{}",
                format_number(i + 1),
                format_number(count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} IPs/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!();

    println!("--- Phase 2: Save to Disk ---");
    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();
    println!("  Save time:   {:.2}s", save_time.as_secs_f64());
    drop(db_bytes);
    println!();

    println!("--- Phase 3: Load Database (mmap) ---");
    let mut load_times = Vec::new();
    for i in 1..=load_iterations {
        let load_start = Instant::now();
        let _db = Database::from(temp_file.to_str().unwrap()).open()?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);
        println!(
            "  Load #{}: {:.3}ms",
            i,
            load_time.as_micros() as f64 / 1000.0
        );
    }
    let avg_load = load_times.iter().sum::<std::time::Duration>() / load_iterations as u32;
    println!("  Average:  {:.3}ms", avg_load.as_micros() as f64 / 1000.0);
    println!();

    println!("--- Phase 4: Query Performance ---");
    let mut opener = Database::from(temp_file.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener.open()?;

    // Calculate unique query count to achieve target cache hit rate
    let unique_queries = if cache_hit_rate >= 100 {
        1 // All queries hit same entry
    } else if cache_hit_rate == 0 {
        query_count // Every query unique
    } else {
        let unique = query_count * (100 - cache_hit_rate) / 100;
        unique.max(1)
    };

    let bench_start = Instant::now();
    let mut found = 0;

    for i in 0..query_count {
        let ip_num = ((i * 43) % unique_queries.min(count)) as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip = std::net::Ipv4Addr::new(octet1 as u8, octet2 as u8, octet3 as u8, octet4 as u8);

        if let Some(matchy::QueryResult::Ip { .. }) = db.lookup_ip(std::net::IpAddr::V4(ip))? {
            found += 1;
        }
    }

    let bench_time = bench_start.elapsed();
    let qps = query_count as f64 / bench_time.as_secs_f64();
    let avg_query = bench_time / query_count as u32;

    println!("  Query count: {}", format_number(query_count));
    println!("  Total time:  {:.2}s", bench_time.as_secs_f64());
    println!("  QPS:         {} queries/sec", format_qps(qps));
    println!(
        "  Avg latency: {:.2}µs",
        avg_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Found:       {}/{}",
        format_number(found),
        format_number(query_count)
    );
    println!();

    if !keep {
        std::fs::remove_file(temp_file)?;
        println!("✓ Benchmark complete (temp file removed)");
    } else {
        println!("✓ Benchmark complete (file kept: {})", temp_file.display());
    }

    Ok(())
}

struct BenchConfig<'a> {
    count: usize,
    temp_file: &'a PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    hit_rate: usize,
    trusted: bool,
    cache_size: usize,
    cache_hit_rate: usize,
}

fn bench_literal_database(config: BenchConfig) -> Result<()> {
    let BenchConfig {
        count,
        temp_file,
        keep,
        load_iterations,
        query_count,
        hit_rate,
        trusted,
        cache_size,
        cache_hit_rate,
    } = config;
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;

    println!("--- Phase 1: Build Literal Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Literal")
        .with_description("en", "Literal database benchmark");

    let empty_data = HashMap::new();

    // Generate realistic literal strings (domains, URLs, file paths, identifiers)
    let tlds = [
        "com", "net", "org", "io", "co", "dev", "app", "tech", "xyz", "cloud",
    ];
    let categories = [
        "api", "cdn", "web", "mail", "ftp", "vpn", "db", "auth", "admin", "test",
    ];
    let services = [
        "service", "server", "endpoint", "gateway", "proxy", "router", "node", "host", "instance",
        "cluster",
    ];

    for i in 0..count {
        // Generate varied literal patterns without wildcards
        let literal = match i % 10 {
            0 => {
                // Domain-style literals
                let cat = categories[i % categories.len()];
                let svc = services[(i / 10) % services.len()];
                let tld = tlds[i % tlds.len()];
                format!("{}-{}-{}.example.{}", cat, svc, i, tld)
            }
            1 => {
                // URL path literals
                let cat = categories[i % categories.len()];
                format!("/api/v2/{}/endpoint/{}/resource", cat, i)
            }
            2 => {
                // File path literals
                let svc = services[i % services.len()];
                format!("/var/log/{}/application-{}.log", svc, i)
            }
            3 => {
                // Email-style literals
                let cat = categories[i % categories.len()];
                let tld = tlds[i % tlds.len()];
                format!("{}user{}@domain{}.{}", cat, i, i % 100, tld)
            }
            4 => {
                // UUID-style literals
                format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    i,
                    (i >> 16) & 0xFFFF,
                    (i >> 8) & 0xFFFF,
                    i & 0xFFFF,
                    i * 1000
                )
            }
            5 => {
                // Database table.column literals
                let cat = categories[i % categories.len()];
                let svc = services[i % services.len()];
                format!("{}_table_{}.{}_column", cat, i, svc)
            }
            6 => {
                // API key style literals
                format!("sk_live_{:016x}_{:016x}", i, i * 7)
            }
            7 => {
                // Container/image literals
                let cat = categories[i % categories.len()];
                format!(
                    "docker.io/myorg/{}-image:v{}.{}.{}",
                    cat,
                    i / 100,
                    i % 10,
                    i % 5
                )
            }
            8 => {
                // Git branch/tag literals
                let cat = categories[i % categories.len()];
                format!("feature/{}-implementation-{}", cat, i)
            }
            _ => {
                // Simple identifier literals
                let cat = categories[i % categories.len()];
                let svc = services[i % services.len()];
                format!("{}_{}_{}", cat, svc, i)
            }
        };
        builder.add_literal(&literal, empty_data.clone())?;

        if count > 10_000 && (i + 1) % 10_000 == 0 {
            println!(
                "  Progress: {}/{}",
                format_number(i + 1),
                format_number(count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} literals/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!();

    println!("--- Phase 2: Save to Disk ---");
    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();
    println!("  Save time:   {:.2}s", save_time.as_secs_f64());
    drop(db_bytes);
    println!();

    println!("--- Phase 3: Load Database (mmap) ---");
    let mut load_times = Vec::new();
    for i in 1..=load_iterations {
        let load_start = Instant::now();
        let mut opener = Database::from(temp_file.to_str().unwrap());
        if trusted {
            opener = opener.trusted();
        }
        let _db = opener.open()?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);
        println!(
            "  Load #{}: {:.3}ms",
            i,
            load_time.as_micros() as f64 / 1000.0
        );
    }
    let avg_load = load_times.iter().sum::<std::time::Duration>() / load_iterations as u32;
    println!("  Average:  {:.3}ms", avg_load.as_micros() as f64 / 1000.0);
    println!();

    println!("--- Phase 4: Query Performance ---");
    let mut opener = Database::from(temp_file.to_str().unwrap());
    if trusted {
        opener = opener.trusted();
    }
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener.open()?;

    // Calculate unique query count to achieve target cache hit rate
    let unique_queries = if cache_hit_rate >= 100 {
        1 // All queries hit same entry
    } else if cache_hit_rate == 0 {
        query_count // Every query unique
    } else {
        let unique = query_count * (100 - cache_hit_rate) / 100;
        unique.max(1)
    };

    let bench_start = Instant::now();
    let mut found = 0;

    let tlds = [
        "com", "net", "org", "io", "co", "dev", "app", "tech", "xyz", "cloud",
    ];
    let categories = [
        "api", "cdn", "web", "mail", "ftp", "vpn", "db", "auth", "admin", "test",
    ];
    let services = [
        "service", "server", "endpoint", "gateway", "proxy", "router", "node", "host", "instance",
        "cluster",
    ];

    for i in 0..query_count {
        // Use modulo to cycle through a limited pool of queries for cache hits
        let query_idx = i % unique_queries;

        // Determine if this query should hit (match) based on hit_rate
        let should_hit = (query_idx * 100 / unique_queries) < hit_rate;

        let test_str = if !should_hit {
            // Generate non-matching query
            format!("nomatch-query-string-{}", query_idx)
        } else {
            // Generate matching query - must exactly match one of the patterns
            let pattern_id = (query_idx * 43) % count;

            match pattern_id % 10 {
                0 => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[(pattern_id / 10) % services.len()];
                    let tld = tlds[pattern_id % tlds.len()];
                    format!("{}-{}-{}.example.{}", cat, svc, pattern_id, tld)
                }
                1 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!("/api/v2/{}/endpoint/{}/resource", cat, pattern_id)
                }
                2 => {
                    let svc = services[pattern_id % services.len()];
                    format!("/var/log/{}/application-{}.log", svc, pattern_id)
                }
                3 => {
                    let cat = categories[pattern_id % categories.len()];
                    let tld = tlds[pattern_id % tlds.len()];
                    format!(
                        "{}user{}@domain{}.{}",
                        cat,
                        pattern_id,
                        pattern_id % 100,
                        tld
                    )
                }
                4 => format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    pattern_id,
                    (pattern_id >> 16) & 0xFFFF,
                    (pattern_id >> 8) & 0xFFFF,
                    pattern_id & 0xFFFF,
                    pattern_id * 1000
                ),
                5 => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[pattern_id % services.len()];
                    format!("{}_table_{}.{}_column", cat, pattern_id, svc)
                }
                6 => format!("sk_live_{:016x}_{:016x}", pattern_id, pattern_id * 7),
                7 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!(
                        "docker.io/myorg/{}-image:v{}.{}.{}",
                        cat,
                        pattern_id / 100,
                        pattern_id % 10,
                        pattern_id % 5
                    )
                }
                8 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!("feature/{}-implementation-{}", cat, pattern_id)
                }
                _ => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[pattern_id % services.len()];
                    format!("{}_{}_{}", cat, svc, pattern_id)
                }
            }
        };

        if let Some(matchy::QueryResult::Pattern { pattern_ids, .. }) = db.lookup(&test_str)? {
            if !pattern_ids.is_empty() {
                found += 1;
            }
        }
    }

    let bench_time = bench_start.elapsed();
    let qps = query_count as f64 / bench_time.as_secs_f64();
    let avg_query = bench_time / query_count as u32;

    println!("  Query count: {}", format_number(query_count));
    println!("  Total time:  {:.2}s", bench_time.as_secs_f64());
    println!("  QPS:         {} queries/sec", format_qps(qps));
    println!(
        "  Avg latency: {:.2}µs",
        avg_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Found:       {}/{}",
        format_number(found),
        format_number(query_count)
    );
    println!();

    if !keep {
        std::fs::remove_file(temp_file)?;
        println!("✓ Benchmark complete (temp file removed)");
    } else {
        println!("✓ Benchmark complete (file kept: {})", temp_file.display());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn bench_pattern_database(
    count: usize,
    temp_file: &PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    hit_rate: usize,
    trusted: bool,
    cache_size: usize,
    cache_hit_rate: usize,
    pattern_style: &str,
) -> Result<()> {
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;

    println!("--- Phase 1: Build Pattern Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Pattern")
        .with_description("en", "Pattern database benchmark");

    let empty_data = HashMap::new();

    // Pattern generation based on style
    let tlds = [
        "com", "net", "org", "ru", "cn", "xyz", "tk", "info", "io", "cc",
    ];
    let malicious_words = [
        "malware", "phishing", "trojan", "evil", "attack", "botnet", "spam", "scam", "fake",
        "virus",
    ];
    let domains = [
        "domain", "site", "server", "host", "web", "portal", "service", "cloud", "zone", "network",
    ];

    for i in 0..count {
        // Generate patterns based on the requested style
        let pattern = match pattern_style {
            "prefix" => {
                // Pure prefix patterns: "prefix-*"
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                match i % 4 {
                    0 => format!("{}-{}-*", word, domain_word),
                    1 => format!("{}-{}-{}-*", word, domain_word, i % 1000),
                    2 => format!("threat-{}-*.{}", domain_word, tld),
                    _ => format!("{}{}-*", word, i % 1000),
                }
            }
            "suffix" => {
                // Pure suffix patterns: "*.domain.com"
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                match i % 4 {
                    0 => format!("*.{}-{}-{}.{}", word, domain_word, i, tld),
                    1 => format!("*.{}{}.{}", domain_word, i, tld),
                    2 => format!("*.{}-threat.{}", word, tld),
                    _ => format!("*.evil-{}.{}", i % 1000, tld),
                }
            }
            "mixed" => {
                // 50% prefix, 50% suffix
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                if i % 2 == 0 {
                    // Prefix
                    format!("{}-{}-*", word, domain_word)
                } else {
                    // Suffix
                    format!("*.{}-{}.{}", word, domain_word, tld)
                }
            }
            _ => {
                // "complex" - original complex patterns with multiple wildcards
                if i % 20 == 0 {
                    // ~5% complex patterns (multiple wildcards, character classes)
                    let word = malicious_words[i % malicious_words.len()];
                    let tld = tlds[(i / 20) % tlds.len()];
                    match (i / 20) % 4 {
                        0 => format!("*[0-9].*.{}-attack-{}.{}", word, i, tld),
                        1 => format!("{}-*-server[0-9][0-9].evil-{}.{}", word, i, tld),
                        2 => format!("*.{}-campaign-*-{}.{}", word, i, tld),
                        _ => format!("*bad*.{}-?.infection-{}.{}", word, i, tld),
                    }
                } else {
                    // 95% simpler but still diverse patterns
                    let word = malicious_words[i % malicious_words.len()];
                    let domain_word = domains[(i / 7) % domains.len()];
                    let tld = tlds[i % tlds.len()];

                    match i % 8 {
                        0 => format!("*.{}-{}-{}.{}", word, domain_word, i, tld),
                        1 => format!("{}-{}*.bad-{}.{}", word, domain_word, i, tld),
                        2 => format!("evil-{}-*.tracker-{}.{}", domain_word, i, tld),
                        3 => format!("*-{}-{}.threat{}.{}", word, domain_word, i, tld),
                        4 => format!("suspicious-*.{}-zone-{}.{}", domain_word, i, tld),
                        5 => format!("*.{}{}.{}-network.{}", word, i, domain_word, tld),
                        6 => format!("bad-{}-{}.*.{}", word, i, tld),
                        _ => format!("{}-threat-*.{}{}.{}", word, domain_word, i, tld),
                    }
                }
            }
        };
        builder.add_glob(&pattern, empty_data.clone())?;

        if count > 10_000 && (i + 1) % 10_000 == 0 {
            println!(
                "  Progress: {}/{}",
                format_number(i + 1),
                format_number(count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} patterns/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!();

    println!("--- Phase 2: Save to Disk ---");
    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();
    println!("  Save time:   {:.2}s", save_time.as_secs_f64());
    drop(db_bytes);
    println!();

    println!("--- Phase 3: Load Database (mmap) ---");
    let mut load_times = Vec::new();
    for i in 1..=load_iterations {
        let load_start = Instant::now();
        let mut opener = Database::from(temp_file.to_str().unwrap());
        if trusted {
            opener = opener.trusted();
        }
        let _db = opener.open()?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);
        println!(
            "  Load #{}: {:.3}ms",
            i,
            load_time.as_micros() as f64 / 1000.0
        );
    }
    let avg_load = load_times.iter().sum::<std::time::Duration>() / load_iterations as u32;
    println!("  Average:  {:.3}ms", avg_load.as_micros() as f64 / 1000.0);
    println!();

    println!("--- Phase 4: Query Performance ---");
    let mut opener = Database::from(temp_file.to_str().unwrap());
    if trusted {
        opener = opener.trusted();
    }
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener.open()?;
    let bench_start = Instant::now();
    let mut found = 0;

    let tlds = [
        "com", "net", "org", "ru", "cn", "xyz", "tk", "info", "io", "cc",
    ];
    let malicious_words = [
        "malware", "phishing", "trojan", "evil", "attack", "botnet", "spam", "scam", "fake",
        "virus",
    ];
    let domains = [
        "domain", "site", "server", "host", "web", "portal", "service", "cloud", "zone", "network",
    ];

    // Generate a pool of queries for cache simulation
    let unique_query_count = if cache_hit_rate == 0 {
        query_count // All unique queries (worst case)
    } else {
        // Calculate how many unique queries we need to achieve target cache hit rate
        // If cache_hit_rate is 80%, we want 20% unique queries
        let unique_pct = 100 - cache_hit_rate;
        (query_count * unique_pct / 100).max(1)
    };

    for i in 0..query_count {
        // Map query index to a unique query ID (for cache hit simulation)
        let query_id = i % unique_query_count;

        // Determine if this query should hit (match) based on hit_rate
        let should_hit = (query_id * 100 / unique_query_count) < hit_rate;

        let test_str = if !should_hit {
            // Generate non-matching query (benign traffic)
            format!("benign-clean-traffic-{}.legitimate-site.com", query_id)
        } else {
            // Generate matching query based on pattern_id and style
            let pattern_id = (query_id * 43) % count;
            let word = malicious_words[pattern_id % malicious_words.len()];
            let domain_word = domains[(pattern_id / 7) % domains.len()];
            let tld = tlds[pattern_id % tlds.len()];

            match pattern_style {
                "prefix" => {
                    // Match prefix patterns
                    match pattern_id % 4 {
                        0 => format!("{}-{}-suffix-{}", word, domain_word, i),
                        1 => format!("{}-{}-{}-end", word, domain_word, pattern_id % 1000),
                        2 => format!("threat-{}-middle.{}", domain_word, tld),
                        _ => format!("{}{}-anything", word, pattern_id % 1000),
                    }
                }
                "suffix" => {
                    // Match suffix patterns
                    match pattern_id % 4 {
                        0 => format!("prefix.{}-{}-{}.{}", word, domain_word, pattern_id, tld),
                        1 => format!("subdomain.{}{}.{}", domain_word, pattern_id, tld),
                        2 => format!("any.{}-threat.{}", word, tld),
                        _ => format!("prefix.evil-{}.{}", pattern_id % 1000, tld),
                    }
                }
                "mixed" => {
                    // Match mixed patterns
                    if pattern_id.is_multiple_of(2) {
                        // Prefix pattern match
                        format!("{}-{}-suffix", word, domain_word)
                    } else {
                        // Suffix pattern match
                        format!("prefix.{}-{}.{}", word, domain_word, tld)
                    }
                }
                _ => {
                    // "complex" - match original complex patterns
                    if pattern_id.is_multiple_of(20) {
                        // Match complex patterns (~5%)
                        match (pattern_id / 20) % 4 {
                            0 => format!("prefix5.middle.{}-attack-{}.{}", word, pattern_id, tld),
                            1 => format!("{}-middle-server99.evil-{}.{}", word, pattern_id, tld),
                            2 => format!("prefix.{}-campaign-middle-{}.{}", word, pattern_id, tld),
                            _ => format!(
                                "firstbadsecond.{}-x.infection-{}.{}",
                                word, pattern_id, tld
                            ),
                        }
                    } else {
                        // Match simpler patterns (95%)
                        match pattern_id % 8 {
                            0 => format!("prefix.{}-{}-{}.{}", word, domain_word, pattern_id, tld),
                            1 => {
                                format!("{}-{}middle.bad-{}.{}", word, domain_word, pattern_id, tld)
                            }
                            2 => format!(
                                "evil-{}-middle.tracker-{}.{}",
                                domain_word, pattern_id, tld
                            ),
                            3 => format!(
                                "prefix-{}-{}.threat{}.{}",
                                word, domain_word, pattern_id, tld
                            ),
                            4 => format!(
                                "suspicious-middle.{}-zone-{}.{}",
                                domain_word, pattern_id, tld
                            ),
                            5 => format!(
                                "prefix.{}{}.{}-network.{}",
                                word, pattern_id, domain_word, tld
                            ),
                            6 => format!("bad-{}-{}.middle.{}", word, pattern_id, tld),
                            _ => format!(
                                "{}-threat-middle.{}{}.{}",
                                word, domain_word, pattern_id, tld
                            ),
                        }
                    }
                }
            }
        };

        if let Some(matchy::QueryResult::Pattern { pattern_ids, .. }) = db.lookup(&test_str)? {
            if !pattern_ids.is_empty() {
                found += 1;
            }
        }
    }

    let bench_time = bench_start.elapsed();
    let qps = query_count as f64 / bench_time.as_secs_f64();
    let avg_query = bench_time / query_count as u32;

    println!("  Query count: {}", format_number(query_count));
    println!("  Total time:  {:.2}s", bench_time.as_secs_f64());
    println!("  QPS:         {} queries/sec", format_qps(qps));
    println!(
        "  Avg latency: {:.2}µs",
        avg_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Found:       {}/{}",
        format_number(found),
        format_number(query_count)
    );
    println!();

    if !keep {
        std::fs::remove_file(temp_file)?;
        println!("✓ Benchmark complete (temp file removed)");
    } else {
        println!("✓ Benchmark complete (file kept: {})", temp_file.display());
    }

    Ok(())
}

fn bench_combined_database(
    count: usize,
    temp_file: &PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    cache_size: usize,
    cache_hit_rate: usize,
) -> Result<()> {
    use matchy::glob::MatchMode;
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;

    println!("--- Phase 1: Build Combined Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Combined")
        .with_description("en", "Combined IP+Pattern benchmark");

    let empty_data = HashMap::new();

    // Add IPs (half the count)
    let ip_count = count / 2;
    for i in 0..ip_count {
        let ip_num = i as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip_str = format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4);
        builder.add_ip(&ip_str, empty_data.clone())?;

        if ip_count > 100_000 && (i + 1) % 500_000 == 0 {
            println!(
                "  IP progress: {}/{}",
                format_number(i + 1),
                format_number(ip_count)
            );
        }
    }

    // Add patterns (other half)
    let pattern_count = count - ip_count;
    for i in 0..pattern_count {
        // Generate varied patterns with ~5% complex ones
        let pattern = if i % 20 == 0 {
            // ~5% complex patterns
            match (i / 20) % 4 {
                0 => format!("*[0-9].*.attacker{}.com", i),
                1 => format!("evil-*-[a-z][a-z].*.domain{}.net", i),
                2 => "*.malware-[0-9][0-9][0-9]-*.com".to_string(),
                _ => "*bad*.phishing-?.*.org".to_string(),
            }
        } else {
            match i % 4 {
                0 => format!("*.domain{}.com", i),
                1 => format!("subdomain{}.*.com", i),
                2 => format!("test-{}-*.com", i),
                _ => format!("*-{}.net", i),
            }
        };
        builder.add_glob(&pattern, empty_data.clone())?;

        if pattern_count > 10_000 && (i + 1) % 5_000 == 0 {
            println!(
                "  Pattern progress: {}/{}",
                format_number(i + 1),
                format_number(pattern_count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} entries/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!("  IPs:         {}", format_number(ip_count));
    println!("  Patterns:    {}", format_number(pattern_count));
    println!();

    println!("--- Phase 2: Save to Disk ---");
    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();
    println!("  Save time:   {:.2}s", save_time.as_secs_f64());
    drop(db_bytes);
    println!();

    println!("--- Phase 3: Load Database (mmap) ---");
    let mut load_times = Vec::new();
    for i in 1..=load_iterations {
        let load_start = Instant::now();
        let _db = Database::from(temp_file.to_str().unwrap()).open()?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);
        println!(
            "  Load #{}: {:.3}ms",
            i,
            load_time.as_micros() as f64 / 1000.0
        );
    }
    let avg_load = load_times.iter().sum::<std::time::Duration>() / load_iterations as u32;
    println!("  Average:  {:.3}ms", avg_load.as_micros() as f64 / 1000.0);
    println!();

    println!("--- Phase 4: Query Performance ---");
    let mut opener = Database::from(temp_file.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener.open()?;

    // Calculate unique query count to achieve target cache hit rate
    let unique_queries = if cache_hit_rate >= 100 {
        1 // All queries hit same entry
    } else if cache_hit_rate == 0 {
        query_count // Every query unique
    } else {
        let unique = query_count * (100 - cache_hit_rate) / 100;
        unique.max(1)
    };

    // Query both IPs and patterns
    let bench_start = Instant::now();
    let mut ip_found = 0;
    let mut pattern_found = 0;

    let half_queries = query_count / 2;
    let unique_half = unique_queries / 2;

    // Query IPs
    for i in 0..half_queries {
        let query_idx = i % unique_half.max(1);
        let ip_num = ((query_idx * 43) % ip_count) as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip = std::net::Ipv4Addr::new(octet1 as u8, octet2 as u8, octet3 as u8, octet4 as u8);

        if let Some(matchy::QueryResult::Ip { .. }) = db.lookup_ip(std::net::IpAddr::V4(ip))? {
            ip_found += 1;
        }
    }

    // Query patterns
    for i in 0..(query_count - half_queries) {
        let query_idx = i % unique_half.max(1);
        let pattern_id = (query_idx * 43) % pattern_count;
        let test_str = if pattern_id.is_multiple_of(20) {
            // Match complex patterns (~5%)
            match (pattern_id / 20) % 4 {
                0 => format!("prefix5.suffix.attacker{}.com", pattern_id),
                1 => format!("evil-middle-ab.end.domain{}.net", pattern_id),
                2 => "prefix.malware-123-suffix.com".to_string(),
                _ => "firstbadsecond.phishing-x.end.org".to_string(),
            }
        } else {
            match pattern_id % 4 {
                0 => format!("prefix.domain{}.com", pattern_id),
                1 => format!("subdomain{}.middle.com", pattern_id),
                2 => format!("test-{}-suffix.com", pattern_id),
                _ => format!("prefix-{}.net", pattern_id),
            }
        };

        if let Some(matchy::QueryResult::Pattern { pattern_ids, .. }) = db.lookup(&test_str)? {
            if !pattern_ids.is_empty() {
                pattern_found += 1;
            }
        }
    }

    let bench_time = bench_start.elapsed();
    let qps = query_count as f64 / bench_time.as_secs_f64();
    let avg_query = bench_time / query_count as u32;

    println!("  Query count: {}", format_number(query_count));
    println!("  Total time:  {:.2}s", bench_time.as_secs_f64());
    println!("  QPS:         {} queries/sec", format_qps(qps));
    println!(
        "  Avg latency: {:.2}µs",
        avg_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  IP found:    {}/{}",
        format_number(ip_found),
        format_number(half_queries)
    );
    println!(
        "  Pattern found: {}/{}",
        format_number(pattern_found),
        format_number(query_count - half_queries)
    );
    println!();

    if !keep {
        std::fs::remove_file(temp_file)?;
        println!("✓ Benchmark complete (temp file removed)");
    } else {
        println!("✓ Benchmark complete (file kept: {})", temp_file.display());
    }

    Ok(())
}
