use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use crate::commands::utils::{
    data_value_to_json, format_cidr, format_number, format_qps, LineScanner,
};

pub fn cmd_match(
    database: PathBuf,
    inputs: Vec<PathBuf>,
    follow: bool,
    format: String,
    show_stats: bool,
    trusted: bool,
    cache_size: usize,
) -> Result<()> {
    use matchy::extractor::PatternExtractor;
    use matchy::Database;
    // use notify::{Watcher, RecursiveMode, Event, EventKind};
    // use std::sync::mpsc::channel;
    // use std::time::Duration;
    // ^ Imports ready for tailing implementation

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
        builder = builder.extract_domains(false).extract_emails(false);
    }

    let extractor = builder
        .build()
        .context("Failed to create pattern extractor")?;

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

    // TODO: Implement multi-file and tailing support
    // The line processing logic (lines 585-714) needs to be extracted into a helper function
    // that can be called for each file. For tailing:
    // 1. Use notify::Watcher to watch file(s) for modifications
    // 2. Track file position (seek offset) to resume after new data appears
    // 3. Handle file rotation (detect when file shrinks or is recreated)
    // 4. Process multiple files concurrently using channels
    //
    // Current limitation: Only processes first file, no tailing support yet.

    if follow {
        anyhow::bail!(
            "--follow flag not yet implemented.\n\n\
             Implementation requires:\n\
               1. Extracting line processing into helper function\n\
               2. Using notify crate for file watching\n\
               3. Tracking file offsets for resumption\n\
               4. Handling log rotation\n\n\
             Contributions welcome!"
        );
    }

    // Validate input
    if inputs.is_empty() {
        anyhow::bail!("No input files specified");
    }

    let _use_stdin = inputs.len() == 1 && inputs[0].to_str() == Some("-");
    let input = &inputs[0];

    if show_stats && inputs.len() > 1 {
        eprintln!("[WARN] Multiple files specified, but only first file will be processed");
        eprintln!("[WARN] Multi-file support coming soon!");
    }

    // Open input for streaming (file or stdin) with 128KB buffer
    const BUFFER_SIZE: usize = 128 * 1024; // 128KB - optimal for log file processing
    let reader: Box<dyn io::BufRead> = if input.to_str() == Some("-") {
        Box::new(io::BufReader::with_capacity(BUFFER_SIZE, io::stdin()))
    } else {
        Box::new(io::BufReader::with_capacity(
            BUFFER_SIZE,
            fs::File::open(input)
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
