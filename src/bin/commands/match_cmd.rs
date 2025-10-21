use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use crate::cli_utils::{format_number, format_qps};
use crate::match_processor::{
    follow_files, follow_files_parallel, process_file_with_aggregate, process_parallel,
    ProcessingStats,
};

#[allow(clippy::too_many_arguments)]
pub fn cmd_match(
    database: PathBuf,
    inputs: Vec<PathBuf>,
    follow: bool,
    threads_arg: Option<String>,
    batch_bytes: usize,
    format: String,
    show_stats: bool,
    show_progress: bool,
    trusted: bool,
    cache_size: usize,
) -> Result<()> {
    use matchy::extractor::PatternExtractor;
    use matchy::Database;

    // Parse thread count: None = auto, "auto" = auto, "0" = auto, "N" = N
    let num_threads = match threads_arg.as_deref() {
        None | Some("auto") | Some("0") => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        Some(s) => s.parse::<usize>().with_context(|| {
            format!("Invalid thread count '{}', expected a number or 'auto'", s)
        })?,
    };

    if show_stats && !follow {
        if num_threads == 1 {
            eprintln!("[INFO] Mode: Sequential (single-threaded)");
        } else {
            eprintln!("[INFO] Mode: Parallel ({} worker threads)", num_threads);
            eprintln!("[INFO] Batch size: {} bytes", batch_bytes);
        }
    }

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

    // Setup Ctrl+C handler for follow mode
    let shutdown = Arc::new(AtomicBool::new(false));
    if follow {
        if show_stats {
            eprintln!("[INFO] Mode: Follow (watch files for new content)");
        }
        let shutdown_clone = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            eprintln!("\n[INFO] Shutting down...");
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .context("Failed to set Ctrl+C handler")?;
    }

    // Validate input
    if inputs.is_empty() {
        anyhow::bail!("No input files specified");
    }

    // Process files
    let overall_start = Instant::now();
    let aggregate_stats: ProcessingStats;
    let files_processed: usize;
    let files_failed: usize;

    if follow {
        // Follow mode - use parallel or sequential based on thread count
        if num_threads > 1 {
            if show_stats {
                eprintln!(
                    "[INFO] Using parallel follow with {} worker threads",
                    num_threads
                );
            }
            aggregate_stats = follow_files_parallel(
                inputs.clone(),
                &database,
                num_threads,
                &format,
                show_stats,
                show_progress,
                trusted,
                cache_size,
                overall_start,
                shutdown,
            )?;
        } else {
            if show_stats {
                eprintln!("[INFO] Using sequential follow (single-threaded)");
            }
            aggregate_stats = follow_files(
                inputs.clone(),
                &db,
                &extractor,
                &format,
                show_stats,
                show_progress,
                overall_start,
                shutdown,
            )?;
        }
        files_processed = inputs.len();
        files_failed = 0;
    } else if num_threads > 1 {
        // Parallel mode
        aggregate_stats = process_parallel(
            inputs.clone(),
            &database,
            num_threads,
            batch_bytes,
            &format,
            show_stats,
            show_progress,
            trusted,
            cache_size,
            overall_start,
        )?;
        files_processed = inputs.len();
        files_failed = 0;
    } else {
        // Sequential mode
        let mut seq_stats = ProcessingStats::new();
        let mut seq_processed = 0;
        let mut seq_failed = 0;
        let mut stdin_already_processed = false;

        // Initialize progress reporter for aggregate progress across files
        let mut progress = if show_progress {
            Some(crate::match_processor::ProgressReporter::new())
        } else {
            None
        };

        for input_path in &inputs {
            // Handle stdin (allow "-" only once)
            if input_path.to_str() == Some("-") {
                if stdin_already_processed {
                    if show_stats {
                        eprintln!("[WARN] Skipping duplicate stdin argument");
                    }
                    continue;
                }
                stdin_already_processed = true;
            }

            // Process this file with aggregate progress tracking
            match process_file_with_aggregate(
                input_path,
                &db,
                &extractor,
                &format,
                show_stats,
                &mut seq_stats,
                &mut progress,
                overall_start,
            ) {
                Ok(()) => {
                    seq_processed += 1;
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to process {}: {}", input_path.display(), e);
                    seq_failed += 1;
                }
            }
        }

        // Add final newline if progress was shown
        if progress.is_some() {
            eprintln!();
        }

        aggregate_stats = seq_stats;
        files_processed = seq_processed;
        files_failed = seq_failed;
    }

    let overall_elapsed = overall_start.elapsed();

    // Output aggregate summary stats to stderr
    if show_stats {
        let db_stats = db.stats();

        eprintln!();
        eprintln!("[INFO] === Processing Complete ===");
        if inputs.len() > 1 {
            eprintln!("[INFO] Files processed: {}", files_processed);
            if files_failed > 0 {
                eprintln!("[INFO] Files failed: {}", files_failed);
            }
        }
        eprintln!(
            "[INFO] Lines processed: {}",
            format_number(aggregate_stats.lines_processed)
        );
        eprintln!(
            "[INFO] Lines with matches: {} ({:.1}%)",
            format_number(aggregate_stats.lines_with_matches),
            if aggregate_stats.lines_processed > 0 {
                (aggregate_stats.lines_with_matches as f64 / aggregate_stats.lines_processed as f64)
                    * 100.0
            } else {
                0.0
            }
        );
        eprintln!(
            "[INFO] Total matches: {}",
            format_number(aggregate_stats.total_matches)
        );
        eprintln!(
            "[INFO] Candidates tested: {}",
            format_number(aggregate_stats.candidates_tested)
        );

        if aggregate_stats.ipv4_count > 0 {
            eprintln!(
                "[INFO]   IPv4: {}",
                format_number(aggregate_stats.ipv4_count)
            );
        }
        if aggregate_stats.ipv6_count > 0 {
            eprintln!(
                "[INFO]   IPv6: {}",
                format_number(aggregate_stats.ipv6_count)
            );
        }
        if aggregate_stats.domain_count > 0 {
            eprintln!(
                "[INFO]   Domains: {}",
                format_number(aggregate_stats.domain_count)
            );
        }
        if aggregate_stats.email_count > 0 {
            eprintln!(
                "[INFO]   Emails: {}",
                format_number(aggregate_stats.email_count)
            );
        }

        eprintln!(
            "[INFO] Throughput: {:.2} MB/s",
            if overall_elapsed.as_secs_f64() > 0.0 {
                (aggregate_stats.total_bytes as f64 / 1_000_000.0) / overall_elapsed.as_secs_f64()
            } else {
                0.0
            }
        );
        eprintln!("[INFO] Total time: {:.2}s", overall_elapsed.as_secs_f64());
        eprintln!(
            "[INFO] Extraction time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            aggregate_stats.extraction_time.as_secs_f64(),
            if aggregate_stats.extraction_samples > 0 {
                aggregate_stats.extraction_time.as_nanos() as f64
                    / 1000.0
                    / aggregate_stats.extraction_samples as f64
            } else {
                0.0
            },
            format_number(aggregate_stats.extraction_samples)
        );
        eprintln!(
            "[INFO] Lookup time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            aggregate_stats.lookup_time.as_secs_f64(),
            if aggregate_stats.lookup_samples > 0 {
                aggregate_stats.lookup_time.as_nanos() as f64
                    / 1000.0
                    / aggregate_stats.lookup_samples as f64
            } else {
                0.0
            },
            format_number(aggregate_stats.lookup_samples)
        );
        eprintln!(
            "[INFO] Query rate: {} candidates/sec (overall)",
            format_qps(if overall_elapsed.as_secs_f64() > 0.0 {
                aggregate_stats.candidates_tested as f64 / overall_elapsed.as_secs_f64()
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

    // Return error code if any files failed
    if files_failed > 0 {
        anyhow::bail!("{} file(s) failed to process", files_failed);
    }

    Ok(())
}
