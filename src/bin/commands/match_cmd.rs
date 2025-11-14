use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use crate::cli_utils::{format_number, format_qps};
use crate::match_processor::{
    analyze_performance, follow_files, follow_files_parallel, format_stage_breakdown,
    process_file_with_aggregate, process_parallel, ProcessingStats,
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
    cache_size: usize,
    extractors_arg: Option<String>,
) -> Result<()> {
    use matchy::extractor::Extractor;
    use matchy::Database;

    // Parse thread count: None = auto (0 triggers auto-tuning), "N" = N
    let num_threads = match threads_arg.as_deref() {
        None | Some("auto") | Some("0") => 0, // 0 = auto-tune in process_parallel
        Some(s) => s.parse::<usize>().with_context(|| {
            format!("Invalid thread count '{}', expected a number or 'auto'", s)
        })?,
    };

    if show_stats && !follow {
        if num_threads == 0 {
            eprintln!("[INFO] Mode: Auto-tuning (detecting optimal configuration)");
        } else if num_threads == 1 {
            eprintln!("[INFO] Mode: Sequential (single-threaded)");
        } else {
            eprintln!("[INFO] Mode: Parallel ({} worker threads)", num_threads);
            eprintln!("[INFO] Batch size: {} bytes", batch_bytes);
        }
    }

    // Load database
    let load_start = Instant::now();
    let mut opener = Database::from(database.to_str().unwrap());
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

    // Parse extractor configuration from CLI flags
    use crate::match_processor::ExtractorConfig;
    let extractor_config = ExtractorConfig::from_arg(extractors_arg.clone());

    // Configure extractor based on database capabilities and CLI flags
    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    // Apply database-based defaults
    let default_ipv4 = has_ip;
    let default_ipv6 = has_ip;
    let default_domains = has_strings;
    let default_emails = has_strings;
    let default_hashes = has_strings;
    let default_bitcoin = has_strings;
    let default_ethereum = has_strings;
    let default_monero = has_strings;

    // Build extractor with CLI overrides
    let builder = Extractor::builder()
        .extract_ipv4(extractor_config.should_enable("ipv4", default_ipv4))
        .extract_ipv6(extractor_config.should_enable("ipv6", default_ipv6))
        .extract_domains(extractor_config.should_enable("domain", default_domains))
        .extract_emails(extractor_config.should_enable("email", default_emails))
        .extract_hashes(extractor_config.should_enable("hash", default_hashes))
        .extract_bitcoin(extractor_config.should_enable("bitcoin", default_bitcoin))
        .extract_ethereum(extractor_config.should_enable("ethereum", default_ethereum))
        .extract_monero(extractor_config.should_enable("monero", default_monero));

    let extractor = builder
        .build()
        .context("Failed to create pattern extractor")?;

    if show_stats {
        // Build list of enabled extractors
        let mut enabled = Vec::new();
        if extractor.extract_ipv4() {
            enabled.push("IPv4");
        }
        if extractor.extract_ipv6() {
            enabled.push("IPv6");
        }
        if extractor.extract_domains() {
            enabled.push("domains");
        }
        if extractor.extract_emails() {
            enabled.push("emails");
        }
        if extractor.extract_hashes() {
            enabled.push("hashes");
        }
        if extractor.extract_bitcoin() {
            enabled.push("Bitcoin");
        }
        if extractor.extract_ethereum() {
            enabled.push("Ethereum");
        }
        if extractor.extract_monero() {
            enabled.push("Monero");
        }

        eprintln!(
            "[INFO] Extractors: {}",
            if enabled.is_empty() {
                "none".to_string()
            } else {
                enabled.join(", ")
            }
        );
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
                cache_size,
                overall_start,
                shutdown,
                extractor_config,
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
    } else if num_threads == 0 || num_threads > 1 {
        // Parallel mode (num_threads=0 means auto-tune, >1 means explicit count)
        aggregate_stats = process_parallel(
            inputs.clone(),
            &database,
            num_threads,
            batch_bytes,
            &format,
            show_stats,
            show_progress,
            cache_size,
            overall_start,
            extractor_config,
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
            "[INFO] Query rate: {} queries/s",
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
        
        // Bottleneck analysis (only for parallel mode with timing data)
        if num_threads > 1 && overall_elapsed.as_secs_f64() > 0.1 {
            eprintln!();
            eprintln!("[INFO] === Performance Analysis ===");
            
            let analysis = analyze_performance(
                &aggregate_stats,
                overall_elapsed,
                num_threads,
                inputs.len(),
                db_stats.cache_hit_rate(),
            );
            
            // Show stage breakdown
            eprintln!();
            eprint!("{}", format_stage_breakdown(&analysis.stage_breakdown));
            
            // Show bottleneck and recommendations
            eprintln!();
            eprintln!("[INFO] Bottleneck: {}", analysis.explanation);
            if !analysis.recommendations.is_empty() {
                eprintln!("[INFO] Recommendations:");
                for rec in &analysis.recommendations {
                    eprintln!("[INFO]   • {}", rec);
                }
            }
        }
    }

    // Return error code if any files failed
    if files_failed > 0 {
        anyhow::bail!("{} file(s) failed to process", files_failed);
    }

    Ok(())
}
