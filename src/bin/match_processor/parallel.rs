use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::stats::ProcessingStats;
use crate::cli_utils::{data_value_to_json, format_cidr_into};

/// Extractor configuration from CLI flags
#[derive(Debug, Clone, Default)]
pub struct ExtractorConfig {
    pub overrides: HashMap<String, bool>,
    /// True if any explicit enables were specified (positive values)
    /// When true, defaults are disabled (exclusive mode)
    has_enables: bool,
}

impl ExtractorConfig {
    pub fn from_arg(arg: Option<String>) -> Self {
        let mut overrides = HashMap::new();
        let mut has_enables = false;

        if let Some(ref extractors_str) = arg {
            for extractor in extractors_str.split(',') {
                let extractor = extractor.trim();
                let (is_disable, name) = if let Some(name) = extractor.strip_prefix('-') {
                    (true, name)
                } else {
                    (false, extractor)
                };

                // Track if any explicit enables (positive values)
                if !is_disable {
                    has_enables = true;
                }

                // Expand group aliases
                let names = Self::expand_alias(name);

                for n in names {
                    overrides.insert(n.to_string(), !is_disable);
                }
            }
        }

        Self {
            overrides,
            has_enables,
        }
    }

    /// Expand group aliases and normalize names
    fn expand_alias(name: &str) -> Vec<&str> {
        match name {
            // Group aliases
            "crypto" => vec!["bitcoin", "ethereum", "monero"],
            "ip" => vec!["ipv4", "ipv6"],
            // Plural normalization
            "domains" => vec!["domain"],
            "emails" => vec!["email"],
            "hashes" => vec!["hash"],
            "ips" => vec!["ipv4", "ipv6"],
            // Pass through as-is
            _ => vec![name],
        }
    }

    pub fn should_enable(&self, name: &str, default: bool) -> bool {
        self.overrides.get(name).copied().unwrap_or(default)
    }

    /// Returns true if any explicit enables were specified
    /// Used to determine if we're in exclusive mode (only enable what was specified)
    pub fn has_explicit_enables(&self) -> bool {
        self.has_enables
    }
}

// Use library's LineBatch directly instead of maintaining duplicate WorkBatch
pub use matchy::processing::LineBatch;

/// Auto-tune thread count based on workload characteristics
/// Returns (num_readers, num_workers)
fn auto_tune_thread_count(inputs: &[PathBuf], show_stats: bool) -> (usize, usize) {
    // Get available parallelism (physical cores or CPU quota)
    // More reliable than gdt_cpus, especially on ARM systems
    let physical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1);

    // Count regular files (exclude stdin)
    let file_count = inputs.iter().filter(|p| p.to_str() != Some("-")).count();

    // Count compressed files
    let compressed_count = inputs
        .iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("gz") || e.eq_ignore_ascii_case("bz2"))
                .unwrap_or(false)
        })
        .count();

    // Decision logic:
    // - Single file or stdin: use all cores (single reader, N-1 workers)
    // - Multiple files: balance readers and workers
    // - Compressed files: may benefit from more workers (decompression is CPU-intensive)

    let (num_readers, num_workers) = if file_count <= 1 {
        // Single file: 1 reader, rest workers
        (1, physical_cores.saturating_sub(1).max(1))
    } else if compressed_count > file_count / 2 {
        // Mostly compressed: decompression is CPU-intensive, allocate ~40% to readers
        // Gzip decompression can easily saturate 1-2 cores per stream
        let readers = (physical_cores * 2 / 5).max(2).min(file_count);
        let workers = physical_cores.saturating_sub(readers).max(1);
        (readers, workers)
    } else {
        // Mixed or uncompressed: balance readers and workers  (1/3 readers, 2/3 workers)
        let readers = (physical_cores / 3).max(1).min(file_count);
        let workers = physical_cores.saturating_sub(readers).max(1);
        (readers, workers)
    };

    if show_stats {
        eprintln!(
            "[INFO] Auto-tuning: {} physical cores detected",
            physical_cores
        );
        eprintln!(
            "[INFO] Workload: {} files ({} compressed)",
            file_count, compressed_count
        );
        eprintln!(
            "[INFO] Configuration: {} reader(s), {} worker(s)",
            num_readers, num_workers
        );

        if file_count <= 1 {
            eprintln!("[INFO] Strategy: Single file - maximize workers");
        } else if compressed_count > file_count / 2 {
            eprintln!("[INFO] Strategy: Compressed files - prioritize workers for decompression");
        } else {
            eprintln!("[INFO] Strategy: Balanced readers/workers for I/O and processing");
        }
    }

    (num_readers, num_workers)
}

/// Match result sent from workers to output thread
pub struct MatchResult {
    pub source_file: PathBuf,
    pub line_number: usize,
    pub matched_text: String,
    pub match_type: String,
    pub input_line: String,
    pub timestamp: f64,
    // Optional fields for different match types
    pub pattern_count: Option<usize>,
    pub data: Option<serde_json::Value>,
    pub prefix_len: Option<u8>,
    pub cidr: Option<String>,
}

// Use library's WorkerStats directly instead of maintaining a duplicate type
pub use matchy::processing::WorkerStats;
/// Process multiple files in parallel using library's producer/reader/worker architecture
///
/// If num_threads is 0 (auto), determines optimal thread count based on:
/// - Physical CPU cores
/// - Number of input files
/// - File types (compressed vs uncompressed)
#[allow(clippy::too_many_arguments)]
pub fn process_parallel(
    inputs: Vec<PathBuf>,
    database_path: &Path,
    num_threads: usize,
    explicit_readers: Option<usize>,
    _batch_bytes: usize,
    output_format: &str,
    show_stats: bool,
    _show_progress: bool,
    cache_size: usize,
    _overall_start: Instant,
    extractor_config: ExtractorConfig,
) -> Result<(ProcessingStats, usize, usize, matchy::processing::RoutingStats)> {
    // Determine reader and worker counts using same logic
    let (num_readers, num_workers) = if let Some(readers) = explicit_readers {
        // Explicit reader count specified
        let workers = if num_threads == 0 {
            // Auto-detect total cores, subtract readers
            let physical_cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .max(1);
            physical_cores.saturating_sub(readers).max(1)
        } else {
            num_threads
        };
        (readers, workers)
    } else if num_threads == 0 {
        // Full auto-tune
        auto_tune_thread_count(&inputs, show_stats)
    } else {
        // Explicit thread count only - auto-tune readers based on workload
        let file_count = inputs.iter().filter(|p| p.to_str() != Some("-")).count();
        let compressed_count = inputs
            .iter()
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("gz") || e.eq_ignore_ascii_case("bz2"))
                    .unwrap_or(false)
            })
            .count();

        let (readers, workers) = if file_count <= 1 {
            (1, num_threads)
        } else if compressed_count > file_count / 2 {
            let readers = (num_threads * 2 / 5).max(2).min(file_count);
            let workers = num_threads.saturating_sub(readers).max(1);
            (readers, workers)
        } else {
            let readers = (num_threads / 3).max(1).min(file_count);
            let workers = num_threads.saturating_sub(readers).max(1);
            (readers, workers)
        };

        if show_stats {
            eprintln!(
                "[INFO] Auto-tuned readers: {} reader(s), {} worker(s) (total: {})",
                readers, workers, num_threads
            );
        }

        (readers, workers)
    };

    let output_json = output_format == "json";

    // Setup progress reporting if requested
    let progress_reporter = if _show_progress {
        Some(Arc::new(Mutex::new(crate::match_processor::ProgressReporter::new())))
    } else {
        None
    };
    let overall_start = _overall_start;

    // Call library's process_files_parallel with worker factory
    let db_path = database_path.to_owned();
    let ext_config = extractor_config.clone();
    
    let result = matchy::processing::process_files_parallel(
        inputs,
        Some(num_readers),
        Some(num_workers),
        move || {
            // Create database
            let db = init_worker_database(&db_path, cache_size)
                .map_err(|e| format!("Database init failed: {}", e))?;
            
            // Create extractor
            let extractor = create_extractor_for_db(&db, &ext_config)
                .map_err(|e| format!("Extractor init failed: {}", e))?;
            
            // Create worker
            let worker = matchy::processing::Worker::builder()
                .extractor(extractor)
                .add_database("default", db)
                .build();
            
            Ok::<_, String>(worker)
        },
        progress_reporter.map(|pr| {
            move |stats: &matchy::processing::WorkerStats| {
                let mut reporter = pr.lock().unwrap();
                if reporter.should_update() {
                    // Convert WorkerStats to CLI ProcessingStats for display
                    let mut ps = ProcessingStats::new();
                    ps.lines_processed = stats.lines_processed;
                    ps.candidates_tested = stats.candidates_tested;
                    ps.total_matches = stats.matches_found;
                    ps.total_bytes = stats.total_bytes;
                    reporter.show(&ps, overall_start.elapsed());
                }
            }
        }),
    ).map_err(|e| anyhow::anyhow!("Parallel processing failed: {}", e))?;

    // Print newline after progress if it was shown
    if _show_progress {
        eprintln!();
    }

    // Output matches in CLI format
    for lib_match in &result.matches {
        if let Some(cli_match) = library_match_to_cli_match(lib_match) {
            output_cli_match(&cli_match, output_json)?;
        }
    }

    // Convert library WorkerStats to CLI ProcessingStats
    let mut aggregate = ProcessingStats::new();
    aggregate.lines_processed = result.worker_stats.lines_processed;
    aggregate.candidates_tested = result.worker_stats.candidates_tested;
    aggregate.total_matches = result.worker_stats.matches_found;
    aggregate.lines_with_matches = result.worker_stats.lines_with_matches;
    aggregate.total_bytes = result.worker_stats.total_bytes;
    aggregate.extraction_time = result.worker_stats.extraction_time;
    aggregate.extraction_samples = result.worker_stats.extraction_samples;
    aggregate.lookup_time = result.worker_stats.lookup_time;
    aggregate.lookup_samples = result.worker_stats.lookup_samples;
    aggregate.ipv4_count = result.worker_stats.ipv4_count;
    aggregate.ipv6_count = result.worker_stats.ipv6_count;
    aggregate.domain_count = result.worker_stats.domain_count;
    aggregate.email_count = result.worker_stats.email_count;
    
    Ok((aggregate, num_workers, num_readers, result.routing_stats))
}

/// Message from worker to output thread
pub enum WorkerMessage {
    Match(MatchResult),
    Stats {
        worker_id: usize,
        stats: WorkerStats,
    },
}

/// Initialize database for a worker thread
/// Initialize database for a worker thread
pub fn init_worker_database(database_path: &Path, cache_size: usize) -> Result<matchy::Database> {
    use matchy::Database;

    let mut opener = Database::from(database_path.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    opener.open().context("Failed to open database")
}

/// Create extractor configured for database capabilities and CLI overrides
pub fn create_extractor_for_db(
    db: &matchy::Database,
    config: &ExtractorConfig,
) -> Result<matchy::extractor::Extractor> {
    use matchy::extractor::Extractor;

    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    // Determine defaults based on whether user specified explicit includes
    // If user says --extractors=ip,domain (positive), ONLY enable those (exclusive mode)
    // If user says --extractors=-crypto (negative), enable all defaults except those
    let use_defaults = !config.has_explicit_enables();

    let default_ipv4 = use_defaults && has_ip;
    let default_ipv6 = use_defaults && has_ip;
    let default_domains = use_defaults && has_strings;
    let default_emails = use_defaults && has_strings;
    let default_hashes = use_defaults && has_strings;
    let default_bitcoin = use_defaults && has_strings;
    let default_ethereum = use_defaults && has_strings;
    let default_monero = use_defaults && has_strings;

    // Build extractor with CLI overrides
    Extractor::builder()
        .extract_ipv4(config.should_enable("ipv4", default_ipv4))
        .extract_ipv6(config.should_enable("ipv6", default_ipv6))
        .extract_domains(config.should_enable("domain", default_domains))
        .extract_emails(config.should_enable("email", default_emails))
        .extract_hashes(config.should_enable("hash", default_hashes))
        .extract_bitcoin(config.should_enable("bitcoin", default_bitcoin))
        .extract_ethereum(config.should_enable("ethereum", default_ethereum))
        .extract_monero(config.should_enable("monero", default_monero))
        .build()
        .context("Failed to create extractor")
}

/// Reusable buffers for match result construction (eliminates per-match allocations)
pub struct MatchBuffers {
    data_values: Vec<serde_json::Value>,
    matched_text: String,
    cidr: String,
}

impl MatchBuffers {
    pub fn new() -> Self {
        Self {
            data_values: Vec::with_capacity(8),
            matched_text: String::with_capacity(256),
            cidr: String::with_capacity(64),
        }
    }
}

/// Worker thread: receives batches, processes them, sends results
/// Now uses library's matchy::parallel::Worker infrastructure
/// Gracefully shuts down when work queue closes
fn worker_thread(
    worker_id: usize,
    work_rx: Arc<Mutex<Receiver<Option<LineBatch>>>>,
    result_tx: SyncSender<Option<WorkerMessage>>,
    database_path: PathBuf,
    cache_size: usize,
    _show_stats: bool,
    extractor_config: ExtractorConfig,
) -> (WorkerStats, Duration, Duration) {
    // Initialize database
    let db = match init_worker_database(&database_path, cache_size) {
        Ok(db) => db,
        Err(e) => {
            eprintln!(
                "[ERROR] Worker {} failed to open database: {}",
                worker_id, e
            );
            return (WorkerStats::default(), Duration::ZERO, Duration::ZERO);
        }
    };

    // Create extractor
    let extractor = match create_extractor_for_db(&db, &extractor_config) {
        Ok(ext) => ext,
        Err(e) => {
            eprintln!(
                "[ERROR] Worker {} failed to create extractor: {}",
                worker_id, e
            );
            return (WorkerStats::default(), Duration::ZERO, Duration::ZERO);
        }
    };

    // Use library's Worker infrastructure
    let mut worker = matchy::processing::Worker::builder()
        .extractor(extractor)
        .add_database("default", db)
        .build();
    let mut last_progress_update = Instant::now();
    let progress_interval = Duration::from_millis(100);

    // Reusable buffers for match result construction
    let mut match_buffers = MatchBuffers::new();

    // Track worker timing (separate from library's WorkerStats)
    let mut idle_time = Duration::ZERO;
    let mut busy_time = Duration::ZERO;

    // Process work batches
    loop {
        // Time waiting for work (idle)
        let wait_start = Instant::now();
        let batch_opt = {
            let rx = work_rx.lock().unwrap();
            rx.recv()
        };
        idle_time += wait_start.elapsed();

        match batch_opt {
            Ok(Some(batch)) => {
                // Time processing the batch (busy)
                let process_start = Instant::now();

                // Process batch using library worker (batch is already LineBatch)
                match worker.process_lines(&batch) {
                    Ok(matches) => {
                        // Convert library matches to CLI format and send
                        for m in matches {
                            if let Some(mut match_result) =
                                build_match_result(&m, &mut match_buffers)
                            {
                                // Extract the line content from the batch
                                match_result.input_line =
                                    extract_line_from_batch(&batch, m.line_number);
                                let _ = result_tx.send(Some(WorkerMessage::Match(match_result)));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[ERROR] Worker {} batch processing failed: {}",
                            worker_id, e
                        );
                    }
                }

                // Track processing time
                busy_time += process_start.elapsed();

                // Send periodic progress updates
                let now = Instant::now();
                if now.duration_since(last_progress_update) >= progress_interval {
                    let _ = result_tx.send(Some(WorkerMessage::Stats {
                        worker_id,
                        stats: worker.stats().clone(),
                    }));
                    last_progress_update = now;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    // Send final stats
    let final_stats = worker.stats().clone();

    let _ = result_tx.send(Some(WorkerMessage::Stats {
        worker_id,
        stats: final_stats.clone(),
    }));

    (final_stats, idle_time, busy_time)
}

/// Extract the line content from a batch given a line number
fn extract_line_from_batch(batch: &LineBatch, line_number: usize) -> String {
    // Calculate which line in this batch (0-indexed within batch)
    let batch_line_index = line_number.saturating_sub(batch.starting_line_number);

    // Find the byte range for this line
    let start_offset = if batch_line_index == 0 {
        0
    } else {
        // Start after the previous line's newline
        batch
            .line_offsets
            .get(batch_line_index - 1)
            .map(|&off| off + 1)
            .unwrap_or(0)
    };

    let end_offset = batch
        .line_offsets
        .get(batch_line_index)
        .copied()
        .unwrap_or(batch.data.len());

    // Extract the line bytes and convert to string
    let line_bytes = &batch.data[start_offset..end_offset];
    String::from_utf8_lossy(line_bytes)
        .trim_end_matches('\n')
        .to_string()
}

/// Convert library LineMatch to CLI MatchResult
fn library_match_to_cli_match(lib_match: &matchy::processing::LineMatch) -> Option<MatchResult> {
    use matchy::QueryResult;

    let mr = &lib_match.match_result;

    match &mr.result {
        QueryResult::Ip { data, prefix_len } => {
            let mut cidr = String::new();
            format_cidr_into(&mr.matched_text, *prefix_len, &mut cidr);

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "ip".to_string(),
                input_line: String::new(),
                timestamp: 0.0,
                pattern_count: None,
                data: Some(data_value_to_json(data)),
                prefix_len: Some(*prefix_len),
                cidr: Some(cidr),
            })
        }
        QueryResult::Pattern { pattern_ids, data } => {
            let data_values: Vec<_> = data
                .iter()
                .filter_map(|opt_dv| opt_dv.as_ref().map(data_value_to_json))
                .collect();

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "pattern".to_string(),
                input_line: String::new(),
                timestamp: 0.0,
                pattern_count: Some(pattern_ids.len()),
                data: if data_values.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Array(data_values))
                },
                prefix_len: None,
                cidr: None,
            })
        }
        QueryResult::NotFound => None,
    }
}

/// Output a CLI match result
fn output_cli_match(result: &MatchResult, output_json: bool) -> Result<()> {
    if output_json {
        let mut match_obj = json!({
            "timestamp": format!("{:.3}", result.timestamp),
            "source_file": result.source_file.display().to_string(),
            "line_number": result.line_number,
            "matched_text": result.matched_text,
            "input_line": result.input_line,
            "match_type": result.match_type,
        });

        if let Some(pattern_count) = result.pattern_count {
            match_obj["pattern_count"] = json!(pattern_count);
        }
        if let Some(ref data) = result.data {
            match_obj["data"] = data.clone();
        }
        if let Some(prefix_len) = result.prefix_len {
            match_obj["prefix_len"] = json!(prefix_len);
        }
        if let Some(ref cidr) = result.cidr {
            match_obj["cidr"] = json!(cidr);
        }

        println!("{}", serde_json::to_string(&match_obj)?);
    }
    Ok(())
}

/// Build CLI match result from library match
pub fn build_match_result(
    lib_match: &matchy::processing::LineMatch,
    match_buffers: &mut MatchBuffers,
) -> Option<MatchResult> {
    use matchy::QueryResult;

    // Reset buffers
    match_buffers.data_values.clear();
    match_buffers.matched_text.clear();
    match_buffers.cidr.clear();

    // Access the nested match_result
    let mr = &lib_match.match_result;

    // Build match result based on query result type
    match &mr.result {
        QueryResult::Ip { data, prefix_len } => {
            format_cidr_into(&mr.matched_text, *prefix_len, &mut match_buffers.cidr);

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "ip".to_string(),
                input_line: String::new(), // Will be filled by caller if needed
                timestamp: 0.0,            // Will be filled by caller
                pattern_count: None,
                data: Some(data_value_to_json(data)),
                prefix_len: Some(*prefix_len),
                cidr: Some(match_buffers.cidr.clone()),
            })
        }
        QueryResult::Pattern { pattern_ids, data } => {
            let data_values: Vec<_> = data
                .iter()
                .filter_map(|opt_dv| opt_dv.as_ref().map(data_value_to_json))
                .collect();

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "pattern".to_string(),
                input_line: String::new(),
                timestamp: 0.0,
                pattern_count: Some(pattern_ids.len()),
                data: if data_values.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Array(data_values))
                },
                prefix_len: None,
                cidr: None,
            })
        }
        QueryResult::NotFound => None,
    }
}

/// Output thread: receives results, serializes to stdout
fn output_thread(
    result_rx: Receiver<Option<WorkerMessage>>,
    output_json: bool,
    show_progress: bool,
    overall_start: Instant,
) -> ProcessingStats {
    let mut stats = ProcessingStats::new();
    // Track stats per worker to avoid double-counting
    let mut worker_stats_map: std::collections::HashMap<usize, WorkerStats> =
        std::collections::HashMap::new();
    let _worker_counter = 0;

    // Initialize progress reporter
    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    while let Ok(Some(msg)) = result_rx.recv() {
        match msg {
            WorkerMessage::Match(result) => {
                if output_json {
                    let mut match_obj = json!({
                        "timestamp": format!("{:.3}", result.timestamp),
                        "source_file": result.source_file.display().to_string(),
                        "line_number": result.line_number,
                        "matched_text": result.matched_text,
                        "input_line": result.input_line,
                        "match_type": result.match_type,
                    });

                    if let Some(pattern_count) = result.pattern_count {
                        match_obj["pattern_count"] = json!(pattern_count);
                    }
                    if let Some(data) = result.data {
                        match_obj["data"] = data;
                    }
                    if let Some(prefix_len) = result.prefix_len {
                        match_obj["prefix_len"] = json!(prefix_len);
                    }
                    if let Some(cidr) = result.cidr {
                        match_obj["cidr"] = json!(cidr);
                    }

                    if let Ok(json_str) = serde_json::to_string(&match_obj) {
                        println!("{}", json_str);
                    }
                }

                stats.lines_with_matches += 1;
                stats.total_bytes += result.input_line.len();
            }
            WorkerMessage::Stats {
                worker_id,
                stats: worker_stats_msg,
            } => {
                // Update this worker's latest stats (replaces previous)
                worker_stats_map.insert(worker_id, worker_stats_msg);

                // Aggregate all workers' current stats for progress display
                let mut aggregate = ProcessingStats::new();
                for stats in worker_stats_map.values() {
                    aggregate.lines_processed += stats.lines_processed;
                    aggregate.candidates_tested += stats.candidates_tested;
                    aggregate.total_matches += stats.matches_found; // Library uses matches_found
                    aggregate.lines_with_matches += stats.lines_with_matches;
                    aggregate.total_bytes += stats.total_bytes;
                    aggregate.ipv4_count += stats.ipv4_count;
                    aggregate.ipv6_count += stats.ipv6_count;
                    aggregate.domain_count += stats.domain_count;
                    aggregate.email_count += stats.email_count;
                }

                // Show progress with aggregated stats
                if let Some(ref mut prog) = progress {
                    if prog.should_update() {
                        prog.show(&aggregate, overall_start.elapsed());
                    }
                }
            }
        }
    }

    // Add final newline if progress was shown
    if progress.is_some() {
        eprintln!();
    }

    stats
}

