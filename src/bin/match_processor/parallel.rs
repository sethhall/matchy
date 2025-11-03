use anyhow::{Context, Result};
use serde_json::json;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::stats::ProcessingStats;
use super::thread_utils::set_thread_name;
use crate::cli_utils::{data_value_to_json, format_cidr_into};

/// Timeout for flushing partial batches without newline (stdin streaming)
/// Only applies to slow/streaming stdin - normal file processing doesn't need this
const FLUSH_TIMEOUT: Duration = Duration::from_millis(500);

/// Minimum bytes to accumulate before applying flush timeout
/// Below this, we wait for more data (avoids flushing trivial amounts)
const MIN_FLUSH_BYTES: usize = 1024; // 1KB

// Use library's LineBatch directly instead of maintaining duplicate WorkBatch
pub use matchy::processing::LineBatch;

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
/// Process multiple files in parallel using worker pool
#[allow(clippy::too_many_arguments)]
pub fn process_parallel(
    inputs: Vec<PathBuf>,
    database_path: &Path,
    num_threads: usize,
    batch_bytes: usize,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    cache_size: usize,
    overall_start: Instant,
) -> Result<ProcessingStats> {
    let output_json = output_format == "json";

    // Create channels for pipeline
    let work_queue_capacity = num_threads * 4;
    let result_queue_capacity = 1000;

    let (work_tx, work_rx) = mpsc::sync_channel::<Option<LineBatch>>(work_queue_capacity);
    let (result_tx, result_rx) = mpsc::sync_channel::<Option<WorkerMessage>>(result_queue_capacity);

    // Spawn output thread
    let output_handle = {
        let result_rx = result_rx;
        thread::spawn(move || {
            set_thread_name("matchy-output");
            output_thread(result_rx, output_json, show_progress, overall_start)
        })
    };

    // Share work receiver across workers using Arc<Mutex>
    let work_rx = Arc::new(std::sync::Mutex::new(work_rx));

    // Spawn worker pool
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_threads {
        let work_rx = Arc::clone(&work_rx);
        let result_tx = result_tx.clone();
        let database_path = database_path.to_owned();

        let handle = thread::spawn(move || {
            set_thread_name(&format!("matchy-worker-{}", worker_id));
            worker_thread(
                worker_id,
                work_rx,
                result_tx,
                database_path,
                cache_size,
                show_stats,
            )
        });
        worker_handles.push(handle);
    }

    // Drop original result sender so output can detect completion
    drop(result_tx);

    // Spawn reader thread
    let reader_handle = {
        let inputs = inputs.clone();
        thread::spawn(move || {
            set_thread_name("matchy-reader");
            reader_thread(inputs, work_tx, batch_bytes, overall_start)
        })
    };

    // Wait for reader to finish
    let reader_result = reader_handle.join().expect("Reader thread panicked");

    // Wait for all workers to finish
    let mut worker_stats = Vec::new();
    for handle in worker_handles {
        match handle.join() {
            Ok(stats) => worker_stats.push(stats),
            Err(_) => eprintln!("[ERROR] Worker thread panicked"),
        }
    }

    // Wait for output thread to finish
    let _output_stats = output_handle.join().expect("Output thread panicked");

    // Aggregate statistics
    let mut aggregate = ProcessingStats::new();
    for stats in worker_stats {
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

    reader_result?;

    Ok(aggregate)
}

/// Message from worker to output thread
pub enum WorkerMessage {
    Match(MatchResult),
    Stats {
        worker_id: usize,
        stats: WorkerStats,
    },
}

/// Reader thread: reads files, chunks them, sends to workers
fn reader_thread(
    inputs: Vec<PathBuf>,
    work_tx: SyncSender<Option<LineBatch>>,
    batch_bytes: usize,
    _overall_start: Instant,
) -> Result<()> {
    let mut stdin_already_processed = false;

    for input_path in inputs {
        // Handle stdin (allow only once)
        if input_path.to_str() == Some("-") {
            if stdin_already_processed {
                continue;
            }
            stdin_already_processed = true;

            // Process stdin (cannot seek, so read in chunks)
            process_stdin(&work_tx, &input_path, batch_bytes)?;
        } else {
            // Process regular file using library's LineFileReader
            match process_file(&work_tx, &input_path, batch_bytes) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[ERROR] Failed to read {}: {}", input_path.display(), e);
                }
            }
        }
    }

    // Send termination signal to workers (None)
    drop(work_tx);

    Ok(())
}

/// Process a regular file using library's LineFileReader
fn process_file(
    work_tx: &SyncSender<Option<LineBatch>>,
    input_path: &Path,
    batch_bytes: usize,
) -> Result<()> {
    use matchy::processing::LineFileReader;

    // Use library's LineFileReader which handles gzip, chunking, and line offsets
    let reader = LineFileReader::new(input_path, batch_bytes)
        .with_context(|| format!("Failed to open {}", input_path.display()))?;

    // Stream batches to workers
    for batch in reader.batches() {
        let batch =
            batch.with_context(|| format!("Failed to read from {}", input_path.display()))?;
        work_tx
            .send(Some(batch))
            .context("Failed to send work batch")?;
    }

    Ok(())
}

/// Process stdin (non-seekable) with timeout-based flushing
fn process_stdin(
    work_tx: &SyncSender<Option<LineBatch>>,
    input_path: &Path,
    batch_bytes: usize,
) -> Result<()> {
    let mut read_buffer = vec![0u8; batch_bytes];
    let mut stdin = io::stdin();
    let mut current_line_number = 1usize;
    let mut leftover = Vec::new();
    let mut last_data_time = Instant::now();

    loop {
        let bytes_read = stdin.read(&mut read_buffer)?;
        if bytes_read == 0 {
            // EOF - send any leftover data
            if !leftover.is_empty() {
                let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &leftover).collect();
                let batch = LineBatch {
                    source: input_path.to_owned(),
                    starting_line_number: current_line_number,
                    data: Arc::new(leftover.clone()),
                    line_offsets: Arc::new(line_offsets),
                };
                work_tx.send(Some(batch))?;
            }
            break;
        }

        // Prepend leftover from previous read
        let mut combined = leftover.clone();
        combined.extend_from_slice(&read_buffer[..bytes_read]);

        // Find last newline
        let chunk_end = if let Some(pos) = memchr::memrchr(b'\n', &combined) {
            pos + 1
        } else {
            // No newline found
            let elapsed = last_data_time.elapsed();

            // If we have accumulated enough data and timeout has elapsed, flush it
            if combined.len() >= MIN_FLUSH_BYTES && elapsed >= FLUSH_TIMEOUT {
                // Force flush even without newline
                let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &combined).collect();
                let batch = LineBatch {
                    source: input_path.to_owned(),
                    starting_line_number: current_line_number,
                    data: Arc::new(combined.clone()),
                    line_offsets: Arc::new(line_offsets),
                };
                work_tx.send(Some(batch))?;

                // No complete lines, but we flushed the partial data
                leftover.clear();
                last_data_time = Instant::now();
            } else {
                // Accumulate and continue
                leftover = combined;
            }
            continue;
        };

        // Found newline - reset timer
        last_data_time = Instant::now();

        // Send chunk
        let chunk = combined[..chunk_end].to_vec();

        // Pre-compute newline offsets (avoid duplicate memchr in workers)
        let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &chunk).collect();
        let line_count = line_offsets.len();

        let batch = LineBatch {
            source: input_path.to_owned(),
            starting_line_number: current_line_number,
            data: Arc::new(chunk),
            line_offsets: Arc::new(line_offsets),
        };
        work_tx.send(Some(batch))?;

        // Save leftover
        leftover = combined[chunk_end..].to_vec();
        current_line_number += line_count;
    }

    Ok(())
}

/// Initialize database for a worker thread
pub fn init_worker_database(
    database_path: &Path,
    cache_size: usize,
) -> Result<matchy::Database> {
    use matchy::Database;

    let mut opener = Database::from(database_path.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    opener.open().context("Failed to open database")
}

/// Create extractor configured for database capabilities
pub fn create_extractor_for_db(db: &matchy::Database) -> Result<matchy::extractor::Extractor> {
    use matchy::extractor::Extractor;

    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    let mut builder = Extractor::builder();
    if !has_ip {
        builder = builder.extract_ipv4(false).extract_ipv6(false);
    }
    if !has_strings {
        builder = builder.extract_domains(false).extract_emails(false);
    }
    builder.build().context("Failed to create extractor")
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
fn worker_thread(
    worker_id: usize,
    work_rx: Arc<Mutex<Receiver<Option<LineBatch>>>>,
    result_tx: SyncSender<Option<WorkerMessage>>,
    database_path: PathBuf,
    cache_size: usize,
    _show_stats: bool,
) -> WorkerStats {
    // Initialize database
    let db = match init_worker_database(&database_path, cache_size) {
        Ok(db) => db,
        Err(e) => {
            eprintln!(
                "[ERROR] Worker {} failed to open database: {}",
                worker_id, e
            );
            return WorkerStats::default();
        }
    };

    // Create extractor
    let extractor = match create_extractor_for_db(&db) {
        Ok(ext) => ext,
        Err(e) => {
            eprintln!(
                "[ERROR] Worker {} failed to create extractor: {}",
                worker_id, e
            );
            return WorkerStats::default();
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

    // Process work batches
    loop {
        let batch_opt = {
            let rx = work_rx.lock().unwrap();
            rx.recv()
        };

        match batch_opt {
            Ok(Some(batch)) => {
                // Process batch using library worker (batch is already LineBatch)
                match worker.process_lines(&batch) {
                    Ok(matches) => {
                        // Convert library matches to CLI format and send
                        for m in matches {
                            if let Some(match_result) = build_match_result(&m, &mut match_buffers) {
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
    final_stats
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
