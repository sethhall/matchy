use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Set thread name for debugging/profiling (macOS-specific)
#[cfg(target_os = "macos")]
fn set_thread_name(name: &str) {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        unsafe {
            libc::pthread_setname_np(cname.as_ptr());
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn set_thread_name(_name: &str) {
    // No-op on non-macOS platforms
}

use super::stats::ProcessingStats;
use crate::cli_utils::{data_value_to_json, format_cidr_into};

/// Timeout for flushing partial batches without newline (stdin streaming)
/// Only applies to slow/streaming stdin - normal file processing doesn't need this
const FLUSH_TIMEOUT: Duration = Duration::from_millis(500);

/// Minimum bytes to accumulate before applying flush timeout
/// Below this, we wait for more data (avoids flushing trivial amounts)
const MIN_FLUSH_BYTES: usize = 1024; // 1KB

/// Work batch sent from reader to workers
#[derive(Clone)]
pub struct WorkBatch {
    pub source_file: PathBuf,
    pub starting_line_number: usize,
    pub data: Arc<Vec<u8>>,
    /// Pre-computed newline offsets (positions of '\n' bytes in data)
    /// Workers use these to avoid re-scanning with memchr
    pub line_offsets: Arc<Vec<usize>>,
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

/// Statistics from a single worker thread
#[derive(Default, Clone)]
pub struct WorkerStats {
    pub lines_processed: usize,
    pub candidates_tested: usize,
    pub total_matches: usize,
    pub lines_with_matches: usize,
    pub total_bytes: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub domain_count: usize,
    pub email_count: usize,
}
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
    trusted: bool,
    cache_size: usize,
    overall_start: Instant,
) -> Result<ProcessingStats> {
    let output_json = output_format == "json";

    // Create channels for pipeline
    let work_queue_capacity = num_threads * 4;
    let result_queue_capacity = 1000;

    let (work_tx, work_rx) = mpsc::sync_channel::<Option<WorkBatch>>(work_queue_capacity);
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
                trusted,
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
        aggregate.total_matches += stats.total_matches;
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
    work_tx: SyncSender<Option<WorkBatch>>,
    batch_bytes: usize,
    _overall_start: Instant,
) -> Result<()> {
    let mut read_buffer = vec![0u8; batch_bytes];
    let mut stdin_already_processed = false;

    for input_path in inputs {
        // Handle stdin (allow only once)
        if input_path.to_str() == Some("-") {
            if stdin_already_processed {
                continue;
            }
            stdin_already_processed = true;

            // Process stdin (cannot seek, so read in chunks)
            process_stdin(&work_tx, &input_path, &mut read_buffer, batch_bytes)?;
        } else {
            // Process regular file
            match process_file(&work_tx, &input_path, &mut read_buffer, batch_bytes) {
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

/// Process a regular file (seekable)
fn process_file(
    work_tx: &SyncSender<Option<WorkBatch>>,
    input_path: &Path,
    read_buffer: &mut [u8],
    _batch_bytes: usize,
) -> Result<()> {
    let mut file = fs::File::open(input_path)
        .with_context(|| format!("Failed to open {}", input_path.display()))?;

    let mut current_line_number = 1usize;

    loop {
        let bytes_read = file.read(read_buffer)?;
        if bytes_read == 0 {
            break;
        }

        // Find last newline using memchr (SIMD-accelerated)
        let chunk_end = if let Some(pos) = memchr::memrchr(b'\n', &read_buffer[..bytes_read]) {
            pos + 1 // Include the newline
        } else {
            bytes_read // No newline found, send entire chunk
        };

        // Copy chunk data (necessary for buffer reuse)
        let chunk = read_buffer[..chunk_end].to_vec();

        // Pre-compute newline offsets (avoid duplicate memchr in workers)
        let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &chunk).collect();
        let line_count = line_offsets.len();

        // Send to workers
        let batch = WorkBatch {
            source_file: input_path.to_owned(),
            starting_line_number: current_line_number,
            data: Arc::new(chunk),
            line_offsets: Arc::new(line_offsets),
        };

        work_tx
            .send(Some(batch))
            .context("Failed to send work batch")?;

        // Seek back to position right after the newline
        if chunk_end < bytes_read {
            file.seek(SeekFrom::Current((chunk_end as i64) - (bytes_read as i64)))?;
        }

        current_line_number += line_count;
    }

    Ok(())
}

/// Process stdin (non-seekable) with timeout-based flushing
fn process_stdin(
    work_tx: &SyncSender<Option<WorkBatch>>,
    input_path: &Path,
    read_buffer: &mut [u8],
    _batch_bytes: usize,
) -> Result<()> {
    let mut stdin = io::stdin();
    let mut current_line_number = 1usize;
    let mut leftover = Vec::new();
    let mut last_data_time = Instant::now();

    loop {
        let bytes_read = stdin.read(read_buffer)?;
        if bytes_read == 0 {
            // EOF - send any leftover data
            if !leftover.is_empty() {
                let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &leftover).collect();
                let batch = WorkBatch {
                    source_file: input_path.to_owned(),
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
                let batch = WorkBatch {
                    source_file: input_path.to_owned(),
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

        let batch = WorkBatch {
            source_file: input_path.to_owned(),
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
    trusted: bool,
    cache_size: usize,
) -> Result<matchy::Database> {
    use matchy::Database;

    let mut opener = Database::from(database_path.to_str().unwrap());
    if trusted {
        opener = opener.trusted();
    }
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    opener.open().context("Failed to open database")
}

/// Create extractor configured for database capabilities
pub fn create_extractor_for_db(
    db: &matchy::Database,
) -> Result<matchy::extractor::PatternExtractor> {
    use matchy::extractor::PatternExtractor;

    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    let mut builder = PatternExtractor::builder();
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
    input_line: String,
    cidr: String,
}

impl MatchBuffers {
    pub fn new() -> Self {
        Self {
            data_values: Vec::with_capacity(8),
            matched_text: String::with_capacity(256),
            input_line: String::with_capacity(512),
            cidr: String::with_capacity(64),
        }
    }
}

/// Worker thread: receives batches, processes them, sends results
fn worker_thread(
    worker_id: usize,
    work_rx: Arc<Mutex<Receiver<Option<WorkBatch>>>>,
    result_tx: SyncSender<Option<WorkerMessage>>,
    database_path: PathBuf,
    trusted: bool,
    cache_size: usize,
    show_stats: bool,
) -> WorkerStats {
    // Initialize database
    let db = match init_worker_database(&database_path, trusted, cache_size) {
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

    let mut stats = WorkerStats::default();
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
                process_batch(
                    &batch,
                    &db,
                    &extractor,
                    &result_tx,
                    &mut stats,
                    show_stats,
                    &mut match_buffers,
                );

                // Send periodic progress updates
                let now = Instant::now();
                if now.duration_since(last_progress_update) >= progress_interval {
                    let _ = result_tx.send(Some(WorkerMessage::Stats {
                        worker_id,
                        stats: stats.clone(),
                    }));
                    last_progress_update = now;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    // Send final stats
    let _ = result_tx.send(Some(WorkerMessage::Stats {
        worker_id,
        stats: stats.clone(),
    }));
    stats
}

/// Lookup a candidate in the database
/// Only allocates string if there's a match (optimization: avoid allocation for non-matches)
fn lookup_candidate<'a>(
    item: matchy::extractor::ExtractedItem<'a>,
    db: &matchy::Database,
) -> Option<(Option<matchy::QueryResult>, String)> {
    match item {
        matchy::extractor::ExtractedItem::Ipv4(ip) => {
            let result = db.lookup_ip(IpAddr::V4(ip)).ok()?;
            // Only allocate string representation if lookup succeeded
            Some((result, ip.to_string()))
        }
        matchy::extractor::ExtractedItem::Ipv6(ip) => {
            let result = db.lookup_ip(IpAddr::V6(ip)).ok()?;
            Some((result, ip.to_string()))
        }
        matchy::extractor::ExtractedItem::Domain(s) => {
            let result = db.lookup(s).ok()?;
            Some((result, s.to_string()))
        }
        matchy::extractor::ExtractedItem::Email(s) => {
            let result = db.lookup(s).ok()?;
            Some((result, s.to_string()))
        }
    }
}

/// Build a match result from query result using reusable buffers
/// Returns None if result is NotFound (shouldn't happen in practice)
fn build_match_result(
    result: &matchy::QueryResult,
    candidate_str: &str,
    line: &[u8],
    line_number: usize,
    source_file: &Path,
    timestamp: f64,
    buffers: &mut MatchBuffers,
) -> Option<MatchResult> {
    match result {
        matchy::QueryResult::Pattern { pattern_ids, data } => {
            let data_json = if !data.is_empty() {
                buffers.data_values.clear();
                for d in data.iter() {
                    if let Some(val) = d.as_ref() {
                        buffers.data_values.push(data_value_to_json(val));
                    }
                }
                if !buffers.data_values.is_empty() {
                    Some(json!(&buffers.data_values))
                } else {
                    None
                }
            } else {
                None
            };

            buffers.matched_text.clear();
            buffers.matched_text.push_str(candidate_str);
            buffers.input_line.clear();
            buffers.input_line.push_str(&String::from_utf8_lossy(line));

            Some(MatchResult {
                source_file: source_file.to_owned(),
                line_number,
                matched_text: buffers.matched_text.clone(),
                match_type: "pattern".to_string(),
                input_line: buffers.input_line.clone(),
                timestamp,
                pattern_count: Some(pattern_ids.len()),
                data: data_json,
                prefix_len: None,
                cidr: None,
            })
        }
        matchy::QueryResult::Ip { data, prefix_len } => {
            buffers.matched_text.clear();
            buffers.matched_text.push_str(candidate_str);
            buffers.input_line.clear();
            buffers.input_line.push_str(&String::from_utf8_lossy(line));
            buffers.cidr.clear();
            format_cidr_into(candidate_str, *prefix_len, &mut buffers.cidr);

            Some(MatchResult {
                source_file: source_file.to_owned(),
                line_number,
                matched_text: buffers.matched_text.clone(),
                match_type: "ip".to_string(),
                input_line: buffers.input_line.clone(),
                timestamp,
                pattern_count: None,
                data: Some(data_value_to_json(data)),
                prefix_len: Some(*prefix_len),
                cidr: Some(buffers.cidr.clone()),
            })
        }
        matchy::QueryResult::NotFound => None,
    }
}

/// Process a single work batch
pub fn process_batch(
    batch: &WorkBatch,
    db: &matchy::Database,
    extractor: &matchy::extractor::PatternExtractor,
    result_tx: &SyncSender<Option<WorkerMessage>>,
    stats: &mut WorkerStats,
    _show_stats: bool,
    buffers: &mut MatchBuffers,
) {
    let chunk: &[u8] = &batch.data;
    let timestamp = 0.0;

    // Pre-allocate buffer for lowercasing (case-insensitive mode only)
    let is_case_insensitive = db.mode() == matchy::MatchMode::CaseInsensitive;
    let mut lowercase_buf = if is_case_insensitive {
        Vec::with_capacity(8192) // Typical log line size
    } else {
        Vec::new()
    };

    // Use pre-computed line offsets from reader (avoids duplicate memchr scan)
    let mut line_start = 0;
    let mut line_number = batch.starting_line_number;
    let mut line_had_match = false;

    // Iterate over pre-computed newline positions, plus chunk end
    for newline_pos in batch
        .line_offsets
        .iter()
        .copied()
        .chain(std::iter::once(chunk.len()))
    {
        let original_line = &chunk[line_start..newline_pos];
        line_start = newline_pos + 1;
        if original_line.is_empty() {
            continue;
        }

        stats.lines_processed += 1;
        stats.total_bytes += original_line.len();

        // CRITICAL OPTIMIZATION: For case-insensitive matching, lowercase the ENTIRE line
        // once with SIMD before extraction and matching. This is 4-8x faster than lowercasing
        // per field and eliminates all case-handling branches in hot paths.
        let line = if is_case_insensitive {
            matchy::simd_utils::ascii_lowercase(original_line, &mut lowercase_buf);
            lowercase_buf.as_slice()
        } else {
            original_line
        };

        let extracted = extractor.extract_from_line(line);

        for item in extracted {
            stats.candidates_tested += 1;

            // Track candidate types (for stats or progress display)
            match &item.item {
                matchy::extractor::ExtractedItem::Ipv4(_) => stats.ipv4_count += 1,
                matchy::extractor::ExtractedItem::Ipv6(_) => stats.ipv6_count += 1,
                matchy::extractor::ExtractedItem::Domain(_) => stats.domain_count += 1,
                matchy::extractor::ExtractedItem::Email(_) => stats.email_count += 1,
            }

            // Lookup candidate
            let (result, candidate_str) = match lookup_candidate(item.item, db) {
                Some(lookup) => lookup,
                None => continue,
            };

            let is_match = match &result {
                Some(matchy::QueryResult::Pattern { pattern_ids, .. }) => !pattern_ids.is_empty(),
                Some(matchy::QueryResult::Ip { .. }) => true,
                _ => false,
            };

            if is_match {
                if !line_had_match {
                    stats.lines_with_matches += 1;
                    line_had_match = true;
                }
                stats.total_matches += 1;

                if let Some(query_result) = result {
                    if let Some(match_result) = build_match_result(
                        &query_result,
                        &candidate_str,
                        original_line, // Use original for display
                        line_number,
                        &batch.source_file,
                        timestamp,
                        buffers,
                    ) {
                        let _ = result_tx.send(Some(WorkerMessage::Match(match_result)));
                    }
                }
            }
        }

        line_number += 1;
        line_had_match = false;
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
                    aggregate.total_matches += stats.total_matches;
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
