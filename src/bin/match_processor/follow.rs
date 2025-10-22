use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use super::sequential::process_line_matches;
use super::stats::ProcessingStats;
use super::thread_utils::set_thread_name;

/// Watch files and process new lines as they appear
#[allow(clippy::too_many_arguments)]
pub fn follow_files(
    inputs: Vec<PathBuf>,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    overall_start: Instant,
    shutdown: Arc<AtomicBool>,
) -> Result<ProcessingStats> {
    if inputs.iter().any(|p| p.to_str() == Some("-")) {
        anyhow::bail!("--follow mode not supported with stdin");
    }

    let mut aggregate_stats = ProcessingStats::new();

    // Initialize progress reporter
    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    // Process existing content first
    if show_stats {
        eprintln!("[INFO] Processing existing file content...");
    }

    for input_path in &inputs {
        let stats = process_existing_content(
            input_path,
            db,
            extractor,
            output_format,
            show_stats,
            false, // Disable per-file progress, we'll show aggregate progress
            overall_start,
        )?;
        aggregate_stats.add(&stats);

        // Show aggregate progress after each file
        if let Some(ref mut prog) = progress {
            if prog.should_update() {
                prog.show(&aggregate_stats, overall_start.elapsed());
            }
        }
    }

    if show_stats {
        eprintln!("[INFO] Watching for new content (Ctrl+C to stop)...");
    }

    // Setup file watcher
    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, Config::default()).context("Failed to create file watcher")?;

    // Track file positions and watch each file
    let mut file_positions = Vec::new();
    for input_path in &inputs {
        let file = File::open(input_path)
            .with_context(|| format!("Failed to open {}", input_path.display()))?;
        let pos = file.metadata()?.len();

        watcher
            .watch(input_path, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch {}", input_path.display()))?;

        file_positions.push((input_path.clone(), pos));
    }

    // Process events until shutdown signal
    while !shutdown.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                if let Some(stats) = handle_file_event(
                    event,
                    &mut file_positions,
                    db,
                    extractor,
                    output_format,
                    show_stats,
                    overall_start,
                )? {
                    aggregate_stats.add(&stats);

                    // Show progress after processing new content
                    if let Some(ref mut prog) = progress {
                        if prog.should_update() {
                            prog.show(&aggregate_stats, overall_start.elapsed());
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("[WARN] File watcher error: {}", e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Normal timeout, check shutdown flag
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    if show_stats {
        eprintln!("[INFO] Follow mode stopped");
    }

    // Add final newline if progress was shown
    if progress.is_some() {
        eprintln!();
    }

    Ok(aggregate_stats)
}

/// Process existing file content up to current position
fn process_existing_content(
    input_path: &Path,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    overall_start: Instant,
) -> Result<ProcessingStats> {
    // Reuse the sequential processing logic
    super::sequential::process_file(
        input_path,
        db,
        extractor,
        output_format,
        show_stats,
        show_progress,
        overall_start,
    )
}

/// Handle a file system event
fn handle_file_event(
    event: Event,
    file_positions: &mut [(PathBuf, u64)],
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    overall_start: Instant,
) -> Result<Option<ProcessingStats>> {
    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            // Find which file was modified
            for path in &event.paths {
                if let Some((_, last_pos)) = file_positions.iter_mut().find(|(p, _)| p == path) {
                    // Process new content
                    let stats = process_new_content(
                        path,
                        last_pos,
                        db,
                        extractor,
                        output_format,
                        show_stats,
                        overall_start,
                    )?;
                    return Ok(Some(stats));
                }
            }
        }
        EventKind::Remove(_) => {
            // File was deleted/rotated
            for path in &event.paths {
                if file_positions.iter().any(|(p, _)| p == path) && show_stats {
                    eprintln!("[WARN] File deleted/rotated: {}", path.display());
                }
                // In a production system, we might try to reopen or handle rotation
                // For now, just continue watching other files
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Process new content added to a file since last read
fn process_new_content(
    input_path: &Path,
    last_pos: &mut u64,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    _show_stats: bool,
    _overall_start: Instant,
) -> Result<ProcessingStats> {
    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open {}", input_path.display()))?;

    let current_size = file.metadata()?.len();

    // Check if file was truncated (e.g., log rotation)
    if current_size < *last_pos {
        *last_pos = 0;
    }

    // Seek to last known position
    file.seek(SeekFrom::Start(*last_pos))?;

    let mut stats = ProcessingStats::new();
    let output_json = output_format == "json";

    // Calculate starting line number (approximate - we don't track across follow sessions)
    let starting_line = 1usize;

    // Read new lines
    let reader = BufReader::new(file);
    for (line_offset, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        let line_bytes = line.as_bytes();

        stats.lines_processed += 1;
        stats.total_bytes += line_bytes.len();

        // Calculate timestamp
        let timestamp = if output_json {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
        } else {
            0.0
        };

        // Process this line
        process_line_matches(
            line_bytes,
            starting_line + line_offset,
            input_path,
            timestamp,
            db,
            extractor,
            output_json,
            &mut stats,
        )?;
    }

    // Update position
    let new_file = File::open(input_path)?;
    *last_pos = new_file.metadata()?.len();

    Ok(stats)
}

/// Parallel follow mode: watch files and process with worker pool
#[allow(clippy::too_many_arguments)]
pub fn follow_files_parallel(
    inputs: Vec<PathBuf>,
    database_path: &Path,
    num_threads: usize,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    trusted: bool,
    cache_size: usize,
    overall_start: Instant,
    shutdown: Arc<AtomicBool>,
) -> Result<ProcessingStats> {
    if inputs.iter().any(|p| p.to_str() == Some("-")) {
        anyhow::bail!("--follow mode not supported with stdin");
    }

    let output_json = output_format == "json";

    // Create channels for pipeline
    let work_queue_capacity = num_threads * 4;
    let result_queue_capacity = 1000;

    let (work_tx, work_rx) =
        mpsc::sync_channel::<Option<super::parallel::LineBatch>>(work_queue_capacity);
    let (result_tx, result_rx) =
        mpsc::sync_channel::<Option<super::parallel::WorkerMessage>>(result_queue_capacity);

    // Spawn output thread - just use the existing parallel one
    let shutdown_output = Arc::clone(&shutdown);
    let output_handle = {
        thread::spawn(move || {
            set_thread_name("matchy-follow-output");
            output_thread_follow(
                result_rx,
                output_json,
                show_progress,
                overall_start,
                shutdown_output,
            )
        })
    };

    // Share work receiver across workers
    let work_rx = Arc::new(Mutex::new(work_rx));

    // Spawn worker pool - same as parallel but checks shutdown signal
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_threads {
        let work_rx = Arc::clone(&work_rx);
        let result_tx = result_tx.clone();
        let database_path = database_path.to_owned();

        let handle = thread::spawn(move || {
            set_thread_name(&format!("matchy-follow-worker-{}", worker_id));
            worker_thread_follow(
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

    // Spawn reader/watcher thread
    let reader_handle = {
        let inputs = inputs.clone();
        let shutdown_reader = Arc::clone(&shutdown);
        thread::spawn(move || {
            set_thread_name("matchy-follow-reader");
            reader_watcher_thread(inputs, work_tx, overall_start, shutdown_reader, show_stats)
        })
    };

    // Wait for reader to finish (on shutdown signal)
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

/// Reader/watcher thread: watches files, reads new content, batches and sends to workers
fn reader_watcher_thread(
    inputs: Vec<PathBuf>,
    work_tx: SyncSender<Option<super::parallel::LineBatch>>,
    _overall_start: Instant,
    shutdown: Arc<AtomicBool>,
    show_stats: bool,
) -> Result<()> {
    // Process existing content first
    if show_stats {
        eprintln!("[INFO] Processing existing file content...");
    }

    let mut file_positions: HashMap<PathBuf, u64> = HashMap::new();
    let mut line_counters: HashMap<PathBuf, usize> = HashMap::new();

    for input_path in &inputs {
        // Read existing content and send as initial batch
        if let Ok(file) = File::open(input_path) {
            if let Ok(metadata) = file.metadata() {
                let size = metadata.len();
                if size > 0 {
                    // Read entire existing file as initial batch
                    let mut content = Vec::new();
                    if let Ok(mut f) = File::open(input_path) {
                        if f.read_to_end(&mut content).is_ok() {
                            // Pre-compute line offsets for workers
                            let line_offsets: Vec<usize> =
                                memchr::memchr_iter(b'\n', &content).collect();
                            let line_count = line_offsets.len();

                            let batch = super::parallel::LineBatch {
                                source: input_path.clone(),
                                starting_line_number: 1,
                                data: Arc::new(content.clone()),
                                line_offsets: Arc::new(line_offsets),
                            };
                            let _ = work_tx.send(Some(batch));

                            // Count lines for tracking
                            line_counters.insert(input_path.clone(), line_count + 1);
                        }
                    }
                }
                file_positions.insert(input_path.clone(), size);
            }
        }
    }

    if show_stats {
        eprintln!("[INFO] Watching for new content (Ctrl+C to stop)...");
    }

    // Setup file watcher
    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, Config::default()).context("Failed to create file watcher")?;

    for input_path in &inputs {
        watcher
            .watch(input_path, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch {}", input_path.display()))?;
    }

    // Process file modification events
    while !shutdown.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                handle_file_event_parallel(
                    event,
                    &mut file_positions,
                    &mut line_counters,
                    &work_tx,
                )?;
            }
            Ok(Err(e)) => {
                eprintln!("[WARN] File watcher error: {}", e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Normal timeout, check shutdown flag
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    // Send termination signal to workers
    drop(work_tx);

    Ok(())
}

/// Worker thread for follow mode - same as parallel but can be interrupted
fn worker_thread_follow(
    worker_id: usize,
    work_rx: Arc<Mutex<Receiver<Option<super::parallel::LineBatch>>>>,
    result_tx: SyncSender<Option<super::parallel::WorkerMessage>>,
    database_path: PathBuf,
    trusted: bool,
    cache_size: usize,
    _show_stats: bool,
) -> super::parallel::WorkerStats {
    use super::parallel::{
        build_match_result, create_extractor_for_db, init_worker_database, MatchBuffers,
        WorkerMessage, WorkerStats,
    };

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

/// Output thread for follow mode - includes shutdown signal awareness
fn output_thread_follow(
    result_rx: Receiver<Option<super::parallel::WorkerMessage>>,
    output_json: bool,
    show_progress: bool,
    overall_start: Instant,
    shutdown: Arc<AtomicBool>,
) -> ProcessingStats {
    use super::parallel::WorkerMessage;
    use serde_json::json;
    use std::sync::atomic::Ordering;

    let mut stats = ProcessingStats::new();
    let mut worker_stats_map: HashMap<usize, super::parallel::WorkerStats> = HashMap::new();

    // Initialize progress reporter
    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    // Use recv_timeout to periodically check shutdown signal
    loop {
        // Check shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match result_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(msg)) => {
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
            Ok(None) => {
                // Channel closed normally (all workers finished)
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Normal timeout - continue loop to check shutdown again
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Channel disconnected - all workers done
                break;
            }
        }
    }

    // Add final newline if progress was shown
    if progress.is_some() {
        eprintln!();
    }

    stats
}

/// Handle file modification event - read new content and send as batch
fn handle_file_event_parallel(
    event: Event,
    file_positions: &mut HashMap<PathBuf, u64>,
    line_counters: &mut HashMap<PathBuf, usize>,
    work_tx: &SyncSender<Option<super::parallel::LineBatch>>,
) -> Result<()> {
    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            for path in &event.paths {
                if let Some(last_pos) = file_positions.get_mut(path) {
                    // Read new content since last position
                    if let Ok(mut file) = File::open(path) {
                        if let Ok(current_size) = file.metadata().map(|m| m.len()) {
                            // Check for truncation (log rotation)
                            if current_size < *last_pos {
                                *last_pos = 0;
                                line_counters.insert(path.clone(), 1);
                            }

                            if current_size > *last_pos {
                                // Seek and read new content
                                if file.seek(SeekFrom::Start(*last_pos)).is_ok() {
                                    let mut new_content = Vec::new();
                                    if file.read_to_end(&mut new_content).is_ok()
                                        && !new_content.is_empty()
                                    {
                                        let starting_line =
                                            line_counters.get(path).copied().unwrap_or(1);

                                        // Pre-compute line offsets for workers
                                        let line_offsets: Vec<usize> =
                                            memchr::memchr_iter(b'\n', &new_content).collect();
                                        let new_lines = line_offsets.len();

                                        let batch = super::parallel::LineBatch {
                                            source: path.clone(),
                                            starting_line_number: starting_line,
                                            data: Arc::new(new_content.clone()),
                                            line_offsets: Arc::new(line_offsets),
                                        };
                                        let _ = work_tx.send(Some(batch));

                                        // Update position and line counter
                                        *last_pos = current_size;
                                        *line_counters.get_mut(path).unwrap() += new_lines;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        EventKind::Remove(_) => {
            for path in &event.paths {
                if file_positions.contains_key(path) {
                    eprintln!("[WARN] File deleted/rotated: {}", path.display());
                    // Could implement log rotation handling here
                }
            }
        }
        _ => {}
    }

    Ok(())
}
