// Arc is passed by value intentionally - Arc::clone() is cheap (atomic increment)
#![allow(clippy::needless_pass_by_value)]

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use super::sequential::process_line_matches;
use super::stats::ProcessingStats;
use super::thread_utils::set_thread_name;

const POLL_INTERVAL_MS: u64 = 100;

#[allow(clippy::too_many_arguments)]
pub fn follow_files(
    inputs: &[PathBuf],
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

    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    if show_stats {
        eprintln!("[INFO] Processing existing file content...");
    }

    for input_path in inputs {
        let stats = process_existing_content(
            input_path,
            db,
            extractor,
            output_format,
            show_stats,
            false,
            overall_start,
        )?;
        aggregate_stats.add(&stats);
    }

    if show_stats {
        eprintln!("[INFO] Watching for new content (Ctrl+C to stop)...");
    }

    let mut file_positions: Vec<(PathBuf, u64)> = Vec::new();
    for input_path in inputs {
        let file = File::open(input_path)
            .with_context(|| format!("Failed to open {}", input_path.display()))?;
        let pos = file.metadata()?.len();
        file_positions.push((input_path.clone(), pos));
    }

    while !shutdown.load(Ordering::Relaxed) {
        let mut had_changes = false;

        for (path, last_pos) in &mut file_positions {
            match std::fs::metadata(path.as_path()) {
                Ok(meta) => {
                    let current_size = meta.len();
                    if current_size > *last_pos {
                        let stats = process_new_content(
                            path.as_path(),
                            last_pos,
                            db,
                            extractor,
                            output_format,
                            show_stats,
                            overall_start,
                        )?;
                        aggregate_stats.add(&stats);
                        had_changes = true;
                    } else if current_size < *last_pos {
                        if show_stats {
                            eprintln!(
                                "[INFO] File truncated, resetting position: {}",
                                path.display()
                            );
                        }
                        *last_pos = 0;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if show_stats {
                        eprintln!(
                            "[WARN] File not found (deleted/rotated?): {}",
                            path.display()
                        );
                    }
                    *last_pos = 0;
                }
                Err(e) => {
                    eprintln!("[WARN] Error checking file {}: {}", path.display(), e);
                }
            }
        }

        if had_changes {
            if let Some(ref mut prog) = progress {
                if prog.should_update() {
                    prog.show(&aggregate_stats, overall_start.elapsed());
                }
            }
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    if show_stats {
        eprintln!("[INFO] Follow mode stopped");
    }

    if progress.is_some() {
        eprintln!();
    }

    Ok(aggregate_stats)
}

fn process_existing_content(
    input_path: &Path,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    overall_start: Instant,
) -> Result<ProcessingStats> {
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

    if current_size < *last_pos {
        *last_pos = 0;
    }

    file.seek(SeekFrom::Start(*last_pos))?;

    let mut stats = ProcessingStats::new();
    let output_json = output_format == "json";

    let reader = BufReader::new(file);
    for line_result in reader.lines() {
        let line = line_result?;
        let line_bytes = line.as_bytes();

        stats.lines_processed += 1;
        stats.total_bytes += line_bytes.len();

        let timestamp = if output_json {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
        } else {
            0.0
        };

        process_line_matches(
            line_bytes,
            input_path,
            timestamp,
            db,
            extractor,
            output_json,
            &mut stats,
        )?;
    }

    let new_file = File::open(input_path)?;
    *last_pos = new_file.metadata()?.len();

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub fn follow_files_parallel(
    inputs: &[PathBuf],
    db: Arc<matchy::Database>,
    num_threads: usize,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    overall_start: Instant,
    shutdown: Arc<AtomicBool>,
    extractor_config: super::parallel::ExtractorConfig,
) -> Result<ProcessingStats> {
    if inputs.iter().any(|p| p.to_str() == Some("-")) {
        anyhow::bail!("--follow mode not supported with stdin");
    }

    let output_json = output_format == "json";

    let work_queue_capacity = num_threads * 4;
    let result_queue_capacity = 1000;

    let (work_tx, work_rx) = bounded::<Option<super::parallel::DataBatch>>(work_queue_capacity);
    let (result_tx, result_rx) =
        bounded::<Option<super::parallel::WorkerMessage>>(result_queue_capacity);

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

    let mut worker_handles = Vec::new();
    for worker_id in 0..num_threads {
        let work_rx = work_rx.clone();
        let result_tx = result_tx.clone();
        let db_clone = Arc::clone(&db);
        let extractor_config = extractor_config.clone();

        let handle = thread::spawn(move || {
            set_thread_name(&format!("matchy-follow-worker-{worker_id}"));
            worker_thread_follow(
                worker_id,
                work_rx,
                result_tx,
                db_clone,
                show_stats,
                extractor_config,
            )
        });
        worker_handles.push(handle);
    }

    drop(result_tx);

    let reader_handle = {
        let inputs = inputs.to_vec();
        let shutdown_reader = Arc::clone(&shutdown);
        thread::spawn(move || {
            set_thread_name("matchy-follow-reader");
            reader_watcher_thread(inputs, work_tx, overall_start, shutdown_reader, show_stats);
        })
    };

    reader_handle.join().expect("Reader thread panicked");

    let mut worker_stats = Vec::new();
    for handle in worker_handles {
        match handle.join() {
            Ok(stats) => worker_stats.push(stats),
            Err(_) => eprintln!("[ERROR] Worker thread panicked"),
        }
    }

    let _output_stats = output_handle.join().expect("Output thread panicked");

    let mut aggregate = ProcessingStats::new();
    for stats in worker_stats {
        aggregate.lines_processed += stats.lines_processed;
        aggregate.candidates_tested += stats.candidates_tested;
        aggregate.total_matches += stats.matches_found;
        aggregate.total_bytes += stats.total_bytes;
        aggregate.ipv4_count += stats.ipv4_count;
        aggregate.ipv6_count += stats.ipv6_count;
        aggregate.domain_count += stats.domain_count;
        aggregate.email_count += stats.email_count;
    }

    Ok(aggregate)
}

fn reader_watcher_thread(
    inputs: Vec<PathBuf>,
    work_tx: Sender<Option<super::parallel::DataBatch>>,
    _overall_start: Instant,
    shutdown: Arc<AtomicBool>,
    show_stats: bool,
) {
    if show_stats {
        eprintln!("[INFO] Processing existing file content...");
    }

    let mut file_positions: HashMap<PathBuf, u64> = HashMap::new();

    for input_path in &inputs {
        if let Ok(file) = File::open(input_path) {
            if let Ok(metadata) = file.metadata() {
                let size = metadata.len();
                if size > 0 {
                    let mut content = Vec::new();
                    if let Ok(mut f) = File::open(input_path) {
                        if f.read_to_end(&mut content).is_ok() {
                            let batch = super::parallel::DataBatch {
                                source: input_path.clone(),
                                data: Arc::new(content),
                            };
                            let _ = work_tx.send(Some(batch));
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

    while !shutdown.load(Ordering::Relaxed) {
        for (path, last_pos) in &mut file_positions {
            match std::fs::metadata(path) {
                Ok(meta) => {
                    let current_size = meta.len();
                    if current_size < *last_pos {
                        if show_stats {
                            eprintln!(
                                "[INFO] File truncated, resetting position: {}",
                                path.display()
                            );
                        }
                        *last_pos = 0;
                    }

                    if current_size > *last_pos {
                        if let Ok(mut file) = File::open(path) {
                            if file.seek(SeekFrom::Start(*last_pos)).is_ok() {
                                let mut new_content = Vec::new();
                                if file.read_to_end(&mut new_content).is_ok()
                                    && !new_content.is_empty()
                                {
                                    let batch = super::parallel::DataBatch {
                                        source: path.clone(),
                                        data: Arc::new(new_content),
                                    };
                                    let _ = work_tx.send(Some(batch));
                                    *last_pos = current_size;
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if show_stats {
                        eprintln!(
                            "[WARN] File not found (deleted/rotated?): {}",
                            path.display()
                        );
                    }
                    *last_pos = 0;
                }
                Err(e) => {
                    eprintln!("[WARN] Error checking file {}: {}", path.display(), e);
                }
            }
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    drop(work_tx);
}

fn worker_thread_follow(
    worker_id: usize,
    work_rx: Receiver<Option<super::parallel::DataBatch>>,
    result_tx: Sender<Option<super::parallel::WorkerMessage>>,
    db: Arc<matchy::Database>,
    _show_stats: bool,
    extractor_config: super::parallel::ExtractorConfig,
) -> super::parallel::WorkerStats {
    use super::parallel::{
        build_match_result, create_extractor_for_db, MatchBuffers, WorkerMessage, WorkerStats,
    };

    let extractor = match create_extractor_for_db(&db, &extractor_config) {
        Ok(ext) => ext,
        Err(e) => {
            eprintln!("[ERROR] Worker {worker_id} failed to create extractor: {e}");
            return WorkerStats::default();
        }
    };

    let mut worker = matchy::processing::Worker::builder()
        .extractor(extractor)
        .add_database("default", db)
        .build();
    let mut last_progress_update = Instant::now();
    let progress_interval = Duration::from_millis(100);

    let mut match_buffers = MatchBuffers::new();

    loop {
        let batch_opt = work_rx.recv();

        match batch_opt {
            Ok(Some(batch)) => {
                match worker.process_batch(&batch) {
                    Ok(matches) => {
                        for m in matches {
                            if let Some(match_result) = build_match_result(&m, &mut match_buffers) {
                                let _ = result_tx.send(Some(WorkerMessage::Match(match_result)));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Worker {worker_id} batch processing failed: {e}");
                    }
                }

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

    let final_stats = worker.stats().clone();
    let _ = result_tx.send(Some(WorkerMessage::Stats {
        worker_id,
        stats: final_stats.clone(),
    }));
    final_stats
}

fn output_thread_follow(
    result_rx: crossbeam_channel::Receiver<Option<super::parallel::WorkerMessage>>,
    output_json: bool,
    show_progress: bool,
    overall_start: Instant,
    shutdown: Arc<AtomicBool>,
) -> ProcessingStats {
    use super::parallel::WorkerMessage;
    use serde_json::json;

    let mut stats = ProcessingStats::new();
    let mut worker_stats_map: HashMap<usize, super::parallel::WorkerStats> = HashMap::new();

    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match result_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(msg)) => match msg {
                WorkerMessage::Match(result) => {
                    if output_json {
                        let mut match_obj = json!({
                            "timestamp": format!("{:.3}", result.timestamp),
                            "source": result.source_file.display().to_string(),
                            "matched_text": result.matched_text,
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
                            println!("{json_str}");
                        }
                    }

                    stats.total_matches += 1;
                }
                WorkerMessage::Stats {
                    worker_id,
                    stats: worker_stats_msg,
                } => {
                    worker_stats_map.insert(worker_id, worker_stats_msg);

                    let mut aggregate = ProcessingStats::new();
                    for stats in worker_stats_map.values() {
                        aggregate.lines_processed += stats.lines_processed;
                        aggregate.candidates_tested += stats.candidates_tested;
                        aggregate.total_matches += stats.matches_found;
                        aggregate.total_bytes += stats.total_bytes;
                        aggregate.ipv4_count += stats.ipv4_count;
                        aggregate.ipv6_count += stats.ipv6_count;
                        aggregate.domain_count += stats.domain_count;
                        aggregate.email_count += stats.email_count;
                    }

                    if let Some(ref mut prog) = progress {
                        if prog.should_update() {
                            prog.show(&aggregate, overall_start.elapsed());
                        }
                    }
                }
            },
            Ok(None) => {
                break;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    if progress.is_some() {
        eprintln!();
    }

    stats
}
