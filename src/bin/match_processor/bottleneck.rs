//! Automatic bottleneck detection and performance tuning recommendations

use std::time::Duration;
use super::stats::ProcessingStats;

/// Identifies the primary bottleneck in the processing pipeline
#[derive(Debug, Clone, PartialEq)]
pub enum Bottleneck {
    /// Disk I/O is the limiting factor
    DiskRead { severity: f64 },
    /// Decompression (gzip) is the limiting factor
    Decompression { severity: f64 },
    /// Workers are spending too much time idle (reader can't keep up)
    ReaderStarved { severity: f64 },
    /// Workers are fully utilized (need more workers)
    WorkerSaturated { severity: f64 },
    /// Pattern extraction is consuming most CPU time
    Extraction { severity: f64 },
    /// Database lookups are consuming most CPU time
    Lookup { severity: f64 },
    /// System is well-balanced
    Balanced,
}

impl Bottleneck {
    /// Get severity as percentage (0-100)
    #[allow(dead_code)]
    pub fn severity_percent(&self) -> f64 {
        match self {
            Self::DiskRead { severity } => severity * 100.0,
            Self::Decompression { severity } => severity * 100.0,
            Self::ReaderStarved { severity } => severity * 100.0,
            Self::WorkerSaturated { severity } => severity * 100.0,
            Self::Extraction { severity } => severity * 100.0,
            Self::Lookup { severity } => severity * 100.0,
            Self::Balanced => 0.0,
        }
    }
}

/// Performance analysis and recommendations
#[derive(Debug)]
pub struct PerformanceAnalysis {
    /// Primary bottleneck
    #[allow(dead_code)]
    pub bottleneck: Bottleneck,
    /// Human-readable explanation
    pub explanation: String,
    /// Actionable recommendations
    pub recommendations: Vec<String>,
    /// Pipeline stage breakdown
    pub stage_breakdown: StageBreakdown,
}

/// Time spent in each pipeline stage (as percentage of total)
/// These are mutually exclusive buckets that should sum to ~100%
#[derive(Debug)]
pub struct StageBreakdown {
    pub read_percent: f64,
    pub decompress_percent: f64,
    pub batch_prep_percent: f64,
    pub worker_idle_percent: f64,
    pub worker_active_percent: f64,  // Everything else (extraction, lookup, result building)
}

/// Analyze processing statistics to identify bottlenecks
pub fn analyze_performance(
    stats: &ProcessingStats,
    total_time: Duration,
    num_workers: usize,
    num_files: usize,
    cache_hit_rate: f64,
) -> PerformanceAnalysis {
    // Get physical core count for realistic recommendations
    let physical_cores = gdt_cpus::num_physical_cores().unwrap_or(1);
    let total_secs = total_time.as_secs_f64();
    
    // Reader activity (sequential, single-threaded)
    let read_pct = stats.read_time.as_secs_f64() / total_secs;
    let decompress_pct = stats.decompress_time.as_secs_f64() / total_secs;
    let batch_prep_pct = stats.batch_prep_time.as_secs_f64() / total_secs;
    
    // Worker activity (parallel, so normalize by dividing by num_workers)
    let worker_idle_pct = if num_workers > 0 {
        (stats.worker_idle_time.as_secs_f64() / num_workers as f64) / total_secs
    } else {
        0.0
    };
    
    // Worker active time = everything not accounted for by reader or idle
    // This includes extraction, lookup, result building, and overhead
    let accounted_for = read_pct + decompress_pct + batch_prep_pct + worker_idle_pct;
    let worker_active_pct = (1.0 - accounted_for).max(0.0);
    
    // For bottleneck detection, use sampled extraction/lookup times
    // These are NOT shown in the breakdown (too inaccurate) but useful for detecting
    // whether extraction or lookup is the bottleneck within worker time
    let extract_pct = if num_workers > 0 {
        (stats.extraction_time.as_secs_f64() / num_workers as f64) / total_secs
    } else {
        0.0
    };
    let lookup_pct = if num_workers > 0 {
        (stats.lookup_time.as_secs_f64() / num_workers as f64) / total_secs
    } else {
        0.0
    };
    
    let stage_breakdown = StageBreakdown {
        read_percent: read_pct * 100.0,
        decompress_percent: decompress_pct * 100.0,
        batch_prep_percent: batch_prep_pct * 100.0,
        worker_idle_percent: worker_idle_pct * 100.0,
        worker_active_percent: worker_active_pct * 100.0,
    };
    
    // Bottleneck detection logic
    let (bottleneck, explanation, recommendations) = if decompress_pct > 0.4 {
        let mut recs = vec![];
        
        if num_files > 1 {
            recs.push(format!(
                "Processing {} compressed files with parallel readers - decompression is still CPU-intensive",
                num_files
            ));
        } else {
            recs.push("Single .gz file - decompression is inherently sequential per file".to_string());
        }
        
        recs.push("Gzip decompression happens in reader thread (workers are waiting for data)".to_string());
        
        (
            Bottleneck::Decompression { severity: decompress_pct },
            format!(
                "Decompression is consuming {:.1}% of total time. Gzip decompression is CPU-intensive.",
                decompress_pct * 100.0
            ),
            recs,
        )
    } else if read_pct > 0.4 {
        (
            Bottleneck::DiskRead { severity: read_pct },
            format!(
                "Disk I/O is consuming {:.1}% of total time. Storage throughput is limiting performance.",
                read_pct * 100.0
            ),
            vec![
                "Use faster storage (SSD instead of HDD)".to_string(),
                "Increase OS disk cache (may help for repeated runs)".to_string(),
                if num_files > 1 {
                    format!(
                        "Processing {} files with parallel readers - I/O throughput is still the bottleneck",
                        num_files
                    )
                } else {
                    "Single large file - sequential reading is optimal".to_string()
                },
            ],
        )
    } else if worker_idle_pct > 0.5 {
        (
            Bottleneck::ReaderStarved { severity: worker_idle_pct },
            format!(
                "Workers are idle {:.1}% of the time waiting for data from reader thread.",
                worker_idle_pct * 100.0
            ),
            vec![
                "Reduce worker threads to match available work".to_string(),
                format!("Try --threads={} (currently: {})", num_workers / 2, num_workers),
                "This is normal for very fast matching on slow I/O".to_string(),
            ],
        )
    } else if worker_active_pct > 0.9 && worker_idle_pct < 0.1 {
        let recommended_threads = (num_workers * 2).min(physical_cores);
        let mut recs = vec![];
        
        if recommended_threads > num_workers {
            recs.push(format!("Increase worker threads: --threads={}", recommended_threads));
            recs.push("Workers are fully utilized - this is a CPU bottleneck".to_string());
        } else {
            recs.push(format!(
                "Already using {} threads (matches {} physical cores)",
                num_workers, physical_cores
            ));
            recs.push("Workers are maxed out - hardware limit reached".to_string());
        }
        
        (
            Bottleneck::WorkerSaturated { severity: worker_active_pct },
            format!(
                "Workers are active {:.1}% of the time with minimal idle time.",
                worker_active_pct * 100.0
            ),
            recs,
        )
    } else if extract_pct > 0.3 {
        (
            Bottleneck::Extraction { severity: extract_pct },
            format!(
                "Pattern extraction is consuming {:.1}% of sampled time.",
                extract_pct * 100.0
            ),
            vec![
                "Extraction overhead is high - consider if all extraction types are needed".to_string(),
                "Use database capabilities to skip unnecessary extraction (automatic)".to_string(),
            ],
        )
    } else if lookup_pct > 0.3 {
        (
            Bottleneck::Lookup { severity: lookup_pct },
            format!(
                "Database lookups are consuming {:.1}% of sampled time.",
                lookup_pct * 100.0
            ),
            vec![
                format!("Current cache hit rate: {:.1}%", cache_hit_rate * 100.0),
                if cache_hit_rate < 0.5 {
                    "Increase cache size with --cache-size (current hit rate is low)".to_string()
                } else if cache_hit_rate < 0.8 {
                    "Consider increasing cache size with --cache-size".to_string()
                } else {
                    "Cache hit rate is good - lookups are the bottleneck".to_string()
                },
                "Consider optimizing database structure if lookups are slow".to_string(),
            ],
        )
    } else {
        (
            Bottleneck::Balanced,
            "System is well-balanced across all stages.".to_string(),
            vec![
                "No obvious bottleneck detected".to_string(),
                "Performance is good - current settings are reasonable".to_string(),
            ],
        )
    };
    
    PerformanceAnalysis {
        bottleneck,
        explanation,
        recommendations,
        stage_breakdown,
    }
}

/// Format stage breakdown as a visual bar chart
pub fn format_stage_breakdown(breakdown: &StageBreakdown) -> String {
    let mut output = String::new();
    
    output.push_str("Pipeline Stage Breakdown:\n");
    output.push_str(&format_stage_bar("Disk Read", breakdown.read_percent));
    output.push_str(&format_stage_bar("Decompression", breakdown.decompress_percent));
    output.push_str(&format_stage_bar("Batch Prep", breakdown.batch_prep_percent));
    output.push_str(&format_stage_bar("Worker Idle", breakdown.worker_idle_percent));
    output.push_str(&format_stage_bar("Worker Active", breakdown.worker_active_percent));
    
    // Calculate and show total to verify math
    let total = breakdown.read_percent + breakdown.decompress_percent + breakdown.batch_prep_percent
        + breakdown.worker_idle_percent + breakdown.worker_active_percent;
    output.push_str(&format!("  {:15} {:7.1}%\n", "Total:", total));
    
    output
}

fn format_stage_bar(label: &str, percent: f64) -> String {
    let bar_width = 50;
    let filled = ((percent / 100.0) * bar_width as f64) as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
    
    format!("  {:15} [{bar}] {:5.1}%\n", label, percent)
}
