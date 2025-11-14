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
#[derive(Debug)]
pub struct StageBreakdown {
    pub read_percent: f64,
    pub decompress_percent: f64,
    pub extraction_percent: f64,
    pub lookup_percent: f64,
    pub worker_idle_percent: f64,
    pub worker_busy_percent: f64,
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
    
    // Calculate percentages
    let read_pct = stats.read_time.as_secs_f64() / total_secs;
    let decompress_pct = stats.decompress_time.as_secs_f64() / total_secs;
    let extract_pct = stats.extraction_time.as_secs_f64() / total_secs;
    let lookup_pct = stats.lookup_time.as_secs_f64() / total_secs;
    
    // Worker time is cumulative across all threads, so divide by num_workers
    let avg_worker_idle_pct = if num_workers > 0 {
        (stats.worker_idle_time.as_secs_f64() / num_workers as f64) / total_secs
    } else {
        0.0
    };
    let avg_worker_busy_pct = if num_workers > 0 {
        (stats.worker_busy_time.as_secs_f64() / num_workers as f64) / total_secs
    } else {
        0.0
    };
    
    let stage_breakdown = StageBreakdown {
        read_percent: read_pct * 100.0,
        decompress_percent: decompress_pct * 100.0,
        extraction_percent: extract_pct * 100.0,
        lookup_percent: lookup_pct * 100.0,
        worker_idle_percent: avg_worker_idle_pct * 100.0,
        worker_busy_percent: avg_worker_busy_pct * 100.0,
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
    } else if avg_worker_idle_pct > 0.5 {
        (
            Bottleneck::ReaderStarved { severity: avg_worker_idle_pct },
            format!(
                "Workers are idle {:.1}% of the time waiting for data from reader thread.",
                avg_worker_idle_pct * 100.0
            ),
            vec![
                "Reduce worker threads to match available work".to_string(),
                format!("Try --threads={} (currently: {})", num_workers / 2, num_workers),
                "This is normal for very fast matching on slow I/O".to_string(),
            ],
        )
    } else if avg_worker_busy_pct > 0.9 && avg_worker_idle_pct < 0.1 {
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
            Bottleneck::WorkerSaturated { severity: avg_worker_busy_pct },
            format!(
                "Workers are busy {:.1}% of the time with minimal idle time.",
                avg_worker_busy_pct * 100.0
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
    output.push_str(&format_stage_bar("Extraction", breakdown.extraction_percent));
    output.push_str(&format_stage_bar("Lookup", breakdown.lookup_percent));
    output.push_str(&format_stage_bar("Worker Idle", breakdown.worker_idle_percent));
    output.push_str(&format_stage_bar("Worker Busy", breakdown.worker_busy_percent));
    
    output
}

fn format_stage_bar(label: &str, percent: f64) -> String {
    let bar_width = 50;
    let filled = ((percent / 100.0) * bar_width as f64) as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
    
    format!("  {:15} [{bar}] {:5.1}%\n", label, percent)
}
