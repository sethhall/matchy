//! Automatic bottleneck detection and performance tuning recommendations

use std::time::Duration;
use super::stats::ProcessingStats;

/// Identifies the primary bottleneck in the processing pipeline
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
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
}


/// Analyze processing statistics to identify bottlenecks
pub fn analyze_performance(
    stats: &ProcessingStats,
    total_time: Duration,
    num_workers: usize,
    num_files: usize,
    cache_hit_rate: f64,
    is_auto_tuned: bool,
) -> PerformanceAnalysis {
    // Get physical core count for realistic recommendations
    let physical_cores = gdt_cpus::num_physical_cores().unwrap_or(1);
    let total_secs = total_time.as_secs_f64();
    
    // Simple ratios for bottleneck detection
    let worker_idle_secs = stats.worker_idle_time.as_secs_f64();
    let worker_busy_secs = stats.worker_busy_time.as_secs_f64();
    
    // Calculate worker idle percentage (average across workers)
    let worker_idle_pct = if num_workers > 0 && total_secs > 0.0 {
        (worker_idle_secs / num_workers as f64) / total_secs
    } else {
        0.0
    };
    
    // Bottleneck detection logic
    // Note: decompress/read times can exceed wall clock when parallel readers are used
    // So check worker idle time as primary indicator
    let (bottleneck, explanation, recommendations) = if worker_idle_pct > 0.6 {
        // Workers are mostly idle - I/O bottleneck
        let mut recs = vec![];
        if !is_auto_tuned && num_files > 1 {
            recs.push("Use --threads=0 for auto-tune".to_string());
        } else if !is_auto_tuned {
            recs.push(format!("Try --threads={} (reduce workers)", num_workers / 2));
        } else {
            // Already auto-tuned, no obvious fix
            recs.push("I/O is the limiting factor".to_string());
        }
        
        (
            Bottleneck::ReaderStarved { severity: worker_idle_pct },
            format!("Bottleneck: Workers idle {:.0}% of time (I/O can't keep up)", worker_idle_pct * 100.0),
            recs,
        )
    } else if worker_idle_pct < 0.1 && worker_busy_secs > total_secs * num_workers as f64 * 0.8 {
        let recommended_threads = (num_workers * 2).min(physical_cores);
        let mut recs = vec![];
        
        if recommended_threads > num_workers {
            recs.push(format!("Try --threads={} (add more workers)", recommended_threads));
        } else {
            recs.push(format!("Already at {} cores (hardware limit)", physical_cores));
        }
        
        (
            Bottleneck::WorkerSaturated { severity: 0.9 },
            "Bottleneck: Workers fully utilized (CPU-bound)".to_string(),
            recs,
        )
    } else if cache_hit_rate < 0.5 && stats.lookup_samples > 10000 && stats.total_matches > 100 {
        // Only suggest cache improvements if:
        // 1. Hit rate is low (< 50%)
        // 2. Significant lookup volume (> 10k lookups)
        // 3. Actually finding matches (> 100 matches)
        (
            Bottleneck::Lookup { severity: cache_hit_rate },
            format!("Bottleneck: Low cache hit rate ({:.0}% with {} lookups)", 
                    cache_hit_rate * 100.0, stats.lookup_samples),
            vec![
                "Try --cache-size=100000 to improve hit rate".to_string(),
            ],
        )
    } else {
        (
            Bottleneck::Balanced,
            "Performance: Well-balanced (no obvious bottleneck)".to_string(),
            vec![],
        )
    };
    
    PerformanceAnalysis {
        bottleneck,
        explanation,
        recommendations,
    }
}

