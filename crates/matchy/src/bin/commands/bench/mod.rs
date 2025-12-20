mod combined;
mod ip;
mod literal;
mod pattern;

use anyhow::Result;
use std::path::{Path, PathBuf};

pub use combined::bench_combined_database;
pub use ip::bench_ip_database;
pub use literal::bench_literal_database;
pub use pattern::bench_pattern_database;

use crate::cli_utils::format_number;

pub struct BenchConfig<'a> {
    pub count: usize,
    pub temp_file: &'a PathBuf,
    pub keep: bool,
    pub load_iterations: usize,
    pub query_count: usize,
    pub hit_rate: usize,
    pub cache_size: usize,
    pub cache_hit_rate: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_bench(
    db_type: &str,
    count: usize,
    output: Option<&Path>,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    hit_rate: usize,
    cache_size: usize,
    cache_hit_rate: usize,
    pattern_style: &str,
) -> Result<()> {
    println!("=== Matchy Database Benchmark ===\n");
    println!("Configuration:");
    println!("  Database type:     {db_type}");
    println!("  Entry count:       {}", format_number(count));
    println!("  Load iterations:   {load_iterations}");
    println!("  Query iterations:  {}", format_number(query_count));
    println!("  Match rate:        {hit_rate}% (queries that find entries)");
    println!(
        "  Cache size:        {}",
        if cache_size == 0 {
            "disabled".to_string()
        } else {
            format_number(cache_size)
        }
    );
    println!(
        "  Cache hit rate:    {}% (query repetition{})",
        cache_hit_rate,
        if cache_hit_rate == 0 {
            " - worst case"
        } else {
            ""
        }
    );
    if db_type == "pattern" {
        println!("  Pattern style:     {pattern_style}");
    }
    println!();

    // Determine output file
    let temp_file = output.map(Path::to_path_buf).unwrap_or_else(|| {
        let mut temp_dir = std::env::temp_dir();
        temp_dir.push(format!("matchy_bench_{db_type}_{count}.mxy"));
        temp_dir
    });

    match db_type {
        "ip" => bench_ip_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            cache_size,
            cache_hit_rate,
        ),
        "literal" => bench_literal_database(&BenchConfig {
            count,
            temp_file: &temp_file,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            cache_size,
            cache_hit_rate,
        }),
        "pattern" => bench_pattern_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            cache_size,
            cache_hit_rate,
            pattern_style,
        ),
        "combined" => bench_combined_database(
            count,
            &temp_file,
            keep,
            load_iterations,
            query_count,
            cache_size,
            cache_hit_rate,
        ),
        _ => {
            anyhow::bail!(
                "Unknown database type: {db_type}. Use 'ip', 'literal', 'pattern', or 'combined'"
            );
        }
    }
}
