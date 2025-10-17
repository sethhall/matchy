mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use commands::{cmd_bench, cmd_build, cmd_inspect, cmd_match, cmd_query, cmd_validate};

#[derive(Parser)]
#[command(name = "matchy")]
#[command(
    about = "Unified database for IP addresses, string literals, and glob patterns",
    long_about = "matchy - High-performance unified database for IP lookups, exact string matching, and glob pattern matching\n\n\
    Build and query databases containing IP addresses (CIDR ranges), exact string literals, \n\
    and glob patterns with wildcards. Uses memory-mapped files for fast, zero-copy queries.\n\n\
    Features:\n\
      • IP address lookups (IPv4/IPv6 with CIDR support)\n\
      • Exact string matching (hash-based)\n\
      • Multi-pattern glob matching (wildcards: *, ?, [abc], [!abc])\n\
      • Extended MMDB format with backward compatibility\n\
      • Zero-copy memory-mapped access\n\
      • Attach custom metadata to any entry\n\n\
    Examples:\n\
      matchy build patterns.txt -o threats.mxy\n\
      matchy query threats.mxy '192.168.1.1'\n\
      matchy query threats.mxy 'evil.example.com'\n\
      matchy inspect threats.mxy --verbose\n\
      matchy validate threats.mxy --level strict"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Match patterns against log files or stdin (operational testing)
    Match {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Log files to process (one entry per line), or "-" for stdin
        /// Multiple files are processed in sequence
        #[arg(value_name = "INPUT", required = true)]
        inputs: Vec<PathBuf>,

        /// Follow log file(s) for new data (like tail -f)
        /// Continuously reads new lines as they are appended
        #[arg(short = 'f', long)]
        follow: bool,

        /// Output format: json (default, NDJSON), or summary (statistics only)
        #[arg(long, default_value = "json")]
        format: String,

        /// Show detailed statistics in stderr (extraction time, candidate breakdown, etc.)
        #[arg(short, long)]
        stats: bool,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,

        /// LRU cache capacity (default: 10000, use 0 to disable)
        #[arg(long, default_value = "10000")]
        cache_size: usize,
    },

    /// Query a pattern database
    Query {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Query string to match against patterns
        #[arg(value_name = "QUERY")]
        query: String,

        /// Quiet mode - no output, only exit code (0 = found, 1 = not found)
        #[arg(short, long)]
        quiet: bool,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,
    },

    /// Inspect a pattern database
    Inspect {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Output metadata as JSON
        #[arg(short, long)]
        json: bool,

        /// Show detailed statistics
        #[arg(short, long)]
        verbose: bool,
    },

    /// Build a unified database from patterns and/or IP addresses
    Build {
        /// Input files containing patterns, IP addresses, or MISP JSON (can specify multiple)
        #[arg(value_name = "INPUT", required = true)]
        inputs: Vec<PathBuf>,

        /// Output database file (.mxy extension)
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Input format: text, csv, json, or misp (for MISP JSON threat intel files)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Database type name (e.g., "MyCompany-ThreatIntel")
        #[arg(short = 't', long)]
        database_type: Option<String>,

        /// Description text (can be specified multiple times with --desc-lang)
        #[arg(short = 'd', long)]
        description: Option<String>,

        /// Language code for description (default: "en")
        #[arg(long, default_value = "en")]
        desc_lang: String,

        /// Verbose output during build
        #[arg(short, long)]
        verbose: bool,

        /// Show detailed debug output (entry processing)
        #[arg(long)]
        debug: bool,

        /// Use case-insensitive matching for patterns (default: case-sensitive)
        #[arg(short = 'i', long)]
        case_insensitive: bool,
    },

    /// Validate a database file for safety and correctness
    Validate {
        /// Path to the matchy database (.mxy file)
        #[arg(value_name = "DATABASE")]
        database: PathBuf,

        /// Validation level: standard, strict (default), or audit
        #[arg(short, long, default_value = "strict")]
        level: String,

        /// Output results as JSON
        #[arg(short, long)]
        json: bool,

        /// Show detailed information (warnings and info messages)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Benchmark database performance (build, load, query)
    Bench {
        /// Type of database to benchmark: ip, literal, pattern, or combined
        #[arg(value_name = "TYPE", default_value = "ip")]
        db_type: String,

        /// Number of entries to test with
        #[arg(short = 'n', long, default_value = "1000000")]
        count: usize,

        /// Output file for the test database (temp file if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Keep the generated database file after benchmarking
        #[arg(short, long)]
        keep: bool,

        /// Number of load iterations to average (default: 3)
        #[arg(long, default_value = "3")]
        load_iterations: usize,

        /// Number of queries for batch benchmark (default: 100000)
        #[arg(long, default_value = "100000")]
        query_count: usize,

        /// Percentage of queries that should match (0-100, default: 10)
        #[arg(long, default_value = "10")]
        hit_rate: usize,

        /// Trust database and skip UTF-8 validation (faster, only for trusted sources)
        #[arg(long)]
        trusted: bool,

        /// LRU cache capacity (default: 10000, use 0 to disable)
        #[arg(long, default_value = "10000")]
        cache_size: usize,

        /// Simulated cache hit rate percentage (0-100, default: 0 - all unique queries)
        /// Set to 80-90 to simulate real-world log patterns where queries repeat
        #[arg(long, default_value = "0")]
        cache_hit_rate: usize,

        /// Pattern style for pattern benchmarks: prefix, suffix, mixed, or complex (default: complex)
        #[arg(long, default_value = "complex")]
        pattern_style: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Match {
            database,
            inputs,
            follow,
            format,
            stats,
            trusted,
            cache_size,
        } => cmd_match(database, inputs, follow, format, stats, trusted, cache_size),
        Commands::Query {
            database,
            query,
            quiet,
            trusted,
        } => cmd_query(database, query, quiet, trusted),
        Commands::Inspect {
            database,
            json,
            verbose,
        } => cmd_inspect(database, json, verbose),
        Commands::Validate {
            database,
            level,
            json,
            verbose,
        } => cmd_validate(database, level, json, verbose),
        Commands::Build {
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
            debug,
            case_insensitive,
        } => cmd_build(
            inputs,
            output,
            format,
            database_type,
            description,
            desc_lang,
            verbose,
            debug,
            case_insensitive,
        ),
        Commands::Bench {
            db_type,
            count,
            output,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
            pattern_style,
        } => cmd_bench(
            db_type,
            count,
            output,
            keep,
            load_iterations,
            query_count,
            hit_rate,
            trusted,
            cache_size,
            cache_hit_rate,
            pattern_style,
        ),
    }
}
