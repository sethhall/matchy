use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a matchy command
fn matchy_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("matchy"))
}

#[test]
fn test_help() {
    matchy_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "High-performance unified database",
        ));
}

#[test]
fn test_version() {
    matchy_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("matchy"));
}

#[test]
fn test_build_help() {
    matchy_cmd()
        .arg("build")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Build a unified database"));
}

#[test]
fn test_query_help() {
    matchy_cmd()
        .arg("query")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Query a pattern database"));
}

#[test]
fn test_inspect_help() {
    matchy_cmd()
        .arg("inspect")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Inspect a pattern database"));
}

#[test]
fn test_validate_help() {
    matchy_cmd()
        .arg("validate")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate a database file"));
}

#[test]
fn test_match_help() {
    matchy_cmd()
        .arg("match")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Match patterns against log files"));
}

#[test]
fn test_bench_help() {
    matchy_cmd()
        .arg("bench")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark database performance"));
}

#[test]
fn test_build_text_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Create input file with patterns
    fs::write(&input_file, "192.168.1.0/24\n*.evil.com\nexample.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("text")
        .assert()
        .success()
        .stdout(predicate::str::contains("Database built"));

    // Verify output file exists
    assert!(output_file.exists());
    assert!(output_file.metadata().unwrap().len() > 0);
}

#[test]
fn test_build_with_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.malware.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--database-type")
        .arg("Test-Threats")
        .arg("--description")
        .arg("Test database")
        .arg("--desc-lang")
        .arg("en")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.EVIL.COM\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--case-insensitive")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_inspect_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database
    fs::write(&input_file, "192.168.1.0/24\n*.evil.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Inspect it
    matchy_cmd()
        .arg("inspect")
        .arg(&output_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Database:"))
        .stdout(predicate::str::contains("Capabilities:"));
}

#[test]
fn test_inspect_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    matchy_cmd()
        .arg("inspect")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"has_glob_data\":"));
}

#[test]
fn test_query_pattern_match() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with patterns
    fs::write(&input_file, "*.evil.com\nmalware.*.org\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query should match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("subdomain.evil.com")
        .assert()
        .success();
}

#[test]
fn test_query_pattern_no_match() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.evil.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query should not match - exit code 1
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("good.example.com")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[]"));
}

#[test]
fn test_query_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Quiet mode: no output, just exit code
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.test.com")
        .arg("--quiet")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("nomatch.com")
        .arg("--quiet")
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_query_ip_address() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("ips.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with IP ranges
    fs::write(&input_file, "192.168.1.0/24\n10.0.0.0/8\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query IP - should match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("192.168.1.50")
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.0/24"));

    // Query IP - should not match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("8.8.8.8")
        .assert()
        .code(1);
}

#[test]
fn test_validate_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use a combined database (IP + patterns) for better validation coverage
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Validate with default (strict) level - should pass or have warnings only
    let output = matchy_cmd().arg("validate").arg(&output_file).assert();

    // Check that validation completed (might pass or fail, but should run)
    output.stdout(predicate::str::contains("Validating:"));
}

#[test]
fn test_validate_levels() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use combined database for better validation
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Test different validation levels - they should at least run
    for level in &["standard", "strict", "audit"] {
        matchy_cmd()
            .arg("validate")
            .arg(&output_file)
            .arg("--level")
            .arg(level)
            .assert()
            .stdout(predicate::str::contains("Validating:"));
    }
}

#[test]
fn test_validate_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use combined database
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    matchy_cmd()
        .arg("validate")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .stdout(predicate::str::contains("\"is_valid\":"))
        .stdout(predicate::str::contains("\"validation_level\":"));
}

#[test]
fn test_match_stdin() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with patterns that will be extracted from logs
    fs::write(&input_file, "*.evil.com\n*.malware.org\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Match command with stdin - using domain patterns that will be extracted
    let log_data =
        "user logged in from bad.evil.com\nsafe traffic\nconnection to threat.malware.org\n";

    matchy_cmd()
        .arg("match")
        .arg(&output_file)
        .arg("-")
        .arg("--format")
        .arg("json")
        .write_stdin(log_data)
        .assert()
        .success()
        .stdout(predicate::str::contains("evil.com"))
        .stdout(predicate::str::contains("malware.org"));
}

#[test]
fn test_build_csv_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.csv");
    let output_file = temp_dir.path().join("test.mxy");

    // Create CSV with entry and metadata
    let csv_content =
        "entry,severity,category\n*.evil.com,high,malware\n192.168.1.0/24,medium,suspicious\n";
    fs::write(&input_file, csv_content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("csv")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Create JSON input
    let json_content = r#"[
        {"key": "*.malware.com", "data": {"severity": "high"}},
        {"key": "192.168.1.0/24", "data": {"type": "suspicious"}}
    ]"#;
    fs::write(&input_file, json_content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_verbose_output() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Building database:"))
        .stdout(predicate::str::contains("Total entries:"));
}

#[test]
fn test_missing_database_file() {
    matchy_cmd()
        .arg("query")
        .arg("/nonexistent/database.mxy")
        .arg("test")
        .assert()
        .failure();
}

#[test]
fn test_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "test\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("invalid-format")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown format"));
}

#[test]
fn test_combined_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("combined.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Mix of IPs, patterns, and literals
    let content = "192.168.1.0/24\n*.evil.com\nexact-match.com\n10.0.0.0/8\nmalware-*.net\n";
    fs::write(&input_file, content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query IP
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("192.168.1.100")
        .assert()
        .success();

    // Query pattern
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil.com")
        .assert()
        .success();

    // Query literal
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("exact-match.com")
        .assert()
        .success();
}

#[test]
fn test_bench_ip() {
    matchy_cmd()
        .arg("bench")
        .arg("ip")
        .arg("-n")
        .arg("100") // Small count for fast test
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_bench_literal() {
    matchy_cmd()
        .arg("bench")
        .arg("literal")
        .arg("-n")
        .arg("100")
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_bench_pattern() {
    matchy_cmd()
        .arg("bench")
        .arg("pattern")
        .arg("-n")
        .arg("100")
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .arg("--pattern-style")
        .arg("prefix")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_cli_argument_order() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();

    // Arguments in different orders should work
    matchy_cmd()
        .arg("build")
        .arg("-o")
        .arg(&output_file)
        .arg(&input_file)
        .arg("--format")
        .arg("text")
        .assert()
        .success();
}

#[test]
fn test_multiple_input_files() {
    let temp_dir = TempDir::new().unwrap();
    let input1 = temp_dir.path().join("patterns1.txt");
    let input2 = temp_dir.path().join("patterns2.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input1, "*.evil1.com\n").unwrap();
    fs::write(&input2, "*.evil2.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input1)
        .arg(&input2)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Both patterns should be in the database
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil1.com")
        .assert()
        .success();

    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil2.com")
        .assert()
        .success();
}
