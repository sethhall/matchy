//! Example: Building a COMBINED IP + Pattern database
//!
//! This demonstrates the POWER of the extended MMDB format:
//! A single database that can query both IP addresses AND patterns!

use matchy::DataValue;
use matchy::DatabaseBuilder;
use matchy::MatchMode;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Building COMBINED IP + Pattern database...\n");
    println!("This is the unified MMDB format - IP lookups AND pattern matching in ONE database!");
    println!("{}", "=".repeat(80));

    // Create a builder
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // ========== ADD IP ADDRESSES ==========
    println!("\n📍 Adding IP address entries:");

    let mut ip_data1 = HashMap::new();
    ip_data1.insert(
        "type".to_string(),
        DataValue::String("Private Network".to_string()),
    );
    ip_data1.insert("rfc".to_string(), DataValue::String("RFC1918".to_string()));
    ip_data1.insert("security_level".to_string(), DataValue::Uint32(1));
    builder.add_entry("192.168.0.0/16", ip_data1)?;
    println!("  ✓ 192.168.0.0/16 - Private Network");

    let mut ip_data2 = HashMap::new();
    ip_data2.insert(
        "service".to_string(),
        DataValue::String("Google Public DNS".to_string()),
    );
    ip_data2.insert(
        "provider".to_string(),
        DataValue::String("Google".to_string()),
    );
    ip_data2.insert("trusted".to_string(), DataValue::Bool(true));
    builder.add_entry("8.8.8.8", ip_data2)?;
    println!("  ✓ 8.8.8.8 - Google DNS");

    let mut ip_data3 = HashMap::new();
    ip_data3.insert(
        "service".to_string(),
        DataValue::String("Cloudflare DNS".to_string()),
    );
    ip_data3.insert(
        "provider".to_string(),
        DataValue::String("Cloudflare".to_string()),
    );
    ip_data3.insert("trusted".to_string(), DataValue::Bool(true));
    builder.add_entry("1.1.1.1", ip_data3)?;
    println!("  ✓ 1.1.1.1 - Cloudflare DNS");

    // ========== ADD PATTERNS ==========
    println!("\n🔍 Adding pattern entries:");

    let mut pattern_data1 = HashMap::new();
    pattern_data1.insert("type".to_string(), DataValue::String("malware".to_string()));
    pattern_data1.insert(
        "severity".to_string(),
        DataValue::String("critical".to_string()),
    );
    pattern_data1.insert("score".to_string(), DataValue::Uint32(95));
    builder.add_entry("*.evil.com", pattern_data1)?;
    println!("  ✓ *.evil.com - Malware domain");

    let mut pattern_data2 = HashMap::new();
    pattern_data2.insert(
        "type".to_string(),
        DataValue::String("tracking".to_string()),
    );
    pattern_data2.insert(
        "category".to_string(),
        DataValue::String("advertising".to_string()),
    );
    pattern_data2.insert("score".to_string(), DataValue::Uint32(50));
    builder.add_entry("*tracker*", pattern_data2)?;
    println!("  ✓ *tracker* - Tracking services");

    let mut pattern_data3 = HashMap::new();
    pattern_data3.insert(
        "type".to_string(),
        DataValue::String("security".to_string()),
    );
    pattern_data3.insert("action".to_string(), DataValue::String("block".to_string()));
    pattern_data3.insert(
        "reason".to_string(),
        DataValue::String("known_malicious".to_string()),
    );
    builder.add_entry("malware-*.example.net", pattern_data3)?;
    println!("  ✓ malware-*.example.net - Malicious subdomains");

    let mut pattern_data4 = HashMap::new();
    pattern_data4.insert("type".to_string(), DataValue::String("safe".to_string()));
    pattern_data4.insert(
        "category".to_string(),
        DataValue::String("search_engine".to_string()),
    );
    pattern_data4.insert("trusted".to_string(), DataValue::Bool(true));
    builder.add_entry("*.google.com", pattern_data4)?;
    println!("  ✓ *.google.com - Google domains");

    // ========== STATISTICS ==========
    let stats = builder.stats();
    println!("\n{}", "=".repeat(80));
    println!("📊 Database Statistics:");
    println!("  Total entries:    {}", stats.total_entries);
    println!(
        "  IP entries:       {} (will build MMDB IP tree)",
        stats.ip_entries
    );
    println!("  Literal entries:  {}", stats.literal_entries);
    println!(
        "  Glob entries:     {} (will build Paraglob automaton)",
        stats.glob_entries
    );

    // ========== BUILD ==========
    println!("\n🔨 Building unified database...");
    println!("  - Building IP search tree...");
    println!("  - Building pattern automaton...");
    println!("  - Encoding data section...");
    println!("  - Assembling MMDB format...");

    let database_bytes = builder.build()?;

    println!("\n✅ DATABASE BUILT SUCCESSFULLY!");
    println!("  Size: {} bytes", database_bytes.len());
    println!("  Format: Extended MMDB (MaxMind DB compatible + Paraglob patterns)");

    // ========== WHAT YOU CAN DO ==========
    println!("\n{}", "=".repeat(80));
    println!("🎯 What you can do with this database:");
    println!("\n  📍 IP Lookups:");
    println!("     • Query '192.168.1.100' → Private Network (RFC1918)");
    println!("     • Query '8.8.8.8' → Google DNS (trusted)");
    println!("     • Standard MMDB binary tree search (O(log n))");

    println!("\n  🔍 Pattern Lookups:");
    println!("     • Query 'ad-tracker.example.com' → Tracking (advertising)");
    println!("     • Query 'malware-x.example.net' → Malicious (block)");
    println!("     • Fast Aho-Corasick pattern matching (O(n))");

    println!("\n  🚀 Performance:");
    println!("     • Memory-mapped file loading (~1ms)");
    println!("     • Zero-copy access to all data");
    println!("     • Shared memory across processes");

    println!("\n  💾 Storage:");
    println!("     • Single file format (.mxy extension)");
    println!("     • Based on MMDB format, compatible with MMDB readers (for IP part)");
    println!("     • Extended with pattern matching capability");

    println!("\n{}", "=".repeat(80));
    println!("🎉 SUCCESS! You now have a unified threat intelligence database!");
    println!(
        "   {} IP ranges + {} literals + {} globs in {} bytes",
        stats.ip_entries,
        stats.literal_entries,
        stats.glob_entries,
        database_bytes.len()
    );

    // Optionally save to disk
    let output_file = "combined_database.mxy";
    std::fs::write(output_file, &database_bytes)?;
    println!("\n💾 Saved to: {output_file}");
    println!("   Ready to load and query!");

    Ok(())
}
