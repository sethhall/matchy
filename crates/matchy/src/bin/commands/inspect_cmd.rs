use anyhow::{Context, Result};
use matchy::{DataValue, Database};
use serde_json::json;
use std::path::Path;

use crate::cli_utils::{
    data_value_to_json, extract_uint_from_datavalue, format_bytes, format_unix_timestamp,
};

pub fn cmd_inspect(database: &Path, json_output: bool, verbose: bool) -> Result<()> {
    // Load database using fluent API
    let db = Database::from(database.to_str().unwrap())
        .open()
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    let has_ip = db.has_ip_data();
    let has_literals = db.has_literal_data();
    let has_globs = db.has_glob_data();
    let has_string = has_literals || has_globs;
    let literal_count = db.literal_count();
    let glob_count = db.glob_count();
    let metadata = db.metadata();
    let file_size = std::fs::metadata(database).map(|meta| meta.len()).ok();
    let metadata_map = metadata.as_ref().and_then(|meta| match meta {
        DataValue::Map(map) => Some(map),
        _ => None,
    });
    let ip_count = metadata_count(metadata_map, "ip_entry_count");
    let ipv4_count = metadata_count(metadata_map, "ipv4_entry_count");
    let ipv6_count = metadata_count(metadata_map, "ipv6_entry_count");
    let supports_ip_lookup = has_ip && ip_count != Some(0);
    let display_format = if supports_ip_lookup && has_string {
        "Matchy combined database"
    } else if supports_ip_lookup {
        "MMDB IP database"
    } else if has_string {
        "Matchy string database"
    } else {
        "Empty database"
    };

    if json_output {
        let mut output = json!({
            "file": database.display().to_string(),
            "format": display_format,
            "has_ip_data": supports_ip_lookup,
            "has_literal_data": has_literals,
            "has_glob_data": has_globs,
            "has_string_data": has_string,
            "ip_count": ip_count,
            "literal_count": literal_count,
            "glob_count": glob_count,
        });
        if let Some(count) = ipv4_count {
            output["ipv4_count"] = json!(count);
        }
        if let Some(count) = ipv6_count {
            output["ipv6_count"] = json!(count);
        }
        if let Some(size) = file_size {
            output["file_size_bytes"] = json!(size);
        }

        if let Some(meta) = metadata {
            output["metadata"] = data_value_to_json(&meta);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Database: {}", database.display());
        println!("Format:   {display_format}");
        if let Some(size) = file_size {
            let display_size = usize::try_from(size).unwrap_or(usize::MAX);
            println!("Size:     {}", format_bytes(display_size));
        }
        println!();

        println!("Contents:");
        match ip_count {
            Some(count) => println!("  IP/CIDR entries:  {count}"),
            None if has_ip => println!("  IP/CIDR entries:  not stored in metadata"),
            None => println!("  IP/CIDR entries:  0"),
        }
        if let (Some(ipv4), Some(ipv6)) = (ipv4_count, ipv6_count) {
            if ip_count.unwrap_or(usize::from(ipv4 > 0 || ipv6 > 0)) > 0 {
                println!("    IPv4 entries:   {ipv4}");
                println!("    IPv6 entries:   {ipv6}");
            }
        }
        println!("  Exact strings:    {literal_count}");
        println!("  Glob patterns:    {glob_count}");

        println!();
        println!("Lookup support:");
        println!(
            "  IP addresses:     {}",
            format_ip_lookup_support(has_ip, ip_count, ipv4_count, ipv6_count)
        );
        println!("  Exact strings:    {}", yes_no(has_literals));
        println!("  Glob patterns:    {}", yes_no(has_globs));
        if has_string {
            println!("  String match mode: {}", format_match_mode(db.mode()));
        }

        if let Some(DataValue::Map(map)) = metadata.as_ref() {
            println!();
            println!("Metadata:");

            // Show database_type if present
            if let Some(DataValue::String(db_type)) = map.get("database_type") {
                println!("  Database type:   {db_type}");
            }

            // Show description if present
            if let Some(DataValue::Map(desc_map)) = map.get("description") {
                println!("  Description:");
                for (lang, desc_value) in desc_map {
                    if let DataValue::String(desc) = desc_value {
                        println!("    {lang}: {desc}");
                    }
                }
            }

            // Show build epoch if present
            if let Some(build_epoch) = map.get("build_epoch") {
                if let Some(epoch) = extract_uint_from_datavalue(build_epoch) {
                    let timestamp_str = format_unix_timestamp(epoch);
                    println!("  Build time:      {timestamp_str} ({epoch})");
                }
            }

            if verbose {
                print_storage_details(has_ip, has_literals, has_globs, ip_count, map);
            }
        }
    }

    Ok(())
}

fn metadata_count(
    metadata: Option<&std::collections::HashMap<String, DataValue>>,
    key: &str,
) -> Option<usize> {
    metadata
        .and_then(|map| map.get(key))
        .and_then(extract_uint_from_datavalue)
        .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_match_mode(mode: matchy::MatchMode) -> &'static str {
    match mode {
        matchy::MatchMode::CaseSensitive => "case-sensitive",
        matchy::MatchMode::CaseInsensitive => "case-insensitive",
    }
}

fn format_ip_lookup_support(
    has_ip: bool,
    ip_count: Option<usize>,
    ipv4_count: Option<usize>,
    ipv6_count: Option<usize>,
) -> String {
    if !has_ip || ip_count == Some(0) {
        return "no".to_string();
    }

    match (ipv4_count, ipv6_count) {
        (Some(ipv4), Some(ipv6)) if ipv4 > 0 && ipv6 > 0 => "yes (IPv4 and IPv6)".to_string(),
        (Some(ipv4), Some(_)) if ipv4 > 0 => "yes (IPv4)".to_string(),
        (Some(_), Some(ipv6)) if ipv6 > 0 => "yes (IPv6)".to_string(),
        _ => "yes".to_string(),
    }
}

fn print_storage_details(
    has_ip: bool,
    has_literals: bool,
    has_globs: bool,
    ip_count: Option<usize>,
    metadata: &std::collections::HashMap<String, DataValue>,
) {
    println!();
    println!("Storage:");
    println!(
        "  Container:        {}",
        if has_literals || has_globs {
            "Matchy extended MMDB"
        } else {
            "MMDB"
        }
    );

    if let (Some(major), Some(minor)) = (
        metadata_count(Some(metadata), "binary_format_major_version"),
        metadata_count(Some(metadata), "binary_format_minor_version"),
    ) {
        println!("  Format version:   {major}.{minor}");
    }

    if let Some(ver) = metadata_count(Some(metadata), "ip_version") {
        println!("  MMDB IP tree:     IPv{ver}");
    }
    if let Some(record_size) = metadata_count(Some(metadata), "record_size") {
        println!("  Record size:      {record_size} bits");
    }
    if has_ip
        && metadata_count(Some(metadata), "ipv4_entry_count").is_none()
        && metadata_count(Some(metadata), "ipv6_entry_count").is_none()
    {
        println!("  IP family split: not stored in metadata");
    }

    let mut sections = Vec::new();
    if has_ip {
        if ip_count == Some(0) {
            sections.push("IP tree (empty)");
        } else {
            sections.push("IP tree");
        }
    }
    if has_literals {
        sections.push("literal hash");
    }
    if has_globs {
        sections.push("glob automaton");
    }
    if sections.is_empty() {
        println!("  Sections:         none");
    } else {
        println!("  Sections:         {}", sections.join(", "));
    }
}
