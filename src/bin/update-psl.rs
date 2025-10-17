//! Update Public Suffix List AC automaton from upstream
//!
//! Run with: cargo update-psl

use matchy::glob::MatchMode;
use matchy::paraglob_offset::Paraglob;
use matchy::serialization::to_bytes;
use std::fs;
use std::process::Command;

const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";
const AC_PATH: &str = "src/data/tld_automaton.ac";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Downloading Public Suffix List from {}", PSL_URL);

    let output = Command::new("curl")
        .arg("-sL") // Silent, follow redirects
        .arg(PSL_URL)
        .output()?;

    if !output.status.success() {
        eprintln!("Failed to download PSL");
        std::process::exit(1);
    }

    let data = String::from_utf8(output.stdout)?;

    // Parse PSL and extract TLD patterns for AC
    let mut patterns = Vec::new();
    let mut unicode_count = 0;
    let mut punycode_added = 0;

    for line in data.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Handle different PSL rule types
        let tld = if line.starts_with("*.") {
            // Wildcard rule: *.ck -> .ck
            &line[1..]
        } else if line.starts_with('!') {
            // Exception rule - skip
            continue;
        } else {
            // Regular rule: add leading dot
            line
        };

        let tld_with_dot = if tld.starts_with('.') {
            tld.to_lowercase()
        } else {
            format!(".{}", tld.to_lowercase())
        };

        // Add the TLD (UTF-8 as-is)
        patterns.push(tld_with_dot.clone());

        // If TLD contains non-ASCII, also add punycode version
        if tld_with_dot.bytes().any(|b| !b.is_ascii()) {
            unicode_count += 1;

            // Convert to punycode using idna crate
            // Note: Need to remove leading dot, convert, then add it back
            let tld_without_dot = &tld_with_dot[1..];
            match idna::domain_to_ascii(tld_without_dot) {
                Ok(punycode) => {
                    let punycode_with_dot = format!(".{}", punycode);
                    // Only add if different from original (some TLDs are already ASCII)
                    if punycode_with_dot != tld_with_dot {
                        patterns.push(punycode_with_dot);
                        punycode_added += 1;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to convert TLD '{}' to punycode: {}",
                        tld_with_dot, e
                    );
                }
            }
        }
    }

    println!("Parsed {} TLD patterns", patterns.len());
    println!("  - {} Unicode TLDs found", unicode_count);
    println!("  - {} punycode versions added", punycode_added);
    println!("  - Total patterns in automaton: {}", patterns.len());

    // Build AC automaton
    println!("Building Aho-Corasick automaton...");
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let paraglob = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive)?;
    let ac_bytes = to_bytes(&paraglob);

    // Save pre-built AC automaton
    fs::write(AC_PATH, &ac_bytes)?;
    println!(
        "✓ Saved AC automaton to {} ({} bytes)",
        AC_PATH,
        ac_bytes.len()
    );

    println!("\nDon't forget to commit:");
    println!("  git add {}", AC_PATH);
    println!("  git commit -m 'Update Public Suffix List AC automaton'");

    Ok(())
}
