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
        .arg("-sL")  // Silent, follow redirects
        .arg(PSL_URL)
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to download PSL");
        std::process::exit(1);
    }
    
    let data = String::from_utf8(output.stdout)?;
    
    // Parse PSL and extract TLD patterns for AC
    let mut patterns = Vec::new();
    
    for line in data.lines() {
        let line = line.trim();
        
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        
        // Handle different PSL rule types
        if line.starts_with("*.") {
            // Wildcard rule: *.ck -> match .ck
            patterns.push(line[1..].to_lowercase()); // Keep the dot
        } else if line.starts_with('!') {
            // Exception rule - skip
            continue;
        } else {
            // Regular rule: add with leading dot
            // "com" -> ".com" to match "example.com"
            patterns.push(format!(".{}", line.to_lowercase()));
        }
    }
    
    println!("Parsed {} TLD patterns", patterns.len());
    
    // Build AC automaton
    println!("Building Aho-Corasick automaton...");
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let paraglob = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive)?;
    let ac_bytes = to_bytes(&paraglob);
    
    // Save pre-built AC automaton
    fs::write(AC_PATH, &ac_bytes)?;
    println!("✓ Saved AC automaton to {} ({} bytes)", AC_PATH, ac_bytes.len());
    
    println!("\nDon't forget to commit:");
    println!("  git add {}", AC_PATH);
    println!("  git commit -m 'Update Public Suffix List AC automaton'");
    
    Ok(())
}
