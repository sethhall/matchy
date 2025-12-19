use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use xxhash_rust::xxh64::xxh64;

/// Simple open-addressed hash set format for PSL lookups.
///
/// Format (all little-endian):
/// ```text
/// [Header - 16 bytes]
///   magic: [u8; 4]     = "PSLH"
///   version: u32       = 1
///   entry_count: u32   = number of entries
///   table_size: u32    = hash table size (entry_count * 1.25, power of 2)
///
/// [Hash Table - table_size * 16 bytes]
///   entries: [hash: u64, string_offset: u32, string_len: u32] * table_size
///   (empty slots have string_offset = 0xFFFFFFFF)
///
/// [String Pool]
///   Concatenated suffix strings (no null terminators, lengths in table)
/// ```
const MAGIC: &[u8; 4] = b"PSLH";
const VERSION: u32 = 1;
const EMPTY_SLOT: u32 = 0xFFFFFFFF;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let psl_path = Path::new("src/data/public_suffix_list.dat");

    // Tell Cargo to rerun if the PSL file changes
    println!("cargo:rerun-if-changed=src/data/public_suffix_list.dat");

    // Read and parse PSL file
    let file = File::open(psl_path).expect("Failed to open public_suffix_list.dat");
    let reader = BufReader::new(file);

    let mut suffixes: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        suffixes.push(line.to_string());
    }

    // Calculate table size (next power of 2 >= entry_count * 1.25)
    let entry_count = suffixes.len() as u32;
    let min_size = (entry_count as f64 * 1.25) as u32;
    let table_size = min_size.next_power_of_two();
    let table_mask = table_size - 1;

    // Build hash table and string pool
    let mut table: Vec<(u64, u32, u32)> = vec![(0, EMPTY_SLOT, 0); table_size as usize];
    let mut string_pool: Vec<u8> = Vec::new();

    for suffix in &suffixes {
        let bytes = suffix.as_bytes();
        let hash = xxh64(bytes, 0);

        // Store string in pool
        let string_offset = string_pool.len() as u32;
        let string_len = bytes.len() as u32;
        string_pool.extend_from_slice(bytes);

        // Find slot using linear probing
        let mut slot = (hash as u32 & table_mask) as usize;
        loop {
            if table[slot].1 == EMPTY_SLOT {
                table[slot] = (hash, string_offset, string_len);
                break;
            }
            slot = (slot + 1) & (table_mask as usize);
        }
    }

    // Write binary format
    let out_path = Path::new(&out_dir).join("psl_hash.bin");
    let mut out_file = File::create(&out_path).expect("Failed to create output file");

    // Header
    out_file.write_all(MAGIC).unwrap();
    out_file.write_all(&VERSION.to_le_bytes()).unwrap();
    out_file.write_all(&entry_count.to_le_bytes()).unwrap();
    out_file.write_all(&table_size.to_le_bytes()).unwrap();

    // Hash table
    for (hash, offset, len) in &table {
        out_file.write_all(&hash.to_le_bytes()).unwrap();
        out_file.write_all(&offset.to_le_bytes()).unwrap();
        out_file.write_all(&len.to_le_bytes()).unwrap();
    }

    // String pool
    out_file.write_all(&string_pool).unwrap();

    // Report stats
    let total_size = 16 + (table_size as usize * 16) + string_pool.len();
    println!(
        "cargo:warning=PSL hash table: {} entries, {} bytes total",
        entry_count, total_size
    );
}
