//! Batch processing infrastructure for efficient file analysis
//!
//! General-purpose building blocks for sequential or parallel line-oriented processing:
//! - **LineBatch**: Pre-chunked data with computed line offsets
//! - **LineFileReader**: Chunks files efficiently with gzip support
//! - **Worker**: Processes batches with extraction + database matching
//! - **MatchResult**: Core match info (no file context)
//! - **LineMatch**: Match with file/line context
//!
//! # Sequential Example
//!
//! ```rust,no_run
//! use matchy::{Database, processing};
//! use matchy::extractor::Extractor;
//!
//! let db = Database::from("threats.mxy").open()?;
//! let extractor = Extractor::new()?;
//!
//! let mut worker = processing::Worker::builder()
//!     .extractor(extractor)
//!     .add_database("threats", db)
//!     .build();
//!
//! let reader = processing::LineFileReader::new("access.log.gz", 128 * 1024)?;
//! for batch in reader.batches() {
//!     let batch = batch?;
//!     let matches = worker.process_lines(&batch)?;
//!     for m in matches {
//!         println!("{}:{} - {}", m.source.display(), m.line_number,
//!                  m.match_result.matched_text);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Parallel Example
//!
//! ```text
//! Reader Thread → [LineBatch queue] → Worker Pool → [Result queue] → Output Thread
//! ```
//!
//! Build your own parallel pipeline using channels and thread pools with these primitives.

use crate::extractor::{ExtractedItem, Extractor, HashType};
use crate::{Database, QueryResult};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Pre-chunked batch of line-oriented data ready for parallel processing
///
/// Contains raw bytes with pre-computed newline positions to avoid
/// duplicate memchr scans in worker threads.
#[derive(Clone)]
pub struct LineBatch {
    /// Source file path
    pub source: PathBuf,
    /// Starting line number in source file (1-indexed)
    pub starting_line_number: usize,
    /// Raw byte data for this batch
    pub data: Arc<Vec<u8>>,
    /// Pre-computed newline positions (offsets of '\n' bytes in data)
    /// Workers use these to avoid re-scanning with memchr
    pub line_offsets: Arc<Vec<usize>>,
}

/// Statistics from parallel line processing
#[derive(Default, Clone, Debug)]
pub struct WorkerStats {
    /// Total lines processed
    pub lines_processed: usize,
    /// Total candidates extracted and tested
    pub candidates_tested: usize,
    /// Total matches found
    pub matches_found: usize,
    /// Lines that had at least one match
    pub lines_with_matches: usize,
    /// Total bytes processed
    pub total_bytes: usize,
    /// Time spent extracting candidates (sampled)
    pub extraction_time: std::time::Duration,
    /// Number of extraction samples
    pub extraction_samples: usize,
    /// Time spent on database lookups (sampled)
    pub lookup_time: std::time::Duration,
    /// Number of lookup samples
    pub lookup_samples: usize,
    /// IPv4 addresses found
    pub ipv4_count: usize,
    /// IPv6 addresses found
    pub ipv6_count: usize,
    /// Domain names found
    pub domain_count: usize,
    /// Email addresses found
    pub email_count: usize,
    /// MD5 hashes found
    pub md5_count: usize,
    /// SHA1 hashes found
    pub sha1_count: usize,
    /// SHA256 hashes found
    pub sha256_count: usize,
    /// SHA384 hashes found
    pub sha384_count: usize,
    /// SHA512 hashes found
    pub sha512_count: usize,
    /// Bitcoin addresses found
    pub bitcoin_count: usize,
    /// Ethereum addresses found
    pub ethereum_count: usize,
    /// Monero addresses found
    pub monero_count: usize,
}

/// Core match result without file/line context
///
/// General-purpose match result suitable for any processing context.
/// Use [`LineMatch`] when you have file/line information.
#[derive(Clone, Debug)]
pub struct MatchResult {
    /// Matched text
    pub matched_text: String,
    /// Type of match (e.g., "IPv4", "IPv6", "Domain", "Email")
    pub match_type: String,
    /// Query result from database
    pub result: QueryResult,
    /// Which database matched (database ID)
    pub database_id: String,
    /// Byte offset in the input data (0-indexed)
    pub byte_offset: usize,
}

/// Match with file/line context
///
/// Wraps [`MatchResult`] with source location information for line-oriented processing.
#[derive(Clone, Debug)]
pub struct LineMatch {
    /// Core match result
    pub match_result: MatchResult,
    /// Source label (file path, "-" for stdin, or any label)
    pub source: PathBuf,
    /// Line number in source (1-indexed)
    pub line_number: usize,
}

/// Reads files in line-oriented chunks with compression support
///
/// Efficiently chunks files by reading fixed-size blocks and finding
/// line boundaries. Pre-computes newline offsets for workers.
///
/// Supports gzip-compressed files via extension detection.
pub struct LineFileReader {
    source_path: PathBuf,
    reader: Box<dyn Read + Send>,
    read_buffer: Vec<u8>,
    current_line_number: usize,
    eof: bool,
}

impl LineFileReader {
    /// Create a new line-oriented chunking reader
    ///
    /// # Arguments
    ///
    /// * `path` - File to read (supports .gz compression)
    /// * `chunk_size` - Target chunk size in bytes (typically 128KB)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use matchy::processing::LineFileReader;
    ///
    /// let reader = LineFileReader::new("access.log.gz", 128 * 1024)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new<P: AsRef<Path>>(path: P, chunk_size: usize) -> io::Result<Self> {
        let path = path.as_ref();

        // Open with automatic decompression
        let reader = crate::file_reader::open(path)?;

        Ok(Self {
            source_path: path.to_path_buf(),
            reader,
            read_buffer: vec![0u8; chunk_size],
            current_line_number: 1,
            eof: false,
        })
    }

    /// Read next batch of lines
    ///
    /// Returns `None` when EOF is reached.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::processing::LineFileReader;
    /// let mut reader = LineFileReader::new("data.log", 128 * 1024)?;
    ///
    /// while let Some(batch) = reader.next_batch()? {
    ///     println!("Batch has {} lines", batch.line_offsets.len());
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn next_batch(&mut self) -> io::Result<Option<LineBatch>> {
        if self.eof {
            return Ok(None);
        }

        let bytes_read = self.reader.read(&mut self.read_buffer)?;
        if bytes_read == 0 {
            self.eof = true;
            return Ok(None);
        }

        // Find last newline using memchr (SIMD-accelerated)
        let chunk_end = if let Some(pos) = memchr::memrchr(b'\n', &self.read_buffer[..bytes_read]) {
            pos + 1 // Include the newline
        } else {
            bytes_read // No newline found, send entire chunk
        };

        // Copy chunk data
        let chunk = self.read_buffer[..chunk_end].to_vec();

        // Pre-compute newline offsets (avoid duplicate memchr in workers)
        let line_offsets: Vec<usize> = memchr::memchr_iter(b'\n', &chunk).collect();
        let line_count = line_offsets.len();

        let batch = LineBatch {
            source: self.source_path.clone(),
            starting_line_number: self.current_line_number,
            data: Arc::new(chunk),
            line_offsets: Arc::new(line_offsets),
        };

        self.current_line_number += line_count;

        Ok(Some(batch))
    }

    /// Returns an iterator over line batches
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::processing::LineFileReader;
    /// let reader = LineFileReader::new("data.log", 128 * 1024)?;
    ///
    /// for batch in reader.batches() {
    ///     let batch = batch?;
    ///     // Process batch...
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn batches(self) -> LineBatchIter {
        LineBatchIter { reader: self }
    }
}

/// Iterator over line batches
pub struct LineBatchIter {
    reader: LineFileReader,
}

impl Iterator for LineBatchIter {
    type Item = io::Result<LineBatch>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_batch() {
            Ok(Some(batch)) => Some(Ok(batch)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Worker that processes batches with extraction + database matching
///
/// Supports multiple databases for cross-referencing threat feeds, allowlists, etc.
/// Use [`WorkerBuilder`] to construct workers.
///
/// # Example
///
/// ```rust,no_run
/// use matchy::{Database, processing};
/// use matchy::extractor::Extractor;
///
/// let db = Database::from("threats.mxy").open()?;
/// let extractor = Extractor::new()?;
///
/// let mut worker = processing::Worker::builder()
///     .extractor(extractor)
///     .add_database("threats", db)
///     .build();
///
/// // Process raw bytes
/// let matches = worker.process_bytes(b"Check 192.168.1.1")?;
/// println!("Found {} matches", matches.len());
///
/// // Check statistics
/// let stats = worker.stats();
/// println!("Processed {} candidates", stats.candidates_tested);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Worker {
    extractor: Extractor,
    databases: Vec<(String, Database)>, // (database_id, database)
    stats: WorkerStats,
}

impl Worker {
    /// Create a worker builder
    pub fn builder() -> WorkerBuilder {
        WorkerBuilder::new()
    }

    /// Process raw bytes without line tracking
    ///
    /// Returns core match results without file/line context.
    /// Useful for non-file processing (matchy-app, streaming, etc.)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::{Database, processing};
    /// # use matchy::extractor::Extractor;
    /// # let db = Database::from("db.mxy").open()?;
    /// # let extractor = Extractor::new()?;
    /// # let mut worker = processing::Worker::builder()
    /// #     .extractor(extractor).add_database("db", db).build();
    /// let text = "Check 192.168.1.1";
    /// let matches = worker.process_bytes(text.as_bytes())?;
    ///
    /// for m in matches {
    ///     println!("{} found in {}", m.matched_text, m.database_id);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn process_bytes(&mut self, data: &[u8]) -> Result<Vec<MatchResult>, String> {
        let mut results = Vec::new();

        // Update byte count
        self.stats.total_bytes += data.len();

        // Sample timing every 1000 operations to avoid overhead
        let should_sample_extraction = self.stats.extraction_samples < 100_000 
            && self.stats.candidates_tested % 1000 == 0;
        
        // Extract all candidates in one pass
        let extraction_start = if should_sample_extraction {
            Some(std::time::Instant::now())
        } else {
            None
        };
        
        let extracted = self.extractor.extract_from_chunk(data);
        
        if let Some(start) = extraction_start {
            self.stats.extraction_time += start.elapsed();
            self.stats.extraction_samples += 1;
        }

        for item in extracted {
            self.stats.candidates_tested += 1;

            // Track candidate types
            match &item.item {
                ExtractedItem::Ipv4(_) => self.stats.ipv4_count += 1,
                ExtractedItem::Ipv6(_) => self.stats.ipv6_count += 1,
                ExtractedItem::Domain(_) => self.stats.domain_count += 1,
                ExtractedItem::Email(_) => self.stats.email_count += 1,
                ExtractedItem::Hash(hash_type, _) => match hash_type {
                    HashType::Md5 => self.stats.md5_count += 1,
                    HashType::Sha1 => self.stats.sha1_count += 1,
                    HashType::Sha256 => self.stats.sha256_count += 1,
                    HashType::Sha384 => self.stats.sha384_count += 1,
                    HashType::Sha512 => self.stats.sha512_count += 1,
                },
                ExtractedItem::Bitcoin(_) => self.stats.bitcoin_count += 1,
                ExtractedItem::Ethereum(_) => self.stats.ethereum_count += 1,
                ExtractedItem::Monero(_) => self.stats.monero_count += 1,
            }

            // Sample lookup timing every 100 lookups
            let should_sample_lookup = self.stats.lookup_samples < 100_000
                && self.stats.candidates_tested % 100 == 0;
            
            // Lookup in all databases
            for (database_id, database) in &self.databases {
                let lookup_start = if should_sample_lookup {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                
                let (result_opt, matched_text) = match &item.item {
                    ExtractedItem::Ipv4(ip) => {
                        let result = database
                            .lookup_ip(std::net::IpAddr::V4(*ip))
                            .map_err(|e| e.to_string())?;
                        (result, ip.to_string())
                    }
                    ExtractedItem::Ipv6(ip) => {
                        let result = database
                            .lookup_ip(std::net::IpAddr::V6(*ip))
                            .map_err(|e| e.to_string())?;
                        (result, ip.to_string())
                    }
                    ExtractedItem::Domain(s)
                    | ExtractedItem::Email(s)
                    | ExtractedItem::Hash(_, s)
                    | ExtractedItem::Bitcoin(s)
                    | ExtractedItem::Ethereum(s)
                    | ExtractedItem::Monero(s) => {
                        let result = database.lookup(s).map_err(|e| e.to_string())?;
                        (result, s.to_string())
                    }
                };
                
                if let Some(start) = lookup_start {
                    self.stats.lookup_time += start.elapsed();
                    self.stats.lookup_samples += 1;
                }

                if let Some(query_result) = result_opt {
                    // Skip QueryResult::NotFound - not a real match
                    if matches!(query_result, crate::QueryResult::NotFound) {
                        continue;
                    }

                    self.stats.matches_found += 1;

                    results.push(MatchResult {
                        matched_text: matched_text.clone(),
                        match_type: item.item.type_name().to_string(),
                        result: query_result,
                        database_id: database_id.clone(),
                        byte_offset: item.span.0,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Process a line-oriented batch with automatic line number calculation
    ///
    /// Returns matches with file/line context computed automatically.
    /// Useful for file processing where line numbers matter.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::{Database, processing};
    /// # use matchy::extractor::Extractor;
    /// # let db = Database::from("db.mxy").open()?;
    /// # let extractor = Extractor::new()?;
    /// # let mut worker = processing::Worker::builder()
    /// #     .extractor(extractor).add_database("db", db).build();
    /// # let reader = processing::LineFileReader::new("data.log", 128*1024)?;
    /// # let batch = reader.batches().next().unwrap()?;
    /// let matches = worker.process_lines(&batch)?;
    ///
    /// for m in matches {
    ///     println!("{}:{} - {}", m.source.display(), m.line_number,
    ///              m.match_result.matched_text);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn process_lines(&mut self, batch: &LineBatch) -> Result<Vec<LineMatch>, String> {
        // Get core match results first
        let match_results = self.process_bytes(&batch.data)?;

        // Track which lines had matches (for statistics)
        let mut lines_with_matches = std::collections::HashSet::new();

        // Wrap each MatchResult with file/line context
        let line_matches: Vec<LineMatch> = match_results
            .into_iter()
            .map(|match_result| {
                // Calculate line number from byte offset
                let newlines_before = batch
                    .line_offsets
                    .iter()
                    .take_while(|&&off| off < match_result.byte_offset)
                    .count();
                let line_number = batch.starting_line_number + newlines_before;

                lines_with_matches.insert(line_number);

                LineMatch {
                    match_result,
                    source: batch.source.clone(),
                    line_number,
                }
            })
            .collect();

        // Update line statistics
        let line_count = batch.line_offsets.len();
        self.stats.lines_processed += line_count;
        self.stats.lines_with_matches += lines_with_matches.len();

        Ok(line_matches)
    }

    /// Get accumulated statistics
    ///
    /// Returns statistics for all batches processed by this worker.
    pub fn stats(&self) -> &WorkerStats {
        &self.stats
    }

    /// Reset statistics to zero
    pub fn reset_stats(&mut self) {
        self.stats = WorkerStats::default();
    }
}

/// Builder for [`Worker`] with support for multiple databases
///
/// # Example
///
/// ```rust,no_run
/// use matchy::{Database, processing};
/// use matchy::extractor::Extractor;
///
/// let threats = Database::from("threats.mxy").open()?;
/// let allowlist = Database::from("allowlist.mxy").open()?;
/// let extractor = Extractor::new()?;
///
/// let worker = processing::Worker::builder()
///     .extractor(extractor)
///     .add_database("threats", threats)
///     .add_database("allowlist", allowlist)
///     .build();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct WorkerBuilder {
    extractor: Option<Extractor>,
    databases: Vec<(String, Database)>,
}

impl WorkerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            extractor: None,
            databases: Vec::new(),
        }
    }

    /// Set the pattern extractor
    pub fn extractor(mut self, extractor: Extractor) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Add a database with an identifier
    ///
    /// The identifier is included in match results to show which database matched.
    pub fn add_database(mut self, id: impl Into<String>, database: Database) -> Self {
        self.databases.push((id.into(), database));
        self
    }

    /// Build the worker
    ///
    /// # Panics
    ///
    /// Panics if extractor was not set or no databases were added.
    pub fn build(self) -> Worker {
        let extractor = self
            .extractor
            .expect("Extractor not set - call .extractor()");
        assert!(
            !self.databases.is_empty(),
            "No databases added - call .add_database() at least once"
        );

        Worker {
            extractor,
            databases: self.databases,
            stats: WorkerStats::default(),
        }
    }
}

impl Default for WorkerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_line_file_reader_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "line 1").unwrap();
        writeln!(file, "line 2").unwrap();
        writeln!(file, "line 3").unwrap();
        file.flush().unwrap();

        let mut reader = LineFileReader::new(file.path(), 1024).unwrap();
        let batch = reader.next_batch().unwrap().unwrap();

        assert_eq!(batch.starting_line_number, 1);
        assert_eq!(batch.line_offsets.len(), 3);
    }

    #[test]
    fn test_line_batch_iter() {
        let mut file = NamedTempFile::new().unwrap();
        for i in 1..=10 {
            writeln!(file, "line {}", i).unwrap();
        }
        file.flush().unwrap();

        let reader = LineFileReader::new(file.path(), 1024).unwrap();
        let batches: Vec<_> = reader.batches().collect::<io::Result<Vec<_>>>().unwrap();

        assert!(!batches.is_empty());
        let total_lines: usize = batches.iter().map(|b| b.line_offsets.len()).sum();
        assert_eq!(total_lines, 10);
    }
}
