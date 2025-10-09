//! Glob pattern matching implementation.
//!
//! This module provides glob pattern support with wildcards (`*`, `?`), character classes
//! (`[...]`, `[!...]`), and literal matching. Patterns are parsed into structured segments
//! and matched efficiently against text.
//!
//! # Glob Syntax
//!
//! - `*` - Matches zero or more of any character (greedy)
//! - `?` - Matches exactly one of any character
//! - `[abc]` - Matches one character from the set (a, b, or c)
//! - `[!abc]` or `[^abc]` - Matches one character NOT in the set
//! - `[a-z]` - Matches one character in the range (a through z)
//! - `\x` - Escapes special character x (literal *)
//!
//! # Examples
//!
//! ```
//! use paraglob_rs::glob::{GlobPattern, MatchMode};
//!
//! // Simple wildcard matching
//! let pattern = GlobPattern::new("*.txt", MatchMode::CaseSensitive)?;
//! assert!(pattern.matches("file.txt"));
//! assert!(pattern.matches("document.txt"));
//! assert!(!pattern.matches("file.pdf"));
//!
//! // Character classes
//! let pattern = GlobPattern::new("file[0-9].txt", MatchMode::CaseSensitive)?;
//! assert!(pattern.matches("file1.txt"));
//! assert!(pattern.matches("file9.txt"));
//! assert!(!pattern.matches("fileA.txt"));
//!
//! // Negated character classes
//! let pattern = GlobPattern::new("file[!0-9].txt", MatchMode::CaseSensitive)?;
//! assert!(pattern.matches("fileA.txt"));
//! assert!(!pattern.matches("file1.txt"));
//! # Ok::<(), paraglob_rs::ParaglobError>(())
//! ```

use crate::error::ParaglobError;
use std::fmt;

/// Match mode for glob patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-sensitive matching
    CaseSensitive,
    /// Case-insensitive matching
    CaseInsensitive,
}

/// A segment of a glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobSegment {
    /// Literal text segment (no wildcards)
    Literal(String),

    /// `*` - matches zero or more of any character
    Star,

    /// `?` - matches exactly one character
    Question,

    /// `[...]` - character class, matches one character from the set
    CharClass {
        /// Characters or ranges to match
        chars: Vec<CharClassItem>,
        /// If true, negated class [!...] or [^...]
        negated: bool,
    },
}

/// Item in a character class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharClassItem {
    /// Single character
    Char(char),
    /// Range of characters (inclusive)
    Range(char, char),
}

/// A parsed glob pattern.
#[derive(Debug, Clone)]
pub struct GlobPattern {
    /// Original pattern string
    pattern: String,
    /// Parsed segments
    segments: Vec<GlobSegment>,
    /// Match mode
    mode: MatchMode,
}

impl GlobPattern {
    /// Creates a new glob pattern from a string.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The glob pattern string
    /// * `mode` - Case-sensitive or case-insensitive matching
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is malformed (e.g., unclosed brackets).
    ///
    /// # Examples
    ///
    /// ```
    /// use paraglob_rs::glob::{GlobPattern, MatchMode};
    ///
    /// let pattern = GlobPattern::new("*.txt", MatchMode::CaseSensitive)?;
    /// assert!(pattern.matches("hello.txt"));
    /// # Ok::<(), paraglob_rs::ParaglobError>(())
    /// ```
    pub fn new(pattern: &str, mode: MatchMode) -> Result<Self, ParaglobError> {
        let segments = Self::parse(pattern, mode)?;
        Ok(Self {
            pattern: pattern.to_string(),
            segments,
            mode,
        })
    }

    /// Returns the original pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns the match mode.
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Returns the parsed segments.
    pub fn segments(&self) -> &[GlobSegment] {
        &self.segments
    }

    /// Checks if the pattern matches the given text.
    ///
    /// # Examples
    ///
    /// ```
    /// use paraglob_rs::glob::{GlobPattern, MatchMode};
    ///
    /// let pattern = GlobPattern::new("hello*world", MatchMode::CaseSensitive)?;
    /// assert!(pattern.matches("hello world"));
    /// assert!(pattern.matches("hello beautiful world"));
    /// assert!(!pattern.matches("goodbye world"));
    /// # Ok::<(), paraglob_rs::ParaglobError>(())
    /// ```
    pub fn matches(&self, text: &str) -> bool {
        self.matches_impl(text, 0, 0)
    }

    /// Recursive matching implementation.
    ///
    /// This uses a backtracking algorithm to handle wildcards efficiently.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to match against
    /// * `text_pos` - Current position in the text (byte offset)
    /// * `seg_idx` - Current segment index in the pattern
    fn matches_impl(&self, text: &str, text_pos: usize, seg_idx: usize) -> bool {
        // If we've consumed all segments, we match if we've also consumed all text
        if seg_idx >= self.segments.len() {
            return text_pos >= text.len();
        }

        match &self.segments[seg_idx] {
            GlobSegment::Literal(lit) => {
                // Try to match literal at current position
                let remaining = &text[text_pos..];
                let matches = match self.mode {
                    MatchMode::CaseSensitive => remaining.starts_with(lit.as_str()),
                    MatchMode::CaseInsensitive => {
                        remaining.len() >= lit.len()
                            && remaining[..lit.len()].eq_ignore_ascii_case(lit)
                    }
                };

                if matches {
                    self.matches_impl(text, text_pos + lit.len(), seg_idx + 1)
                } else {
                    false
                }
            }

            GlobSegment::Question => {
                // Match exactly one character
                if let Some(ch) = text[text_pos..].chars().next() {
                    self.matches_impl(text, text_pos + ch.len_utf8(), seg_idx + 1)
                } else {
                    false
                }
            }

            GlobSegment::CharClass { chars, negated } => {
                // Match one character from (or not from) the class
                if let Some(ch) = text[text_pos..].chars().next() {
                    let ch_normalized = match self.mode {
                        MatchMode::CaseSensitive => ch,
                        MatchMode::CaseInsensitive => ch.to_ascii_lowercase(),
                    };

                    let in_class = chars.iter().any(|item| match item {
                        CharClassItem::Char(c) => {
                            let c_normalized = match self.mode {
                                MatchMode::CaseSensitive => *c,
                                MatchMode::CaseInsensitive => c.to_ascii_lowercase(),
                            };
                            ch_normalized == c_normalized
                        }
                        CharClassItem::Range(start, end) => {
                            let start_norm = match self.mode {
                                MatchMode::CaseSensitive => *start,
                                MatchMode::CaseInsensitive => start.to_ascii_lowercase(),
                            };
                            let end_norm = match self.mode {
                                MatchMode::CaseSensitive => *end,
                                MatchMode::CaseInsensitive => end.to_ascii_lowercase(),
                            };
                            ch_normalized >= start_norm && ch_normalized <= end_norm
                        }
                    });

                    let matches = if *negated { !in_class } else { in_class };

                    if matches {
                        self.matches_impl(text, text_pos + ch.len_utf8(), seg_idx + 1)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            GlobSegment::Star => {
                // `*` matches zero or more characters
                // Try matching with zero characters first (greedy is handled by trying longest first)

                // Special case: if star is at the end, it matches everything remaining
                if seg_idx + 1 >= self.segments.len() {
                    return true;
                }

                // Try matching star with 0, 1, 2, ... characters
                // We need to try all possibilities due to backtracking
                for i in text_pos..=text.len() {
                    if self.matches_impl(text, i, seg_idx + 1) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Parses a glob pattern string into segments.
    fn parse(pattern: &str, _mode: MatchMode) -> Result<Vec<GlobSegment>, ParaglobError> {
        let mut segments = Vec::new();
        let mut chars = pattern.chars().peekable();
        let mut literal_buf = String::new();

        // Helper to flush accumulated literal
        let flush_literal = |buf: &mut String, segs: &mut Vec<GlobSegment>| {
            if !buf.is_empty() {
                segs.push(GlobSegment::Literal(std::mem::take(buf)));
            }
        };

        while let Some(ch) = chars.next() {
            match ch {
                '*' => {
                    flush_literal(&mut literal_buf, &mut segments);
                    segments.push(GlobSegment::Star);
                }

                '?' => {
                    flush_literal(&mut literal_buf, &mut segments);
                    segments.push(GlobSegment::Question);
                }

                '[' => {
                    flush_literal(&mut literal_buf, &mut segments);

                    // Parse character class
                    let mut negated = false;
                    let mut class_items = Vec::new();

                    // Check for negation
                    if let Some(&next_ch) = chars.peek() {
                        if next_ch == '!' || next_ch == '^' {
                            negated = true;
                            chars.next();
                        }
                    }

                    // Parse class contents
                    let mut prev_char: Option<char> = None;
                    let mut expect_range_end = false;

                    loop {
                        let class_ch = chars.next().ok_or_else(|| {
                            ParaglobError::InvalidPattern("Unclosed character class".to_string())
                        })?;

                        if class_ch == ']' && (!class_items.is_empty() || prev_char.is_some()) {
                            // End of character class
                            if let Some(ch) = prev_char {
                                class_items.push(CharClassItem::Char(ch));
                            }
                            break;
                        }

                        if class_ch == '-'
                            && prev_char.is_some()
                            && chars.peek().is_some()
                            && chars.peek() != Some(&']')
                        {
                            // This is a range
                            expect_range_end = true;
                        } else if expect_range_end {
                            // Complete the range
                            let start = prev_char.unwrap();
                            let end = class_ch;
                            if start > end {
                                return Err(ParaglobError::InvalidPattern(format!(
                                    "Invalid character range: {}-{}",
                                    start, end
                                )));
                            }
                            class_items.push(CharClassItem::Range(start, end));
                            prev_char = None;
                            expect_range_end = false;
                        } else {
                            // Regular character
                            if let Some(ch) = prev_char {
                                class_items.push(CharClassItem::Char(ch));
                            }
                            prev_char = Some(class_ch);
                        }
                    }

                    if class_items.is_empty() {
                        return Err(ParaglobError::InvalidPattern(
                            "Empty character class".to_string(),
                        ));
                    }

                    segments.push(GlobSegment::CharClass {
                        chars: class_items,
                        negated,
                    });
                }

                '\\' => {
                    // Escape sequence - next character is literal
                    if let Some(escaped) = chars.next() {
                        literal_buf.push(escaped);
                    } else {
                        return Err(ParaglobError::InvalidPattern(
                            "Trailing backslash in pattern".to_string(),
                        ));
                    }
                }

                _ => {
                    literal_buf.push(ch);
                }
            }
        }

        // Flush remaining literal
        flush_literal(&mut literal_buf, &mut segments);

        // Optimize: merge consecutive literals
        segments = Self::optimize_segments(segments);

        Ok(segments)
    }

    /// Optimizes segments by merging consecutive literals.
    fn optimize_segments(segments: Vec<GlobSegment>) -> Vec<GlobSegment> {
        let mut optimized = Vec::new();
        let mut literal_buf = String::new();

        for seg in segments {
            if let GlobSegment::Literal(s) = seg {
                literal_buf.push_str(&s);
            } else {
                if !literal_buf.is_empty() {
                    optimized.push(GlobSegment::Literal(std::mem::take(&mut literal_buf)));
                }
                optimized.push(seg);
            }
        }

        if !literal_buf.is_empty() {
            optimized.push(GlobSegment::Literal(literal_buf));
        }

        optimized
    }
}

impl fmt::Display for GlobPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_pattern() {
        let pattern = GlobPattern::new("hello", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("hello"));
        assert!(!pattern.matches("hello world"));
        assert!(!pattern.matches("Hell o"));
        assert!(!pattern.matches(""));
    }

    #[test]
    fn test_literal_case_insensitive() {
        let pattern = GlobPattern::new("hello", MatchMode::CaseInsensitive).unwrap();
        assert!(pattern.matches("hello"));
        assert!(pattern.matches("HELLO"));
        assert!(pattern.matches("HeLLo"));
        assert!(!pattern.matches("hello world"));
    }

    #[test]
    fn test_star_wildcard() {
        let pattern = GlobPattern::new("*.txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches(".txt"));
        assert!(pattern.matches("file.txt"));
        assert!(pattern.matches("my.file.txt"));
        assert!(!pattern.matches("file.pdf"));
        assert!(!pattern.matches("txt"));
    }

    #[test]
    fn test_star_middle() {
        let pattern = GlobPattern::new("hello*world", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("helloworld"));
        assert!(pattern.matches("hello world"));
        assert!(pattern.matches("hello beautiful world"));
        assert!(!pattern.matches("hello"));
        assert!(!pattern.matches("world"));
        assert!(!pattern.matches("goodbye world"));
    }

    #[test]
    fn test_multiple_stars() {
        let pattern = GlobPattern::new("*hello*world*", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("hello world"));
        assert!(pattern.matches("say hello to the world today"));
        assert!(pattern.matches("helloworld"));
        assert!(!pattern.matches("hello"));
        assert!(!pattern.matches("world"));
    }

    #[test]
    fn test_question_mark() {
        let pattern = GlobPattern::new("file?.txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("file1.txt"));
        assert!(pattern.matches("fileA.txt"));
        assert!(pattern.matches("file?.txt"));
        assert!(!pattern.matches("file.txt"));
        assert!(!pattern.matches("file10.txt"));
    }

    #[test]
    fn test_multiple_questions() {
        let pattern = GlobPattern::new("???", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("abc"));
        assert!(pattern.matches("123"));
        assert!(!pattern.matches("ab"));
        assert!(!pattern.matches("abcd"));
    }

    #[test]
    fn test_char_class_simple() {
        let pattern = GlobPattern::new("file[123].txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("file1.txt"));
        assert!(pattern.matches("file2.txt"));
        assert!(pattern.matches("file3.txt"));
        assert!(!pattern.matches("file4.txt"));
        assert!(!pattern.matches("fileA.txt"));
    }

    #[test]
    fn test_char_class_range() {
        let pattern = GlobPattern::new("file[0-9].txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("file0.txt"));
        assert!(pattern.matches("file5.txt"));
        assert!(pattern.matches("file9.txt"));
        assert!(!pattern.matches("fileA.txt"));
    }

    #[test]
    fn test_char_class_multiple_ranges() {
        let pattern = GlobPattern::new("[a-zA-Z]", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("a"));
        assert!(pattern.matches("z"));
        assert!(pattern.matches("A"));
        assert!(pattern.matches("Z"));
        assert!(!pattern.matches("0"));
        assert!(!pattern.matches("!"));
    }

    #[test]
    fn test_char_class_negated() {
        let pattern = GlobPattern::new("file[!0-9].txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("fileA.txt"));
        assert!(pattern.matches("file_.txt"));
        assert!(!pattern.matches("file0.txt"));
        assert!(!pattern.matches("file9.txt"));
    }

    #[test]
    fn test_char_class_negated_caret() {
        let pattern = GlobPattern::new("[^abc]", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("d"));
        assert!(pattern.matches("z"));
        assert!(!pattern.matches("a"));
        assert!(!pattern.matches("b"));
    }

    #[test]
    fn test_escape_sequences() {
        let pattern = GlobPattern::new(r"file\*.txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("file*.txt"));
        assert!(!pattern.matches("file1.txt"));
        assert!(!pattern.matches("fileany.txt"));
    }

    #[test]
    fn test_escape_question() {
        let pattern = GlobPattern::new(r"file\?.txt", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("file?.txt"));
        assert!(!pattern.matches("file1.txt"));
    }

    #[test]
    fn test_complex_pattern() {
        let pattern = GlobPattern::new("**/[a-z]*.{txt,md}", MatchMode::CaseSensitive).unwrap();
        // Note: This pattern has literal {txt,md} - we don't support brace expansion yet
        assert!(pattern.matches("some/path/file.{txt,md}"));
    }

    #[test]
    fn test_empty_pattern() {
        let pattern = GlobPattern::new("", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches(""));
        assert!(!pattern.matches("anything"));
    }

    #[test]
    fn test_star_only() {
        let pattern = GlobPattern::new("*", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches(""));
        assert!(pattern.matches("anything"));
        assert!(pattern.matches("multiple words"));
    }

    #[test]
    fn test_invalid_char_class_unclosed() {
        let result = GlobPattern::new("file[abc", MatchMode::CaseSensitive);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_char_class_empty() {
        let result = GlobPattern::new("file[]", MatchMode::CaseSensitive);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_range() {
        let result = GlobPattern::new("[z-a]", MatchMode::CaseSensitive);
        assert!(result.is_err());
    }

    #[test]
    fn test_trailing_backslash() {
        let result = GlobPattern::new(r"file\", MatchMode::CaseSensitive);
        assert!(result.is_err());
    }

    #[test]
    fn test_case_insensitive_char_class() {
        let pattern = GlobPattern::new("[a-z]", MatchMode::CaseInsensitive).unwrap();
        assert!(pattern.matches("a"));
        assert!(pattern.matches("A"));
        assert!(pattern.matches("z"));
        assert!(pattern.matches("Z"));
    }

    #[test]
    fn test_utf8_support() {
        let pattern = GlobPattern::new("hello*", MatchMode::CaseSensitive).unwrap();
        assert!(pattern.matches("hello世界"));
        assert!(pattern.matches("hello🌍"));
    }
}
