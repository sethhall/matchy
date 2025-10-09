// See the file "COPYING" in the main distribution directory for copyright.

/**
 * @file paraglob.hpp
 * @brief Fast multi-pattern glob matching using Aho-Corasick algorithm
 * 
 * Paraglob provides efficient matching of multiple glob patterns against text.
 * It uses the Aho-Corasick algorithm internally to find all matching patterns
 * in linear time relative to the input text length.
 * 
 * This is a C++ wrapper around the Rust paraglob implementation, providing
 * binary compatibility with the original C++ paraglob library.
 * 
 * Supported glob patterns:
 * - `*` matches zero or more characters
 * - `?` matches exactly one character
 * - `[abc]` matches any character in the set
 * - `[a-z]` matches any character in the range
 * - `[!abc]` matches any character NOT in the set
 * 
 * @example
 * @code
 * #include <paraglob/paraglob.hpp>
 * #include <iostream>
 * 
 * int main() {
 *     // Create and compile a pattern database
 *     std::vector<std::string> patterns = {"*.txt", "foo*bar", "test[123]"};
 *     paraglob::Paraglob pg(patterns);
 *     
 *     // Find matching patterns
 *     auto matches = pg.get("foo.txt");
 *     for (const auto& pattern : matches) {
 *         std::cout << "Matched: " << pattern << std::endl;
 *     }
 *     
 *     // Save to binary format for fast loading
 *     pg.save_to_file_binary("patterns.pgb");
 *     
 *     // Load from binary (memory-mapped, zero-copy)
 *     auto loaded = paraglob::Paraglob::load_from_file_binary("patterns.pgb");
 *     auto more_matches = loaded->get("test1");
 * }
 * @endcode
 */

#ifndef PARAGLOB_HPP
#define PARAGLOB_HPP

#include "../paraglob_rs.h"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

namespace paraglob {

/**
 * @class Paraglob
 * @brief Multi-pattern glob matcher with Aho-Corasick algorithm
 * 
 * Paraglob efficiently matches multiple glob patterns against input text.
 * Patterns are compiled once into an internal automaton, then matching
 * runs in O(n) time where n is the length of the input text.
 * 
 * This implementation wraps the Rust paraglob library and provides
 * binary compatibility with the original C++ paraglob.
 * 
 * The class supports two modes:
 * 1. **Standard mode**: Patterns compiled in-memory (build mode)
 * 2. **Binary mode**: Patterns loaded from memory-mapped file (zero-copy)
 * 
 * @note This class is not copyable but is movable.
 * @note All methods are thread-safe for const operations after compilation.
 * 
 * @see load_from_file_binary() for memory-mapped usage
 */
class Paraglob {
private:
    // Opaque handle to Rust implementation (binary mode)
    paraglob_rs::paraglob_db* db_;
    
    // Build mode storage (when constructing from patterns)
    std::vector<std::string> patterns_;
    std::vector<uint32_t> pattern_ids_;
    bool is_binary_mode_;
    bool is_compiled_;
    
    // Helper: compile patterns to temporary file and load
    void compile_patterns();
    
    // Helper: get temporary filename for binary compilation
    static std::string get_temp_filename();
    
public:
    // ========================================================================
    // Constructors and Destructor
    // ========================================================================
    
    /**
     * @brief Construct an empty Paraglob
     * 
     * Creates an empty pattern database. Use add() to add patterns,
     * then call compile() before matching.
     * 
     * @see add(), compile()
     */
    Paraglob();
    
    /**
     * @brief Construct and compile Paraglob from pattern list
     * 
     * Creates a Paraglob with the given patterns and immediately compiles
     * them into an internal automaton ready for matching.
     * 
     * @param patterns  Vector of glob patterns to match
     * @throws std::runtime_error if any pattern fails to add or compilation fails
     * 
     * @par Example:
     * @code
     * std::vector<std::string> patterns = {"*.txt", "*.log", "data_*"};
     * paraglob::Paraglob pg(patterns);  // Ready to use immediately
     * @endcode
     */
    explicit Paraglob(const std::vector<std::string>& patterns);
    
    /**
     * @brief Construct Paraglob from serialized data
     * 
     * Reconstructs a Paraglob from data previously saved with serialize().
     * The patterns are extracted and recompiled.
     * 
     * @param serialized  Unique pointer to serialized pattern data
     * @throws std::runtime_error if data is invalid or compilation fails
     * 
     * @note This uses the binary format. The data should be from serialize_binary()
     *       or save_to_file_binary().
     * 
     * @see serialize_binary(), load_from_file_binary()
     */
    explicit Paraglob(std::unique_ptr<std::vector<uint8_t>> serialized);
    
    /**
     * @brief Destructor
     * 
     * Cleans up all resources including memory-mapped files if applicable.
     */
    ~Paraglob();
    
    // Delete copy constructor and assignment
    Paraglob(const Paraglob&) = delete;
    Paraglob& operator=(const Paraglob&) = delete;
    
    // Enable move constructor and assignment
    Paraglob(Paraglob&& other) noexcept;
    Paraglob& operator=(Paraglob&& other) noexcept;
    
    // ========================================================================
    // Pattern Management
    // ========================================================================
    
    /**
     * @brief Add a glob pattern to the database
     * 
     * Adds a pattern to the Paraglob. Must call compile() after adding
     * all patterns before performing any matches.
     * 
     * @param pattern  Glob pattern string (supports *, ?, [abc], [a-z], [!abc])
     * @return true if pattern was added successfully, false on failure
     * 
     * @throws std::runtime_error if called on a binary-mode instance
     * 
     * @note Empty patterns are accepted (match everything)
     * @note Patterns with only wildcards (* or ?) are handled specially
     * 
     * @par Example:
     * @code
     * paraglob::Paraglob pg;
     * pg.add("*.txt");      // Match all .txt files
     * pg.add("log_[0-9]");  // Match log_0 through log_9
     * pg.add("test?");      // Match test followed by any character
     * pg.compile();         // Must compile before matching
     * @endcode
     * 
     * @see compile()
     */
    bool add(const std::string& pattern);
    
    /**
     * @brief Compile patterns into internal automaton
     * 
     * Finalizes the pattern database and builds the internal Aho-Corasick
     * automaton. Must be called after adding patterns and before matching.
     * 
     * @throws std::runtime_error if compilation fails
     * @throws std::runtime_error if called on a binary-mode instance
     * 
     * @note Can be called multiple times (re-compiles)
     * @note After compilation, adding more patterns requires recompilation
     * 
     * @see add()
     */
    void compile();
    
    // ========================================================================
    // Pattern Matching
    // ========================================================================
    
    /**
     * @brief Find all patterns matching the input text
     * 
     * Searches the input text and returns all glob patterns that match.
     * Matching is performed in O(n) time where n is the length of the text.
     * 
     * @param text  Input string to match against patterns
     * @return Vector of matching pattern strings (may be empty)
     * 
     * @throws std::runtime_error if not compiled yet (build mode only)
     * 
     * @note Returned patterns are deduplicated and sorted
     * @note Thread-safe for concurrent calls (read-only operation)
     * 
     * @par Example:
     * @code
     * paraglob::Paraglob pg({"*.txt", "*.log", "data_*"});
     * auto matches = pg.get("data_file.txt");
     * // matches = {"*.txt", "data_*"}
     * @endcode
     * 
     * @see get_with_ids()
     */
    std::vector<std::string> get(const std::string& text);
    
    /**
     * @brief Find all patterns with their IDs
     * 
     * Like get(), but returns pairs of (pattern_id, pattern_string).
     * Pattern IDs are stable and can be used for external indexing.
     * 
     * @param text  Input string to match against patterns
     * @return Vector of (pattern_id, pattern_string) pairs
     * 
     * @throws std::runtime_error if not compiled yet (build mode only)
     * 
     * @note Pattern IDs are assigned sequentially starting from 0
     * @note IDs correspond to lexicographically sorted pattern order
     * 
     * @par Example:
     * @code
     * auto pg = paraglob::Paraglob::load_from_file_binary("patterns.pgb");
     * auto matches = pg->get_with_ids("test.txt");
     * for (const auto& [id, pattern] : matches) {
     *     std::cout << "Pattern #" << id << ": " << pattern << std::endl;
     * }
     * @endcode
     * 
     * @see get_all_patterns_with_ids()
     */
    std::vector<std::pair<uint32_t, std::string>> get_with_ids(const std::string& text);
    
    /**
     * @brief Get all patterns with their assigned IDs
     * 
     * Returns all patterns in the database along with their IDs.
     * Useful for building external mappings or lookups.
     * 
     * @return Vector of (pattern_id, pattern_string) pairs for all patterns
     * 
     * @note Patterns are in lexicographically sorted order
     * @note Pattern IDs correspond to this sorted order (0, 1, 2, ...)
     * @note Thread-safe (read-only operation)
     * 
     * @see get_with_ids()
     */
    std::vector<std::pair<uint32_t, std::string>> get_all_patterns_with_ids() const;
    
    // ========================================================================
    // Status and Introspection
    // ========================================================================
    
    /**
     * @brief Check if patterns are compiled and ready for matching
     * 
     * @return true if compile() has been called or loaded from binary, false otherwise
     * 
     * @note Binary-mode instances are always compiled
     */
    bool is_compiled() const { return is_compiled_; }
    
    /**
     * @brief Get total number of patterns in database
     * 
     * @return Number of patterns (0 if not compiled)
     * 
     * @note Thread-safe (read-only operation)
     */
    size_t pattern_count() const;
    
    /**
     * @brief Get binary format version
     * 
     * @return Format version number (currently 1)
     * 
     * @throws std::runtime_error if not compiled
     */
    uint32_t version() const;
    
    // ========================================================================
    // Serialization (Legacy Format)
    // ========================================================================
    
    /**
     * @brief Serialize patterns to byte array
     * 
     * Serializes the compiled pattern database to a byte array.
     * The result can be saved to disk or transmitted over network.
     * 
     * @return Unique pointer to byte vector containing serialized data
     * 
     * @note This is the binary format used by the Rust implementation.
     * 
     * @see save_to_file_binary()
     */
    std::unique_ptr<std::vector<uint8_t>> serialize() const;
    
    // ========================================================================
    // Binary Format (Fast, Memory-Mapped)
    // ========================================================================
    
    /**
     * @brief Save to binary format for fast loading
     * 
     * Saves the compiled pattern database to a binary file optimized for
     * memory-mapped loading. This format includes the compiled automaton,
     * allowing instant loading without recompilation.
     * 
     * @param filename  Path where binary file should be written
     * @return true on success, false on I/O error
     * 
     * @note Binary files are portable across systems with same endianness
     * @note Includes version header for format compatibility checking
     * 
     * @par Performance:
     * - Saving: O(n) where n is total pattern data size
     * - Loading: O(1) - just mmap, no parsing or compilation
     * 
     * @see load_from_file_binary(), serialize_binary()
     */
    bool save_to_file_binary(const char* filename) const;
    
    /**
     * @brief Serialize to binary format as byte array
     * 
     * Like save_to_file_binary() but returns data in memory instead of
     * writing to a file.
     * 
     * @return Unique pointer to byte vector containing binary format data
     * 
     * @see save_to_file_binary(), load_from_buffer_binary()
     */
    std::unique_ptr<std::vector<uint8_t>> serialize_binary() const;
    
    /**
     * @brief Load from binary file (memory-mapped, zero-copy)
     * 
     * Loads a pattern database from a binary file using memory mapping.
     * This is extremely fast as no data copying or recompilation occurs.
     * 
     * @param filename  Path to binary file created with save_to_file_binary()
     * @return Unique pointer to Paraglob, or nullptr on error
     * 
     * @note The file remains mapped for the lifetime of the Paraglob object
     * @note Multiple Paraglob instances can share the same mapped file
     * @note Validates file format and version before loading
     * 
     * @par Performance:
     * - Load time: O(1) - instant, just mmap
     * - Memory: Minimal - OS pages in data on-demand
     * - Startup: No compilation overhead
     * 
     * @par Example:
     * @code
     * // Save once
     * paraglob::Paraglob pg({"*.txt", "*.log"});
     * pg.save_to_file_binary("patterns.pgb");
     * 
     * // Load many times (fast)
     * auto loaded = paraglob::Paraglob::load_from_file_binary("patterns.pgb");
     * auto matches = loaded->get("test.txt");
     * @endcode
     * 
     * @see save_to_file_binary(), load_from_buffer_binary()
     */
    static std::unique_ptr<Paraglob> load_from_file_binary(const char* filename);
    
    /**
     * @brief Load from memory buffer (zero-copy)
     * 
     * Loads a pattern database from a memory buffer containing binary format
     * data. No data is copied - the Paraglob operates directly on the buffer.
     * 
     * @param buffer  Pointer to binary format data
     * @param size    Size of buffer in bytes
     * @return Unique pointer to Paraglob, or nullptr on error
     * 
     * @warning Caller must ensure buffer remains valid for Paraglob lifetime
     * @warning Buffer ownership remains with caller
     * 
     * @note Validates buffer format and version before loading
     * @note Useful for embedding pattern data in executables or shared memory
     * 
     * @see load_from_file_binary(), serialize_binary()
     */
    static std::unique_ptr<Paraglob> load_from_buffer_binary(const uint8_t* buffer, size_t size);
    
    // ========================================================================
    // Debugging and Inspection
    // ========================================================================
    
    /**
     * @brief Get string representation for debugging
     * 
     * Returns a human-readable string showing all patterns in the database.
     * Primarily for debugging and testing purposes.
     * 
     * @return String containing formatted pattern list
     * 
     * @note Output format is implementation-defined and may change
     * @note Can be large for databases with many patterns
     */
    std::string str() const;
    
    /**
     * @brief Compare two Paraglob instances for equality
     * 
     * Two Paraglob instances are equal if they contain the same set of patterns,
     * regardless of internal structure or compilation state.
     * 
     * @param other  Another Paraglob to compare with
     * @return true if pattern sets are identical
     * 
     * @note Only compares patterns, not compiled automaton structure
     */
    bool operator==(const Paraglob& other) const;
};

} // namespace paraglob

#endif // PARAGLOB_HPP
