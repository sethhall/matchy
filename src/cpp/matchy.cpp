// See the file "COPYING" in the main distribution directory for copyright.

#include "matchy/matchy.hpp"

#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <unistd.h>

// Use C functions from the matchy namespace
using matchy::matchy_t;
using matchy::matchy_builder_t;
using matchy::matchy_result_t;
using matchy::matchy_builder_new;
using matchy::matchy_builder_add;
using matchy::matchy_builder_save;
using matchy::matchy_builder_build;
using matchy::matchy_builder_free;
using matchy::matchy_open;
using matchy::matchy_open_buffer;
using matchy::matchy_close;
using matchy::matchy_query;
using matchy::matchy_free_result;
using matchy::matchy_free_string;
using matchy::matchy_format;
using matchy::matchy_has_pattern_data;
using matchy::matchy_get_pattern_string;
using matchy::matchy_pattern_count;
// MATCHY_SUCCESS is a #define, not a namespace member

namespace paraglob {

// ============================================================================
// Constructors and Destructor
// ============================================================================

Paraglob::Paraglob()
    : db_(nullptr)
    , builder_(nullptr)
    , temp_file_()
    , is_binary_mode_(false)
    , is_compiled_(false)
{
}

Paraglob::Paraglob(const std::vector<std::string>& patterns)
    : db_(nullptr)
    , builder_(nullptr)
    , temp_file_()
    , patterns_(patterns)
    , is_binary_mode_(false)
    , is_compiled_(false)
{
    compile();
}

Paraglob::Paraglob(std::unique_ptr<std::vector<uint8_t>> serialized)
    : db_(nullptr)
    , builder_(nullptr)
    , temp_file_()
    , is_binary_mode_(true)
    , is_compiled_(true)
{
    if (!serialized || serialized->empty()) {
        throw std::runtime_error("Cannot construct Paraglob from empty serialized data");
    }
    
    // Load from buffer
    db_ = matchy_open_buffer(serialized->data(), serialized->size());
    if (db_ == nullptr) {
        throw std::runtime_error("Failed to load Paraglob from serialized data");
    }
}

Paraglob::~Paraglob() {
    if (db_ != nullptr) {
        matchy_close(db_);
        db_ = nullptr;
    }
    if (builder_ != nullptr) {
        matchy_builder_free(builder_);
        builder_ = nullptr;
    }
    // Clean up temp file if it exists
    if (!temp_file_.empty()) {
        std::remove(temp_file_.c_str());
    }
}

Paraglob::Paraglob(Paraglob&& other) noexcept
    : db_(other.db_)
    , builder_(other.builder_)
    , temp_file_(std::move(other.temp_file_))
    , patterns_(std::move(other.patterns_))
    , pattern_ids_(std::move(other.pattern_ids_))
    , is_binary_mode_(other.is_binary_mode_)
    , is_compiled_(other.is_compiled_)
{
    other.db_ = nullptr;
    other.builder_ = nullptr;
    other.is_binary_mode_ = false;
    other.is_compiled_ = false;
}

Paraglob& Paraglob::operator=(Paraglob&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        if (db_ != nullptr) {
            matchy_close(db_);
        }
        if (builder_ != nullptr) {
            matchy_builder_free(builder_);
        }
        if (!temp_file_.empty()) {
            std::remove(temp_file_.c_str());
        }
        
        // Move from other
        db_ = other.db_;
        builder_ = other.builder_;
        temp_file_ = std::move(other.temp_file_);
        patterns_ = std::move(other.patterns_);
        pattern_ids_ = std::move(other.pattern_ids_);
        is_binary_mode_ = other.is_binary_mode_;
        is_compiled_ = other.is_compiled_;
        
        // Clear other
        other.db_ = nullptr;
        other.builder_ = nullptr;
        other.is_binary_mode_ = false;
        other.is_compiled_ = false;
    }
    return *this;
}

// ============================================================================
// Pattern Management
// ============================================================================

bool Paraglob::add(const std::string& pattern) {
    if (is_binary_mode_) {
        throw std::runtime_error("Cannot add patterns to a binary-mode Paraglob");
    }
    
    patterns_.push_back(pattern);
    is_compiled_ = false;  // Need to recompile
    return true;
}

void Paraglob::compile() {
    if (is_binary_mode_) {
        throw std::runtime_error("Cannot compile a binary-mode Paraglob");
    }
    
    if (patterns_.empty()) {
        throw std::runtime_error("Cannot compile empty pattern set");
    }
    
    // Create builder
    builder_ = matchy_builder_new();
    if (builder_ == nullptr) {
        throw std::runtime_error("Failed to create pattern builder");
    }
    
    // Add all patterns with empty JSON data (pattern-only mode)
    for (const auto& pattern : patterns_) {
        if (matchy_builder_add(builder_, pattern.c_str(), "{}") != MATCHY_SUCCESS) {
            matchy_builder_free(builder_);
            builder_ = nullptr;
            throw std::runtime_error("Failed to add pattern: " + pattern);
        }
    }
    
    // Save to temp file and load it
    temp_file_ = get_temp_filename();
    if (matchy_builder_save(builder_, temp_file_.c_str()) != MATCHY_SUCCESS) {
        matchy_builder_free(builder_);
        builder_ = nullptr;
        throw std::runtime_error("Failed to save compiled patterns");
    }
    
    // Free builder - no longer needed
    matchy_builder_free(builder_);
    builder_ = nullptr;
    
    // Load from file
    db_ = matchy_open(temp_file_.c_str());
    if (db_ == nullptr) {
        throw std::runtime_error("Failed to load compiled patterns");
    }
    
    is_binary_mode_ = true;  // Now in binary mode
    is_compiled_ = true;
}

std::string Paraglob::get_temp_filename() {
    char temp_template[] = "/tmp/paraglob_XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd == -1) {
        throw std::runtime_error("Failed to create temp file");
    }
    close(fd);
    return std::string(temp_template);
}

// ============================================================================
// Pattern Matching
// ============================================================================

std::vector<std::string> Paraglob::get(const std::string& text) {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Paraglob must be compiled before matching");
    }
    
    // Use matchy query - it returns pattern matches
    matchy_result_t result = matchy_query(db_, text.c_str());
    
    std::vector<std::string> matched_patterns;
    
    if (result.found) {
        // If we built the patterns ourselves, we have them stored
        if (!patterns_.empty()) {
            matched_patterns = patterns_;
        } else {
            // Loaded from binary - need to get all pattern strings from database
            // and check each one to see if it matches
            size_t count = matchy_pattern_count(db_);
            for (size_t i = 0; i < count; ++i) {
                char* pattern_str = matchy_get_pattern_string(db_, static_cast<uint32_t>(i));
                if (pattern_str != nullptr) {
                    std::string pattern(pattern_str);
                    matchy_free_string(pattern_str);
                    
                    // Query this pattern against the text to see if it matches
                    matchy_result_t check = matchy_query(db_, text.c_str());
                    if (check.found) {
                        matched_patterns.push_back(pattern);
                    }
                    matchy_free_result(&check);
                }
            }
        }
    }
    
    matchy_free_result(&result);
    
    // Sort and deduplicate
    std::sort(matched_patterns.begin(), matched_patterns.end());
    matched_patterns.erase(std::unique(matched_patterns.begin(), matched_patterns.end()), 
                          matched_patterns.end());
    
    return matched_patterns;
}

std::vector<std::pair<uint32_t, std::string>> Paraglob::get_with_ids(const std::string& text) {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Paraglob must be compiled before matching");
    }
    
    // Get matching patterns
    auto matched_patterns = get(text);
    
    // Map to IDs based on sorted pattern order
    auto all_with_ids = get_all_patterns_with_ids();
    std::vector<std::pair<uint32_t, std::string>> result;
    
    for (const auto& matched : matched_patterns) {
        for (const auto& [id, pattern] : all_with_ids) {
            if (pattern == matched) {
                result.push_back({id, pattern});
                break;
            }
        }
    }
    
    return result;
}

std::vector<std::pair<uint32_t, std::string>> Paraglob::get_all_patterns_with_ids() const {
    // Return patterns sorted with sequential IDs
    std::vector<std::string> sorted = patterns_;
    std::sort(sorted.begin(), sorted.end());
    
    std::vector<std::pair<uint32_t, std::string>> result;
    for (uint32_t i = 0; i < sorted.size(); ++i) {
        result.push_back({i, sorted[i]});
    }
    return result;
}

// ============================================================================
// Serialization
// ============================================================================

std::unique_ptr<std::vector<uint8_t>> Paraglob::serialize() const {
    return serialize_binary();
}

bool Paraglob::save_to_file_binary(const char* filename) const {
    if (!is_compiled_ || db_ == nullptr) {
        return false;
    }
    
    // If we have a temp file, just copy it
    if (!temp_file_.empty()) {
        std::ifstream src(temp_file_, std::ios::binary);
        std::ofstream dst(filename, std::ios::binary);
        if (!src || !dst) {
            return false;
        }
        dst << src.rdbuf();
        return dst.good();
    }
    
    return false;
}

std::unique_ptr<std::vector<uint8_t>> Paraglob::serialize_binary() const {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Cannot serialize uncompiled Paraglob");
    }
    
    // TODO: Need C API function to get buffer from db
    // For now, save to temp file and read it back
    throw std::runtime_error("serialize_binary() not yet implemented - use save_to_file_binary() instead");
}

std::unique_ptr<Paraglob> Paraglob::load_from_file_binary(const char* filename) {
    matchy_t* db = matchy_open(filename);
    if (db == nullptr) {
        return nullptr;
    }
    
    // Check if this database has pattern data
    if (!matchy_has_pattern_data(db)) {
        matchy_close(db);
        return nullptr;
    }
    
    auto pg = std::make_unique<Paraglob>();
    pg->db_ = db;
    pg->is_binary_mode_ = true;
    pg->is_compiled_ = true;
    pg->patterns_.clear();
    
    return pg;
}

std::unique_ptr<Paraglob> Paraglob::load_from_buffer_binary(const uint8_t* buffer, size_t size) {
    matchy_t* db = matchy_open_buffer(buffer, size);
    if (db == nullptr) {
        return nullptr;
    }
    
    // Check if this database has pattern data
    if (!matchy_has_pattern_data(db)) {
        matchy_close(db);
        return nullptr;
    }
    
    auto pg = std::make_unique<Paraglob>();
    pg->db_ = db;
    pg->is_binary_mode_ = true;
    pg->is_compiled_ = true;
    
    return pg;
}

// ============================================================================
// Debugging and Inspection
// ============================================================================

std::string Paraglob::str() const {
    std::ostringstream oss;
    oss << "Paraglob{";
    
    if (is_binary_mode_ && db_ != nullptr) {
        oss << "patterns=" << patterns_.size();
        oss << ", binary_mode=true";
        oss << ", format=" << matchy_format(db_);
    } else {
        oss << "patterns=" << patterns_.size();
        oss << ", binary_mode=false";
        oss << ", compiled=" << (is_compiled_ ? "true" : "false");
    }
    
    oss << "}";
    return oss.str();
}

bool Paraglob::operator==(const Paraglob& other) const {
    // Compare pattern sets (sorted)
    std::vector<std::string> this_patterns = patterns_;
    std::vector<std::string> other_patterns = other.patterns_;
    
    std::sort(this_patterns.begin(), this_patterns.end());
    std::sort(other_patterns.begin(), other_patterns.end());
    
    return this_patterns == other_patterns;
}

// ============================================================================
// Status and Introspection
// ============================================================================

size_t Paraglob::pattern_count() const {
    if (!is_compiled_ || db_ == nullptr) {
        return patterns_.size();
    }
    
    // Get count from database if loaded, otherwise from stored patterns
    size_t db_count = matchy_pattern_count(db_);
    if (db_count > 0) {
        return db_count;
    }
    
    return patterns_.size();
}

uint32_t Paraglob::version() const {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Cannot get version from uncompiled Paraglob");
    }
    
    // Return format version (3 for current format)
    return 3;
}

} // namespace paraglob
