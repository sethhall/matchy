// See the file "COPYING" in the main distribution directory for copyright.

#include "paraglob/paraglob.hpp"

#include <algorithm>
#include <sstream>

// Use C functions from the paraglob_rs namespace
using paraglob_rs::paraglob_db;
using paraglob_rs::paraglob_builder;
using paraglob_rs::paraglob_error_t;
using paraglob_rs::paraglob_error_t_PARAGLOB_SUCCESS;
using paraglob_rs::paraglob_open_mmap;
using paraglob_rs::paraglob_open_buffer;
using paraglob_rs::paraglob_close;
using paraglob_rs::paraglob_find_all;
using paraglob_rs::paraglob_free_results;
using paraglob_rs::paraglob_pattern_count;
using paraglob_rs::paraglob_version;
using paraglob_rs::paraglob_builder_new;
using paraglob_rs::paraglob_builder_add;
using paraglob_rs::paraglob_builder_compile;
using paraglob_rs::paraglob_builder_free;
using paraglob_rs::paraglob_save;

namespace paraglob {

// ============================================================================
// Constructors and Destructor
// ============================================================================

Paraglob::Paraglob()
    : db_(nullptr)
    , is_binary_mode_(false)
    , is_compiled_(false)
{
}

Paraglob::Paraglob(const std::vector<std::string>& patterns)
    : db_(nullptr)
    , patterns_(patterns)
    , is_binary_mode_(false)
    , is_compiled_(false)
{
    compile();
}

Paraglob::Paraglob(std::unique_ptr<std::vector<uint8_t>> serialized)
    : db_(nullptr)
    , is_binary_mode_(true)
    , is_compiled_(true)
{
    if (!serialized || serialized->empty()) {
        throw std::runtime_error("Cannot construct Paraglob from empty serialized data");
    }
    
    // Load from buffer
    db_ = paraglob_open_buffer(serialized->data(), serialized->size());
    if (db_ == nullptr) {
        throw std::runtime_error("Failed to load Paraglob from serialized data");
    }
}

Paraglob::~Paraglob() {
    if (db_ != nullptr) {
        paraglob_close(db_);
        db_ = nullptr;
    }
}

Paraglob::Paraglob(Paraglob&& other) noexcept
    : db_(other.db_)
    , patterns_(std::move(other.patterns_))
    , pattern_ids_(std::move(other.pattern_ids_))
    , is_binary_mode_(other.is_binary_mode_)
    , is_compiled_(other.is_compiled_)
{
    other.db_ = nullptr;
    other.is_binary_mode_ = false;
    other.is_compiled_ = false;
}

Paraglob& Paraglob::operator=(Paraglob&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        if (db_ != nullptr) {
            paraglob_close(db_);
        }
        
        // Move from other
        db_ = other.db_;
        patterns_ = std::move(other.patterns_);
        pattern_ids_ = std::move(other.pattern_ids_);
        is_binary_mode_ = other.is_binary_mode_;
        is_compiled_ = other.is_compiled_;
        
        // Clear other
        other.db_ = nullptr;
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
    
    // Use builder API
    paraglob_builder* builder = paraglob_builder_new(1);  // case-sensitive by default
    if (builder == nullptr) {
        throw std::runtime_error("Failed to create pattern builder");
    }
    
    // Add all patterns
    for (const auto& pattern : patterns_) {
        if (paraglob_builder_add(builder, pattern.c_str()) != paraglob_error_t_PARAGLOB_SUCCESS) {
            paraglob_builder_free(builder);
            throw std::runtime_error("Failed to add pattern: " + pattern);
        }
    }
    
    // Compile
    db_ = paraglob_builder_compile(builder);
    // builder is now consumed - don't free it
    
    if (db_ == nullptr) {
        throw std::runtime_error("Failed to compile patterns");
    }
    
    is_binary_mode_ = true;  // Now in binary mode
    is_compiled_ = true;
}

// ============================================================================
// Pattern Matching
// ============================================================================

std::vector<std::string> Paraglob::get(const std::string& text) {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Paraglob must be compiled before matching");
    }
    
    size_t count = 0;
    int* pattern_ids = paraglob_find_all(db_, text.c_str(), &count);
    
    std::vector<std::string> result;
    if (pattern_ids != nullptr && count > 0) {
        // Build pattern ID to string mapping if needed
        auto all_patterns = get_all_patterns_with_ids();
        
        for (size_t i = 0; i < count; ++i) {
            uint32_t id = static_cast<uint32_t>(pattern_ids[i]);
            for (const auto& [pid, pattern] : all_patterns) {
                if (pid == id) {
                    result.push_back(pattern);
                    break;
                }
            }
        }
        
        paraglob_free_results(pattern_ids);
        
        // Sort and deduplicate
        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
    }
    
    return result;
}

std::vector<std::pair<uint32_t, std::string>> Paraglob::get_with_ids(const std::string& text) {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Paraglob must be compiled before matching");
    }
    
    size_t count = 0;
    int* pattern_ids = paraglob_find_all(db_, text.c_str(), &count);
    
    std::vector<std::pair<uint32_t, std::string>> result;
    if (pattern_ids != nullptr && count > 0) {
        // Build pattern ID to string mapping
        auto all_patterns = get_all_patterns_with_ids();
        
        for (size_t i = 0; i < count; ++i) {
            uint32_t id = static_cast<uint32_t>(pattern_ids[i]);
            for (const auto& [pid, pattern] : all_patterns) {
                if (pid == id) {
                    result.push_back({id, pattern});
                    break;
                }
            }
        }
        
        paraglob_free_results(pattern_ids);
        
        // Sort by ID and deduplicate
        std::sort(result.begin(), result.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        result.erase(std::unique(result.begin(), result.end()), result.end());
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
    
    paraglob_error_t result = paraglob_save(db_, filename);
    return result == paraglob_error_t_PARAGLOB_SUCCESS;
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
    paraglob_db* db = paraglob_open_mmap(filename);
    if (db == nullptr) {
        return nullptr;
    }
    
    auto pg = std::make_unique<Paraglob>();
    pg->db_ = db;
    pg->is_binary_mode_ = true;
    pg->is_compiled_ = true;
    
    // Try to determine pattern count for informational purposes
    size_t pattern_count = paraglob_pattern_count(db);
    // We can't retrieve the actual patterns from binary mode without additional API
    // but we can track the count
    pg->patterns_.clear();
    
    return pg;
}

std::unique_ptr<Paraglob> Paraglob::load_from_buffer_binary(const uint8_t* buffer, size_t size) {
    paraglob_db* db = paraglob_open_buffer(buffer, size);
    if (db == nullptr) {
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
        size_t count = paraglob_pattern_count(db_);
        oss << "patterns=" << count;
        oss << ", binary_mode=true";
        oss << ", version=" << paraglob_version(db_);
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
        return 0;
    }
    
    return paraglob_pattern_count(db_);
}

uint32_t Paraglob::version() const {
    if (!is_compiled_ || db_ == nullptr) {
        throw std::runtime_error("Cannot get version from uncompiled Paraglob");
    }
    
    return paraglob_version(db_);
}

} // namespace paraglob
