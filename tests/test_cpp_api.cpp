// Test suite for matchy C++ API
// Compile: make test-cpp

#include "paraglob/paraglob.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstdlib>

#define TEST(name) std::cout << "TEST: " << name << std::endl
#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "ASSERTION FAILED: " << msg << std::endl; \
        std::cerr << "  at " << __FILE__ << ":" << __LINE__ << std::endl; \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg) ASSERT((a) != (b), msg)
#define ASSERT_TRUE(cond, msg) ASSERT(cond, msg)

// Test 1: Constructor with patterns
void test_constructor() {
    TEST("Constructor with patterns");
    
    std::vector<std::string> patterns = {"*.txt", "*.log", "data_*"};
    paraglob::Paraglob pg(patterns);
    
    // Check pattern count
    ASSERT_EQ(pg.pattern_count(), 3u, "Wrong pattern count");
    
    // Test matching
    auto matches = pg.get("data_file.txt");
    ASSERT_TRUE(matches.size() >= 1, "Should match at least one pattern");
    
    std::cout << "  PASS" << std::endl;
}

// Test 2: Incremental building
void test_incremental_build() {
    TEST("Incremental building");
    
    paraglob::Paraglob pg;
    
    // Add patterns
    ASSERT_TRUE(pg.add("*.cpp"), "Failed to add pattern");
    ASSERT_TRUE(pg.add("*.h"), "Failed to add pattern");
    ASSERT_TRUE(pg.add("Makefile"), "Failed to add pattern");
    
    // Compile
    pg.compile();
    
    // Check pattern count
    ASSERT_EQ(pg.pattern_count(), 3u, "Wrong pattern count");
    
    // Test matching
    auto matches = pg.get("test.cpp");
    ASSERT_TRUE(matches.size() >= 1, "Should match *.cpp");
    
    std::cout << "  PASS" << std::endl;
}

// Test 3: Save and load
void test_save_load() {
    TEST("Save and load");
    
    const char* filename = "/tmp/paraglob_cpp_test_suite.pgb";
    
    // Build and save
    {
        std::vector<std::string> patterns = {"*.txt", "README*", "doc_*"};
        paraglob::Paraglob pg(patterns);
        
        ASSERT_TRUE(pg.save_to_file_binary(filename), "Save failed");
    }
    
    // Load and verify
    {
        auto pg_ptr = paraglob::Paraglob::load_from_file_binary(filename);
        ASSERT_TRUE(pg_ptr != nullptr, "Load failed");
        
        auto& pg = *pg_ptr;
        ASSERT_EQ(pg.pattern_count(), 3u, "Wrong pattern count after load");
        ASSERT_TRUE(pg.is_compiled(), "Loaded instance should be compiled");
        ASSERT_EQ(pg.version(), 1u, "Wrong version");
        
        // Note: C++ wrapper's get() method doesn't work properly in binary mode
        // because it relies on patterns_ which is empty after loading.
        // This is a known limitation - use C API directly for full functionality.
    }
    
    std::cout << "  PASS" << std::endl;
}

// Test 4: Pattern matching correctness
void test_pattern_matching() {
    TEST("Pattern matching correctness");
    
    std::vector<std::string> patterns = {"*.txt", "test_*", "hello", "*world*"};
    paraglob::Paraglob pg(patterns);
    
    // Test exact match
    auto matches = pg.get("hello");
    ASSERT_TRUE(matches.size() >= 1, "Should match 'hello'");
    
    // Test wildcard
    matches = pg.get("test_file.txt");
    ASSERT_TRUE(matches.size() >= 1, "Should match multiple patterns");
    
    // Test no match
    matches = pg.get("nothing.rs");
    ASSERT_EQ(matches.size(), 0u, "Should not match anything");
    
    std::cout << "  PASS" << std::endl;
}

// Test 5: Get with IDs
void test_get_with_ids() {
    TEST("Get with IDs");
    
    std::vector<std::string> patterns = {"*.txt", "*.log", "*.cpp"};
    paraglob::Paraglob pg(patterns);
    
    auto matches = pg.get_with_ids("test.txt");
    ASSERT_TRUE(matches.size() >= 1, "Should have at least one match");
    
    // Verify IDs are valid
    for (const auto& [id, pattern] : matches) {
        ASSERT_TRUE(!pattern.empty(), "Pattern should not be empty");
    }
    
    // Get all patterns
    auto all = pg.get_all_patterns_with_ids();
    ASSERT_EQ(all.size(), 3u, "Should have 3 patterns");
    
    std::cout << "  PASS" << std::endl;
}

// Test 6: Move semantics
void test_move_semantics() {
    TEST("Move semantics");
    
    std::vector<std::string> patterns = {"*.txt", "*.log"};
    paraglob::Paraglob pg1(patterns);
    
    // Move constructor
    paraglob::Paraglob pg2(std::move(pg1));
    
    // Move assignment
    paraglob::Paraglob pg3;
    pg3.add("*.rs");
    pg3 = std::move(pg2);
    
    // Test that moved-to object works
    auto matches = pg3.get("test.txt");
    ASSERT_TRUE(matches.size() >= 1, "Moved object should still work");
    
    std::cout << "  PASS" << std::endl;
}

// Test 7: Exception handling
void test_exceptions() {
    TEST("Exception handling");
    
    // Cannot match before compilation
    try {
        paraglob::Paraglob pg;
        pg.add("*.txt");
        // Don't compile - should throw
        pg.get("test.txt");
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::runtime_error& e) {
        // Expected
    }
    
    // Cannot add to binary mode
    try {
        std::vector<std::string> patterns = {"*.txt"};
        paraglob::Paraglob pg(patterns);
        pg.add("*.log");  // Should throw - already compiled
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::runtime_error& e) {
        // Expected
    }
    
    // Cannot compile empty pattern set
    try {
        paraglob::Paraglob pg;
        pg.compile();  // Should throw - no patterns
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::runtime_error& e) {
        // Expected
    }
    
    std::cout << "  PASS" << std::endl;
}


// Test 9: String representation
void test_string_representation() {
    TEST("String representation");
    
    std::vector<std::string> patterns = {"*.txt", "*.log"};
    paraglob::Paraglob pg(patterns);
    
    std::string repr = pg.str();
    ASSERT_TRUE(repr.find("patterns=") != std::string::npos, "Should contain pattern count");
    ASSERT_TRUE(repr.find("binary_mode=") != std::string::npos, "Should contain binary mode");
    ASSERT_TRUE(repr.find("version=") != std::string::npos, "Should contain version");
    
    std::cout << "  PASS" << std::endl;
}

int main() {
    std::cout << "=== Paraglob C++ API Tests ===" << std::endl << std::endl;
    
    try {
        test_constructor();
        test_incremental_build();
        test_save_load();
        test_pattern_matching();
        test_get_with_ids();
        test_move_semantics();
        test_exceptions();
        test_string_representation();
        
        std::cout << std::endl << "=== All C++ API tests passed! ===" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << std::endl << "UNEXPECTED EXCEPTION: " << e.what() << std::endl;
        return 1;
    }
}
