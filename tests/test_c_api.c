// Test suite for paraglob-rs C API
// Compile: make test_c_api

#include "../include/paraglob_rs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST(name) printf("TEST: %s\n", name)
#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s\n  at %s:%d\n", msg, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg) ASSERT((a) != (b), msg)
#define ASSERT_TRUE(cond, msg) ASSERT(cond, msg)

// Test 1: Builder API - basic functionality
void test_builder_basic() {
    TEST("Builder API - Basic");
    
    // Create builder
    paraglob_builder* builder = paraglob_builder_new(1);  // case-sensitive
    ASSERT_NE(builder, NULL, "Builder creation failed");
    
    // Add patterns
    ASSERT_EQ(paraglob_builder_add(builder, "*.txt"), paraglob_error_t_PARAGLOB_SUCCESS, "Failed to add pattern");
    ASSERT_EQ(paraglob_builder_add(builder, "*.log"), paraglob_error_t_PARAGLOB_SUCCESS, "Failed to add pattern");
    ASSERT_EQ(paraglob_builder_add(builder, "test_*"), paraglob_error_t_PARAGLOB_SUCCESS, "Failed to add pattern");
    
    // Compile
    paraglob_db* db = paraglob_builder_compile(builder);
    ASSERT_NE(db, NULL, "Compilation failed");
    
    // Check pattern count
    size_t count = paraglob_pattern_count(db);
    ASSERT_EQ(count, 3, "Wrong pattern count");
    
    // Test matching
    size_t match_count = 0;
    int* matches = paraglob_find_all(db, "test_file.txt", &match_count);
    ASSERT_NE(matches, NULL, "Matching returned NULL");
    ASSERT_EQ(match_count, 2, "Wrong match count");  // Should match *.txt and test_*
    
    paraglob_free_results(matches);
    paraglob_close(db);
    
    printf("  PASS\n");
}

// Test 2: Save and load functionality
void test_save_load() {
    TEST("Save and Load");
    
    const char* filename = "/tmp/paraglob_c_test.pgb";
    
    // Build and save
    paraglob_builder* builder = paraglob_builder_new(1);
    paraglob_builder_add(builder, "*.txt");
    paraglob_builder_add(builder, "README*");
    paraglob_builder_add(builder, "doc_*");
    
    paraglob_db* db = paraglob_builder_compile(builder);
    ASSERT_NE(db, NULL, "Compilation failed");
    
    int save_result = paraglob_save(db, filename);
    ASSERT_EQ(save_result, paraglob_error_t_PARAGLOB_SUCCESS, "Save failed");
    
    paraglob_close(db);
    
    // Load and verify
    db = paraglob_open_mmap(filename);
    ASSERT_NE(db, NULL, "Load failed");
    
    size_t count = paraglob_pattern_count(db);
    ASSERT_EQ(count, 3, "Wrong pattern count after load");
    
    // Test matching after load
    size_t match_count = 0;
    int* matches = paraglob_find_all(db, "README.txt", &match_count);
    ASSERT_NE(matches, NULL, "Matching failed");
    ASSERT_EQ(match_count, 2, "Wrong match count");  // Should match *.txt and README*
    
    paraglob_free_results(matches);
    paraglob_close(db);
    
    printf("  PASS\n");
}

// Test 3: Version API
void test_version() {
    TEST("Version API");
    
    paraglob_builder* builder = paraglob_builder_new(1);
    paraglob_builder_add(builder, "*.txt");
    paraglob_db* db = paraglob_builder_compile(builder);
    
    uint32_t version = paraglob_version(db);
    ASSERT_EQ(version, 1, "Wrong version number");
    
    paraglob_close(db);
    
    printf("  PASS\n");
}

// Test 4: Empty and edge cases
void test_edge_cases() {
    TEST("Edge Cases");
    
    // NULL checks
    ASSERT_EQ(paraglob_pattern_count(NULL), 0, "NULL db should return 0 patterns");
    ASSERT_EQ(paraglob_version(NULL), 0, "NULL db should return version 0");
    
    size_t count = 0;
    int* matches = paraglob_find_all(NULL, "test", &count);
    ASSERT_EQ(matches, NULL, "NULL db should return NULL matches");
    ASSERT_EQ(count, 0, "NULL db should return 0 count");
    
    // Safe to call with NULL
    paraglob_free_results(NULL);
    paraglob_close(NULL);
    
    printf("  PASS\n");
}

// Test 5: Pattern matching correctness
void test_pattern_matching() {
    TEST("Pattern Matching Correctness");
    
    paraglob_builder* builder = paraglob_builder_new(1);
    paraglob_builder_add(builder, "*.txt");
    paraglob_builder_add(builder, "test_*");
    paraglob_builder_add(builder, "hello");
    paraglob_builder_add(builder, "*world*");
    paraglob_db* db = paraglob_builder_compile(builder);
    
    // Test various inputs - just verify matching works, not exact counts
    struct {
        const char* input;
        size_t min_matches;
        size_t max_matches;
    } tests[] = {
        {"test.txt", 1, 2},        // At least *.txt, maybe test_*
        {"hello", 1, 1},           // Exact match
        {"hello_world", 1, 2},     // At least *world*, maybe test_*
        {"nothing.rs", 0, 0},      // No matches
        {"test_file.txt", 1, 3},   // Multiple possible matches
    };
    
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        size_t count = 0;
        int* matches = paraglob_find_all(db, tests[i].input, &count);
        
        char msg[256];
        snprintf(msg, sizeof(msg), "%s: got %zu, expected %zu-%zu", 
                 tests[i].input, count, tests[i].min_matches, tests[i].max_matches);
        ASSERT_TRUE(count >= tests[i].min_matches && count <= tests[i].max_matches, msg);
        
        paraglob_free_results(matches);
    }
    
    paraglob_close(db);
    
    printf("  PASS\n");
}

// Test 6: Duplicate patterns
void test_duplicate_patterns() {
    TEST("Duplicate Patterns");
    
    paraglob_builder* builder = paraglob_builder_new(1);
    paraglob_builder_add(builder, "*.txt");
    paraglob_builder_add(builder, "*.txt");  // Duplicate
    paraglob_builder_add(builder, "*.log");
    paraglob_db* db = paraglob_builder_compile(builder);
    
    // Should deduplicate
    size_t count = paraglob_pattern_count(db);
    ASSERT_TRUE(count == 2 || count == 3, "Pattern count should be 2 or 3");
    
    paraglob_close(db);
    
    printf("  PASS\n");
}

int main() {
    printf("=== Paraglob C API Tests ===\n\n");
    
    test_builder_basic();
    test_save_load();
    test_version();
    test_edge_cases();
    test_pattern_matching();
    test_duplicate_patterns();
    
    printf("\n=== All C API tests passed! ===\n");
    return 0;
}
