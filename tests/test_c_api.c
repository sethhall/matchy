// Test suite for matchy C API

#include "matchy/matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== Matchy C API Tests ===\n\n");
    
    // Create builder
    matchy_builder_t* builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Builder creation failed\n");
        return 1;
    }
    printf("✓ Builder created\n");
    
    // Add patterns with simple data
    if (matchy_builder_add(builder, "*.txt", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern\n");
        return 1;
    }
    printf("✓ Pattern 1 added\n");
    
    if (matchy_builder_add(builder, "*.log", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern 2\n");
        return 1;
    }
    printf("✓ Pattern 2 added\n");
    
    if (matchy_builder_add(builder, "test_*", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern 3\n");
        return 1;
    }
    printf("✓ Pattern 3 added\n");
    
    // Build to temp file
    const char* tmpfile = "/tmp/matchy_c_test.db";
    if (matchy_builder_save(builder, tmpfile) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save\n");
        return 1;
    }
    printf("✓ Database saved\n");
    
    matchy_builder_free(builder);
    
    // Open and test
    matchy_t* db = matchy_open(tmpfile);
    if (db == NULL) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    printf("✓ Database opened\n");
    
    // Check pattern count
    size_t count = matchy_pattern_count(db);
    printf("✓ Pattern count: %zu\n", count);
    if (count != 3) {
        fprintf(stderr, "Wrong pattern count: expected 3, got %zu\n", count);
        return 1;
    }
    
    // Test matching
    matchy_result_t result = matchy_query(db, "test_file.txt");
    if (!result.found) {
        fprintf(stderr, "No match found\n");
        return 1;
    }
    printf("✓ Query found match\n");
    
    // Free the result
    matchy_free_result(&result);
    
    matchy_close(db);
    
    printf("\n=== All C API tests passed! ===\n");
    return 0;
}
