# Makefile for matchy C/C++ API tests

# Detect OS
UNAME_S := $(shell uname -s)

# Compiler settings
CC = clang
CXX = clang++
CFLAGS = -Wall -Wextra -std=c11 -I./include
CXXFLAGS = -Wall -Wextra -std=c++17 -I./include -I./src/cpp
LDFLAGS = -L./target/release

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -lmatchy -lc++
else
	LDFLAGS += -lmatchy -lstdc++ -lpthread -ldl -lm
endif

# Rust library
RUST_LIB = target/release/libmatchy.a

# Test targets
C_TEST = tests/test_c_api
CPP_TEST = tests/test_cpp_api

.PHONY: all clean test test-c test-cpp build-rust

all: build-rust test

# Build Rust library
build-rust:
	@echo "Building Rust library..."
	@cargo build --release

# Build C test
$(C_TEST): tests/test_c_api.c $(RUST_LIB)
	@echo "Building C API tests..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build C++ test
$(CPP_TEST): tests/test_cpp_api.cpp src/cpp/paraglob.cpp $(RUST_LIB)
	@echo "Building C++ API tests..."
	$(CXX) $(CXXFLAGS) tests/test_cpp_api.cpp src/cpp/paraglob.cpp -o $@ $(LDFLAGS)

# Run C tests
test-c: $(C_TEST)
	@echo ""
	@echo "================================"
	@echo "Running C API tests..."
	@echo "================================"
	@./$(C_TEST)
	@echo ""

# Run C++ tests
test-cpp: $(CPP_TEST)
	@echo ""
	@echo "================================"
	@echo "Running C++ API tests..."
	@echo "================================"
	@./$(CPP_TEST)
	@echo ""

# Run all tests
test: test-c test-cpp
	@echo "================================"
	@echo "All FFI tests passed!"
	@echo "================================"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(C_TEST) $(CPP_TEST)
	@rm -f /tmp/paraglob_*.pgb
	@cargo clean

# Help
help:
	@echo "Paraglob C/C++ API Testing"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build Rust library and run all tests (default)"
	@echo "  test       - Run all FFI tests (C and C++)"
	@echo "  test-c     - Run C API tests only"
	@echo "  test-cpp   - Run C++ API tests only"
	@echo "  build-rust - Build Rust library"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help"
