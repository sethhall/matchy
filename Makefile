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
C_EXT_TEST = tests/test_c_api_extensions
MMDB_TEST = tests/test_mmdb_compat
CPP_TEST = tests/test_cpp_api

.PHONY: all clean test test-c test-c-ext test-mmdb test-cpp build-rust ci-local ci-quick fmt clippy docs check-docs

all: build-rust test

# Build Rust library
build-rust:
	@echo "Building Rust library..."
	@cargo build --release

# Build C test
$(C_TEST): tests/test_c_api.c $(RUST_LIB)
	@echo "Building C API tests..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build C API extensions test
$(C_EXT_TEST): tests/test_c_api_extensions.c $(RUST_LIB)
	@echo "Building C API extensions tests..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build MMDB compatibility test
$(MMDB_TEST): tests/test_mmdb_compat.c src/c_api/mmdb_varargs.c $(RUST_LIB)
	@echo "Building MMDB compatibility tests..."
	$(CC) $(CFLAGS) tests/test_mmdb_compat.c src/c_api/mmdb_varargs.c -o $@ $(LDFLAGS)

# Build C++ test
$(CPP_TEST): tests/test_cpp_api.cpp src/cpp/matchy.cpp $(RUST_LIB)
	@echo "Building C++ API tests..."
	$(CXX) $(CXXFLAGS) tests/test_cpp_api.cpp src/cpp/matchy.cpp -o $@ $(LDFLAGS)

# Run C tests
test-c: $(C_TEST)
	@echo ""
	@echo "================================"
	@echo "Running C API tests..."
	@echo "================================"
	@./$(C_TEST)
	@echo ""

# Run C API extensions tests
test-c-ext: $(C_EXT_TEST)
	@echo ""
	@echo "================================"
	@echo "Running C API Extensions tests..."
	@echo "================================"
	@./$(C_EXT_TEST)
	@echo ""

# Run MMDB compatibility tests
test-mmdb: $(MMDB_TEST)
	@echo ""
	@echo "================================"
	@echo "Running MMDB Compatibility tests..."
	@echo "================================"
	@./$(MMDB_TEST)
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
test: test-c test-c-ext test-mmdb test-cpp
	@echo "================================"
	@echo "All FFI tests passed!"
	@echo "================================"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(C_TEST) $(C_EXT_TEST) $(MMDB_TEST) $(CPP_TEST)
	@rm -f /tmp/matchy_*.db /tmp/paraglob_*.pgb
	@cargo clean

# ================================
# CI Checks - Run before pushing!
# ================================

# Run all CI checks locally (matches CI exactly)
ci-local:
	@echo "================================"
	@echo "Running ALL CI checks..."
	@echo "================================"
	@$(MAKE) fmt
	@$(MAKE) clippy
	@$(MAKE) check-docs
	@$(MAKE) test-rust
	@$(MAKE) test-doc
	@echo ""
	@echo "✅ All CI checks passed!"
	@echo "================================"

# Quick CI checks (fast feedback)
ci-quick:
	@echo "================================"
	@echo "Running quick CI checks..."
	@echo "================================"
	@$(MAKE) fmt
	@$(MAKE) clippy
	@echo ""
	@echo "✅ Quick checks passed!"
	@echo "================================"

# Check code formatting
fmt:
	@echo "\n📝 Checking code formatting..."
	@cargo fmt --all -- --check
	@echo "✅ Formatting OK"

# Run clippy lints
clippy:
	@echo "\n🔍 Running clippy lints..."
	@cargo clippy --all-targets --all-features -- -D warnings
	@echo "✅ Clippy OK"

# Check documentation builds without warnings
check-docs:
	@echo "\n📚 Checking documentation..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items
	@echo "✅ Documentation OK"

# Alternative: just build docs (allows warnings)
docs:
	@echo "\n📚 Building documentation..."
	@cargo doc --no-deps --document-private-items --open

# Run Rust tests
test-rust:
	@echo "\n🧪 Running Rust tests..."
	@cargo test --verbose
	@cargo test --test integration_tests --verbose
	@echo "✅ Tests OK"

# Run doc tests
test-doc:
	@echo "\n📖 Running doc tests..."
	@cargo test --doc
	@echo "✅ Doc tests OK"

# Help
help:
	@echo "Matchy Development & CI"
	@echo ""
	@echo "🚀 CI Targets (run before pushing!):"
	@echo "  ci-local   - Run ALL CI checks locally (matches CI exactly)"
	@echo "  ci-quick   - Run quick checks only (fmt + clippy)"
	@echo ""
	@echo "🔍 Individual CI Checks:"
	@echo "  fmt        - Check code formatting (cargo fmt --check)"
	@echo "  clippy     - Run clippy lints with warnings as errors"
	@echo "  check-docs - Build docs with warnings as errors"
	@echo "  test-rust  - Run all Rust tests"
	@echo "  test-doc   - Run documentation tests"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  all        - Build Rust library and run all tests (default)"
	@echo "  test       - Run all FFI tests (C, C++, extensions, MMDB compat)"
	@echo "  test-c     - Run C API tests only"
	@echo "  test-c-ext - Run C API extensions tests only"
	@echo "  test-mmdb  - Run MMDB compatibility tests only"
	@echo "  test-cpp   - Run C++ API tests only"
	@echo ""
	@echo "🛠️  Building:"
	@echo "  build-rust - Build Rust library"
	@echo "  docs       - Build and open documentation (allows warnings)"
	@echo ""
	@echo "🧹 Maintenance:"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help"
	@echo ""
	@echo "💡 Tip: Run 'make ci-local' before every commit!"
