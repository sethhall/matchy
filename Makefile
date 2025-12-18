# Makefile for matchy C/C++ API tests

# Detect OS
UNAME_S := $(shell uname -s)

# Compiler settings
CC = clang
CFLAGS = -Wall -Wextra -std=c11 -I./crates/matchy/include
LDFLAGS = -L./target/release

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -lmatchy
else
	LDFLAGS += -lmatchy -lpthread -ldl -lm
endif

# Rust library
RUST_LIB = target/release/libmatchy.a

# Test targets
C_TEST = crates/matchy/tests/test_c_api
C_EXT_TEST = crates/matchy/tests/test_c_api_extensions
MMDB_TEST = crates/matchy/tests/test_mmdb_compat

.PHONY: all clean test test-c test-c-ext test-mmdb build-rust ci-local ci-quick fmt clippy docs check-docs check-wasm

all: build-rust test

# Build Rust library
build-rust:
	@echo "Building Rust library..."
	@cargo build --release -p matchy

# Build C test
$(C_TEST): crates/matchy/tests/test_c_api.c $(RUST_LIB)
	@echo "Building C API tests..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build C API extensions test
$(C_EXT_TEST): crates/matchy/tests/test_c_api_extensions.c $(RUST_LIB)
	@echo "Building C API extensions tests..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build MMDB compatibility test
$(MMDB_TEST): crates/matchy/tests/test_mmdb_compat.c crates/matchy/src/c_api/mmdb_varargs.c $(RUST_LIB)
	@echo "Building MMDB compatibility tests..."
	$(CC) $(CFLAGS) crates/matchy/tests/test_mmdb_compat.c crates/matchy/src/c_api/mmdb_varargs.c -o $@ $(LDFLAGS)

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

# Run all tests
test: test-c test-c-ext test-mmdb
	@echo "================================"
	@echo "All FFI tests passed!"
	@echo "================================"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(C_TEST) $(C_EXT_TEST) $(MMDB_TEST)
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
	@$(MAKE) check-wasm
	@$(MAKE) test-rust
	@$(MAKE) test-doc
	@$(MAKE) build-rust
	@$(MAKE) test
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
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@if [ "$$(uname -m)" = "arm64" ]; then \
		echo "🔍 Also checking x86_64 target (since we're on ARM)..."; \
		rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true; \
		cargo clippy --workspace --lib --bins --target x86_64-unknown-linux-gnu -- -D warnings; \
	fi
	@echo "✅ Clippy OK"

# Check documentation builds without warnings
check-docs:
	@echo "\n📚 Checking documentation..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
	@echo "✅ Documentation OK"

# Alternative: just build docs (allows warnings)
docs:
	@echo "\n📚 Building documentation..."
	@cargo doc --workspace --no-deps --document-private-items --open

# Run Rust tests
test-rust:
	@echo "\n🧪 Running Rust tests..."
	@cargo test --workspace --verbose
	@echo "✅ Tests OK"

# Run doc tests
test-doc:
	@echo "\n📖 Running doc tests..."
	@cargo test --workspace --doc
	@echo "✅ Doc tests OK"

# Check WASM compilation
check-wasm:
	@echo "\n🌐 Checking WASM compilation..."
	@rustup target add wasm32-unknown-unknown 2>/dev/null || true
	@rustup target add wasm32-wasip1 2>/dev/null || true
	@cargo check -p matchy-wasm --target wasm32-unknown-unknown
	@cargo check -p matchy --target wasm32-wasip1 --no-default-features
	@echo "✅ WASM OK"

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
	@echo "  check-wasm - Check WASM and WASI compilation"
	@echo "  test-rust  - Run all Rust tests"
	@echo "  test-doc   - Run documentation tests"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  all        - Build Rust library and run all tests (default)"
	@echo "  test       - Run all FFI tests (C API, extensions, MMDB compat)"
	@echo "  test-c     - Run C API tests only"
	@echo "  test-c-ext - Run C API extensions tests only"
	@echo "  test-mmdb  - Run MMDB compatibility tests only"
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
