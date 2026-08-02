use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=MATCHY_SKIP_CBINDGEN");
    if env::var_os("CARGO_FEATURE_C_API").is_none() {
        return;
    }
    generate_c_header();
}

fn generate_c_header() {
    // Fuzzing builds compile Matchy as a dependency and must not rewrite a
    // tracked source artifact with the fuzz workspace's cbindgen version.
    let cargo_fuzz_build = env::var_os("CARGO_CFG_FUZZING").is_some()
        || ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS"]
            .into_iter()
            .filter_map(|name| env::var(name).ok())
            .any(|flags| {
                flags
                    .split(|character: char| character == '\u{1f}' || character.is_whitespace())
                    .any(|argument| argument == "fuzzing")
            });
    if env::var_os("MATCHY_SKIP_CBINDGEN").is_some() || cargo_fuzz_build {
        println!(
            "cargo:warning=Skipping cbindgen because MATCHY_SKIP_CBINDGEN or cfg(fuzzing) is set"
        );
        return;
    }

    // Skip header generation on docs.rs - the source directory is read-only
    // The C API documentation doesn't need the generated header
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Skipping cbindgen on docs.rs (read-only filesystem)");
        return;
    }

    // Get crate directory
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Ensure include directory exists
    let include_dir = PathBuf::from(&crate_dir).join("include").join("matchy");
    std::fs::create_dir_all(&include_dir).expect("Failed to create include directory");

    // Generate C header with cbindgen
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Unable to find cbindgen.toml configuration file");

    let header_path = include_dir.join("matchy.h");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(&header_path);

    // Post-process: fix sockaddr references (cbindgen doesn't handle libc::sockaddr properly)
    let header_content =
        std::fs::read_to_string(&header_path).expect("Failed to read generated header");
    let fixed_header = header_content.replace(
        "const sockaddr *sockaddr",
        "const struct sockaddr *sockaddr",
    );
    std::fs::write(&header_path, fixed_header).expect("Failed to write fixed header");

    // Tell cargo to rerun if these change
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
