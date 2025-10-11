use std::env;
use std::path::PathBuf;

fn main() {
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
