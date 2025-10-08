use std::env;
use std::path::PathBuf;

fn main() {
    // Get crate directory
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Ensure include directory exists
    let include_dir = PathBuf::from(&crate_dir).join("include");
    std::fs::create_dir_all(&include_dir).expect("Failed to create include directory");

    // Generate C header with cbindgen
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Unable to find cbindgen.toml configuration file");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(include_dir.join("paraglob_rs.h"));

    // Tell cargo to rerun if these change
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
