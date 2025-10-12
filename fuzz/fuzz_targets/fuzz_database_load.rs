#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // This should never crash or panic, even on garbage input
    let _ = matchy::Database::from_bytes(data.to_vec());
});
