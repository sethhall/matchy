/// Set thread name for debugging/profiling (cross-platform)
#[cfg(target_os = "macos")]
pub fn set_thread_name(name: &str) {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        // SAFETY: pthread_setname_np on macOS sets current thread's name.
        // - cname is a valid null-terminated C string (CString guarantees this)
        // - cname lives for the duration of the call
        // - Function only reads from the pointer, no ownership transfer
        unsafe {
            libc::pthread_setname_np(cname.as_ptr());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_thread_name(name: &str) {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        // SAFETY: pthread_setname_np on Linux sets a thread's name.
        // - pthread_self() returns the calling thread's ID (always valid)
        // - cname is a valid null-terminated C string (CString guarantees this)
        // - cname lives for the duration of the call
        // - Function only reads from the pointer, no ownership transfer
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), cname.as_ptr());
        }
    }
}

#[cfg(target_os = "windows")]
pub fn set_thread_name(_name: &str) {
    // Windows 10+ supports SetThreadDescription but requires additional dependencies
    // Thread naming is debug-only, so we skip it for simplicity
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn set_thread_name(_name: &str) {
    // No-op on other platforms
}
