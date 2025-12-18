//! Live database update support.
//!
//! Internal module providing background file watching and optional HTTP updates.
//! This functionality is exposed through the unified `Database` type.

use crate::database::{next_cache_generation, Database, DatabaseError, DatabaseOptions};
use arc_swap::ArcSwap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

#[cfg(feature = "auto-update")]
use std::fs::File;
#[cfg(feature = "auto-update")]
use std::io::Write;

pub(crate) const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

#[cfg(feature = "auto-update")]
pub(crate) const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 3600;

#[cfg(feature = "auto-update")]
const HTTP_TIMEOUT_SECS: u64 = 90;

#[cfg(feature = "auto-update")]
const MAX_DOWNLOAD_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GB

#[cfg(feature = "auto-update")]
fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("matchy")
}

#[cfg(feature = "auto-update")]
fn cached_db_path(cache_dir: &Path, original_path: &Path) -> PathBuf {
    let filename = original_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "database.mxy".to_string());
    cache_dir.join(filename)
}

/// Event fired when database is reloaded.
pub struct ReloadEvent {
    /// Path to the database file.
    pub path: PathBuf,
    /// Whether reload succeeded.
    pub success: bool,
    /// Error message if reload failed.
    pub error: Option<String>,
    /// Generation counter after reload.
    pub generation: u64,
    /// What triggered the reload.
    pub source: ReloadSource,
}

/// Event fired when falling back to previous database version.
pub struct FallbackEvent {
    /// The error that triggered the fallback.
    pub error: String,
    /// Generation of the database we fell back to.
    pub generation: u64,
}

/// What triggered a database reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadSource {
    /// Local file changed (mtime different).
    FileChange,
    /// Remote URL had new version (ETag different).
    #[cfg(feature = "auto-update")]
    NetworkUpdate,
}

/// Callback type for reload notifications.
pub type ReloadCallback = Arc<dyn Fn(ReloadEvent) + Send + Sync>;

/// Callback type for fallback notifications.
pub type FallbackCallback = Arc<dyn Fn(FallbackEvent) + Send + Sync>;

pub(crate) struct UpdaterThread {
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for UpdaterThread {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Internal live database state.
pub(crate) struct LiveState {
    pub(crate) current: Arc<ArcSwap<Database>>,
    pub(crate) previous: Arc<ArcSwap<Option<Arc<Database>>>>,
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) fallback_callback: Option<FallbackCallback>,
    pub(crate) _updater: UpdaterThread,
}

thread_local! {
    pub(crate) static LOCAL_DB: std::cell::RefCell<Option<(u64, Arc<Database>)>> = const { std::cell::RefCell::new(None) };
}

/// Configuration for live database updates.
#[derive(Clone, Default)]
pub(crate) struct LiveOptions {
    pub(crate) enabled: bool,
    pub(crate) poll_interval: Option<Duration>,
    pub(crate) reload_callback: Option<ReloadCallback>,
    pub(crate) fallback_callback: Option<FallbackCallback>,
    #[cfg(feature = "auto-update")]
    pub(crate) auto_update_enabled: bool,
    #[cfg(feature = "auto-update")]
    pub(crate) update_interval: Option<Duration>,
    #[cfg(feature = "auto-update")]
    pub(crate) cache_dir: Option<PathBuf>,
}

impl LiveOptions {
    pub(crate) fn start_updater(
        &self,
        path: PathBuf,
        initial_db: Database,
        cache_capacity: Option<usize>,
    ) -> Result<LiveState, DatabaseError> {
        let initial_gen = next_cache_generation();

        #[cfg(feature = "auto-update")]
        let update_url = if self.auto_update_enabled {
            initial_db.update_url()
        } else {
            None
        };

        #[cfg(feature = "auto-update")]
        let cache_dir = self.cache_dir.clone().unwrap_or_else(default_cache_dir);

        let current = Arc::new(ArcSwap::from_pointee(initial_db));
        let previous: Arc<ArcSwap<Option<Arc<Database>>>> = Arc::new(ArcSwap::from_pointee(None));
        let generation = Arc::new(AtomicU64::new(initial_gen));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_current = Arc::clone(&current);
        let thread_previous = Arc::clone(&previous);
        let thread_generation = Arc::clone(&generation);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_path = path.clone();
        let thread_callback = self.reload_callback.clone();
        let thread_cache_capacity = cache_capacity;
        let poll_interval = self
            .poll_interval
            .unwrap_or(Duration::from_millis(DEFAULT_POLL_INTERVAL_MS));

        #[cfg(feature = "auto-update")]
        let thread_update_interval = self.update_interval;
        #[cfg(feature = "auto-update")]
        let thread_update_url = update_url;
        #[cfg(feature = "auto-update")]
        let thread_cache_dir = cache_dir;
        #[cfg(feature = "auto-update")]
        let thread_original_path = path;

        let handle = thread::spawn(move || {
            let mut last_mtime: Option<SystemTime> = get_file_mtime(&thread_path);

            #[cfg(feature = "auto-update")]
            let mut last_update_check = std::time::Instant::now();
            #[cfg(feature = "auto-update")]
            let cached_path = cached_db_path(&thread_cache_dir, &thread_original_path);
            #[cfg(feature = "auto-update")]
            let mut etag: Option<String> = load_etag(&cached_path);

            loop {
                if thread_shutdown.load(Ordering::Acquire) {
                    break;
                }

                thread::sleep(poll_interval);

                if thread_shutdown.load(Ordering::Acquire) {
                    break;
                }

                let mut reload_path: Option<PathBuf> = None;
                #[cfg(feature = "auto-update")]
                let mut reload_source = ReloadSource::FileChange;
                #[cfg(not(feature = "auto-update"))]
                let reload_source = ReloadSource::FileChange;

                let current_mtime = get_file_mtime(&thread_path);
                if current_mtime != last_mtime {
                    reload_path = Some(thread_path.clone());
                    last_mtime = current_mtime;
                }

                #[cfg(feature = "auto-update")]
                if let (Some(interval), Some(ref url)) =
                    (thread_update_interval, &thread_update_url)
                {
                    if last_update_check.elapsed() >= interval {
                        last_update_check = std::time::Instant::now();

                        match check_for_update(
                            url,
                            etag.as_deref(),
                            &thread_cache_dir,
                            &thread_original_path,
                        ) {
                            UpdateCheckResult::NewVersion {
                                etag: new_etag,
                                path,
                            } => {
                                reload_path = Some(path);
                                reload_source = ReloadSource::NetworkUpdate;
                                etag = Some(new_etag.clone());
                                save_etag(&cached_path, &new_etag);
                            }
                            UpdateCheckResult::NotModified => {}
                            UpdateCheckResult::Error(e) => {
                                if let Some(ref callback) = thread_callback {
                                    callback(ReloadEvent {
                                        path: thread_path.clone(),
                                        success: false,
                                        error: Some(e),
                                        generation: thread_generation.load(Ordering::Acquire),
                                        source: ReloadSource::NetworkUpdate,
                                    });
                                }
                            }
                        }
                    }
                }

                if let Some(path_to_load) = reload_path {
                    let new_gen = next_cache_generation();
                    let reload_options = DatabaseOptions {
                        path: path_to_load.clone(),
                        cache_capacity: thread_cache_capacity,
                        cache_generation: Some(new_gen),
                        ..Default::default()
                    };

                    match Database::open_with_options(reload_options) {
                        Ok(new_db) => {
                            let old_db = thread_current.load_full();
                            thread_previous.store(Arc::new(Some(old_db)));
                            let old_gen = thread_generation.swap(new_gen, Ordering::Release);
                            thread_current.store(Arc::new(new_db));
                            Database::clear_cache_generation(old_gen);

                            if let Some(ref callback) = thread_callback {
                                callback(ReloadEvent {
                                    path: path_to_load,
                                    success: true,
                                    error: None,
                                    generation: new_gen,
                                    source: reload_source,
                                });
                            }
                        }
                        Err(e) => {
                            if let Some(ref callback) = thread_callback {
                                callback(ReloadEvent {
                                    path: path_to_load,
                                    success: false,
                                    error: Some(e.to_string()),
                                    generation: thread_generation.load(Ordering::Acquire),
                                    source: reload_source,
                                });
                            }
                        }
                    }
                }
            }
        });

        Ok(LiveState {
            current,
            previous,
            generation,
            fallback_callback: self.fallback_callback.clone(),
            _updater: UpdaterThread {
                shutdown,
                handle: Some(handle),
            },
        })
    }
}

fn get_file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(feature = "auto-update")]
pub(crate) fn etag_path(db_path: &Path) -> PathBuf {
    let mut etag_path = db_path.to_path_buf();
    let ext = etag_path
        .extension()
        .map(|e| format!("{}.etag", e.to_string_lossy()))
        .unwrap_or_else(|| "etag".to_string());
    etag_path.set_extension(ext);
    etag_path
}

#[cfg(feature = "auto-update")]
pub(crate) fn load_etag(db_path: &Path) -> Option<String> {
    std::fs::read_to_string(etag_path(db_path)).ok()
}

#[cfg(feature = "auto-update")]
pub(crate) fn save_etag(db_path: &Path, etag: &str) {
    let _ = std::fs::write(etag_path(db_path), etag);
}

#[cfg(feature = "auto-update")]
#[derive(Debug)]
pub(crate) enum UpdateCheckResult {
    NewVersion { etag: String, path: PathBuf },
    NotModified,
    Error(String),
}

#[cfg(feature = "auto-update")]
pub(crate) fn check_for_update(
    url: &str,
    current_etag: Option<&str>,
    cache_dir: &Path,
    original_path: &Path,
) -> UpdateCheckResult {
    use ureq::AgentBuilder;

    if let Err(e) = std::fs::create_dir_all(cache_dir) {
        return UpdateCheckResult::Error(format!("Failed to create cache dir: {}", e));
    }

    let agent = AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build();

    let mut request = agent.get(url);

    if let Some(etag) = current_etag {
        request = request.set("If-None-Match", etag);
    }

    match request.call() {
        Ok(response) => {
            if response.status() == 304 {
                return UpdateCheckResult::NotModified;
            }

            let new_etag = response
                .header("ETag")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs().to_string())
                        .unwrap_or_default()
                });

            let cached_path = cached_db_path(cache_dir, original_path);
            let temp_path = cached_path.with_extension("tmp");
            match File::create(&temp_path) {
                Ok(mut file) => {
                    let mut reader = response.into_reader();
                    let mut buffer = [0u8; 8192];
                    let mut total_bytes: u64 = 0;

                    loop {
                        match std::io::Read::read(&mut reader, &mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                total_bytes += n as u64;
                                if total_bytes > MAX_DOWNLOAD_SIZE {
                                    let _ = std::fs::remove_file(&temp_path);
                                    return UpdateCheckResult::Error(format!(
                                        "Download exceeds maximum size of {} bytes",
                                        MAX_DOWNLOAD_SIZE
                                    ));
                                }
                                if file.write_all(&buffer[..n]).is_err() {
                                    let _ = std::fs::remove_file(&temp_path);
                                    return UpdateCheckResult::Error("Write failed".to_string());
                                }
                            }
                            Err(e) => {
                                let _ = std::fs::remove_file(&temp_path);
                                return UpdateCheckResult::Error(format!("Read failed: {}", e));
                            }
                        }
                    }

                    if std::fs::rename(&temp_path, &cached_path).is_err() {
                        let _ = std::fs::remove_file(&temp_path);
                        return UpdateCheckResult::Error("Rename failed".to_string());
                    }

                    UpdateCheckResult::NewVersion {
                        etag: new_etag,
                        path: cached_path,
                    }
                }
                Err(e) => UpdateCheckResult::Error(format!("Failed to create temp file: {}", e)),
            }
        }
        Err(ureq::Error::Status(304, _)) => UpdateCheckResult::NotModified,
        Err(e) => UpdateCheckResult::Error(format!("HTTP request failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataValue, DatabaseBuilder, MatchMode};
    use std::collections::HashMap;
    use std::fs;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    fn build_test_db(literal: &str) -> Vec<u8> {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert("key".to_string(), DataValue::String(literal.to_string()));
        builder.add_literal(literal, data).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn test_live_database_basic() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        fs::write(&db_path, build_test_db("test.com")).unwrap();

        let db = Database::from(&db_path).watch().open().unwrap();

        let result = db.lookup("test.com").unwrap();
        assert!(result.is_some());
        assert!(db.generation() > 0);
    }

    #[test]
    fn test_live_database_reload() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        fs::write(&db_path, build_test_db("example.com")).unwrap();

        let reload_count = Arc::new(AtomicUsize::new(0));
        let reload_count_clone = Arc::clone(&reload_count);

        let db = Database::from(&db_path)
            .watch()
            .poll_interval(Duration::from_millis(50))
            .on_reload(move |event| {
                if event.success {
                    reload_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            })
            .open()
            .unwrap();

        let initial_gen = db.generation();

        thread::sleep(Duration::from_millis(100));

        let temp_path = db_path.with_extension("tmp");
        fs::write(&temp_path, build_test_db("example.org")).unwrap();
        fs::rename(&temp_path, &db_path).unwrap();

        thread::sleep(Duration::from_millis(200));

        assert!(
            db.generation() > initial_gen,
            "Generation should have increased after reload"
        );
        assert!(
            reload_count.load(Ordering::SeqCst) >= 1,
            "Reload callback should have been called"
        );
    }

    #[test]
    fn test_live_database_corrupt_file_keeps_old_version() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");
        let new_path = temp_dir.path().join("test.mxy.new");

        fs::write(&db_path, build_test_db("good.com")).unwrap();

        let error_count = Arc::new(AtomicUsize::new(0));
        let error_count_clone = Arc::clone(&error_count);

        let db = Database::from(&db_path)
            .watch()
            .poll_interval(Duration::from_millis(50))
            .on_reload(move |event| {
                if !event.success {
                    error_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            })
            .open()
            .unwrap();

        let initial_gen = db.generation();
        assert!(db.lookup("good.com").unwrap().is_some());

        thread::sleep(Duration::from_millis(100));

        fs::write(&new_path, b"this is not a valid database file").unwrap();
        fs::rename(&new_path, &db_path).unwrap();

        thread::sleep(Duration::from_millis(200));

        assert_eq!(
            db.generation(),
            initial_gen,
            "Generation should NOT increase after failed reload"
        );
        assert!(
            error_count.load(Ordering::SeqCst) >= 1,
            "Error callback should have been called"
        );
        assert!(
            db.lookup("good.com").unwrap().is_some(),
            "Old data should still be accessible"
        );
    }

    #[test]
    fn test_live_database_update_url_from_metadata() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder.add_literal("test.com", HashMap::new()).unwrap();
        let builder = builder.with_update_url("https://example.com/db.mxy");
        fs::write(&db_path, builder.build().unwrap()).unwrap();

        let db = Database::from(&db_path).watch().open().unwrap();

        assert_eq!(
            db.update_url(),
            Some("https://example.com/db.mxy".to_string())
        );
    }

    #[test]
    fn test_previous_database_stored_after_reload() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        fs::write(&db_path, build_test_db("version1.com")).unwrap();

        let reload_count = Arc::new(AtomicUsize::new(0));
        let reload_count_clone = Arc::clone(&reload_count);

        let db = Database::from(&db_path)
            .watch()
            .poll_interval(Duration::from_millis(50))
            .on_reload(move |event| {
                if event.success {
                    reload_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            })
            .open()
            .unwrap();

        assert!(db.lookup("version1.com").unwrap().is_some());
        let initial_gen = db.generation();

        thread::sleep(Duration::from_millis(100));

        let temp_path = db_path.with_extension("tmp");
        fs::write(&temp_path, build_test_db("version2.com")).unwrap();
        fs::rename(&temp_path, &db_path).unwrap();

        thread::sleep(Duration::from_millis(200));

        assert!(
            db.generation() > initial_gen,
            "Generation should increase after reload"
        );
        assert!(
            reload_count.load(Ordering::SeqCst) >= 1,
            "Reload callback should have been called"
        );

        assert!(
            db.lookup("version2.com").unwrap().is_some(),
            "New data should be accessible after reload"
        );
    }

    #[test]
    fn test_fallback_callback_can_be_set() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        fs::write(&db_path, build_test_db("test.com")).unwrap();

        let fallback_count = Arc::new(AtomicUsize::new(0));
        let fallback_count_clone = Arc::clone(&fallback_count);

        let db = Database::from(&db_path)
            .watch()
            .poll_interval(Duration::from_millis(50))
            .on_fallback(move |_event| {
                fallback_count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .open()
            .unwrap();

        assert!(db.lookup("test.com").unwrap().is_some());
        assert_eq!(fallback_count.load(Ordering::SeqCst), 0);
    }
}

#[cfg(all(test, feature = "auto-update"))]
mod auto_update_tests {
    use super::*;
    use crate::{DatabaseBuilder, MatchMode};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn build_test_db(literal: &str) -> Vec<u8> {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder.add_literal(literal, HashMap::new()).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn test_etag_sidecar_storage() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        fs::write(&db_path, build_test_db("test.com")).unwrap();

        save_etag(&db_path, "\"abc123\"");

        let loaded = load_etag(&db_path);
        assert_eq!(loaded, Some("\"abc123\"".to_string()));

        let etag_file = etag_path(&db_path);
        assert!(etag_file.exists());
        assert_eq!(etag_file, temp_dir.path().join("test.mxy.etag"));
    }

    #[test]
    fn test_check_for_update_initial_fetch() {
        let mut server = mockito::Server::new();
        let db_bytes = build_test_db("remote.com");

        let mock = server
            .mock("GET", "/db.mxy")
            .with_status(200)
            .with_header("ETag", "\"v1\"")
            .with_body(&db_bytes)
            .create();

        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");
        fs::write(&original_path, build_test_db("local.com")).unwrap();

        let url = format!("{}/db.mxy", server.url());
        let result = check_for_update(&url, None, &cache_dir, &original_path);

        mock.assert();

        match result {
            UpdateCheckResult::NewVersion { etag, path } => {
                assert_eq!(etag, "\"v1\"");
                let db_content = fs::read(&path).unwrap();
                assert_eq!(db_content, db_bytes);
            }
            other => panic!("Expected NewVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_check_for_update_not_modified() {
        let mut server = mockito::Server::new();

        let mock = server
            .mock("GET", "/db.mxy")
            .match_header("If-None-Match", "\"v1\"")
            .with_status(304)
            .create();

        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");
        fs::write(&original_path, build_test_db("local.com")).unwrap();

        let url = format!("{}/db.mxy", server.url());
        let result = check_for_update(&url, Some("\"v1\""), &cache_dir, &original_path);

        mock.assert();

        match result {
            UpdateCheckResult::NotModified => {}
            other => panic!("Expected NotModified, got {:?}", other),
        }
    }

    #[test]
    fn test_check_for_update_new_version_with_etag() {
        let mut server = mockito::Server::new();
        let db_bytes = build_test_db("updated.com");

        let mock = server
            .mock("GET", "/db.mxy")
            .match_header("If-None-Match", "\"v1\"")
            .with_status(200)
            .with_header("ETag", "\"v2\"")
            .with_body(&db_bytes)
            .create();

        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");
        fs::write(&original_path, build_test_db("old.com")).unwrap();

        let url = format!("{}/db.mxy", server.url());
        let result = check_for_update(&url, Some("\"v1\""), &cache_dir, &original_path);

        mock.assert();

        match result {
            UpdateCheckResult::NewVersion { etag, .. } => {
                assert_eq!(etag, "\"v2\"");
            }
            other => panic!("Expected NewVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_check_for_update_network_error() {
        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");
        fs::write(&original_path, build_test_db("local.com")).unwrap();

        let result = check_for_update("http://localhost:1", None, &cache_dir, &original_path);

        match result {
            UpdateCheckResult::Error(_) => {}
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_check_for_update_generates_etag_if_missing() {
        let mut server = mockito::Server::new();
        let db_bytes = build_test_db("remote.com");

        let mock = server
            .mock("GET", "/db.mxy")
            .with_status(200)
            .with_body(&db_bytes)
            .create();

        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");
        fs::write(&original_path, build_test_db("local.com")).unwrap();

        let url = format!("{}/db.mxy", server.url());
        let result = check_for_update(&url, None, &cache_dir, &original_path);

        mock.assert();

        match result {
            UpdateCheckResult::NewVersion { etag, .. } => {
                assert!(!etag.is_empty(), "Should generate fallback etag");
            }
            other => panic!("Expected NewVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_full_auto_update_integration() {
        use crate::database::Database;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let mut server = mockito::Server::new();
        let url = format!("{}/db.mxy", server.url());

        let mut initial_builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        initial_builder
            .add_literal("initial.com", HashMap::new())
            .unwrap();
        let initial_builder = initial_builder.with_update_url(&url);
        let initial_db = initial_builder.build().unwrap();

        let mut updated_builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        updated_builder
            .add_literal("updated.com", HashMap::new())
            .unwrap();
        let updated_builder = updated_builder.with_update_url(&url);
        let updated_db = updated_builder.build().unwrap();

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");

        fs::write(&db_path, &initial_db).unwrap();

        let mock = server
            .mock("GET", "/db.mxy")
            .with_status(200)
            .with_header("ETag", "\"v2\"")
            .with_body(&updated_db)
            .expect_at_least(1)
            .create();

        let reload_count = Arc::new(AtomicUsize::new(0));
        let reload_count_clone = Arc::clone(&reload_count);

        let db = Database::from(&db_path)
            .auto_update()
            .poll_interval(Duration::from_millis(50))
            .update_interval(Duration::from_millis(100))
            .cache_dir(&cache_dir)
            .on_reload(move |event| {
                if event.success {
                    reload_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            })
            .open()
            .unwrap();

        assert!(
            db.lookup("initial.com").unwrap().is_some(),
            "Should find initial.com in initial database"
        );

        thread::sleep(Duration::from_millis(500));

        mock.assert();

        let reloads = reload_count.load(Ordering::SeqCst);
        assert!(
            reloads >= 1,
            "Should have reloaded at least once, got {}",
            reloads
        );

        assert!(
            db.lookup("updated.com").unwrap().is_some(),
            "Should find updated.com after auto-update"
        );
    }

    #[test]
    fn test_auto_update_requires_embedded_url() {
        use crate::database::Database;

        let db_without_url = {
            let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
            builder.add_literal("test.com", HashMap::new()).unwrap();
            builder.build().unwrap()
        };

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");
        fs::write(&db_path, &db_without_url).unwrap();

        let result = Database::from(&db_path).auto_update().open();

        match result {
            Ok(_) => {
                panic!("Should fail to open with auto_update() when database has no embedded URL")
            }
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("update URL") || err.contains("auto-update"),
                    "Error should mention missing update URL: {}",
                    err
                );
            }
        }
    }

    #[test]
    fn test_auto_update_304_not_modified() {
        use crate::database::Database;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let mut server = mockito::Server::new();
        let url = format!("{}/db.mxy", server.url());

        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        builder.add_literal("test.com", HashMap::new()).unwrap();
        let builder = builder.with_update_url(&url);
        let db_bytes = builder.build().unwrap();

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");
        let cache_dir = temp_dir.path().join("cache");

        fs::write(&db_path, &db_bytes).unwrap();

        let mock = server
            .mock("GET", "/db.mxy")
            .with_status(304)
            .expect_at_least(1)
            .create();

        let reload_count = Arc::new(AtomicUsize::new(0));
        let reload_count_clone = Arc::clone(&reload_count);

        let db = Database::from(&db_path)
            .auto_update()
            .poll_interval(Duration::from_millis(50))
            .update_interval(Duration::from_millis(100))
            .cache_dir(&cache_dir)
            .on_reload(move |event| {
                if event.success {
                    reload_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            })
            .open()
            .unwrap();

        thread::sleep(Duration::from_millis(300));

        mock.assert();

        let reloads = reload_count.load(Ordering::SeqCst);
        assert_eq!(
            reloads, 0,
            "Should NOT reload when server returns 304, got {} reloads",
            reloads
        );

        assert!(
            db.lookup("test.com").unwrap().is_some(),
            "Original data should still be accessible"
        );
    }
}
