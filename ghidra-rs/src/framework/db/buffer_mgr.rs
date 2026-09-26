use super::buffer::DataBuffer;
use crate::framework::application::Application;
use std::io;
use std::sync::{Arc, RwLock};

/// Prefix used for temporary buffer cache files. Mirrors `BufferMgr.CACHE_FILE_PREFIX`.
const CACHE_FILE_PREFIX: &str = "ghidra";

/// Extension used for temporary buffer cache files. Mirrors `BufferMgr.CACHE_FILE_EXT`.
const CACHE_FILE_EXT: &str = ".cache";

pub struct BufferMgr {
    buffer_size: usize,
    buffers: Vec<Option<Arc<RwLock<DataBuffer>>>>,
}

impl BufferMgr {
    pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

    /// Delete any stale buffer cache files left behind in the user's temp directory by a
    /// previous, uncleanly-terminated session.
    ///
    /// Port of the static `BufferMgr.cleanupOldCacheFiles()`. Java reaches for the global
    /// `Application.getUserTempDirectory()` singleton directly; this port instead takes an
    /// explicit `&dyn Application`, consistent with how the rest of this crate avoids Java-style
    /// static singleton access (see [`crate::framework::application::Application`]'s own doc
    /// comment). Mirrors Java's `BufferFileFilter(CACHE_FILE_PREFIX, CACHE_FILE_EXT)` name match
    /// (prefix `"ghidra"`, extension `".cache"`) and its per-file `file.delete()` loop: read
    /// errors on the directory itself are surfaced, but an individual file's delete failure is
    /// ignored (matching `File.delete()`'s silent `boolean` return, whose result Java's loop
    /// never checks either).
    pub fn cleanup_old_cache_files(app: &dyn Application) -> io::Result<()> {
        let tmp_dir = app.user_temp_directory();
        let entries = match std::fs::read_dir(&tmp_dir) {
            Ok(entries) => entries,
            // Mirrors `tmpDir.listFiles(...)` returning `null` (e.g. `tmpDir` does not exist or
            // is not a directory), in which case Java's `cleanupOldCacheFiles()` simply returns.
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name.starts_with(CACHE_FILE_PREFIX) && name.ends_with(CACHE_FILE_EXT) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            buffers: Vec::new(),
        }
    }

    pub fn create_buffer(&mut self) -> io::Result<i32> {
        let id = self.buffers.len() as i32;
        let buf = DataBuffer::new(id, self.buffer_size);
        self.buffers.push(Some(Arc::new(RwLock::new(buf))));
        Ok(id)
    }

    pub fn get_buffer(&self, id: i32) -> io::Result<Arc<RwLock<DataBuffer>>> {
        self.buffers
            .get(id as usize)
            .and_then(|b| b.as_ref())
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Buffer not found"))
    }

    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }

    pub fn delete_buffer(&mut self, id: i32) -> io::Result<()> {
        if let Some(slot) = self.buffers.get_mut(id as usize) {
            *slot = None;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Buffer not found"))
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::framework::platform::Platform;
    use crate::framework::seam_stubs::ApplicationLayoutLike;
    use std::path::PathBuf;

    /// Minimal `Application` test double that only needs to answer
    /// [`Application::user_temp_directory`] (overridden directly rather than through
    /// `application_layout()`, which this test never exercises).
    struct MockApp {
        temp_dir: PathBuf,
    }

    impl Application for MockApp {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            unimplemented!("not exercised by cleanup_old_cache_files tests")
        }

        fn current_platform(&self) -> Box<dyn Platform> {
            unimplemented!("not exercised by cleanup_old_cache_files tests")
        }

        fn user_temp_directory(&self) -> PathBuf {
            self.temp_dir.clone()
        }
    }

    #[test]
    fn test_cleanup_deletes_only_matching_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_file = dir.path().join("ghidra12345.cache");
        let other_file = dir.path().join("keepme.txt");
        std::fs::write(&cache_file, b"stale").unwrap();
        std::fs::write(&other_file, b"keep").unwrap();

        let app = MockApp { temp_dir: dir.path().to_path_buf() };
        BufferMgr::cleanup_old_cache_files(&app).unwrap();

        assert!(!cache_file.exists());
        assert!(other_file.exists());
    }

    #[test]
    fn test_cleanup_is_a_noop_when_temp_dir_missing() {
        let app = MockApp { temp_dir: PathBuf::from("/nonexistent/ghidra-rs-test-dir-xyz") };
        // Mirrors `tmpDir.listFiles(...)` returning null for a missing directory: no error.
        assert!(BufferMgr::cleanup_old_cache_files(&app).is_ok());
    }

    #[test]
    fn test_cleanup_ignores_non_matching_extension_or_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let wrong_ext = dir.path().join("ghidra.tmp");
        let wrong_prefix = dir.path().join("other.cache");
        std::fs::write(&wrong_ext, b"a").unwrap();
        std::fs::write(&wrong_prefix, b"b").unwrap();

        let app = MockApp { temp_dir: dir.path().to_path_buf() };
        BufferMgr::cleanup_old_cache_files(&app).unwrap();

        assert!(wrong_ext.exists());
        assert!(wrong_prefix.exists());
    }
}
