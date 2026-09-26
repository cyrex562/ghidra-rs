//! Port of `ghidra.formats.gfilesystem.FileCache` (with its nested `FileCacheEntry`,
//! `FileCacheEntryBuilder`, `RefPinningByteArrayProvider` and `FileCacheMaintenanceDaemon`).
//!
//! Caches files keyed by the MD5 of their contents. Small files (under
//! [`MAX_INMEM_FILESIZE`]) are kept in memory; larger ones are written, XOR-obfuscated (see
//! [`ObfuscatedOutputStream`]), to `<cacheDir>/<first two md5 hex digits>/<md5>`.
//!
//! Java keeps in-memory entries in a soft-valued `ReferenceMap`, evicted only under memory
//! pressure. Rust has no soft references, so they are kept until
//! [`release_file_cache_entry`](FileCache::release_file_cache_entry) or
//! [`purge`](FileCache::purge).

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::file_byte_provider::{AccessMode, ObfuscatedFileByteProvider};
use crate::app::util::bin::obfuscated_output_stream::ObfuscatedOutputStream;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use super::fs_utilities;
use super::fsrl::Fsrl;
use super::g_file_system::GFileSystemError;

/// Max size of a file that will be kept in memory (2Mb). Mirrors
/// `FileCache.MAX_INMEM_FILESIZE`.
pub const MAX_INMEM_FILESIZE: usize = 2 * 1024 * 1024;
const FREESPACE_RESERVE_BYTES: u64 = 50 * 1024 * 1024;
const MD5_BYTE_LEN: usize = 16;
/// Length of an MD5 hex string. Mirrors `FileCache.MD5_HEXSTR_LEN`.
pub const MD5_HEXSTR_LEN: usize = MD5_BYTE_LEN * 2;
const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;
const MAX_FILE_AGE_MS: u64 = MS_PER_DAY;
const MAINT_INTERVAL_MS: u64 = MS_PER_DAY * 2;

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn modified_millis(p: &Path) -> Option<u64> {
    fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

fn set_last_modified_now(p: &Path) {
    if let Ok(f) = File::options().write(true).open(p) {
        let _ = f.set_modified(SystemTime::now());
    }
}

/// `[0-9a-fA-F][0-9a-fA-F]`
fn is_nesting_dir_name(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `[0-9a-fA-F]{32}`
fn is_cache_file_name(s: &str) -> bool {
    s.len() == MD5_HEXSTR_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A cached file: either an on-disk (obfuscated) file or, if small enough, an in-memory byte
/// array.
///
/// Mirrors `FileCache.FileCacheEntry`. Equality and hashing are by MD5, as in Java.
#[derive(Clone, Debug)]
pub struct FileCacheEntry {
    md5: String,
    file: Option<PathBuf>,
    bytes: Option<Arc<[u8]>>,
}

impl PartialEq for FileCacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.md5 == other.md5
    }
}
impl Eq for FileCacheEntry {}
impl std::hash::Hash for FileCacheEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.md5.hash(state);
    }
}

impl FileCacheEntry {
    fn from_file(file: PathBuf, md5: String) -> Self {
        FileCacheEntry { md5, file: Some(file), bytes: None }
    }

    fn from_bytes(bytes: Arc<[u8]>, md5: String) -> Self {
        FileCacheEntry { md5, file: None, bytes: Some(bytes) }
    }

    /// The contents of this entry as a new [`ByteProvider`] identified by `fsrl` (given this
    /// entry's MD5 if it has none). Mirrors `asByteProvider(FSRL)`.
    ///
    /// # Errors
    /// If the cache file cannot be opened.
    pub fn as_byte_provider(&self, fsrl: &Fsrl) -> io::Result<Box<dyn ByteProvider>> {
        let fsrl = if fsrl.md5().is_none() { fsrl.with_md5(Some(&self.md5)) } else { fsrl.clone() };
        if let Some(file) = &self.file {
            set_last_modified_now(file);
        }
        match (&self.bytes, &self.file) {
            (Some(bytes), _) => Ok(Box::new(RefPinningByteArrayProvider(ByteArrayProvider::with_fsrl(
                Arc::clone(bytes),
                Some(fsrl),
            )))),
            (None, Some(file)) => {
                Ok(Box::new(ObfuscatedFileByteProvider::new(file, Some(fsrl), AccessMode::Read)?))
            }
            (None, None) => unreachable!("a FileCacheEntry always has a file or bytes"),
        }
    }

    /// The MD5 of this entry's contents. Mirrors `getMD5()`.
    pub fn get_md5(&self) -> &str {
        &self.md5
    }

    /// The length of this entry's contents. Mirrors `length()`.
    pub fn length(&self) -> u64 {
        match (&self.bytes, &self.file) {
            (Some(b), _) => b.len() as u64,
            (None, Some(f)) => fs::metadata(f).map(|m| m.len()).unwrap_or(0),
            (None, None) => 0,
        }
    }

    /// The on-disk (obfuscated) cache file, if this entry is not held in memory.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }
}

/// A [`ByteArrayProvider`] over an in-memory cache entry that keeps the entry's bytes alive
/// while open and releases them on close. Mirrors `FileCache.RefPinningByteArrayProvider`.
struct RefPinningByteArrayProvider(ByteArrayProvider);

impl ByteProvider for RefPinningByteArrayProvider {
    fn get_file(&self) -> Option<PathBuf> {
        None
    }
    fn get_name(&self) -> Option<String> {
        ByteProvider::get_name(&self.0)
    }
    fn get_absolute_path(&self) -> Option<String> {
        self.0.get_absolute_path()
    }
    fn get_fsrl(&self) -> Option<&Fsrl> {
        ByteProvider::get_fsrl(&self.0)
    }
    fn length(&self) -> u64 {
        ByteProvider::length(&self.0)
    }
    fn is_valid_index(&self, index: u64) -> bool {
        ByteProvider::is_valid_index(&self.0, index)
    }
    fn close(&mut self) -> io::Result<()> {
        self.0.hard_close();
        Ok(())
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        ByteProvider::read_byte(&self.0, index)
    }
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        ByteProvider::read_bytes(&self.0, index, length)
    }
    fn get_input_stream(&self, index: u64) -> io::Result<Box<dyn io::Read>> {
        self.0.get_input_stream(index)
    }
}

/// File caching implementation. See the module docs.
///
/// Mirrors `ghidra.formats.gfilesystem.FileCache`.
pub struct FileCache {
    cache_dir: PathBuf,
    new_dir: PathBuf,
    mem_cache: Mutex<HashMap<String, FileCacheEntry>>,
    clean_daemon: Option<JoinHandle<()>>,
}

impl FileCache {
    /// Creates a cache storing its files under `cache_dir`, creating it (and its `new`
    /// staging subdirectory) if needed, and starting a background maintenance pass if the last
    /// one is older than the maintenance interval. Mirrors `FileCache(File)`.
    ///
    /// # Errors
    /// If the directories cannot be created.
    pub fn new(cache_dir: &Path) -> io::Result<Self> {
        let new_dir = cache_dir.join("new");
        if fs::create_dir_all(cache_dir).is_err() || fs::create_dir_all(&new_dir).is_err() {
            return Err(io::Error::other(format!(
                "Unable to initialize cache dir {}",
                cache_dir.display()
            )));
        }
        let clean_daemon = Self::perform_cache_maint_if_needed(cache_dir, 1);
        Ok(FileCache {
            cache_dir: cache_dir.to_path_buf(),
            new_dir,
            mem_cache: Mutex::new(HashMap::new()),
            clean_daemon,
        })
    }

    /// Ages off files in an old-style (2-level nested) cache directory, if it exists. Mirrors
    /// the deprecated `performCacheMaintOnOldDirIfNeeded(File)`.
    pub fn perform_cache_maint_on_old_dir_if_needed(old_cache_dir: &Path) {
        if old_cache_dir.is_dir() {
            Self::perform_cache_maint_if_needed(old_cache_dir, 2);
        }
    }

    fn mem_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, FileCacheEntry>> {
        self.mem_cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Deletes all stored files that live under a two-hex-digit nesting directory, and clears
    /// the in-memory entries. Mirrors `purge()`.
    pub fn purge(&self) {
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.path().is_dir() && is_nesting_dir_name(&name) {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        self.mem_cache().clear();
    }

    /// Returns `true` if an entry with `md5` exists. Mirrors `hasEntry(String)`.
    pub fn has_entry(&self, md5: &str) -> bool {
        self.mem_cache().contains_key(md5) || self.get_file_by_md5(md5).is_some()
    }

    fn ensure_available_space(&self, size_hint: i64) -> io::Result<()> {
        if size_hint > MAX_INMEM_FILESIZE as i64 {
            if let Some(usable) = usable_space(&self.cache_dir) {
                if usable < size_hint as u64 + FREESPACE_RESERVE_BYTES {
                    return Err(io::Error::other(format!(
                        "Not enough storage available in {} to store file sized: {size_hint}",
                        self.cache_dir.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// The entry for `md5`, or `None` if nothing matches. Touches an on-disk entry's
    /// modification time (the cache ages files off by it). Mirrors `getFileCacheEntry(String)`.
    pub fn get_file_cache_entry(&self, md5: Option<&str>) -> Option<FileCacheEntry> {
        let md5 = md5?;
        if let Some(fce) = self.mem_cache().get(md5) {
            return Some(fce.clone());
        }
        let fce = self.get_file_by_md5(md5)?;
        if let Some(f) = &fce.file {
            set_last_modified_now(f);
        }
        Some(fce)
    }

    /// Drops the in-memory entry for `md5`, if any. Mirrors `releaseFileCacheEntry(String)`.
    pub fn release_file_cache_entry(&self, md5: &str) {
        if let Some(fce) = self.mem_cache().remove(md5) {
            Msg::debug(
                "FileCache",
                &format!("Releasing memCache entry: {}, {}", fce.md5, fce.length()),
            );
        }
    }

    fn get_file_by_md5(&self, md5: &str) -> Option<FileCacheEntry> {
        let f = self.cache_dir.join(Self::get_cache_rel_path(md5));
        f.exists().then(|| FileCacheEntry::from_file(f, md5.to_string()))
    }

    fn create_temp_file(&self) -> PathBuf {
        loop {
            let name = format!("{:032x}", rand::random::<u128>());
            let p = self.new_dir.join(name);
            if !p.exists() {
                return p;
            }
        }
    }

    /// Creates a builder that accepts bytes (it is an [`io::Write`]) and then yields a
    /// [`FileCacheEntry`] from [`finish`](FileCacheEntryBuilder::finish). `size_hint` is the
    /// expected size, or `-1` if unknown. Mirrors `createCacheEntryBuilder(long)`.
    ///
    /// # Errors
    /// If there is not enough free space for a large `size_hint`, or the temp file cannot be
    /// created.
    pub fn create_cache_entry_builder(&self, size_hint: i64) -> io::Result<FileCacheEntryBuilder<'_>> {
        self.ensure_available_space(size_hint)?;
        FileCacheEntryBuilder::new(self, size_hint)
    }

    /// Adds a plaintext file to this cache, consuming (deleting) it. Mirrors
    /// `giveFile(File, TaskMonitor)`.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn give_file(&self, file: &Path, monitor: &dyn TaskMonitor) -> Result<FileCacheEntry, GFileSystemError> {
        let result = (|| {
            let mut fis = File::open(file)?;
            let len = fis.metadata()?.len() as i64;
            let mut builder = self.create_cache_entry_builder(len)?;
            fs_utilities::stream_copy(&mut fis, &mut builder, monitor)?;
            Ok(builder.finish()?)
        })();
        if fs::remove_file(file).is_err() {
            Msg::warn("FileCache", &format!("Failed to delete temporary file: {}", file.display()));
        }
        result
    }

    /// Moves an already-obfuscated temp file (co-located under the cache dir) into place.
    fn add_tmp_file_to_cache(&self, tmp_file: &Path, md5: &str) -> io::Result<FileCacheEntry> {
        let dest = self.cache_dir.join(Self::get_cache_rel_path(md5));
        if let Some(dest_dir) = dest.parent() {
            if !dest_dir.exists() && fs::create_dir_all(dest_dir).is_err() {
                return Err(io::Error::other(format!(
                    "Failed to create cache dir {}",
                    dest_dir.display()
                )));
            }
        }
        let _ = fs::rename(tmp_file, &dest);
        let _ = fs::remove_file(tmp_file);
        if !dest.exists() {
            return Err(io::Error::other(format!(
                "Failed to move {} to {}",
                tmp_file.display(),
                dest.display()
            )));
        }
        set_last_modified_now(&dest);
        Ok(FileCacheEntry::from_file(dest, md5.to_string()))
    }

    fn get_cache_rel_path(md5: &str) -> PathBuf {
        PathBuf::from(&md5[..2.min(md5.len())]).join(md5)
    }

    /// Returns `true` while the background maintenance pass started by the constructor is
    /// still running. Mirrors `isCleaning()`.
    pub fn is_cleaning(&self) -> bool {
        self.clean_daemon.as_ref().is_some_and(|h| !h.is_finished())
    }

    fn perform_cache_maint_if_needed(cache_dir: &Path, nesting_level: u32) -> Option<JoinHandle<()>> {
        let last_maint_file = cache_dir.join(".lastmaint");
        let last_maint_ts =
            if last_maint_file.is_file() { modified_millis(&last_maint_file).unwrap_or(0) } else { 0 };
        if last_maint_ts + MAINT_INTERVAL_MS > now_millis() {
            return None;
        }
        let cache_dir = cache_dir.to_path_buf();
        std::thread::Builder::new()
            .name(format!(
                "FileCacheMaintenanceDaemon for {}",
                cache_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
            ))
            .spawn(move || {
                let mut daemon = FileCacheMaintenanceDaemon { storage_estimate_bytes: 0, nesting_level };
                daemon.run(&cache_dir, &last_maint_file);
            })
            .ok()
    }
}

impl std::fmt::Display for FileCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileCache [cacheDir={}]", self.cache_dir.display())
    }
}

#[cfg(unix)]
fn usable_space(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly sized out-param.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    (rc == 0).then(|| st.f_bavail as u64 * st.f_frsize as u64)
}

#[cfg(not(unix))]
fn usable_space(_dir: &Path) -> Option<u64> {
    None
}

/// Ages off cache files older than a day. Mirrors `FileCache.FileCacheMaintenanceDaemon`.
struct FileCacheMaintenanceDaemon {
    storage_estimate_bytes: u64,
    nesting_level: u32,
}

impl FileCacheMaintenanceDaemon {
    fn run(&mut self, cache_dir: &Path, last_maint_file: &Path) {
        Msg::info("FileCache", &format!("Starting cache cleanup: {}", cache_dir.display()));
        self.cache_maint_for_dir(cache_dir, 0);
        Msg::info(
            "FileCache",
            &format!("Finished cache cleanup, estimated storage used: {}", self.storage_estimate_bytes),
        );
        if let Err(e) = fs::write(last_maint_file, format!("Last maint run at {}", now_millis())) {
            Msg::error(
                "FileCache",
                &format!("Unable to write file cache maintenance file: {}: {e}", last_maint_file.display()),
            );
        }
    }

    fn cache_maint_for_dir(&mut self, dir: &Path, dir_level: u32) {
        if dir_level < self.nesting_level {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if entry.path().is_dir() && is_nesting_dir_name(&name) {
                        self.cache_maint_for_dir(&entry.path(), dir_level + 1);
                    }
                }
            }
        } else if dir_level == self.nesting_level {
            self.cache_maint_for_leaf_dir(dir);
        }
    }

    fn cache_maint_for_leaf_dir(&mut self, dir: &Path) {
        let cutoff = now_millis().saturating_sub(MAX_FILE_AGE_MS);
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let f = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if f.is_file() && is_cache_file_name(&name) {
                if modified_millis(&f).unwrap_or(0) < cutoff {
                    if fs::remove_file(&f).is_ok() {
                        Msg::debug("FileCache", &format!("Expired cache file {}", f.display()));
                        continue;
                    }
                    Msg::error("FileCache", &format!("Failed to delete cache file {}", f.display()));
                }
                self.storage_estimate_bytes += fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
            }
        }
    }
}

enum Delegate {
    Memory(Vec<u8>),
    File(ObfuscatedOutputStream<File>),
}

/// Accepts the bytes of a new cache entry (small ones in memory, switching to an obfuscated
/// temp file once past [`MAX_INMEM_FILESIZE`]) while computing their MD5.
///
/// Mirrors `FileCache.FileCacheEntryBuilder`. Call [`finish`](Self::finish) to obtain the
/// [`FileCacheEntry`]; dropping an unfinished builder deletes its temp file.
pub struct FileCacheEntryBuilder<'a> {
    cache: &'a FileCache,
    delegate: Option<Delegate>,
    hasher: Md5,
    delegate_length: u64,
    tmp_file: Option<PathBuf>,
    fce: Option<FileCacheEntry>,
}

impl<'a> FileCacheEntryBuilder<'a> {
    fn new(cache: &'a FileCache, size_hint: i64) -> io::Result<Self> {
        let size_hint = if size_hint <= 0 { 512 } else { size_hint };
        let mut builder = FileCacheEntryBuilder {
            cache,
            delegate: None,
            hasher: Md5::new(),
            delegate_length: 0,
            tmp_file: None,
            fce: None,
        };
        if (size_hint as u64) < MAX_INMEM_FILESIZE as u64 {
            builder.delegate = Some(Delegate::Memory(Vec::with_capacity(size_hint as usize)));
        } else {
            let tmp = cache.create_temp_file();
            builder.delegate = Some(Delegate::File(ObfuscatedOutputStream::new(File::create(&tmp)?)));
            builder.tmp_file = Some(tmp);
        }
        Ok(builder)
    }

    fn switch_to_temp_file_if_necessary(&mut self, bytes_to_add: usize) -> io::Result<()> {
        self.delegate_length += bytes_to_add as u64;
        if self.tmp_file.is_none() && self.delegate_length > MAX_INMEM_FILESIZE as u64 {
            let tmp = self.cache.create_temp_file();
            let mut os = ObfuscatedOutputStream::new(File::create(&tmp)?);
            if let Some(Delegate::Memory(bytes)) = self.delegate.take() {
                // Java re-hashes the old bytes through a fresh hasher; the running hash over
                // the same bytes is identical.
                os.write_all(&bytes)?;
            }
            self.delegate = Some(Delegate::File(os));
            self.tmp_file = Some(tmp);
        }
        Ok(())
    }

    /// Finalizes this builder, pushing the written bytes into the cache. Calling it again
    /// returns the same entry. Mirrors `finish()`.
    ///
    /// # Errors
    /// If the temp file cannot be flushed or moved into the cache.
    pub fn finish(&mut self) -> io::Result<FileCacheEntry> {
        if let Some(delegate) = self.delegate.take() {
            let md5 = fs_utilities::hex_lower(&std::mem::take(&mut self.hasher).finalize());
            let fce = match delegate {
                Delegate::File(mut os) => {
                    os.flush()?;
                    drop(os);
                    let tmp = self.tmp_file.take().expect("file delegate has a temp file");
                    self.cache.add_tmp_file_to_cache(&tmp, &md5)?
                }
                Delegate::Memory(bytes) => {
                    let fce = FileCacheEntry::from_bytes(Arc::from(bytes), md5.clone());
                    self.cache.mem_cache().insert(md5, fce.clone());
                    fce
                }
            };
            self.fce = Some(fce);
        }
        self.fce.clone().ok_or_else(|| io::Error::other("FileCacheEntryBuilder has no entry"))
    }
}

impl Write for FileCacheEntryBuilder<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.delegate.is_none() {
            return Err(io::Error::other("FileCacheEntryBuilder already finished"));
        }
        self.switch_to_temp_file_if_necessary(buf.len())?;
        self.hasher.update(buf);
        match self.delegate.as_mut().expect("checked above") {
            Delegate::Memory(v) => v.extend_from_slice(buf),
            Delegate::File(os) => os.write_all(buf)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.delegate.as_mut() {
            Some(Delegate::File(os)) => os.flush(),
            _ => Ok(()),
        }
    }
}

impl Drop for FileCacheEntryBuilder<'_> {
    fn drop(&mut self) {
        if self.delegate.is_some() {
            Msg::warn(
                "FileCache",
                &format!(
                    "FAIL TO CLOSE FileCacheEntryBuilder, currentSize={}, file={}",
                    self.delegate_length,
                    self.tmp_file.as_ref().map_or("not set".to_string(), |p| p.display().to_string())
                ),
            );
            self.delegate = None;
            if let Some(tmp) = self.tmp_file.take() {
                let _ = fs::remove_file(tmp);
            }
        }
    }
}

/// Keeps the maintenance thread from being reported as a leak in tests that sleep briefly.
#[allow(dead_code)]
fn wait_for_cleaning(cache: &FileCache, timeout: Duration) {
    let start = std::time::Instant::now();
    while cache.is_cleaning() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    fn md5_hex(data: &[u8]) -> String {
        fs_utilities::hex_lower(&Md5::digest(data))
    }

    #[test]
    fn small_entry_is_held_in_memory_and_found_by_md5() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FileCache::new(dir.path()).unwrap();
        let mut b = cache.create_cache_entry_builder(-1).unwrap();
        b.write_all(b"hello").unwrap();
        let fce = b.finish().unwrap();
        assert_eq!(fce.get_md5(), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(fce.length(), 5);
        assert!(fce.file().is_none());
        assert!(cache.has_entry(fce.get_md5()));
        let again = cache.get_file_cache_entry(Some(fce.get_md5())).unwrap();
        assert_eq!(again, fce);
        let bp = again.as_byte_provider(&Fsrl::from_string("tmp:///x").unwrap()).unwrap();
        assert_eq!(bp.read_bytes(0, 5).unwrap(), b"hello");
        assert_eq!(bp.get_fsrl().unwrap().md5(), Some(fce.get_md5()));
        cache.release_file_cache_entry(fce.get_md5());
        assert!(!cache.has_entry(fce.get_md5()));
        assert!(cache.get_file_cache_entry(None).is_none());
    }

    #[test]
    fn large_entry_switches_to_obfuscated_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FileCache::new(dir.path()).unwrap();
        let data: Vec<u8> = (0..MAX_INMEM_FILESIZE + 1000).map(|i| (i % 253) as u8).collect();
        let mut b = cache.create_cache_entry_builder(-1).unwrap();
        for chunk in data.chunks(100_000) {
            b.write_all(chunk).unwrap();
        }
        let fce = b.finish().unwrap();
        assert_eq!(fce.get_md5(), md5_hex(&data));
        let f = fce.file().unwrap();
        assert_eq!(f, dir.path().join(&fce.get_md5()[..2]).join(fce.get_md5()));
        assert_ne!(std::fs::read(f).unwrap()[..16], data[..16], "stored obfuscated");
        let bp = fce.as_byte_provider(&Fsrl::from_string("tmp:///big").unwrap()).unwrap();
        assert_eq!(bp.length(), data.len() as u64);
        assert_eq!(bp.read_bytes(MAX_INMEM_FILESIZE as u64 - 5, 10).unwrap(), data[MAX_INMEM_FILESIZE - 5..MAX_INMEM_FILESIZE + 5]);
        assert!(cache.has_entry(fce.get_md5()));
        // The staging dir is left empty.
        assert_eq!(std::fs::read_dir(dir.path().join("new")).unwrap().count(), 0);
        cache.purge();
        assert!(!cache.has_entry(fce.get_md5()));
    }

    #[test]
    fn give_file_consumes_plaintext_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FileCache::new(&dir.path().join("cache")).unwrap();
        let f = dir.path().join("plain.txt");
        std::fs::write(&f, b"hello").unwrap();
        let fce = cache.give_file(&f, &DummyMonitor).unwrap();
        assert!(!f.exists());
        assert_eq!(fce.get_md5(), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn maintenance_ages_off_old_files_and_stamps_lastmaint() {
        let dir = tempfile::tempdir().unwrap();
        let md5 = "0123456789abcdef0123456789abcdef";
        let nested = dir.path().join("01");
        std::fs::create_dir_all(&nested).unwrap();
        let old = nested.join(md5);
        std::fs::write(&old, b"x").unwrap();
        let f = File::options().write(true).open(&old).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(3 * 24 * 3600)).unwrap();
        drop(f);
        let cache = FileCache::new(dir.path()).unwrap();
        wait_for_cleaning(&cache, Duration::from_secs(10));
        assert!(!old.exists());
        assert!(dir.path().join(".lastmaint").is_file());
        // A fresh stamp means the next construction does not start another pass.
        let cache2 = FileCache::new(dir.path()).unwrap();
        assert!(cache2.clean_daemon.is_none());
    }
}
