//! Port of `ghidra.formats.gfilesystem.FileSystemService`.
//!
//! Provides methods for dealing with GFilesystem files and filesystems. Most methods take
//! [`Fsrl`] references to files, which are always valid, rather than [`GFile`](super::g_file::GFile)s,
//! which are only valid while their (possibly nested) filesystem is open. Filesystems are used
//! through [`FileSystemRef`] handles that pin them in the service's instance cache.
//!
//! Files written to the cache directory are obfuscated to prevent interference from virus
//! scanners (see [`FileCache`]).
//!
//! # Differences from Java
//!
//! * Java's service is a process-wide singleton (`getInstance()`); here it is a value the
//!   caller constructs with a cache directory and a [`FileSystemFactoryMgr`] of registered
//!   filesystems (Java's registry is itself a classpath-scanning singleton). Filesystems share
//!   byte providers through `Rc`, so the service is single-threaded and is not offered as a
//!   process-global.
//! * Java schedules [`FileSystemInstanceManager::cache_maint`] every ten seconds on a timer
//!   thread. The instance cache is `Rc`-based, so there is no timer here; callers run
//!   [`perform_cache_maint`](FileSystemService::perform_cache_maint) periodically instead.
//! * `newCryptoSession()` is not ported yet: it needs `CryptoProviders` (see
//!   `PORT_MANIFEST.tsv`).

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use super::annotations::file_system_info::PRIORITY_LOWEST;
use super::factory::file_system_factory_mgr::FileSystemFactoryMgr;
use super::file_cache::{FileCache, FileCacheEntry, FileCacheEntryBuilder};
use super::file_cache_name_index::FileCacheNameIndex;
use super::file_system_instance_manager::FileSystemInstanceManager;
use super::file_system_probe_conflict_resolver::FileSystemProbeConflictResolver;
use super::file_system_ref::FileSystemRef;
use super::fs_utilities;
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file_system::{AnyGFileSystem, FsHandle, GFileSystem, GFileSystemError};
use super::local_file_system::LocalFileSystem;
use super::refd_byte_provider::RefdByteProvider;
use super::refd_file::RefdFile;

/// Produces the contents of a derived (decompressed, decrypted, ...) file as a stream, for
/// [`FileSystemService::get_derived_byte_provider`]. Mirrors
/// `FileSystemService.DerivedStreamProducer`; any matching closure is one.
pub trait DerivedStreamProducer {
    /// A new stream supplying all the bytes of the derived file.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    fn produce_derived_stream(&mut self) -> Result<Box<dyn Read + '_>, GFileSystemError>;
}

impl<F> DerivedStreamProducer for F
where
    F: FnMut() -> Result<Box<dyn Read>, GFileSystemError>,
{
    fn produce_derived_stream(&mut self) -> Result<Box<dyn Read + '_>, GFileSystemError> {
        self()
    }
}

/// Writes the contents of a derived file to a stream, for
/// [`FileSystemService::get_derived_byte_provider_push`]. Mirrors
/// `FileSystemService.DerivedStreamPushProducer`; any matching closure is one.
pub trait DerivedStreamPushProducer {
    /// Writes the derived file's bytes to `os` (without closing it).
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    fn push(&mut self, os: &mut dyn Write) -> Result<(), GFileSystemError>;
}

impl<F> DerivedStreamPushProducer for F
where
    F: FnMut(&mut dyn Write) -> Result<(), GFileSystemError>,
{
    fn push(&mut self, os: &mut dyn Write) -> Result<(), GFileSystemError> {
        self(os)
    }
}

fn io_err(msg: String) -> GFileSystemError {
    GFileSystemError::Io(io::Error::other(msg))
}

/// Provides methods for dealing with GFilesystem files and filesystems. See the module docs.
///
/// Mirrors `ghidra.formats.gfilesystem.FileSystemService`.
///
/// The service's state is shared (`Rc`) so that filesystems it mounts can keep a
/// [`WeakFileSystemService`] handle to it, standing in for the `fsService` field Java
/// filesystems hold (e.g. `AbstractFileSystem.fsService`). The handle is weak because the
/// service's instance cache owns those filesystems.
pub struct FileSystemService {
    inner: Rc<ServiceState>,
}

/// The shared state behind a [`FileSystemService`] and its [`WeakFileSystemService`] handles.
struct ServiceState {
    local_fs: Rc<LocalFileSystem>,
    fs_factory_mgr: FileSystemFactoryMgr,
    cache_fsrl: FsrlRoot,
    file_cache: FileCache,
    fs_instance_manager: Rc<FileSystemInstanceManager>,
    file_cache_name_index: FileCacheNameIndex,
}

/// A non-owning handle to a [`FileSystemService`], held by filesystems that need the service
/// after they are created (Java's `fsService` field).
#[derive(Clone)]
pub struct WeakFileSystemService(std::rc::Weak<ServiceState>);

impl WeakFileSystemService {
    /// The service, if it is still alive.
    pub fn upgrade(&self) -> Option<FileSystemService> {
        self.0.upgrade().map(|inner| FileSystemService { inner })
    }

    /// The service, or an [`io::Error`] if it has been dropped.
    ///
    /// # Errors
    /// If the service no longer exists.
    pub fn get(&self) -> io::Result<FileSystemService> {
        self.upgrade().ok_or_else(|| io::Error::other("FileSystemService has been disposed"))
    }
}

impl std::fmt::Debug for WeakFileSystemService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WeakFileSystemService")
    }
}

impl FileSystemService {
    /// A weak handle to this service, for filesystems that need it after creation.
    pub fn downgrade(&self) -> WeakFileSystemService {
        WeakFileSystemService(Rc::downgrade(&self.inner))
    }

    /// Creates a service that caches files under `fscache_dir` and mounts the filesystems
    /// registered in `fs_factory_mgr`. Mirrors `FileSystemService(File)`.
    ///
    /// # Errors
    /// If the cache directory cannot be initialized (Java throws a `RuntimeException`).
    pub fn new(fscache_dir: &Path, fs_factory_mgr: FileSystemFactoryMgr) -> io::Result<Self> {
        let file_cache = FileCache::new(fscache_dir).map_err(|e| {
            io::Error::new(e.kind(), format!("Failed to init global cache {}: {e}", fscache_dir.display()))
        })?;
        let local_fs = Rc::new(LocalFileSystem::make_global_root_fs());
        let local_handle: FsHandle = local_fs.clone();
        Ok(FileSystemService {
            inner: Rc::new(ServiceState {
                fs_instance_manager: FileSystemInstanceManager::new(local_handle),
                local_fs,
                fs_factory_mgr,
                cache_fsrl: FsrlRoot::make_root("cache"),
                file_cache,
                file_cache_name_index: FileCacheNameIndex::new(),
            }),
        })
    }

    /// The registry of filesystem factories this service mounts with.
    pub fn get_factory_mgr(&self) -> &FileSystemFactoryMgr {
        &self.inner.fs_factory_mgr
    }

    /// Forcefully closes all open filesystems and clears caches. Mirrors `clear()`.
    pub fn clear(&self) {
        self.inner.fs_instance_manager.clear();
        self.inner.file_cache_name_index.clear();
    }

    /// Closes unused filesystems. Mirrors `closeUnusedFileSystems()`.
    pub fn close_unused_file_systems(&self) {
        self.inner.fs_instance_manager.close_all_unused();
    }

    /// Evicts filesystems that have been unused for a while. This is the work Java's service
    /// schedules on a ten-second timer (see the module docs).
    pub fn perform_cache_maint(&self) {
        self.inner.fs_instance_manager.cache_maint();
    }

    /// Releases `fs_ref`, and if no other references remain, removes its filesystem from the
    /// shared cache (closing it). Mirrors `releaseFileSystemImmediate(FileSystemRef)`.
    pub fn release_file_system_immediate(&self, fs_ref: Option<FileSystemRef>) {
        if let Some(fs_ref) = fs_ref {
            if !fs_ref.is_closed() {
                self.inner.fs_instance_manager.release_immediate(fs_ref);
            }
        }
    }

    /// The local filesystem. Mirrors `getLocalFS()`.
    pub fn get_local_fs(&self) -> &LocalFileSystem {
        &self.inner.local_fs
    }

    /// Returns `true` if `fsrl` is a path on the local computer's filesystem (not a file
    /// embedded in a container). Mirrors `isLocal(FSRL)`.
    pub fn is_local(&self, fsrl: &Fsrl) -> bool {
        self.inner.local_fs.is_same_fs(fsrl)
    }

    /// The FSRL of a file on the local filesystem. Mirrors `getLocalFSRL(File)`.
    pub fn get_local_fsrl(&self, f: &Path) -> Fsrl {
        self.inner.local_fs.get_local_fsrl(f)
    }

    /// Returns `true` if a filesystem is mounted at the container `fsrl`. Mirrors
    /// `isFilesystemMountedAt(FSRL)`.
    pub fn is_filesystem_mounted_at(&self, fsrl: &Fsrl) -> bool {
        self.inner.fs_instance_manager.is_filesystem_mounted_at(fsrl)
    }

    /// The file `fsrl` points to, with a ref pinning its filesystem that the caller must
    /// release. Mirrors `getRefdFile(FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// If the file is not found, on I/O errors, or on cancellation.
    pub fn get_refd_file(&self, fsrl: &Fsrl, monitor: &dyn TaskMonitor) -> Result<RefdFile, GFileSystemError> {
        let fs_ref = self.get_filesystem(&fsrl.fs(), monitor)?;
        let gfile = fs_ref.get_filesystem().lookup(fsrl.path())?.ok_or_else(|| {
            io_err(format!(
                "File [{}] not found in filesystem [{}]",
                fsrl.path().unwrap_or(""),
                fs_ref.get_filesystem().get_fsrl()
            ))
        })?;
        Ok(RefdFile::new(fs_ref, gfile))
    }

    /// A ref to the filesystem `fs_fsrl`, either already mounted or mounted now from its
    /// container file (recursively opening parent filesystems as needed). The caller must
    /// release the ref. Mirrors `getFilesystem(FSRLRoot, TaskMonitor)`.
    ///
    /// # Errors
    /// If `fs_fsrl` has no container, the container cannot be read, or mounting fails.
    pub fn get_filesystem(
        &self,
        fs_fsrl: &FsrlRoot,
        monitor: &dyn TaskMonitor,
    ) -> Result<FileSystemRef, GFileSystemError> {
        if let Some(r) = self.inner.fs_instance_manager.get_ref(fs_fsrl) {
            return Ok(r);
        }
        let Some(container) = fs_fsrl.container() else {
            return Err(io_err(format!("Bad FSRL {fs_fsrl}")));
        };
        let container_byte_provider = self.get_byte_provider(container, true, monitor)?;
        let fs = self.inner.fs_factory_mgr.mount_file_system(
            fs_fsrl.protocol(),
            container_byte_provider,
            self,
            monitor,
        )?;
        let r = fs.get_ref_manager().create(&fs).map_err(io::Error::other)?;
        self.inner.fs_instance_manager.add(&fs).map_err(io::Error::other)?;
        Ok(r)
    }

    /// A [`ByteProvider`] with the contents of the file `fsrl`, which the caller must close.
    /// If `fully_qualified_fsrl`, the provider's FSRL always carries an MD5. Mirrors
    /// `getByteProvider(FSRL, boolean, TaskMonitor)`.
    ///
    /// # Errors
    /// If the file is not found, its hash no longer matches `fsrl`'s, on I/O errors, or on
    /// cancellation.
    pub fn get_byte_provider(
        &self,
        fsrl: &Fsrl,
        fully_qualified_fsrl: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
        if let Some(fce) = self.inner.file_cache.get_file_cache_entry(fsrl.md5()) {
            return Ok(fce.as_byte_provider(fsrl)?);
        }

        let fs_ref = self.get_filesystem(&fsrl.fs(), monitor)?;
        let fs = Rc::clone(fs_ref.get_filesystem());
        let file = fs.lookup(fsrl.path())?.ok_or_else(|| io_err(format!("File not found: {fsrl}")))?;
        let mut fsrl = fsrl.clone();
        if file.get_fsrl().md5().is_some() {
            fsrl = file.get_fsrl().clone();
            // try again to fetch cached file now that we have an md5
            if let Some(fce) = self.inner.file_cache.get_file_cache_entry(fsrl.md5()) {
                return Ok(fce.as_byte_provider(&fsrl)?);
            }
        }
        let provider = fs
            .get_byte_provider(&*file, monitor)?
            .ok_or_else(|| io_err(format!("Unable to get ByteProvider for {fsrl}")))?;

        // use the returned provider's FSRL as it may have more info
        let mut result_fsrl = provider.get_fsrl().cloned().unwrap_or_else(|| file.get_fsrl().clone());
        if result_fsrl.md5().is_none() && (fsrl.md5().is_some() || fully_qualified_fsrl) {
            let md5 = match fs.get_md5_hash(&*file, true, monitor) {
                Some(hash) => hash?,
                None => Some(fs_utilities::get_md5(&*provider, monitor)?),
            };
            result_fsrl = result_fsrl.with_md5(md5.as_deref());
        }
        if fsrl.md5().is_some() && !fsrl.is_md5_equal(result_fsrl.md5()) {
            return Err(io_err(format!(
                "Unable to retrieve requested file, hash has changed: {fsrl}, new hash: {}",
                result_fsrl.md5().unwrap_or("null")
            )));
        }
        let dup = fs_ref.dup().map_err(io::Error::other)?;
        Ok(Box::new(RefdByteProvider::new(dup, provider, Some(result_fsrl))))
    }

    fn cache_derived<'s>(
        &'s self,
        container_fsrl: &Fsrl,
        derived_name: &str,
        size_hint: i64,
        monitor: &dyn TaskMonitor,
        fill: &mut dyn FnMut(&mut FileCacheEntryBuilder<'s>) -> Result<(), GFileSystemError>,
    ) -> Result<FileCacheEntry, GFileSystemError> {
        // The name index is queried and updated in separate steps; a race only means the
        // derived file may be produced twice (same as Java).
        let container_md5 = Self::assert_fully_qualified_fsrl(container_fsrl)?;
        let derived_md5 = self.inner.file_cache_name_index.get(container_md5, derived_name)?;
        if let Some(fce) = self.inner.file_cache.get_file_cache_entry(derived_md5.as_deref()) {
            return Ok(fce);
        }
        monitor.set_message(&format!(
            "Caching {} {derived_name}",
            container_fsrl.name().unwrap_or_default()
        ));
        if size_hint > 0 {
            monitor.initialize(size_hint);
        }
        let mut builder = self.inner.file_cache.create_cache_entry_builder(size_hint)?;
        let filled = fill(&mut builder);
        // Java's try-with-resources closes (== finishes) the builder even on error.
        let fce = builder.finish()?;
        filled?;
        self.inner.file_cache_name_index.add(container_md5, derived_name, fce.get_md5())?;
        Ok(fce)
    }

    fn derived_result(&self, fce: &FileCacheEntry, derived_fsrl: Option<&Fsrl>) -> io::Result<Box<dyn ByteProvider>> {
        let fsrl = match derived_fsrl {
            Some(f) => f.with_md5(Some(fce.get_md5())),
            None => self.create_cached_file_fsrl(fce.get_md5()),
        };
        fce.as_byte_provider(&fsrl)
    }

    /// A [`ByteProvider`] with the derived (decompressed, decrypted, ...) contents of a file,
    /// served from the file cache, or produced by `producer` and cached for next time.
    ///
    /// `container_fsrl` must carry an MD5; `derived_name` identifies the derived file within
    /// it; the result has `derived_fsrl` (given the derived MD5) or a pseudo `cache://` FSRL.
    /// Mirrors `getDerivedByteProvider(FSRL, FSRL, String, long, DerivedStreamProducer,
    /// TaskMonitor)`.
    ///
    /// # Errors
    /// If `container_fsrl` has no MD5, the producer fails, on I/O errors, or on cancellation.
    pub fn get_derived_byte_provider(
        &self,
        container_fsrl: &Fsrl,
        derived_fsrl: Option<&Fsrl>,
        derived_name: &str,
        size_hint: i64,
        producer: &mut dyn DerivedStreamProducer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
        let fce = self.cache_derived(container_fsrl, derived_name, size_hint, monitor, &mut |b| {
            let mut is = producer.produce_derived_stream()?;
            fs_utilities::stream_copy(&mut is, b, monitor)?;
            Ok(())
        })?;
        Ok(self.derived_result(&fce, derived_fsrl)?)
    }

    /// Like [`get_derived_byte_provider`](Self::get_derived_byte_provider), but `pusher`
    /// writes the derived bytes to a stream. Mirrors `getDerivedByteProviderPush(FSRL, FSRL,
    /// String, long, DerivedStreamPushProducer, TaskMonitor)`.
    ///
    /// # Errors
    /// See [`get_derived_byte_provider`](Self::get_derived_byte_provider).
    pub fn get_derived_byte_provider_push(
        &self,
        container_fsrl: &Fsrl,
        derived_fsrl: Option<&Fsrl>,
        derived_name: &str,
        size_hint: i64,
        pusher: &mut dyn DerivedStreamPushProducer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
        let fce = self.cache_derived(container_fsrl, derived_name, size_hint, monitor, &mut |b| {
            pusher.push(b)
        })?;
        Ok(self.derived_result(&fce, derived_fsrl)?)
    }

    fn create_cached_file_fsrl(&self, md5: &str) -> Fsrl {
        self.inner.cache_fsrl.with_path_md5(Some(&format!("/{md5}")), Some(md5))
    }

    /// A builder the caller writes bytes to; [`finish`](FileCacheEntryBuilder::finish) yields
    /// a cache entry. Mirrors `createTempFile(long)`.
    ///
    /// # Errors
    /// If there is not enough free space, or the temp file cannot be created.
    pub fn create_temp_file(&self, size_hint: i64) -> io::Result<FileCacheEntryBuilder<'_>> {
        self.inner.file_cache.create_cache_entry_builder(size_hint)
    }

    /// A [`ByteProvider`] over `temp_file_cache_entry` with a decorative `tmp://` FSRL named
    /// `name`. Mirrors `getNamedTempFile(FileCacheEntry, String)`.
    ///
    /// # Errors
    /// If the cache file cannot be opened.
    pub fn get_named_temp_file(
        &self,
        temp_file_cache_entry: &FileCacheEntry,
        name: &str,
    ) -> io::Result<Box<dyn ByteProvider>> {
        let path = fs_utilities::append_path(&[Some("/"), Some(name)]).unwrap_or_else(|| "/".into());
        let result_fsrl =
            FsrlRoot::make_root("tmp").with_path_md5(Some(&path), Some(temp_file_cache_entry.get_md5()));
        temp_file_cache_entry.as_byte_provider(&result_fsrl)
    }

    /// The plain local file holding `provider`'s bytes, if there is one. Mirrors
    /// `getFileIfAvailable(ByteProvider)`.
    ///
    /// Java unwraps a `RefdByteProvider` and then accepts only file-backed providers; here
    /// every provider reports its own backing file through [`ByteProvider::get_file`]
    /// ([`RefdByteProvider`] delegates, and the obfuscated cache providers report none), so
    /// that answer is used directly.
    pub fn get_file_if_available(&self, provider: &dyn ByteProvider) -> Option<PathBuf> {
        provider.get_file()
    }

    /// Exports `provider`'s bytes to a new plaintext temp file named with `filename_prefix`.
    /// Mirrors `createPlaintextTempFile(ByteProvider, String, TaskMonitor)`.
    ///
    /// # Errors
    /// If the copy fails or is cancelled.
    pub fn create_plaintext_temp_file(
        &self,
        provider: &dyn ByteProvider,
        filename_prefix: &str,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<PathBuf> {
        let tmp_file = create_temp_file(filename_prefix)?;
        let name = provider.get_name().unwrap_or_default();
        monitor.set_message(&format!("Copying {name} to temp file"));
        monitor.initialize(provider.length() as i64);
        match fs_utilities::copy_byte_provider_to_file(provider, &tmp_file, monitor) {
            Ok(_) => Ok(tmp_file),
            Err(GFileSystemError::Cancelled(_)) => {
                Err(io::Error::other(format!("Copy was cancelled: {name}")))
            }
            Err(GFileSystemError::Io(e)) => Err(e),
        }
    }

    /// Allows the resources used to cache `fsrl` to be released. Mirrors
    /// `releaseFileCache(FSRL)`.
    pub fn release_file_cache(&self, fsrl: &Fsrl) {
        if let Some(md5) = fsrl.md5() {
            self.inner.file_cache.release_file_cache_entry(md5);
        }
    }

    /// Adds a plaintext local file to the cache, consuming it, and returns a provider over the
    /// cached copy identified by `fsrl`. Mirrors `pushFileToCache(File, FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn push_file_to_cache(
        &self,
        file: &Path,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
        let fce = self.inner.file_cache.give_file(file, monitor)?;
        Ok(fce.as_byte_provider(fsrl)?)
    }

    /// Returns `true` if the derived file `derived_name` of `container_fsrl` is in the cache.
    /// Mirrors `hasDerivedFile(FSRL, String, TaskMonitor)`.
    ///
    /// # Errors
    /// If `container_fsrl` has no MD5.
    pub fn has_derived_file(
        &self,
        container_fsrl: &Fsrl,
        derived_name: &str,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        let container_md5 = Self::assert_fully_qualified_fsrl(container_fsrl)?;
        let derived_md5 = self.inner.file_cache_name_index.get(container_md5, derived_name)?;
        Ok(derived_md5.is_some_and(|md5| self.inner.file_cache.has_entry(&md5)))
    }

    /// Returns `true` if the container file probably holds a supported filesystem. Mirrors
    /// `isFileFilesystemContainer(FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn is_file_filesystem_container(
        &self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        let mut byte_provider = self.get_byte_provider(container_fsrl, false, monitor)?;
        let result = self.inner.fs_factory_mgr.test(&*byte_provider, self, monitor);
        let _ = byte_provider.close();
        result
    }

    /// Auto-detects a filesystem in the container file `container_fsrl`: an already-mounted
    /// one, or a new one found by probing with the registered factories whose priority is at
    /// least `priority_filter`. Returns `Ok(None)` if nothing can handle the file. Mirrors
    /// `probeFileForFilesystem(FSRL, TaskMonitor, FileSystemProbeConflictResolver, int)`.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn probe_file_for_filesystem(
        &self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver>,
        priority_filter: i32,
    ) -> Result<Option<FileSystemRef>, GFileSystemError> {
        if let Some(r) = self.inner.fs_instance_manager.get_filesystem_ref_mounted_at(container_fsrl) {
            return Ok(Some(r));
        }
        let result = (|| {
            let byte_provider = self.get_byte_provider(container_fsrl, true, monitor)?;
            let Some(fs) = self.inner.fs_factory_mgr.probe(
                byte_provider,
                self,
                conflict_resolver,
                priority_filter,
                monitor,
            )?
            else {
                return Ok(None);
            };
            if let Some(container) = fs.get_fsrl().container() {
                if let Some(existing) = self.inner.fs_instance_manager.get_filesystem_ref_mounted_at(container) {
                    // Someone mounted the same container meanwhile: use theirs.
                    fs.close()?;
                    return Ok(Some(existing));
                }
            }
            self.inner.fs_instance_manager.add(&fs).map_err(io::Error::other)?;
            Ok(Some(fs.get_ref_manager().create(&fs).map_err(io::Error::other)?))
        })();
        if let Err(GFileSystemError::Io(e)) = &result {
            Msg::trace("FileSystemService", &format!("Probe exception: {e}"));
        }
        result
    }

    /// [`probe_file_for_filesystem`](Self::probe_file_for_filesystem) with no priority
    /// filter. Mirrors the three-argument overload.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn probe_file_for_filesystem_default(
        &self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver>,
    ) -> Result<Option<FileSystemRef>, GFileSystemError> {
        self.probe_file_for_filesystem(container_fsrl, monitor, conflict_resolver, PRIORITY_LOWEST)
    }

    /// Mounts a filesystem of the specific type `FS` from `container_fsrl`, outside the
    /// service's cache and ref tracking; the caller must close it. Returns `Ok(None)` (after
    /// logging an error) if `FS` is not registered. Mirrors
    /// `mountSpecificFileSystem(FSRL, Class, TaskMonitor)`.
    ///
    /// # Errors
    /// On I/O errors, cancellation, or if the factory produced a different type.
    pub fn mount_specific_file_system<FS: GFileSystem>(
        &self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Rc<FS>>, GFileSystemError> {
        let Some(fs_type) = self.inner.fs_factory_mgr.get_file_system_type::<FS>() else {
            Msg::error(
                "FileSystemService",
                &format!(
                    "Specific file system implemention {} not registered correctly in file system factory.",
                    std::any::type_name::<FS>()
                ),
            );
            return Ok(None);
        };
        let byte_provider = self.get_byte_provider(container_fsrl, true, monitor)?;
        let fs = self.inner.fs_factory_mgr.mount_file_system(&fs_type, byte_provider, self, monitor)?;
        let fs_for_close = Rc::clone(&fs);
        match fs.into_any_rc().downcast::<FS>() {
            Ok(typed) => Ok(Some(typed)),
            Err(_) => {
                fs_for_close.close()?;
                Err(io_err(format!(
                    "Bad file system type returned by factory. Expecting {} but factory produced {}",
                    std::any::type_name::<FS>(),
                    fs_for_close.get_type()
                )))
            }
        }
    }

    /// Opens (probes and mounts) the filesystem in `container_fsrl`, outside the service's
    /// cache and ref tracking; the caller must close it. Mirrors
    /// `openFileSystemContainer(FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    pub fn open_file_system_container(
        &self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<FsHandle>, GFileSystemError> {
        let byte_provider = self.get_byte_provider(container_fsrl, true, monitor)?;
        self.inner.fs_factory_mgr.probe(byte_provider, self, None, PRIORITY_LOWEST, monitor)
    }

    /// A copy of `fsrl` that carries an MD5 (except for files without data streams, e.g.
    /// directories). Mirrors `getFullyQualifiedFSRL(FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// If the file is not found, on I/O errors, or on cancellation.
    pub fn get_fully_qualified_fsrl(
        &self,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Fsrl, GFileSystemError> {
        if fsrl.md5().is_some() {
            return Ok(fsrl.clone());
        }
        let fs_ref = self.get_filesystem(&fsrl.fs(), monitor)?;
        let fs = Rc::clone(fs_ref.get_filesystem());
        self.get_fully_qualified_fsrl_in(&*fs, fsrl, monitor)
    }

    fn assert_fully_qualified_fsrl(fsrl: &Fsrl) -> Result<&str, GFileSystemError> {
        fsrl.md5().ok_or_else(|| io_err(format!("Bad FSRL, expected fully qualified: {fsrl}")))
    }

    fn get_fully_qualified_fsrl_in(
        &self,
        fs: &dyn AnyGFileSystem,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Fsrl, GFileSystemError> {
        if fsrl.md5().is_some() {
            return Ok(fsrl.clone());
        }
        let file = fs.lookup(fsrl.path())?.ok_or_else(|| io_err(format!("File not found: {fsrl}")))?;
        if file.get_fsrl().md5().is_some() || file.is_directory() {
            return Ok(file.get_fsrl().clone());
        }

        let mut fsrl = fsrl.clone();
        let mut container_fsrl = fsrl.fs().container().cloned();
        if container_fsrl.as_ref().is_some_and(|c| c.md5().is_none()) {
            // re-home the fsrl to the parent container's fsrl since filesystems always have
            // fully qualified fsrls
            container_fsrl = fs.get_fsrl().container().cloned();
            let nested = FsrlRoot::nested_fs_copy(container_fsrl.as_ref(), &fsrl.fs());
            fsrl = nested.with_path_from(&fsrl);
        }

        if let Some(hash) = fs.get_md5_hash(&*file, true, monitor) {
            return Ok(fsrl.with_md5(hash?.as_deref()));
        }

        let path = fsrl.path().unwrap_or("").to_string();
        let mut md5 = match container_fsrl.as_ref().and_then(Fsrl::md5) {
            Some(cmd5) => self.inner.file_cache_name_index.get(cmd5, &path)?,
            None => None,
        };
        if md5.is_none() {
            let mut bp = fs
                .get_byte_provider(&*file, monitor)?
                .ok_or_else(|| io_err(format!("Unable to get bytes for {fsrl}")))?;
            let computed = match bp.get_fsrl().and_then(Fsrl::md5) {
                Some(m) => Ok(m.to_string()),
                None => fs_utilities::get_md5(&*bp, monitor),
            };
            let _ = bp.close();
            md5 = Some(computed?);
        }
        if let (Some(cmd5), true) = (container_fsrl.as_ref().and_then(Fsrl::md5), fs.is_static()) {
            self.inner.file_cache_name_index.add(cmd5, &path, md5.as_deref().unwrap_or(""))?;
        }
        Ok(fsrl.with_md5(md5.as_deref()))
    }

    /// The descriptions of all registered filesystems. Mirrors `getAllFilesystemNames()`.
    pub fn get_all_filesystem_names(&self) -> Vec<String> {
        self.inner.fs_factory_mgr.get_all_filesystem_names()
    }

    /// The FSRL roots of all currently mounted filesystems. Mirrors
    /// `getMountedFilesystems()`.
    pub fn get_mounted_filesystems(&self) -> Vec<FsrlRoot> {
        self.inner.fs_instance_manager.get_mounted_filesystems()
    }

    /// A new ref to the already-mounted filesystem `fs_fsrl`, or `None`. Mirrors
    /// `getMountedFilesystem(FSRLRoot)`.
    pub fn get_mounted_filesystem(&self, fs_fsrl: &FsrlRoot) -> Option<FileSystemRef> {
        self.inner.fs_instance_manager.get_ref(fs_fsrl)
    }
}

/// Atomically creates a uniquely named file in the system temp directory, like Java's
/// `Application.createTempFile(prefix, Long.toString(System.currentTimeMillis()))`.
fn create_temp_file(filename_prefix: &str) -> io::Result<PathBuf> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let dir = std::env::temp_dir();
    loop {
        let random: u64 = rand::random();
        let path = dir.join(format!("{filename_prefix}{random}{millis}"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}
