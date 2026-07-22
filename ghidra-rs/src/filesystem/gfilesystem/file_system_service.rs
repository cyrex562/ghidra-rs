use std::io;
use std::path::{Path, PathBuf};

use crate::filesystem::gfilesystem::annotations::file_system_info::PRIORITY_LOWEST;
use crate::filesystem::gfilesystem::crypto::crypto_session::CryptoSession;
use crate::filesystem::gfilesystem::file_system_probe_conflict_resolver::FileSystemProbeConflictResolver;
use crate::filesystem::gfilesystem::file_system_ref::FileSystemRef;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::filesystem::gfilesystem::refd_file::RefdFile;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::seam_stubs::{
    FileCacheEntryBuilderLike, FileCacheEntryLike, FsrlLike, FsrlRootLike, GFileSystemLike,
    LocalFileSystemLike,
};
use crate::util::task::TaskMonitor;

/// Callback used by
/// [`FileSystemService::get_derived_byte_provider`] to produce a derivative stream
/// from a source file.
///
/// This is the Rust equivalent of `FileSystemService.DerivedStreamProducer`. The Java
/// version returns a lazy `InputStream`; this port produces the bytes eagerly, matching the
/// same simplification already used by
/// [`GFileSystem::get_input_stream`](crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_input_stream).
pub trait DerivedStreamProducer {
    /// Produces all the bytes of the derived file.
    fn produce_derived_stream(&mut self) -> Result<Vec<u8>, GFileSystemError>;
}

/// Callback used by
/// [`FileSystemService::get_derived_byte_provider_push`] to produce a derivative stream
/// from a source file by writing to a supplied sink.
///
/// This is the Rust equivalent of `FileSystemService.DerivedStreamPushProducer`.
pub trait DerivedStreamPushProducer {
    /// Writes the bytes of the derived file to `out`. Implementations should not close `out`.
    fn push(&mut self, out: &mut dyn io::Write) -> Result<(), GFileSystemError>;
}

/// Provides methods for dealing with GFilesystem files and filesystems, mirroring
/// `ghidra.formats.gfilesystem.FileSystemService`.
///
/// This is a cycle cut-point: the Java class sits at the center of the `gfilesystem` package,
/// referenced by `GFileSystemFactoryByteProvider::create` and `GFileSystemProbeByteProvider`
/// (both already ported against the [`FileSystemServiceLike`](crate::filesystem::seam_stubs::FileSystemServiceLike)
/// marker seam) while itself depending on `GFileSystem`, `FileSystemRef`, `FSRL`, `FSRLRoot`,
/// `CryptoSession`, `LocalFileSystem` and the `FileCache` family -- a dependency cycle no
/// concrete struct could resolve. As a trait, `FileSystemService` never calls a method on any
/// of its own type parameters (each is either forwarded to the caller or used only as an
/// opaque lookup key, exactly as the Java implementation's callers experience it through this
/// public API), so `Fs`, `Fsrl` and `FsrlRoot` need only their existing minimal marker seams.
///
/// `Fs` is the concrete filesystem type (as used by [`FileSystemRef`] and
/// [`FileSystemProbeConflictResolver`]), `Fsrl` stands in for `FSRL`, and `FsrlRoot` stands in
/// for `FSRLRoot`.
///
/// Not ported: the static `getInstance()`/`isInitialized()` singleton accessors. Java's
/// process-wide singleton pattern has no equivalent on a trait -- implementors that want a
/// shared instance can expose their own constructor plus a `OnceLock`/`Arc` at the call site.
pub trait FileSystemService<Fs, Fsrl, FsrlRoot>
where
    Fs: GFileSystemLike,
    Fsrl: FsrlLike,
    FsrlRoot: FsrlRootLike,
{
    /// Forcefully closes all open filesystems and clears caches.
    fn clear(&mut self);

    /// Closes filesystems that are not currently in use.
    fn close_unused_file_systems(&mut self);

    /// Releases the specified filesystem ref, and if no other references remain, removes it
    /// from the shared cache of filesystem instances.
    fn release_file_system_immediate(&mut self, fs_ref: Box<dyn FileSystemRef<Fs>>);

    /// A direct reference to the local filesystem.
    fn get_local_fs(&self) -> &dyn LocalFileSystemLike;

    /// Returns `true` if `fsrl` is a path on the local computer's filesystem.
    fn is_local(&self, fsrl: &Fsrl) -> bool;

    /// Builds an FSRL of a file located on the local filesystem.
    fn get_local_fsrl(&self, f: &Path) -> Fsrl;

    /// Returns `true` if there is a filesystem mounted at the requested location.
    fn is_filesystem_mounted_at(&self, fsrl: &FsrlRoot) -> bool;

    /// Returns the file pointed to by the FSRL, along with a filesystem ref the caller is
    /// responsible for releasing.
    fn get_refd_file(
        &mut self,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<RefdFile<Box<dyn FileSystemRef<Fs>>, Fs, Fsrl>, GFileSystemError>;

    /// Returns a filesystem instance for the requested FSRLRoot, either from an already loaded
    /// instance in the global fscache, or by instantiating the requested filesystem from its
    /// container file.
    fn get_filesystem(
        &mut self,
        fs_fsrl: &FsrlRoot,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn FileSystemRef<Fs>>, GFileSystemError>;

    /// Returns a byte provider with the contents of the requested file.
    ///
    /// `fully_qualified_fsrl`, if true, requires the returned provider's FSRL to have an MD5
    /// hash.
    fn get_byte_provider(
        &mut self,
        fsrl: &Fsrl,
        fully_qualified_fsrl: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError>;

    /// Returns a byte provider containing the derived (decompressed, decrypted, etc) contents
    /// of the requested file, using `producer` to generate the bytes if not already cached.
    fn get_derived_byte_provider(
        &mut self,
        container_fsrl: &Fsrl,
        derived_fsrl: Option<&Fsrl>,
        derived_name: &str,
        size_hint: i64,
        producer: &mut dyn DerivedStreamProducer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError>;

    /// Same as [`get_derived_byte_provider`](FileSystemService::get_derived_byte_provider), but
    /// the derived bytes are pushed into a sink by `pusher` instead of pulled from a stream.
    fn get_derived_byte_provider_push(
        &mut self,
        container_fsrl: &Fsrl,
        derived_fsrl: Option<&Fsrl>,
        derived_name: &str,
        size_hint: i64,
        pusher: &mut dyn DerivedStreamPushProducer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError>;

    /// Returns a builder that will allow the caller to write bytes to a new temp file.
    fn create_temp_file(&mut self, size_hint: i64) -> io::Result<Box<dyn FileCacheEntryBuilderLike>>;

    /// Returns a byte provider for the specified cache entry, using the specified filename.
    fn get_named_temp_file(
        &self,
        temp_file_cache_entry: &dyn FileCacheEntryLike,
        name: &str,
    ) -> io::Result<Box<dyn ByteProvider>>;

    /// Converts a byte provider to the underlying file that contains its contents, or `None`
    /// if there is no available backing file.
    fn get_file_if_available(&self, provider: &dyn ByteProvider) -> Option<PathBuf>;

    /// Exports the bytes in a byte provider into a plaintext (non-obfuscated) temp file.
    fn create_plaintext_temp_file(
        &self,
        provider: &mut dyn ByteProvider,
        filename_prefix: &str,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<PathBuf>;

    /// Allows the resources used by caching the specified file to be released.
    fn release_file_cache(&mut self, fsrl: &Fsrl);

    /// Adds a plaintext file to the cache, consuming it, and returns a byte provider with its
    /// contents.
    fn push_file_to_cache(
        &mut self,
        file: &Path,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn ByteProvider>, GFileSystemError>;

    /// Returns `true` if the specified derived file exists in the file cache.
    fn has_derived_file(
        &self,
        container_fsrl: &Fsrl,
        derived_name: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError>;

    /// Returns `true` if the container file probably holds one of the currently supported
    /// filesystem types.
    fn is_file_filesystem_container(
        &mut self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError>;

    /// Auto-detects a filesystem in the container file pointed to by the FSRL, using
    /// `conflict_resolver` to choose between multiple candidate filesystem types (`None`
    /// chooses the first candidate) and ignoring filesystem types below `priority_filter`.
    ///
    /// Returns `Ok(None)` if no filesystem implementation could handle the container file.
    fn probe_file_for_filesystem(
        &mut self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver<Fs>>,
        priority_filter: i32,
    ) -> Result<Option<Box<dyn FileSystemRef<Fs>>>, GFileSystemError>;

    /// Convenience wrapper over
    /// [`probe_file_for_filesystem`](FileSystemService::probe_file_for_filesystem) that does
    /// not filter candidate filesystem types by priority.
    fn probe_file_for_filesystem_default(
        &mut self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver<Fs>>,
    ) -> Result<Option<Box<dyn FileSystemRef<Fs>>>, GFileSystemError> {
        self.probe_file_for_filesystem(container_fsrl, monitor, conflict_resolver, PRIORITY_LOWEST)
    }

    /// Mounts the filesystem registered under `fs_type` using the specified container file.
    ///
    /// The newly mounted filesystem is not managed by this service or controlled with
    /// filesystem refs; the caller is responsible for closing it when no longer needed.
    ///
    /// This is a simplified port of Java's `<FSTYPE extends GFileSystem> FSTYPE
    /// mountSpecificFileSystem(FSRL, Class<FSTYPE>, TaskMonitor)`: Rust has no `Class` token or
    /// reflection to map a type to its registered `fs_type` string, so the caller supplies
    /// `fs_type` directly, and the trait's fixed `Fs` parameter (rather than a per-call
    /// generic) stands in for the downcast Java performs after mounting.
    fn mount_specific_file_system(
        &mut self,
        container_fsrl: &Fsrl,
        fs_type: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<Fs, GFileSystemError>;

    /// Opens the filesystem contained at the specified location.
    ///
    /// The newly mounted filesystem is not managed by this service or controlled with
    /// filesystem refs; the caller is responsible for closing it when no longer needed.
    ///
    /// Unlike [`mount_specific_file_system`](FileSystemService::mount_specific_file_system),
    /// this probes for whichever filesystem type matches, so it returns the opaque
    /// [`GFileSystemLike`] marker rather than the trait's fixed `Fs` parameter.
    fn open_file_system_container(
        &mut self,
        container_fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GFileSystemLike>, GFileSystemError>;

    /// Returns a copy of `fsrl` with an MD5 value populated, if not already present.
    fn get_fully_qualified_fsrl(
        &mut self,
        fsrl: &Fsrl,
        monitor: &dyn TaskMonitor,
    ) -> Result<Fsrl, GFileSystemError>;

    /// Returns the names of all detected GFilesystem filesystem types.
    fn get_all_filesystem_names(&self) -> Vec<String>;

    /// Returns the FSRLRoots of all currently mounted filesystems.
    fn get_mounted_filesystems(&self) -> Vec<FsrlRoot>;

    /// Returns a new filesystem ref handle to an already mounted filesystem, or `None` if
    /// nothing is mounted at `fs_fsrl`.
    fn get_mounted_filesystem(&self, fs_fsrl: &FsrlRoot) -> Option<Box<dyn FileSystemRef<Fs>>>;

    /// Returns a new crypto session the caller can use to query for passwords. The caller is
    /// responsible for closing the instance when done.
    fn new_crypto_session(&mut self) -> Box<dyn CryptoSession<Fsrl>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    // ── Mock seam types ─────────────────────────────────────────────────────

    struct MockFs {
        name: &'static str,
    }
    impl GFileSystemLike for MockFs {}

    #[derive(Clone)]
    struct MockFsrl {
        path: String,
        md5: Option<String>,
    }
    impl FsrlLike for MockFsrl {}

    struct MockFsrlRoot(String);
    impl FsrlRootLike for MockFsrlRoot {}

    struct MockLocalFs;
    impl LocalFileSystemLike for MockLocalFs {}

    struct MockCacheEntryBuilder;
    impl FileCacheEntryBuilderLike for MockCacheEntryBuilder {}

    struct MockCacheEntry;
    impl FileCacheEntryLike for MockCacheEntry {}

    // ── Mock FileSystemRef ─────────────────────────────────────────────────

    struct MockRef {
        fs: Rc<MockFs>,
        closed: bool,
    }

    impl FileSystemRef<MockFs> for MockRef {
        fn dup(&self) -> Box<dyn FileSystemRef<MockFs>> {
            Box::new(MockRef { fs: self.fs.clone(), closed: false })
        }
        fn get_filesystem(&self) -> &MockFs {
            &self.fs
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    // ── Mock ByteProvider ─────────────────────────────────────────────────

    struct VecByteProvider(Vec<u8>);

    impl ByteProvider for VecByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.0.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds")
            })
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
    }

    // ── Mock DerivedStreamProducer ───────────────────────────────────────────

    struct FixedProducer(Vec<u8>);
    impl DerivedStreamProducer for FixedProducer {
        fn produce_derived_stream(&mut self) -> Result<Vec<u8>, GFileSystemError> {
            Ok(self.0.clone())
        }
    }

    // ── Mock FileSystemService ───────────────────────────────────────────────
    //
    // Backs a minimal, real in-memory derived-file cache keyed by (container md5, derived
    // name) to exercise get_derived_byte_provider's cache-or-produce behavior, matching the
    // Java implementation's actual semantics rather than a trivially-true stub.

    struct MockService {
        local_fs: MockLocalFs,
        mounted: RefCell<HashMap<String, Rc<MockFs>>>,
        derived_cache: RefCell<HashMap<(String, String), Vec<u8>>>,
        crypto_sessions_opened: Cell<u32>,
    }

    impl MockService {
        fn new() -> Self {
            MockService {
                local_fs: MockLocalFs,
                mounted: RefCell::new(HashMap::new()),
                derived_cache: RefCell::new(HashMap::new()),
                crypto_sessions_opened: Cell::new(0),
            }
        }
    }

    impl FileSystemService<MockFs, MockFsrl, MockFsrlRoot> for MockService {
        fn clear(&mut self) {
            self.mounted.borrow_mut().clear();
        }

        fn close_unused_file_systems(&mut self) {}

        fn release_file_system_immediate(&mut self, _fs_ref: Box<dyn FileSystemRef<MockFs>>) {}

        fn get_local_fs(&self) -> &dyn LocalFileSystemLike {
            &self.local_fs
        }

        fn is_local(&self, fsrl: &MockFsrl) -> bool {
            !fsrl.path.starts_with("archive:")
        }

        fn get_local_fsrl(&self, f: &Path) -> MockFsrl {
            MockFsrl { path: f.to_string_lossy().into_owned(), md5: None }
        }

        fn is_filesystem_mounted_at(&self, fsrl: &MockFsrlRoot) -> bool {
            self.mounted.borrow().contains_key(&fsrl.0)
        }

        fn get_refd_file(
            &mut self,
            _fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
        ) -> Result<RefdFile<Box<dyn FileSystemRef<MockFs>>, MockFs, MockFsrl>, GFileSystemError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_filesystem(
            &mut self,
            fs_fsrl: &MockFsrlRoot,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn FileSystemRef<MockFs>>, GFileSystemError> {
            let fs = self
                .mounted
                .borrow_mut()
                .entry(fs_fsrl.0.clone())
                .or_insert_with(|| Rc::new(MockFs { name: "mockfs" }))
                .clone();
            Ok(Box::new(MockRef { fs, closed: false }))
        }

        fn get_byte_provider(
            &mut self,
            _fsrl: &MockFsrl,
            _fully_qualified_fsrl: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
            Ok(Box::new(VecByteProvider(Vec::new())))
        }

        fn get_derived_byte_provider(
            &mut self,
            container_fsrl: &MockFsrl,
            _derived_fsrl: Option<&MockFsrl>,
            derived_name: &str,
            _size_hint: i64,
            producer: &mut dyn DerivedStreamProducer,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
            let container_md5 = container_fsrl.md5.clone().unwrap_or_default();
            let key = (container_md5, derived_name.to_string());
            let bytes = {
                let mut cache = self.derived_cache.borrow_mut();
                if let Some(existing) = cache.get(&key) {
                    existing.clone()
                } else {
                    let produced = producer.produce_derived_stream()?;
                    cache.insert(key, produced.clone());
                    produced
                }
            };
            Ok(Box::new(VecByteProvider(bytes)))
        }

        fn get_derived_byte_provider_push(
            &mut self,
            _container_fsrl: &MockFsrl,
            _derived_fsrl: Option<&MockFsrl>,
            _derived_name: &str,
            _size_hint: i64,
            pusher: &mut dyn DerivedStreamPushProducer,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
            let mut buf = Vec::new();
            pusher.push(&mut buf)?;
            Ok(Box::new(VecByteProvider(buf)))
        }

        fn create_temp_file(
            &mut self,
            _size_hint: i64,
        ) -> io::Result<Box<dyn FileCacheEntryBuilderLike>> {
            Ok(Box::new(MockCacheEntryBuilder))
        }

        fn get_named_temp_file(
            &self,
            _temp_file_cache_entry: &dyn FileCacheEntryLike,
            _name: &str,
        ) -> io::Result<Box<dyn ByteProvider>> {
            Ok(Box::new(VecByteProvider(Vec::new())))
        }

        fn get_file_if_available(&self, _provider: &dyn ByteProvider) -> Option<PathBuf> {
            None
        }

        fn create_plaintext_temp_file(
            &self,
            _provider: &mut dyn ByteProvider,
            _filename_prefix: &str,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/tmp/mock"))
        }

        fn release_file_cache(&mut self, _fsrl: &MockFsrl) {}

        fn push_file_to_cache(
            &mut self,
            _file: &Path,
            _fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn ByteProvider>, GFileSystemError> {
            Ok(Box::new(VecByteProvider(Vec::new())))
        }

        fn has_derived_file(
            &self,
            container_fsrl: &MockFsrl,
            derived_name: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, GFileSystemError> {
            let container_md5 = container_fsrl.md5.clone().unwrap_or_default();
            Ok(self
                .derived_cache
                .borrow()
                .contains_key(&(container_md5, derived_name.to_string())))
        }

        fn is_file_filesystem_container(
            &mut self,
            _container_fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, GFileSystemError> {
            Ok(false)
        }

        fn probe_file_for_filesystem(
            &mut self,
            _container_fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
            _conflict_resolver: Option<&dyn FileSystemProbeConflictResolver<MockFs>>,
            _priority_filter: i32,
        ) -> Result<Option<Box<dyn FileSystemRef<MockFs>>>, GFileSystemError> {
            Ok(None)
        }

        fn mount_specific_file_system(
            &mut self,
            _container_fsrl: &MockFsrl,
            _fs_type: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<MockFs, GFileSystemError> {
            Ok(MockFs { name: "mounted" })
        }

        fn open_file_system_container(
            &mut self,
            _container_fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn GFileSystemLike>, GFileSystemError> {
            Ok(Box::new(MockFs { name: "opened" }))
        }

        fn get_fully_qualified_fsrl(
            &mut self,
            fsrl: &MockFsrl,
            _monitor: &dyn TaskMonitor,
        ) -> Result<MockFsrl, GFileSystemError> {
            let mut result = fsrl.clone();
            if result.md5.is_none() {
                result.md5 = Some(format!("md5:{}", result.path));
            }
            Ok(result)
        }

        fn get_all_filesystem_names(&self) -> Vec<String> {
            vec!["zip".to_string(), "tar".to_string()]
        }

        fn get_mounted_filesystems(&self) -> Vec<MockFsrlRoot> {
            self.mounted.borrow().keys().cloned().map(MockFsrlRoot).collect()
        }

        fn get_mounted_filesystem(&self, fs_fsrl: &MockFsrlRoot) -> Option<Box<dyn FileSystemRef<MockFs>>> {
            self.mounted.borrow().get(&fs_fsrl.0).map(|fs| {
                let boxed: Box<dyn FileSystemRef<MockFs>> =
                    Box::new(MockRef { fs: fs.clone(), closed: false });
                boxed
            })
        }

        fn new_crypto_session(&mut self) -> Box<dyn CryptoSession<MockFsrl>> {
            self.crypto_sessions_opened.set(self.crypto_sessions_opened.get() + 1);
            unimplemented!("not exercised by this smoke test")
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn is_local_distinguishes_local_from_archive_paths() {
        let service = MockService::new();
        assert!(service.is_local(&MockFsrl { path: "/tmp/a".to_string(), md5: None }));
        assert!(!service.is_local(&MockFsrl { path: "archive:/tmp/a.zip!/b".to_string(), md5: None }));
    }

    #[test]
    fn get_filesystem_caches_the_same_ref_by_fsrl_root() {
        let mut service = MockService::new();
        let monitor = crate::util::task::DummyMonitor;
        let root = MockFsrlRoot("archive:/tmp/a.zip".to_string());

        assert!(!service.is_filesystem_mounted_at(&root));
        let ref1 = service.get_filesystem(&root, &monitor).unwrap();
        assert!(service.is_filesystem_mounted_at(&root));
        let ref2 = service.get_filesystem(&root, &monitor).unwrap();
        assert_eq!(ref1.get_filesystem().name, ref2.get_filesystem().name);
    }

    #[test]
    fn get_derived_byte_provider_only_invokes_producer_once() {
        let mut service = MockService::new();
        let monitor = crate::util::task::DummyMonitor;
        let container = MockFsrl { path: "/tmp/a.zip".to_string(), md5: Some("abc123".to_string()) };

        assert!(!service.has_derived_file(&container, "inner.bin", &monitor).unwrap());

        let mut producer = FixedProducer(b"derived bytes".to_vec());
        let mut bp =
            service.get_derived_byte_provider(&container, None, "inner.bin", -1, &mut producer, &monitor).unwrap();
        let len = bp.length().unwrap();
        assert_eq!(bp.read_bytes(0, len as usize).unwrap(), b"derived bytes");

        assert!(service.has_derived_file(&container, "inner.bin", &monitor).unwrap());

        // Second call must hit the cache rather than calling the producer again.
        let mut producer2 = FixedProducer(b"SHOULD NOT BE USED".to_vec());
        let mut bp2 =
            service.get_derived_byte_provider(&container, None, "inner.bin", -1, &mut producer2, &monitor).unwrap();
        let len2 = bp2.length().unwrap();
        assert_eq!(bp2.read_bytes(0, len2 as usize).unwrap(), b"derived bytes");
    }

    #[test]
    fn get_fully_qualified_fsrl_fills_in_missing_md5() {
        let mut service = MockService::new();
        let monitor = crate::util::task::DummyMonitor;
        let fsrl = MockFsrl { path: "/tmp/a".to_string(), md5: None };
        let qualified = service.get_fully_qualified_fsrl(&fsrl, &monitor).unwrap();
        assert_eq!(qualified.md5.as_deref(), Some("md5:/tmp/a"));
    }

    #[test]
    fn probe_file_for_filesystem_default_forwards_lowest_priority() {
        let mut service = MockService::new();
        let monitor = crate::util::task::DummyMonitor;
        let fsrl = MockFsrl { path: "/tmp/a".to_string(), md5: None };
        let result = service.probe_file_for_filesystem_default(&fsrl, &monitor, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn boxed_dyn_file_system_service_is_accepted() {
        let mut service: Box<dyn FileSystemService<MockFs, MockFsrl, MockFsrlRoot>> =
            Box::new(MockService::new());
        let names = service.get_all_filesystem_names();
        assert_eq!(names, vec!["zip".to_string(), "tar".to_string()]);
        service.clear();
    }
}
