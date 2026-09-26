//! Port of `ghidra.formats.gfilesystem.AbstractSinglePayloadFileSystem`.
//!
//! Base state and behaviour for filesystems that present a single payload file (typically the
//! decompressed contents of a compressed container, e.g. gzip / lzss / Android sparse images).
//!
//! The Java abstract class declares no abstract methods of its own; its subclasses only add a
//! constructor and a `@FileSystemInfo` annotation. It is therefore ported as a shared-state
//! struct, [`AbstractSinglePayloadFileSystemBase`], that each concrete filesystem embeds and
//! dereferences to.
//!
//! Each concrete filesystem implements [`SinglePayloadFileSystem`] (its metadata plus access
//! to the embedded base) and thereby gets its [`GFileSystem`] implementation, the way Java
//! subclasses inherit `AbstractSinglePayloadFileSystem`'s. The base owns the filesystem's
//! [`FileSystemRefManager`] (Java's `refManager` field), and closing goes through `&self`
//! (filesystems are shared handles), so the payload provider sits behind a private `RefCell`.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::byte_provider_wrapper::ByteProviderWrapper;
use crate::util::task::TaskMonitor;

use super::annotations::file_system_info::FileSystemInfo;
use super::file_system_ref_manager::FileSystemRefManager;
use super::fileinfo::file_attributes::FileAttributes;
use super::g_file_system::{GFileSystem, GFileSystemError};
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::single_file_system_index_helper::{
    SingleFileSystemIndexHelper, SinglePayloadFsHandle, SinglePayloadGFile,
};

/// The [`ByteProvider`] a single-payload filesystem hands out for its payload file: a
/// whole-range view of the shared payload provider, tagged with the payload file's FSRL.
pub type SinglePayloadByteProvider = ByteProviderWrapper<Rc<dyn ByteProvider>>;

/// Shared state and behaviour of a filesystem holding exactly one payload file.
///
/// Mirrors `ghidra.formats.gfilesystem.AbstractSinglePayloadFileSystem`.
pub struct AbstractSinglePayloadFileSystemBase {
    fs_fsrl: FsrlRoot,
    fs_index: SingleFileSystemIndexHelper,
    payload_provider: RefCell<Option<Rc<dyn ByteProvider>>>,
    ref_manager: FileSystemRefManager,
}

impl AbstractSinglePayloadFileSystemBase {
    /// Creates the filesystem `fs_fsrl` whose single file, `payload_filename`, has the
    /// contents of `payload_provider` and the attributes `payload_attrs`.
    ///
    /// The payload file's length is the provider's length and its MD5 is taken from the
    /// provider's FSRL, if it has one.
    ///
    /// Mirrors `AbstractSinglePayloadFileSystem(FSRLRoot, ByteProvider, String,
    /// FileAttributes)`; pass [`FileAttributes::new`] for the three-argument form (which uses
    /// `FileAttributes.EMPTY`).
    pub fn new(
        fs_fsrl: FsrlRoot,
        payload_provider: Rc<dyn ByteProvider>,
        payload_filename: &str,
        payload_attrs: FileAttributes,
    ) -> Self {
        let md5 = payload_provider.get_fsrl().and_then(Fsrl::md5);
        let mut fs_index = SingleFileSystemIndexHelper::new(
            &fs_fsrl,
            payload_filename,
            payload_provider.length() as i64,
            md5,
        );
        fs_index.set_payload_file_attributes(payload_attrs);
        AbstractSinglePayloadFileSystemBase {
            fs_fsrl,
            fs_index,
            payload_provider: RefCell::new(Some(payload_provider)),
            ref_manager: FileSystemRefManager::new(),
        }
    }

    /// The payload file; `None` once closed. Mirrors `getPayloadFile()`.
    pub fn get_payload_file(&self) -> Option<&SinglePayloadGFile> {
        self.fs_index.get_payload_file()
    }

    /// Closes the filesystem: clears the index and releases the payload provider.
    ///
    /// Mirrors `close()`. Java unconditionally closes the payload provider (ignoring errors, via
    /// `FSUtilities.uncheckedClose`). Here byte providers previously handed out by
    /// [`get_byte_provider`](Self::get_byte_provider) share ownership of it, so it is closed
    /// only if this filesystem held the last reference; otherwise it is released when the last
    /// outstanding provider is dropped, rather than being closed underneath it.
    ///
    /// Notifying the [ref manager](Self::get_ref_manager) (Java's `refManager.onClose()`) is
    /// done by the [`GFileSystem::close`] implementation, which has the filesystem handle
    /// listeners are given.
    pub fn close(&self) -> io::Result<()> {
        self.fs_index.clear();
        let taken = self.payload_provider.borrow_mut().take();
        if let Some(mut provider) = taken {
            if let Some(p) = Rc::get_mut(&mut provider) {
                // Mirrors FSUtilities.uncheckedClose: close errors are ignored.
                let _ = p.close();
            }
        }
        Ok(())
    }

    /// The filesystem's volume name: the name of its container file. Mirrors `getName()`.
    pub fn get_name(&self) -> String {
        self.fs_fsrl.container().and_then(Fsrl::name).unwrap_or_default()
    }

    /// This filesystem's FSRL root. Mirrors `getFSRL()`.
    pub fn get_fsrl(&self) -> &FsrlRoot {
        &self.fs_fsrl
    }

    fn owned(&self, f: &SinglePayloadGFile) -> Box<dyn GFile<SinglePayloadFsHandle>> {
        Box::new(self.fs_index.to_owned_file(f))
    }

    /// The filesystem's ref manager. Mirrors `getRefManager()`.
    pub fn get_ref_manager(&self) -> &FileSystemRefManager {
        &self.ref_manager
    }

    /// `true` once [`close`](Self::close)d. Mirrors `isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.fs_index.is_closed()
    }

    /// Always 1. Mirrors `getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        1
    }

    /// The root directory. Mirrors the inherited `GFileSystem.getRootDir()`.
    pub fn get_root_dir(&self) -> &SinglePayloadGFile {
        self.fs_index.get_root_dir()
    }

    /// Looks up the root (`None` / `"/"`) or the payload file by path. Mirrors
    /// `lookup(String)`.
    pub fn lookup(&self, path: Option<&str>) -> Option<&SinglePayloadGFile> {
        self.fs_index.lookup(path)
    }

    /// Looks up a file using `name_comp` to compare names. Mirrors
    /// `lookup(String, Comparator<String>)`.
    pub fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> Option<&SinglePayloadGFile> {
        self.fs_index.lookup_with(None, path, name_comp)
    }

    /// A [`ByteProvider`] over `file`'s contents if it is the payload file, otherwise `None`.
    ///
    /// Mirrors `getByteProvider(GFile, TaskMonitor)`: the result wraps the shared payload
    /// provider and carries `file`'s FSRL.
    pub fn get_byte_provider(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> Option<SinglePayloadByteProvider> {
        if !self.fs_index.is_payload_file(file) {
            return None;
        }
        let provider = Rc::clone(self.payload_provider.borrow().as_ref()?);
        Some(ByteProviderWrapper::new(provider, Some(file.get_fsrl().clone())))
    }

    /// The files in `directory` (`None` means the root). Mirrors `getListing(GFile)`.
    ///
    /// # Errors
    /// If the filesystem has been closed.
    pub fn get_listing(
        &self,
        directory: Option<&dyn GFile<SinglePayloadFsHandle>>,
    ) -> io::Result<Vec<&SinglePayloadGFile>> {
        self.fs_index.get_listing(directory)
    }

    /// The payload file's attributes, or empty attributes for any other file. Mirrors
    /// `getFileAttributes(GFile, TaskMonitor)`.
    pub fn get_file_attributes(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> &FileAttributes {
        self.fs_index.get_file_attributes(file)
    }
}

/// A filesystem built on [`AbstractSinglePayloadFileSystemBase`]: Java's subclasses of
/// `AbstractSinglePayloadFileSystem`. Implementing this (metadata plus the embedded base) gives
/// the type its [`GFileSystem`] implementation.
pub trait SinglePayloadFileSystem: 'static {
    /// The filesystem's `@FileSystemInfo` metadata.
    const INFO: FileSystemInfo;

    /// The embedded base state.
    fn base(&self) -> &AbstractSinglePayloadFileSystemBase;
}

impl<T: SinglePayloadFileSystem> GFileSystem for T {
    type Fs = SinglePayloadFsHandle;

    fn get_name(&self) -> String {
        self.base().get_name()
    }

    fn get_type(&self) -> String {
        T::INFO.fs_type.to_string()
    }

    fn get_description(&self) -> String {
        T::INFO.description.to_string()
    }

    fn get_fsrl(&self) -> &FsrlRoot {
        self.base().get_fsrl()
    }

    fn is_closed(&self) -> bool {
        self.base().is_closed()
    }

    fn get_ref_manager(&self) -> &FileSystemRefManager {
        self.base().get_ref_manager()
    }

    fn get_file_count(&self) -> i32 {
        self.base().get_file_count()
    }

    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<SinglePayloadFsHandle>>>> {
        Ok(self.base().lookup(path).map(|f| self.base().owned(f)))
    }

    fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> io::Result<Option<Box<dyn GFile<SinglePayloadFsHandle>>>> {
        Ok(self
            .base()
            .lookup_with_comparator(path, name_comp)
            .map(|f| self.base().owned(f)))
    }

    fn get_byte_provider(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        Ok(self
            .base()
            .get_byte_provider(file, monitor)
            .map(|p| Box::new(p) as Box<dyn ByteProvider>))
    }

    fn get_listing(
        &self,
        directory: Option<&dyn GFile<SinglePayloadFsHandle>>,
    ) -> io::Result<Vec<Box<dyn GFile<SinglePayloadFsHandle>>>> {
        Ok(self
            .base()
            .get_listing(directory)?
            .into_iter()
            .map(|f| self.base().owned(f))
            .collect())
    }

    fn get_file_attributes(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle>,
        monitor: &dyn TaskMonitor,
    ) -> FileAttributes {
        self.base().get_file_attributes(file, monitor).clone()
    }

    /// Mirrors `close()`: notifies the ref manager's listeners, then clears the index and
    /// releases the payload provider.
    fn close(&self) -> io::Result<()> {
        // A second close finds the manager already closed; Java would throw there, but closing
        // an already-closed filesystem is harmless, so it is ignored.
        let _ = self.base().get_ref_manager().on_close(self);
        self.base().close()
    }
}

/// An in-memory [`ByteProvider`] used by single-payload filesystem tests across the crate.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;
    use std::io;
    use std::path::PathBuf;
    use std::rc::Rc;

    use crate::app::util::bin::byte_provider::ByteProvider;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;

    /// Byte-array provider with an optional FSRL and an observable closed flag.
    pub struct MemProvider {
        pub bytes: Vec<u8>,
        pub fsrl: Option<Fsrl>,
        pub closed: Rc<Cell<bool>>,
    }

    impl MemProvider {
        pub fn new(bytes: Vec<u8>, fsrl: Option<Fsrl>) -> Self {
            MemProvider { bytes, fsrl, closed: Rc::new(Cell::new(false)) }
        }
    }

    impl ByteProvider for MemProvider {
        fn get_file(&self) -> Option<PathBuf> {
            None
        }
        fn get_name(&self) -> Option<String> {
            self.fsrl.as_ref().and_then(Fsrl::name)
        }
        fn get_absolute_path(&self) -> Option<String> {
            self.fsrl.as_ref().and_then(|f| f.path().map(str::to_owned))
        }
        fn length(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.length()
        }
        fn close(&mut self) -> io::Result<()> {
            self.closed.set(true);
            Ok(())
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start
                .checked_add(length as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "overflow"))?;
            self.bytes
                .get(start..end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn get_fsrl(&self) -> Option<&Fsrl> {
            self.fsrl.as_ref()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemProvider;
    use super::*;
    use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
    use crate::util::task::DummyMonitor;

    fn container() -> Fsrl {
        Fsrl::from_string("file:///data/archive.gz").unwrap()
    }

    fn make_fs(bytes: &[u8]) -> (AbstractSinglePayloadFileSystemBase, Rc<std::cell::Cell<bool>>) {
        let fs_fsrl = container().make_nested("gzip");
        let payload_fsrl = Fsrl::from_string("file:///cache/payload").unwrap().with_md5(Some("feedface"));
        let provider = MemProvider::new(bytes.to_vec(), Some(payload_fsrl));
        let closed = provider.closed.clone();
        let attrs = FileAttributes::of([(FileAttributeType::CommentAttr, Some("hi".into()))]);
        (AbstractSinglePayloadFileSystemBase::new(fs_fsrl, Rc::new(provider), "archive", attrs), closed)
    }

    #[test]
    fn name_fsrl_and_counts() {
        let (fs, _) = make_fs(b"hello");
        assert_eq!(fs.get_name(), "archive.gz");
        assert_eq!(fs.get_fsrl().to_string(), "file:///data/archive.gz|gzip://");
        assert_eq!(fs.get_file_count(), 1);
        assert!(!fs.is_closed());
    }

    #[test]
    fn payload_file_takes_length_and_md5_from_provider() {
        let (fs, _) = make_fs(b"hello");
        let p = fs.get_payload_file().unwrap();
        assert_eq!(p.get_length(), 5);
        assert_eq!(p.get_fsrl().md5(), Some("feedface"));
        assert_eq!(p.get_fsrl().to_string(), "file:///data/archive.gz|gzip:///archive?MD5=feedface");
    }

    #[test]
    fn byte_provider_only_for_payload_and_tagged_with_its_fsrl() {
        let (fs, _) = make_fs(b"hello");
        let monitor = DummyMonitor;
        let payload = fs.lookup(Some("/archive")).unwrap();
        let bp = fs.get_byte_provider(payload, &monitor).unwrap();
        assert_eq!(bp.read_bytes(0, 5).unwrap(), b"hello");
        assert_eq!(bp.get_fsrl(), Some(payload.get_fsrl()));
        assert_eq!(bp.get_name().as_deref(), Some("archive"));
        assert!(fs.get_byte_provider(fs.get_root_dir(), &monitor).is_none());
    }

    #[test]
    fn listing_and_attributes() {
        let (fs, _) = make_fs(b"hello");
        let monitor = DummyMonitor;
        let listing = fs.get_listing(None).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "archive");
        let attrs = fs.get_file_attributes(listing[0], &monitor);
        assert_eq!(attrs.get_str(FileAttributeType::CommentAttr, ""), "hi");
        assert!(fs.get_file_attributes(fs.get_root_dir(), &monitor).get_attributes().is_empty());
    }

    #[test]
    fn close_releases_provider_and_index() {
        let (mut fs, closed) = make_fs(b"hello");
        fs.close().unwrap();
        assert!(fs.is_closed());
        assert!(closed.get());
        assert!(fs.get_payload_file().is_none());
        assert!(fs.get_listing(None).is_err());
    }

    #[test]
    fn close_with_outstanding_provider_keeps_it_readable() {
        let (mut fs, closed) = make_fs(b"hello");
        let monitor = DummyMonitor;
        let bp = {
            let payload = fs.get_payload_file().unwrap();
            fs.get_byte_provider(payload, &monitor).unwrap()
        };
        fs.close().unwrap();
        assert!(!closed.get());
        assert_eq!(bp.read_bytes(0, 5).unwrap(), b"hello");
    }
}
