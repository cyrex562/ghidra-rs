//! Port of `ghidra.file.formats.cpio.CpioFileSystem`.
//!
//! A filesystem over a cpio archive, built on [`AbstractFileSystemBase`] and the hand-written
//! [`CpioArchiveReader`] (standing in for Apache commons-compress's `CpioArchiveInputStream`).
//!
//! As in Java, a member's bytes are handed out as a derived byte provider cached by the
//! [`FileSystemService`] (keyed by the archive's MD5 and the member's path), and the
//! filesystem notifies its ref manager when it closes.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::io;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::abstract_file_system::{AbstractFileSystemBase, AbstractFsHandle};
use crate::filesystem::gfilesystem::annotations::file_system_info::{FileSystemInfo, PRIORITY_DEFAULT};
use crate::filesystem::gfilesystem::file_system_index_helper::copy_file;
use crate::filesystem::gfilesystem::file_system_ref_manager::FileSystemRefManager;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::{FileAttributeValue, FileAttributes};
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_system::{GFileSystem, GFileSystemError};
use crate::util::task::TaskMonitor;

use super::cpio_archive::{CpioArchiveEntry, CpioArchiveReader};

/// Mirrors `CpioFileSystem.MAX_SANE_SYMLINK`.
const MAX_SANE_SYMLINK: u64 = 64 * 1024;

/// A filesystem over the members of a cpio archive.
///
/// Mirrors `ghidra.file.formats.cpio.CpioFileSystem`. It is shared through
/// [`FsHandle`](crate::filesystem::gfilesystem::g_file_system::FsHandle)s, so the archive
/// provider (released on close) sits behind a `RefCell`.
pub struct CpioFileSystem {
    base: AbstractFileSystemBase<CpioArchiveEntry>,
    provider: RefCell<Option<Rc<dyn ByteProvider>>>,
}

impl CpioFileSystem {
    /// `@FileSystemInfo(type = "cpio")`.
    pub const FS_TYPE: &'static str = "cpio";
    /// `@FileSystemInfo(description = "CPIO")`.
    pub const DESCRIPTION: &'static str = "CPIO";
    /// `@FileSystemInfo` default priority.
    pub const PRIORITY: i32 = PRIORITY_DEFAULT;
    /// The `@FileSystemInfo` annotation.
    pub const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, Self::PRIORITY);

    /// Opens the cpio archive in `provider` and indexes its members, numbering them in archive
    /// order. Symlink members are indexed with their target (their data), or
    /// `"???badsymlink???"` if implausibly large.
    ///
    /// Mirrors `CpioFileSystem(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`.
    ///
    /// # Errors
    /// Any error reading the archive, except running out of input, which (as in Java) silently
    /// ends the listing.
    pub fn new(
        fs_fsrl: FsrlRoot,
        provider: Rc<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Self> {
        let mut base = AbstractFileSystemBase::new(fs_fsrl, fs_service);
        monitor.set_message("Opening CPIO...");
        match Self::index_entries(&mut base, provider.as_ref(), monitor) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // silently ignore EOFExceptions
            }
            other => other?,
        }
        Ok(CpioFileSystem { base, provider: RefCell::new(Some(provider)) })
    }

    fn index_entries(
        base: &mut AbstractFileSystemBase<CpioArchiveEntry>,
        provider: &dyn ByteProvider,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let mut reader = CpioArchiveReader::new(provider);
        let mut file_num = 0i64;
        while let Some(entry) = reader.next_entry()? {
            monitor.set_message(entry.name());
            let index = base.fs_index_mut();
            if entry.is_symbolic_link() {
                let link_dest = if entry.size() < MAX_SANE_SYMLINK {
                    String::from_utf8_lossy(&reader.read_entry_data()?).into_owned()
                } else {
                    "???badsymlink???".to_owned()
                };
                let (name, size) = (entry.name().to_owned(), entry.size() as i64);
                index.store_symlink(&name, file_num, &link_dest, size, entry);
            } else {
                let (name, size) = (entry.name().to_owned(), entry.size() as i64);
                let is_dir = entry.is_directory();
                index.store_file(&name, file_num, is_dir, size, entry);
            }
            file_num += 1;
        }
        Ok(())
    }

    /// Mirrors the private `getFileType(CpioArchiveEntry)`.
    fn entry_file_type(entry: &CpioArchiveEntry) -> FileType {
        if entry.is_symbolic_link() {
            FileType::SymbolicLink
        } else if entry.is_directory() {
            FileType::Directory
        } else if entry.is_regular_file() {
            FileType::File
        } else {
            FileType::Other
        }
    }

    fn owned(f: &dyn GFile<AbstractFsHandle>) -> Box<dyn GFile<AbstractFsHandle>> {
        Box::new(copy_file(f))
    }
}

impl GFileSystem for CpioFileSystem {
    type Fs = AbstractFsHandle;

    fn get_name(&self) -> String {
        self.base.get_name()
    }

    fn get_type(&self) -> String {
        Self::FS_TYPE.to_string()
    }

    fn get_description(&self) -> String {
        Self::DESCRIPTION.to_string()
    }

    fn get_fsrl(&self) -> &FsrlRoot {
        self.base.get_fsrl()
    }

    /// `true` once [`close`](GFileSystem::close)d. Mirrors `isClosed()`.
    fn is_closed(&self) -> bool {
        self.provider.borrow().is_none()
    }

    fn get_ref_manager(&self) -> &FileSystemRefManager {
        self.base.get_ref_manager()
    }

    fn get_file_count(&self) -> i32 {
        self.base.get_file_count()
    }

    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.lookup(path).map(|f| Self::owned(f)))
    }

    fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> io::Result<Option<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.lookup_with_comparator(path, name_comp).map(|f| Self::owned(f)))
    }

    /// A [`ByteProvider`] with the contents of `file` (after resolving symlinks), or `None` if
    /// it has no cpio entry.
    ///
    /// Mirrors `getByteProvider(GFile, TaskMonitor)`: the archive is rescanned for the first
    /// entry equal to the file's entry, whose data becomes a derived byte provider of the
    /// service (keyed by the archive's FSRL and the file's path, carrying the file's FSRL).
    ///
    /// # Errors
    /// If the file is not a regular file, the filesystem is closed, the entry cannot be found
    /// again, reading the archive fails, or the service is gone.
    fn get_byte_provider(
        &self,
        file: &dyn GFile<AbstractFsHandle>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        let index = self.base.fs_index();
        let Some(file) = index.resolve_symlinks(file)?.map(|f| copy_file(f)) else {
            return Ok(None);
        };
        let Some(target_entry) = index.get_metadata(&file) else { return Ok(None) };
        if !target_entry.is_regular_file() {
            return Err(io::Error::other(format!(
                "CPIO entry {} is not a regular file.",
                file.get_name()
            ))
            .into());
        }
        let provider = self
            .provider
            .borrow()
            .clone()
            .ok_or_else(|| io::Error::other("CPIO filesystem is closed"))?;
        let fs_service = self.base.fs_service().get()?;
        let container_fsrl = provider
            .get_fsrl()
            .ok_or_else(|| io::Error::other("CPIO container has no FSRL"))?
            .clone();
        let mut reader = CpioArchiveReader::new(provider.as_ref());
        while let Some(current) = reader.next_entry()? {
            if &current == target_entry {
                let mut producer = || -> Result<Box<dyn io::Read>, GFileSystemError> {
                    Ok(Box::new(io::Cursor::new(reader.read_entry_data()?)))
                };
                let bp = fs_service.get_derived_byte_provider(
                    &container_fsrl,
                    Some(file.get_fsrl()),
                    file.get_path(),
                    current.size() as i64,
                    &mut producer,
                    monitor,
                )?;
                return Ok(Some(bp));
            }
        }
        Err(io::Error::other(format!("Unable to seek to entry: {}", file.get_name())).into())
    }

    fn get_listing(
        &self,
        directory: Option<&dyn GFile<AbstractFsHandle>>,
    ) -> io::Result<Vec<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.get_listing(directory).into_iter().map(|f| Self::owned(f)).collect())
    }

    /// The attributes of `file`'s cpio entry (empty if it has none). Device numbers are only
    /// reported for the old formats and the checksum only for the new ones, as in Java.
    ///
    /// Mirrors `getFileAttributes(GFile, TaskMonitor)`.
    fn get_file_attributes(
        &self,
        file: &dyn GFile<AbstractFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> FileAttributes {
        let mut result = FileAttributes::new();
        let index = self.base.fs_index();
        let Some(entry) = index.get_metadata(file) else { return result };
        result.add(FileAttributeType::NameAttr, Some(entry.name().into()));
        result.add(FileAttributeType::SizeAttr, Some((entry.size() as i64).into()));
        result.add(
            FileAttributeType::ModifiedDateAttr,
            Some(FileAttributeValue::Date(entry.last_modified_millis())),
        );
        result.add(FileAttributeType::UserIdAttr, Some((entry.uid() as i64).into()));
        result.add(FileAttributeType::GroupIdAttr, Some((entry.gid() as i64).into()));
        result.add(FileAttributeType::FileTypeAttr, Some(Self::entry_file_type(entry).into()));
        result.add(
            FileAttributeType::SymlinkDestAttr,
            index.get_symlink_path(Some(file)).map(Into::into),
        );
        result.add_named("Mode", Some(format!("{:x}", entry.mode()).into()));
        result.add_named("Inode", Some(format!("{:x}", entry.inode()).into()));
        result.add_named("Format", Some(format!("{:x}", entry.format()).into()));
        // Java adds both device values in one try block, ignoring the new-format exception.
        if let (Ok(dev), Ok(rdev)) = (entry.device(), entry.remote_device()) {
            result.add_named("Device ID", Some(format!("{dev:x}").into()));
            result.add_named("Remote Device", Some(format!("{rdev:x}").into()));
        }
        if let Ok(chksum) = entry.chksum() {
            result.add_named("Checksum", Some(format!("{chksum:x}").into()));
        }
        result
    }

    /// Mirrors `resolveSymlinks(GFile)` (inherited from `AbstractFileSystem`).
    fn resolve_symlinks(
        &self,
        file: &dyn GFile<AbstractFsHandle>,
    ) -> io::Result<Option<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.resolve_symlinks(file)?.map(|f| Self::owned(f)))
    }

    /// The type of `file`, or [`FileType::Unknown`] if it has no cpio entry (e.g. an
    /// auto-created directory). Mirrors `getFileType(GFile, TaskMonitor)`.
    fn get_file_type(&self, file: &dyn GFile<AbstractFsHandle>, _monitor: &dyn TaskMonitor) -> FileType {
        self.base.fs_index().get_metadata(file).map_or(FileType::Unknown, Self::entry_file_type)
    }

    /// Closes the filesystem: notifies the ref manager, clears the index and releases the
    /// archive provider (closing it if nothing else still shares it).
    ///
    /// Mirrors `close()`.
    fn close(&self) -> io::Result<()> {
        // A second close finds the manager already closed; Java would throw there, but closing
        // an already-closed filesystem is harmless, so it is ignored.
        let _ = self.base.get_ref_manager().on_close(self);
        self.base.fs_index().clear();
        let taken = self.provider.borrow_mut().take();
        if let Some(mut provider) = taken {
            if let Some(p) = Rc::get_mut(&mut provider) {
                p.close()?;
            }
        }
        Ok(())
    }
}

impl Deref for CpioFileSystem {
    type Target = AbstractFileSystemBase<CpioArchiveEntry>;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for CpioFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::cpio::cpio_archive::test_archives::newc_archive;
    use crate::file::formats::cpio::cpio_archive::{C_ISDIR, C_ISFIFO, C_ISLNK, C_ISREG};
    use crate::filesystem::gfilesystem::abstract_single_payload_file_system::test_support::MemProvider;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::util::task::DummyMonitor;

    const CONTAINER: &str = "file:///tmp/initrd.cpio?MD5=00112233445566778899aabbccddeeff";

    struct Fixture {
        _dir: tempfile::TempDir,
        svc: FileSystemService,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        Fixture { _dir: dir, svc }
    }

    fn open(fx: &Fixture, bytes: Vec<u8>) -> io::Result<CpioFileSystem> {
        let container = Fsrl::from_string(CONTAINER).unwrap();
        let provider: Rc<dyn ByteProvider> = Rc::new(MemProvider::new(bytes, Some(container.clone())));
        CpioFileSystem::new(container.make_nested("cpio"), provider, &fx.svc, &DummyMonitor)
    }

    fn sample(fx: &Fixture) -> CpioFileSystem {
        open(
            fx,
            newc_archive(&[
                ("bin", C_ISDIR | 0o755, b""),
                ("bin/busybox", C_ISREG | 0o755, b"\x7fELF...."),
                ("bin/sh", C_ISLNK | 0o777, b"busybox"),
                ("etc/fifo", C_ISFIFO | 0o644, b""),
                ("etc/dangling", C_ISLNK | 0o777, b"../nowhere/x"),
            ]),
        )
        .unwrap()
    }

    fn contents(p: &dyn ByteProvider) -> Vec<u8> {
        p.read_bytes(0, p.length()).unwrap()
    }

    fn look(fs: &CpioFileSystem, p: &str) -> Box<dyn GFile<AbstractFsHandle>> {
        GFileSystem::lookup(fs, Some(p)).unwrap().unwrap()
    }

    #[test]
    fn indexes_members_in_archive_order() {
        let fx = fixture();
        let fs = sample(&fx);
        assert_eq!(GFileSystem::get_name(&fs), "initrd.cpio");
        assert_eq!(fs.get_type(), "cpio");
        assert_eq!(fs.get_description(), "CPIO");
        // root + bin + busybox + sh + etc (auto-created) + fifo + dangling
        assert_eq!(GFileSystem::get_file_count(&fs), 7);
        let root: Vec<String> =
            GFileSystem::get_listing(&fs, None).unwrap().iter().map(|f| f.get_name().to_owned()).collect();
        assert_eq!(root, ["bin", "etc"]);
        assert_eq!(fs.fs_index().get_file_by_index(1).unwrap().get_path(), "/bin/busybox");
        let sh = look(&fs, "/bin/sh");
        assert_eq!(fs.fs_index().get_symlink_path(Some(&*sh)), Some("busybox"));
        assert_eq!(sh.get_length(), 7);
    }

    #[test]
    fn file_types() {
        let fx = fixture();
        let fs = sample(&fx);
        let m = &DummyMonitor;
        let ty = |p: &str| GFileSystem::get_file_type(&fs, &*look(&fs, p), m);
        assert_eq!(ty("/bin"), FileType::Directory);
        assert_eq!(ty("/bin/busybox"), FileType::File);
        assert_eq!(ty("/bin/sh"), FileType::SymbolicLink);
        assert_eq!(ty("/etc/fifo"), FileType::Other);
        assert_eq!(ty("/etc"), FileType::Unknown);
    }

    #[test]
    fn byte_provider_follows_symlinks_and_is_cached_by_the_service() {
        let fx = fixture();
        let fs = sample(&fx);
        let m = &DummyMonitor;
        let busybox = look(&fs, "/bin/busybox");
        let p = GFileSystem::get_byte_provider(&fs, &*busybox, m).unwrap().unwrap();
        assert_eq!(contents(&*p), b"\x7fELF....");
        let fsrl = p.get_fsrl().unwrap();
        assert_eq!(fsrl.path(), Some("/bin/busybox"));
        assert!(fsrl.md5().is_some(), "derived provider FSRL carries the payload MD5");
        assert!(fx
            .svc
            .has_derived_file(&Fsrl::from_string(CONTAINER).unwrap(), "/bin/busybox", m)
            .unwrap());

        let sh = look(&fs, "/bin/sh");
        let p = GFileSystem::get_byte_provider(&fs, &*sh, m).unwrap().unwrap();
        assert_eq!(contents(&*p), b"\x7fELF....");

        let dangling = look(&fs, "/etc/dangling");
        assert!(GFileSystem::get_byte_provider(&fs, &*dangling, m).unwrap().is_none());
        let etc = look(&fs, "/etc");
        assert!(GFileSystem::get_byte_provider(&fs, &*etc, m).unwrap().is_none());
        let bin = look(&fs, "/bin");
        let err = GFileSystem::get_byte_provider(&fs, &*bin, m).err().unwrap();
        assert_eq!(err.to_string(), "CPIO entry bin is not a regular file.");
    }

    #[test]
    fn byte_provider_fails_once_service_is_gone() {
        let fx = fixture();
        let fs = sample(&fx);
        let busybox = look(&fs, "/bin/busybox");
        drop(fx);
        assert!(GFileSystem::get_byte_provider(&fs, &*busybox, &DummyMonitor).is_err());
    }

    #[test]
    fn attributes() {
        let fx = fixture();
        let fs = sample(&fx);
        let sh = look(&fs, "/bin/sh");
        let a = GFileSystem::get_file_attributes(&fs, &*sh, &DummyMonitor);
        assert_eq!(a.get_str(FileAttributeType::NameAttr, ""), "bin/sh");
        assert_eq!(a.get_long(FileAttributeType::SizeAttr, -1), 7);
        assert_eq!(a.get_long(FileAttributeType::UserIdAttr, -1), 1000);
        assert_eq!(a.get_long(FileAttributeType::GroupIdAttr, -1), 100);
        assert_eq!(
            a.get(FileAttributeType::ModifiedDateAttr),
            Some(&FileAttributeValue::Date(1_600_000_000_000))
        );
        assert_eq!(
            a.get(FileAttributeType::FileTypeAttr),
            Some(&FileAttributeValue::FileType(FileType::SymbolicLink))
        );
        assert_eq!(a.get_str(FileAttributeType::SymlinkDestAttr, ""), "busybox");
        assert_eq!(a.get_named("Mode"), Some(&FileAttributeValue::Str("a1ff".into())));
        assert_eq!(a.get_named("Format"), Some(&FileAttributeValue::Str("1".into())));
        assert_eq!(a.get_named("Checksum"), Some(&FileAttributeValue::Str("0".into())));
        assert!(a.get_named("Device ID").is_none());
        let etc = look(&fs, "/etc");
        assert!(GFileSystem::get_file_attributes(&fs, &*etc, &DummyMonitor).get_attributes().is_empty());
    }

    #[test]
    fn truncated_archive_keeps_entries_read_so_far() {
        let fx = fixture();
        let mut bytes = newc_archive(&[("a", C_ISREG, b"1234"), ("b", C_ISREG, b"5678")]);
        bytes.truncate(120);
        let fs = open(&fx, bytes).unwrap();
        assert!(GFileSystem::lookup(&fs, Some("a")).unwrap().is_some());
        assert!(GFileSystem::lookup(&fs, Some("b")).unwrap().is_none());
    }

    #[test]
    fn bad_archive_propagates_error() {
        let fx = fixture();
        assert!(open(&fx, b"not a cpio archive".to_vec()).is_err());
    }

    #[test]
    fn close_through_shared_ref_clears_index_and_notifies_ref_manager() {
        let fx = fixture();
        let fs = sample(&fx);
        assert!(!fs.is_closed());
        let shared = &fs;
        GFileSystem::close(shared).unwrap();
        assert!(fs.is_closed());
        assert!(GFileSystem::get_ref_manager(&fs).is_closed());
        assert_eq!(GFileSystem::get_file_count(&fs), 0);
        assert!(GFileSystem::lookup(&fs, Some("/bin/busybox")).unwrap().is_none());
        // Closing twice is harmless.
        GFileSystem::close(&fs).unwrap();
    }
}
