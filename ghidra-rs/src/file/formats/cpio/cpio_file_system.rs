//! Port of `ghidra.file.formats.cpio.CpioFileSystem`.
//!
//! A filesystem over a cpio archive, built on [`AbstractFileSystemBase`] and the hand-written
//! [`CpioArchiveReader`] (standing in for Apache commons-compress's `CpioArchiveInputStream`).
//!
//! Differences from Java, both forced by what is ported so far:
//! - The Java constructor's `FileSystemService` parameter is not taken: there is no concrete
//!   `FileSystemService` yet, and Java only uses it in `getByteProvider` to wrap the entry's
//!   stream in a cached derived byte provider. cpio stores member data uncompressed and
//!   contiguously, so [`CpioFileSystem::get_byte_provider`] instead returns a
//!   [`ByteProviderWrapper`] over the entry's byte range of the archive -- the same bytes,
//!   without the cache copy.
//! - `refManager.onClose()` is not modeled (see [`AbstractFileSystemBase`]).

use std::io;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::byte_provider_wrapper::ByteProviderWrapper;
use crate::filesystem::gfilesystem::abstract_file_system::{AbstractFileSystemBase, AbstractFsHandle};
use crate::filesystem::gfilesystem::annotations::file_system_info::PRIORITY_DEFAULT;
use crate::filesystem::gfilesystem::file_system_index_helper::copy_file;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::{FileAttributeValue, FileAttributes};
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::util::task::TaskMonitor;

use super::cpio_archive::{CpioArchiveEntry, CpioArchiveReader};

/// Mirrors `CpioFileSystem.MAX_SANE_SYMLINK`.
const MAX_SANE_SYMLINK: u64 = 64 * 1024;

/// The [`ByteProvider`] handed out for a cpio member: a range of the shared archive provider.
pub type CpioByteProvider = ByteProviderWrapper<Rc<dyn ByteProvider>>;

/// A filesystem over the members of a cpio archive.
///
/// Mirrors `ghidra.file.formats.cpio.CpioFileSystem`.
pub struct CpioFileSystem {
    base: AbstractFileSystemBase<CpioArchiveEntry>,
    provider: Option<Rc<dyn ByteProvider>>,
}

impl CpioFileSystem {
    /// `@FileSystemInfo(type = "cpio")`.
    pub const FS_TYPE: &'static str = "cpio";
    /// `@FileSystemInfo(description = "CPIO")`.
    pub const DESCRIPTION: &'static str = "CPIO";
    /// `@FileSystemInfo` default priority.
    pub const PRIORITY: i32 = PRIORITY_DEFAULT;

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
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Self> {
        let mut base = AbstractFileSystemBase::new(fs_fsrl);
        monitor.set_message("Opening CPIO...");
        match Self::index_entries(&mut base, provider.as_ref(), monitor) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // silently ignore EOFExceptions
            }
            other => other?,
        }
        Ok(CpioFileSystem { base, provider: Some(provider) })
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

    /// Closes the filesystem: clears the index and releases the archive provider (closing it
    /// if no byte provider handed out by this filesystem still shares it).
    ///
    /// Mirrors `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        self.base.fs_index_mut().clear();
        if let Some(mut provider) = self.provider.take() {
            if let Some(p) = Rc::get_mut(&mut provider) {
                p.close()?;
            }
        }
        Ok(())
    }

    /// `true` once [`close`](Self::close)d. Mirrors `isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.provider.is_none()
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

    /// The type of `file`, or [`FileType::Unknown`] if it has no cpio entry (e.g. an
    /// auto-created directory). Mirrors `getFileType(GFile, TaskMonitor)`.
    pub fn get_file_type(
        &self,
        file: &dyn GFile<AbstractFsHandle, Fsrl>,
        _monitor: &dyn TaskMonitor,
    ) -> FileType {
        self.base.fs_index().get_metadata(file).map_or(FileType::Unknown, Self::entry_file_type)
    }

    /// The attributes of `file`'s cpio entry (empty if it has none). Device numbers are only
    /// reported for the old formats and the checksum only for the new ones, as in Java.
    ///
    /// Mirrors `getFileAttributes(GFile, TaskMonitor)`.
    pub fn get_file_attributes(
        &self,
        file: &dyn GFile<AbstractFsHandle, Fsrl>,
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

    /// A [`ByteProvider`] with the contents of `file` (after resolving symlinks), or `None` if
    /// it has no cpio entry.
    ///
    /// Mirrors `getByteProvider(GFile, TaskMonitor)`: the archive is rescanned for the first
    /// entry equal (by name) to the file's entry, whose data is returned; see the module docs
    /// for how the result differs from Java's derived byte provider.
    ///
    /// # Errors
    /// If the file is not a regular file, the filesystem is closed, the entry cannot be found
    /// again, or reading the archive fails.
    pub fn get_byte_provider(
        &self,
        file: &dyn GFile<AbstractFsHandle, Fsrl>,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Option<CpioByteProvider>> {
        let index = self.base.fs_index();
        let Some(file) = index.resolve_symlinks(file)?.map(|f| copy_file(f)) else {
            return Ok(None);
        };
        let Some(target_entry) = index.get_metadata(&file) else { return Ok(None) };
        if !target_entry.is_regular_file() {
            return Err(io::Error::other(format!(
                "CPIO entry {} is not a regular file.",
                file.get_name()
            )));
        }
        let provider = self
            .provider
            .as_ref()
            .ok_or_else(|| io::Error::other("CPIO filesystem is closed"))?;
        let mut reader = CpioArchiveReader::new(provider.as_ref());
        while let Some(current) = reader.next_entry()? {
            if &current == target_entry {
                return Ok(Some(ByteProviderWrapper::with_range_and_fsrl(
                    Rc::clone(provider),
                    current.data_offset(),
                    current.size(),
                    Some(file.get_fsrl().clone()),
                )));
            }
        }
        Err(io::Error::other(format!("Unable to seek to entry: {}", file.get_name())))
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
    use crate::util::task::DummyMonitor;

    fn open(bytes: Vec<u8>) -> io::Result<CpioFileSystem> {
        let container = Fsrl::from_string("file:///tmp/initrd.cpio").unwrap();
        let provider: Rc<dyn ByteProvider> = Rc::new(MemProvider::new(bytes, Some(container.clone())));
        CpioFileSystem::new(container.make_nested("cpio"), provider, &DummyMonitor)
    }

    fn sample() -> CpioFileSystem {
        open(newc_archive(&[
            ("bin", C_ISDIR | 0o755, b""),
            ("bin/busybox", C_ISREG | 0o755, b"\x7fELF...."),
            ("bin/sh", C_ISLNK | 0o777, b"busybox"),
            ("etc/fifo", C_ISFIFO | 0o644, b""),
            ("etc/dangling", C_ISLNK | 0o777, b"../nowhere/x"),
        ]))
        .unwrap()
    }

    fn contents(p: &CpioByteProvider) -> Vec<u8> {
        p.read_bytes(0, p.length()).unwrap()
    }

    #[test]
    fn indexes_members_in_archive_order() {
        let fs = sample();
        assert_eq!(fs.get_name(), "initrd.cpio");
        // root + bin + busybox + sh + etc (auto-created) + fifo + dangling
        assert_eq!(fs.get_file_count(), 7);
        let root: Vec<&str> = fs.get_listing(None).iter().map(|f| f.get_name()).collect();
        assert_eq!(root, ["bin", "etc"]);
        assert_eq!(fs.fs_index().get_file_by_index(1).unwrap().get_path(), "/bin/busybox");
        let sh = fs.lookup(Some("/bin/sh")).unwrap();
        assert_eq!(fs.fs_index().get_symlink_path(Some(sh)), Some("busybox"));
        assert_eq!(sh.get_length(), 7);
    }

    #[test]
    fn file_types() {
        let fs = sample();
        let m = &DummyMonitor;
        let ty = |p: &str| fs.get_file_type(fs.lookup(Some(p)).unwrap(), m);
        assert_eq!(ty("/bin"), FileType::Directory);
        assert_eq!(ty("/bin/busybox"), FileType::File);
        assert_eq!(ty("/bin/sh"), FileType::SymbolicLink);
        assert_eq!(ty("/etc/fifo"), FileType::Other);
        assert_eq!(ty("/etc"), FileType::Unknown);
    }

    #[test]
    fn byte_provider_follows_symlinks() {
        let fs = sample();
        let m = &DummyMonitor;
        let busybox = fs.lookup(Some("/bin/busybox")).unwrap();
        let p = fs.get_byte_provider(busybox, m).unwrap().unwrap();
        assert_eq!(contents(&p), b"\x7fELF....");
        assert_eq!(
            p.get_fsrl().unwrap().to_string(),
            "file:///tmp/initrd.cpio|cpio:///bin/busybox"
        );
        let sh = fs.lookup(Some("/bin/sh")).unwrap();
        let p = fs.get_byte_provider(sh, m).unwrap().unwrap();
        assert_eq!(contents(&p), b"\x7fELF....");

        let dangling = fs.lookup(Some("/etc/dangling")).unwrap();
        assert!(fs.get_byte_provider(dangling, m).unwrap().is_none());
        let etc = fs.lookup(Some("/etc")).unwrap();
        assert!(fs.get_byte_provider(etc, m).unwrap().is_none());
        let bin = fs.lookup(Some("/bin")).unwrap();
        let err = fs.get_byte_provider(bin, m).err().unwrap();
        assert_eq!(err.to_string(), "CPIO entry bin is not a regular file.");
    }

    #[test]
    fn attributes() {
        let fs = sample();
        let sh = fs.lookup(Some("/bin/sh")).unwrap();
        let a = fs.get_file_attributes(sh, &DummyMonitor);
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
        let etc = fs.lookup(Some("/etc")).unwrap();
        assert!(fs.get_file_attributes(etc, &DummyMonitor).get_attributes().is_empty());
    }

    #[test]
    fn truncated_archive_keeps_entries_read_so_far() {
        let mut bytes = newc_archive(&[("a", C_ISREG, b"1234"), ("b", C_ISREG, b"5678")]);
        bytes.truncate(120);
        let fs = open(bytes).unwrap();
        assert!(fs.lookup(Some("a")).is_some());
        assert!(fs.lookup(Some("b")).is_none());
    }

    #[test]
    fn bad_archive_propagates_error() {
        assert!(open(b"not a cpio archive".to_vec()).is_err());
    }

    #[test]
    fn close_clears_index() {
        let mut fs = sample();
        assert!(!fs.is_closed());
        fs.close().unwrap();
        assert!(fs.is_closed());
        assert_eq!(fs.get_file_count(), 0);
        assert!(fs.lookup(Some("/bin/busybox")).is_none());
    }
}
