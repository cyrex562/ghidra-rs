//! Rust port of `ghidra.file.formats.sevenzip.SevenZipFileSystem`.
//!
//! A `GFileSystem` that drives the 7-Zip libraries to open archives and extract files.
//!
//! # Shape
//!
//! The Java class is concrete *and* a base: `ZipFileSystem`, `ISO9660FileSystem` and
//! `HFSPlusFileSystem` all extend it. Those three subclasses override no behaviour at all --
//! they exist purely to carry a different `@FileSystemInfo` annotation (a different filesystem
//! type name, description, factory and priority) so the same 7-Zip machinery surfaces under
//! "zip", "iso9660" and "hfs" FSRLs. So the split here is:
//!
//! * [`SevenZipFileSystemBase`] -- the shared state and all the concrete behaviour.
//! * [`SevenZipFileSystem`] -- the trait declaring exactly what the subclasses vary: the
//!   filesystem-info metadata. Rust has no analog of a Java annotation, and the annotation is
//!   the *only* thing the hierarchy overrides, so it becomes the trait.
//!
//! # 7-Zip seam
//!
//! `net.sf.sevenzipjbinding` is a third-party JNI binding, not an in-repo Ghidra type, so it
//! has no port to reuse and no entry in `seam_stubs.rs`. Its contract is modelled here as a
//! small set of traits ([`InArchive`], [`ArchiveItem`], [`ArchiveExtractCallback`]) plus the
//! two result enums, in the same spirit as
//! [`SZByteProviderStream`](super::sz_byte_provider_stream::SZByteProviderStream), which maps
//! the binding's `IInStream` onto Rust's [`Read`](std::io::Read)/[`Seek`](std::io::Seek).
//! Java's `ISequentialOutStream` return from `getStream()` (return `this` to receive bytes,
//! `null` to skip the entry) collapses to a `bool` here, since the callback is always the
//! callback object itself.
//!
//! # Synchronization
//!
//! The Java class synchronizes on `fsIndex` because concurrent calls into the native 7-Zip
//! library have been observed to core-dump the JVM. Rust's `&mut self` on the mutating entry
//! points enforces the same exclusion statically, so no lock is needed here.
//!
//! WARNING (carried from the Java doc): care must be taken to serialize access to the
//! underlying 7-Zip library.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::rc::Rc;

use crate::file::seam_stubs::{
    FileAttributeValue, FileAttributes, FileCacheEntry, FileCacheEntryBuilder,
    FileSystemIndexHelper,
};
use crate::filesystem::gfilesystem::crypto::crypto_session::CryptoSession;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{
    FsGetListing, FsrlLike as GFileFsrlLike, GFileImpl, HasFsrlRoot,
};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::util::exception::{CancelledException, CryptoException};
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

const ORIGINATOR: &str = "SevenZipFileSystem";

// ─── 7-Zip library seam ───────────────────────────────────────────────────────

/// Mirrors `net.sf.sevenzipjbinding.SevenZipException`.
///
/// The cause chain is modelled explicitly (rather than through
/// [`std::error::Error::source`]) because [`unwrap_sz_exception`] has to walk it and
/// distinguish a nested `SevenZipException` from a nested `IOException`.
#[derive(Debug)]
pub struct SevenZipError {
    message: String,
    cause: Option<Box<SevenZipCause>>,
}

/// The two kinds of exception `SevenZipException` is ever constructed around in this file.
#[derive(Debug)]
pub enum SevenZipCause {
    SevenZip(SevenZipError),
    Io(io::Error),
}

impl SevenZipError {
    /// Mirrors `new SevenZipException(String)`.
    pub fn new(message: impl Into<String>) -> Self {
        SevenZipError { message: message.into(), cause: None }
    }

    /// Mirrors `new SevenZipException(Throwable)` where the cause is an `IOException`.
    pub fn from_io(cause: io::Error) -> Self {
        SevenZipError {
            message: cause.to_string(),
            cause: Some(Box::new(SevenZipCause::Io(cause))),
        }
    }

    /// Mirrors `new SevenZipException(String, SevenZipException)`.
    pub fn wrapping(message: impl Into<String>, cause: SevenZipError) -> Self {
        SevenZipError {
            message: message.into(),
            cause: Some(Box::new(SevenZipCause::SevenZip(cause))),
        }
    }

    /// The wrapped cause, if any. Mirrors `getCause()`.
    pub fn cause(&self) -> Option<&SevenZipCause> {
        self.cause.as_deref()
    }
}

impl fmt::Display for SevenZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SevenZipError {}

/// Result alias for the 7-Zip seam, mirroring Java's `throws SevenZipException`.
pub type SzResult<T> = Result<T, SevenZipError>;

/// Mirrors `net.sf.sevenzipjbinding.ArchiveFormat`.
///
/// [`fmt::Display`] renders the same string as the Java enum's `toString()` (its
/// `methodName`), which is what `getFileAttributes` reports as "Archive Format".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    Split,
    Rar,
    Rar5,
    Lzma,
    Iso,
    Hfs,
    Gzip,
    Cpio,
    BZip2,
    SevenZip,
    Z,
    Arj,
    Cab,
    Lzh,
    Nsis,
    Deb,
    Rpm,
    Udf,
    Wim,
    Xar,
    Fat,
    Ntfs,
}

impl ArchiveFormat {
    /// The 7-Zip method name for this format, as returned by the Java enum's `getMethodName()`.
    pub fn method_name(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "Zip",
            ArchiveFormat::Tar => "Tar",
            ArchiveFormat::Split => "Split",
            ArchiveFormat::Rar => "Rar",
            ArchiveFormat::Rar5 => "Rar5",
            ArchiveFormat::Lzma => "Lzma",
            ArchiveFormat::Iso => "Iso",
            ArchiveFormat::Hfs => "HFS",
            ArchiveFormat::Gzip => "gzip",
            ArchiveFormat::Cpio => "Cpio",
            ArchiveFormat::BZip2 => "BZip2",
            ArchiveFormat::SevenZip => "7z",
            ArchiveFormat::Z => "Z",
            ArchiveFormat::Arj => "Arj",
            ArchiveFormat::Cab => "Cab",
            ArchiveFormat::Lzh => "Lzh",
            ArchiveFormat::Nsis => "Nsis",
            ArchiveFormat::Deb => "Deb",
            ArchiveFormat::Rpm => "Rpm",
            ArchiveFormat::Udf => "Udf",
            ArchiveFormat::Wim => "Wim",
            ArchiveFormat::Xar => "Xar",
            ArchiveFormat::Fat => "FAT",
            ArchiveFormat::Ntfs => "NTFS",
        }
    }
}

impl fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.method_name())
    }
}

/// Mirrors `net.sf.sevenzipjbinding.ExtractAskMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractAskMode {
    Extract,
    Test,
    Skip,
}

/// Mirrors `net.sf.sevenzipjbinding.ExtractOperationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractOperationResult {
    Ok,
    UnsupportedMethod,
    DataError,
    CrcError,
    UnknownOperationResult,
    WrongPassword,
}

/// Mirrors `net.sf.sevenzipjbinding.simple.ISimpleInArchiveItem`, one entry in an archive.
///
/// Every accessor can fail because the underlying native call can; the `Option` layer on top
/// mirrors the Java getters that return boxed types and may hand back `null` for a property
/// the archive format does not record.
pub trait ArchiveItem {
    /// Mirrors `getItemIndex()`.
    fn item_index(&self) -> i32;

    /// Mirrors `getPath()`.
    fn path(&self) -> SzResult<String>;

    /// Mirrors `getSize()`.
    fn size(&self) -> SzResult<Option<i64>>;

    /// Mirrors `getPackedSize()`.
    fn packed_size(&self) -> SzResult<Option<i64>> {
        Ok(None)
    }

    /// Mirrors `isFolder()`.
    fn is_folder(&self) -> SzResult<bool>;

    /// Mirrors `isEncrypted()`.
    fn is_encrypted(&self) -> SzResult<bool>;

    /// Mirrors `getComment()`.
    fn comment(&self) -> SzResult<Option<String>> {
        Ok(None)
    }

    /// Mirrors `getCRC()`.
    fn crc(&self) -> SzResult<Option<i32>> {
        Ok(None)
    }

    /// Mirrors `getMethod()`.
    fn method(&self) -> SzResult<Option<String>> {
        Ok(None)
    }

    /// Mirrors `getCreationTime()`, as epoch milliseconds.
    fn creation_time(&self) -> SzResult<Option<i64>> {
        Ok(None)
    }

    /// Mirrors `getLastWriteTime()`, as epoch milliseconds.
    fn last_write_time(&self) -> SzResult<Option<i64>> {
        Ok(None)
    }
}

/// Mirrors the parts of `net.sf.sevenzipjbinding.IArchiveExtractCallback`,
/// `ISequentialOutStream` and `ICryptoGetTextPassword` that a 7-Zip extract drives.
///
/// The Java callbacks implement all three interfaces at once, so they are one trait here.
pub trait ArchiveExtractCallback {
    /// Mirrors `getStream(int, ExtractAskMode)`. Returning `true` means "send me this entry's
    /// bytes through [`write`](Self::write)"; `false` is Java's `null` return, i.e. skip.
    fn get_stream(&mut self, index: i32, extract_ask_mode: ExtractAskMode) -> SzResult<bool>;

    /// Mirrors `prepareOperation(ExtractAskMode)`.
    fn prepare_operation(&mut self, extract_ask_mode: ExtractAskMode) -> SzResult<()>;

    /// Mirrors `cryptoGetTextPassword()`.
    fn crypto_get_text_password(&mut self) -> SzResult<String>;

    /// Mirrors `ISequentialOutStream.write(byte[])`, returning the number of bytes accepted.
    fn write(&mut self, data: &[u8]) -> SzResult<usize>;

    /// Mirrors `setOperationResult(ExtractOperationResult)`.
    fn set_operation_result(&mut self, result: ExtractOperationResult) -> SzResult<()>;

    /// Mirrors `setTotal(long)`.
    fn set_total(&mut self, _total: i64) -> SzResult<()> {
        Ok(())
    }

    /// Mirrors `setCompleted(long)`.
    fn set_completed(&mut self, _complete: i64) -> SzResult<()> {
        Ok(())
    }
}

/// Mirrors `net.sf.sevenzipjbinding.IInArchive`, an opened archive.
pub trait InArchive {
    /// Mirrors `getArchiveFormat()`.
    fn archive_format(&self) -> ArchiveFormat;

    /// Mirrors `getSimpleInterface().getArchiveItems()`.
    fn archive_items(&self) -> SzResult<Vec<Rc<dyn ArchiveItem>>>;

    /// Mirrors `extract(int[], boolean, IArchiveExtractCallback)`.
    fn extract(
        &self,
        indices: &[i32],
        test_mode: bool,
        callback: &mut dyn ArchiveExtractCallback,
    ) -> SzResult<()>;

    /// Mirrors `close()`.
    fn close(&mut self) -> SzResult<()>;
}

// ─── FSRL stand-ins ───────────────────────────────────────────────────────────

/// Stand-in for `ghidra.formats.gfilesystem.FSRL`, used to parameterize [`GFileImpl`] and the
/// index until a concrete `FSRL` type is ported (the ported
/// [`Fsrl`](crate::filesystem::gfilesystem::fsrl::Fsrl) is a trait with no implementer yet).
///
/// Mirrors the three `FSRL` operations this filesystem actually performs: reading the name,
/// reading the MD5, and deriving a copy with an MD5 attached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SzFsrl {
    path: String,
    md5: Option<String>,
}

impl SzFsrl {
    /// Creates an FSRL for `path` with no MD5 recorded.
    pub fn new(path: impl Into<String>) -> Self {
        SzFsrl { path: path.into(), md5: None }
    }

    /// Mirrors `FSRL.getMD5()`.
    pub fn md5(&self) -> Option<&str> {
        self.md5.as_deref()
    }

    /// Mirrors `FSRL.withMD5(String)`.
    pub fn with_md5(&self, md5: impl Into<String>) -> Self {
        SzFsrl { path: self.path.clone(), md5: Some(md5.into()) }
    }

    /// Mirrors `FSRL.getName()`.
    pub fn name(&self) -> &str {
        base_name_of(&self.path)
    }
}

impl GFileFsrlLike for SzFsrl {
    fn fsrl_name(&self) -> String {
        self.name().to_string()
    }

    fn fsrl_path(&self) -> String {
        self.path.clone()
    }

    fn append_path(&self, segment: &str) -> Self {
        let path = if self.path.ends_with('/') {
            format!("{}{}", self.path, segment)
        } else {
            format!("{}/{}", self.path, segment)
        };
        SzFsrl { path, md5: None }
    }
}

/// Marker `FsrlLike` impl so an [`SzFsrl`] can be used as a [`CryptoSession`] lookup key.
impl crate::filesystem::seam_stubs::FsrlLike for SzFsrl {}

/// Stand-in for `ghidra.formats.gfilesystem.FSRLRoot`, this filesystem's own `fsFSRL`.
///
/// Only `getContainer()` is exercised by this class (to name the archive being opened).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SzFsrlRoot {
    container: SzFsrl,
}

impl SzFsrlRoot {
    /// Creates a root whose container is the archive at `container`.
    pub fn new(container: SzFsrl) -> Self {
        SzFsrlRoot { container }
    }

    /// Mirrors `FSRLRoot.getContainer()`.
    pub fn get_container(&self) -> &SzFsrl {
        &self.container
    }
}

/// Filesystem handle stored inside each [`GFileImpl`] this filesystem hands out.
///
/// The Java `GFileImpl` holds a back-reference to the owning `GFileSystem`; storing the real
/// [`SevenZipFileSystemBase`] there would make every file alias the filesystem it lives in, so
/// this carries only what `GFileImpl` needs from it: the root FSRL, and a listing hook.
/// Listing is served from [`SevenZipFileSystemBase`] itself, so the hook is inert here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SzFsHandle {
    root: SzFsrl,
}

impl SzFsHandle {
    /// Creates a handle rooted at `root`.
    pub fn new(root: SzFsrl) -> Self {
        SzFsHandle { root }
    }
}

impl HasFsrlRoot<SzFsrl> for SzFsHandle {
    fn root_fsrl(&self) -> &SzFsrl {
        &self.root
    }
}

impl FsGetListing<SzFsHandle, SzFsrl> for SzFsHandle {
    fn fs_get_listing(
        &self,
        _file: &dyn GFile<SzFsHandle, SzFsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<SzFsHandle, SzFsrl>>>> {
        Ok(vec![])
    }
}

/// The concrete [`GFile`] type this filesystem indexes.
pub type SzGFile = GFileImpl<SzFsHandle, SzFsrl>;

// ─── FileSystemService seam ───────────────────────────────────────────────────

/// The two `ghidra.formats.gfilesystem.FileSystemService` operations this filesystem uses.
///
/// The ported [`FileSystemService`](crate::filesystem::gfilesystem::file_system_service::FileSystemService)
/// cannot serve this class yet: its `create_temp_file` hands back the empty
/// `FileCacheEntryBuilderLike` marker, which has no `write`/`finish`, because `FileCache`
/// itself is unported. This narrow seam names exactly what is needed and should be dropped in
/// favour of the real service once `FileCache` lands.
pub trait SevenZipFsService {
    /// Mirrors `FileSystemService.newCryptoSession()`.
    fn new_crypto_session(&self) -> Box<dyn CryptoSession<SzFsrl>>;

    /// Mirrors `FileSystemService.createTempFile(long)`.
    fn create_temp_file(&self, size_hint: i64) -> io::Result<FileCacheEntryBuilder>;
}

// ─── The abstract operations ──────────────────────────────────────────────────

/// The behaviour `SevenZipFileSystem`'s subclasses vary.
///
/// In Java this is the `@FileSystemInfo` annotation: `SevenZipFileSystem` declares
/// `type = "7zip"`, and `ZipFileSystem` / `ISO9660FileSystem` / `HFSPlusFileSystem` each
/// re-declare it with a different type, description, factory and priority while inheriting
/// every method unchanged. Rust has no annotation inheritance, so the metadata becomes an
/// overridable trait; [`SevenZipFileSystemBase`] supplies the `"7zip"` flavour.
pub trait SevenZipFileSystem {
    /// Mirrors `@FileSystemInfo(type = ...)`.
    fn fs_type(&self) -> &str;

    /// Mirrors `@FileSystemInfo(description = ...)`.
    fn description(&self) -> &str;

    /// Mirrors `@FileSystemInfo(priority = ...)`, defaulting to
    /// `FileSystemInfo.PRIORITY_DEFAULT`.
    fn priority(&self) -> i32 {
        PRIORITY_DEFAULT
    }
}

/// Mirrors `FileSystemInfo.PRIORITY_DEFAULT`.
pub const PRIORITY_DEFAULT: i32 = 0;

/// Mirrors `FileSystemInfo.PRIORITY_HIGH`, the priority `ZipFileSystem` declares.
pub const PRIORITY_HIGH: i32 = 10;

// ─── The shared state and behaviour ───────────────────────────────────────────

/// The shared state and concrete behaviour of `SevenZipFileSystem`.
///
/// See the [module docs](self) for why the class is split into this struct plus the
/// [`SevenZipFileSystem`] trait.
pub struct SevenZipFileSystemBase<S: SevenZipFsService> {
    /// Mirrors the inherited `AbstractFileSystem.fsFSRL`.
    fs_fsrl: SzFsrlRoot,
    /// Mirrors the inherited `AbstractFileSystem.fsService`.
    fs_service: S,
    /// Mirrors the inherited `AbstractFileSystem.fsIndex`.
    fs_index: FileSystemIndexHelper<SzFsHandle, SzFsrl, Rc<dyn ArchiveItem>>,
    /// Per-embedded-file passwords, keyed by archive item index.
    passwords: HashMap<i32, String>,
    archive: Option<Box<dyn InArchive>>,
    /// Mirrors the `szBPStream` field. The Java field holds the `SZByteProviderStream` wrapping
    /// the container; here it only has to record whether the filesystem is still open (which is
    /// all the Java code reads it for, in `isClosed()`), because
    /// [`mount`](Self::mount) hands the stream to the archive opener.
    sz_bp_stream_open: bool,
    items: Vec<Rc<dyn ArchiveItem>>,
    archive_format: Option<ArchiveFormat>,
}

impl<S: SevenZipFsService> SevenZipFileSystem for SevenZipFileSystemBase<S> {
    fn fs_type(&self) -> &str {
        "7zip"
    }

    fn description(&self) -> &str {
        "7Zip"
    }
}

impl<S: SevenZipFsService> SevenZipFileSystemBase<S> {
    /// Mirrors `SevenZipFileSystem(FSRLRoot, FileSystemService)`.
    pub fn new(fsrl: SzFsrlRoot, fs_service: S) -> Self {
        let root = SzFsrl::new("/");
        let fs_index = FileSystemIndexHelper::new(SzFsHandle::new(root.clone()), root);
        SevenZipFileSystemBase {
            fs_fsrl: fsrl,
            fs_service,
            fs_index,
            passwords: HashMap::new(),
            archive: None,
            sz_bp_stream_open: false,
            items: Vec::new(),
            archive_format: None,
        }
    }

    /// Mirrors the inherited `AbstractFileSystem.getFSRL()`.
    pub fn get_fsrl(&self) -> &SzFsrlRoot {
        &self.fs_fsrl
    }

    /// Mirrors the inherited `AbstractFileSystem.getName()`, the container file's name.
    pub fn get_name(&self) -> &str {
        self.fs_fsrl.get_container().name()
    }

    /// Mirrors the inherited `AbstractFileSystem.getRootDir()`.
    pub fn get_root_dir(&self) -> &SzGFile {
        self.fs_index.get_root_dir()
    }

    /// Opens the specified 7-Zip container and initializes this file system with its contents.
    ///
    /// Mirrors `mount(ByteProvider, TaskMonitor)`. Java opens the container by wrapping it in a
    /// [`SZByteProviderStream`](super::sz_byte_provider_stream::SZByteProviderStream) and
    /// calling the static `SevenZip.openInArchive`; since the native opener has no Rust
    /// counterpart, the already-opened `archive` is passed in and the caller is responsible for
    /// having wrapped the container. `open_archive` is what
    /// `SevenZipFileSystemFactory.initNativeLibraries()` + `SevenZip.openInArchive()` produce
    /// together, so a failure there is the `IOException("Could not initialize 7zip native
    /// libraries")` / `IOException("Failed to open archive: ...")` case.
    pub fn mount(
        &mut self,
        archive: Box<dyn InArchive>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MountError> {
        self.sz_bp_stream_open = true;
        self.archive_format = Some(archive.archive_format());
        self.items = archive
            .archive_items()
            .map_err(|e| MountError::Io(self.failed_to_open(e)))?;
        self.archive = Some(archive);

        self.index_files(monitor)?;
        self.ensure_passwords(monitor).map_err(MountError::Io)?;
        Ok(())
    }

    fn failed_to_open(&self, cause: SevenZipError) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Failed to open archive: {}: {cause}",
                self.fs_fsrl.get_container().name()
            ),
        )
    }

    /// Mirrors `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(mut archive) = self.archive.take() {
            if let Err(e) = archive.close() {
                unchecked_close_failed("Problem closing 7-Zip archive", &e);
            }
        }
        self.sz_bp_stream_open = false;
        self.fs_index.clear();
        self.items.clear();
        Ok(())
    }

    /// Mirrors `isClosed()`, which reports on the container stream rather than the archive.
    pub fn is_closed(&self) -> bool {
        !self.sz_bp_stream_open
    }

    fn index_files(&mut self, monitor: &dyn TaskMonitor) -> Result<(), MountError> {
        monitor.set_message("Indexing files");
        monitor.initialize(self.items.len() as i64);
        for item in self.items.clone() {
            if monitor.is_cancelled() {
                return Err(MountError::Cancelled(CancelledException::default()));
            }

            let item_size = item
                .size()
                .map_err(|e| MountError::Io(self.failed_to_open(e)))?
                .unwrap_or(-1);
            let is_folder = item
                .is_folder()
                .map_err(|e| MountError::Io(self.failed_to_open(e)))?;
            let path = self
                .fixup_item_path(item.as_ref())
                .map_err(|e| MountError::Io(self.failed_to_open(e)))?;

            self.fs_index.store_file(
                &path,
                item.item_index() as i64,
                is_folder,
                item_size,
                Rc::clone(&item),
            );
        }
        Ok(())
    }

    fn fixup_item_path(&self, item: &dyn ArchiveItem) -> SzResult<String> {
        let mut item_path = item.path()?;
        if self.items.len() == 1 && item_path.trim().is_empty() {
            // special case when there is a single unnamed file.
            // use the name of the 7zip file itself, minus the extension
            item_path = strip_extension(self.fs_fsrl.get_container().name()).to_string();
        }
        if item_path.is_empty() {
            item_path = "<blank>".to_string();
        }
        Ok(item_path)
    }

    /// Mirrors `getPasswordForFile(GFile, ISimpleInArchiveItem, TaskMonitor)`.
    fn get_password_for_file(
        &mut self,
        file_name: &str,
        file_fsrl: &SzFsrl,
        encrypted_item: &dyn ArchiveItem,
        monitor: &dyn TaskMonitor,
    ) -> Option<String> {
        let container_fsrl = self.fs_fsrl.get_container().clone();
        let item_index = encrypted_item.item_index();
        if !self.passwords.contains_key(&item_index) {
            let mut crypto_session = self.fs_service.new_crypto_session();
            let prompt = if self.passwords.is_empty() {
                container_fsrl.name().to_string()
            } else {
                format!("{} in {}", file_name, container_fsrl.name())
            };
            let candidates: Vec<_> = crypto_session
                .get_passwords_for(&container_fsrl, &prompt)
                .collect();
            for password_value in candidates {
                monitor.set_message(&format!("Testing password for {file_name}"));

                // we are forced to use strings by 7zip's api
                let password: String =
                    password_value.get_password_chars().unwrap_or(&[]).iter().collect();
                let encrypted_item_indexes = match self.get_encrypted_item_indexes() {
                    Ok(indexes) => indexes,
                    Err(e) => {
                        Msg::error(
                            ORIGINATOR,
                            &format!(
                                "Error when testing password for {}: {e}",
                                file_fsrl.fsrl_path()
                            ),
                        );
                        return None;
                    }
                };
                // `getEncryptedItemIndexes()[0]` in Java; an empty array would have thrown
                // there, so there is nothing left to test here either.
                let Some(&initial_index) = encrypted_item_indexes.first() else {
                    break;
                };

                let mut test_cb =
                    TestPasswordsCallback::new(&password, initial_index, &self.items, monitor);

                // call the SZ extract method using "TEST" mode (ie. no bytes are extracted)
                // on any files that don't have a password yet
                let archive = match self.archive.as_ref() {
                    Some(archive) => archive,
                    None => break,
                };
                if let Err(e) =
                    archive.extract(&encrypted_item_indexes, true /* test mode */, &mut test_cb)
                {
                    Msg::error(
                        ORIGINATOR,
                        &format!(
                            "Error when testing password for {}: {e}",
                            file_fsrl.fsrl_path()
                        ),
                    );
                    return None;
                }
                let success_file_indexes = test_cb.into_success_file_indexes();
                for unlocked_file_index in &success_file_indexes {
                    self.passwords.insert(*unlocked_file_index, password.clone());
                }
                if !success_file_indexes.is_empty() {
                    crypto_session.add_successful_password(&container_fsrl, password_value);
                }
                if self.passwords.contains_key(&item_index) {
                    break;
                }
            }
            crypto_session.close();
        }
        self.passwords.get(&item_index).cloned()
    }

    /// Mirrors `getEncryptedItemIndexes()`.
    fn get_encrypted_item_indexes(&self) -> SzResult<Vec<i32>> {
        let mut result = Vec::new();
        for item in &self.items {
            if item.is_encrypted()? && !self.passwords.contains_key(&item.item_index()) {
                result.push(item.item_index());
            }
        }
        Ok(result)
    }

    /// Mirrors `ensurePasswords(TaskMonitor)`.
    ///
    /// Alert! Unusual code!
    ///
    /// Background: contrary to normal expectations, zip container files can have a unique
    /// password per-embedded-file. Other archive formats may not have that feature, but the
    /// SevenZip jbinding API is designed to allow a per-embedded-file password.
    ///
    /// The following loop tests passwords against the file, first trying a common password
    /// against all the embedded files (this is the most likely scenario), and then when a
    /// password has been found that successfully unlocks the first subset of files, each
    /// remaining subsequent encrypted file's name is used to prompt for the next password.
    ///
    /// If the loop ends without finding a password for an encrypted file, that file will not be
    /// readable unless a password is found for it (see `get_password_for_file`).
    fn ensure_passwords(&mut self, monitor: &dyn TaskMonitor) -> io::Result<()> {
        let mut encrypted_items = self
            .get_encrypted_items_without_passwords()
            .map_err(|e| self.failed_to_open(e))?;

        while let Some(encrypted_item) = self.first_item_without_password(&encrypted_items) {
            if monitor.is_cancelled() {
                break;
            }
            let item_index = encrypted_item.item_index();
            let (file_name, file_fsrl) = match self.fs_index.get_file_by_index(item_index as i64) {
                Some(g_file) => (g_file.get_name().to_string(), g_file.get_fsrl().clone()),
                None => {
                    let path = encrypted_item.path().unwrap_or_else(|_| "<unknown>".to_string());
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Unable to retrieve file {path}"),
                    ));
                }
            };
            self.get_password_for_file(&file_name, &file_fsrl, encrypted_item.as_ref(), monitor);
            if self.passwords.is_empty() {
                // we didn't find any password for any file in the archive.  Abort the loop
                // instead of badgering the user by using other files as prompts
                break;
            }
            encrypted_items.retain(|item| item.item_index() != item_index);
        }

        let no_password_found_list = self
            .get_encrypted_items_without_passwords()
            .map_err(|e| self.failed_to_open(e))?;
        if !no_password_found_list.is_empty() {
            Msg::warn(
                ORIGINATOR,
                &format!(
                    "Unable to find password for {} file(s) in {}",
                    no_password_found_list.len(),
                    self.fs_fsrl.get_container().name()
                ),
            );
        }
        Ok(())
    }

    /// Mirrors `getFirstItemWithoutPassword(List)`.
    fn first_item_without_password(
        &self,
        encrypted_items: &[Rc<dyn ArchiveItem>],
    ) -> Option<Rc<dyn ArchiveItem>> {
        encrypted_items
            .iter()
            .find(|item| !self.passwords.contains_key(&item.item_index()))
            .map(Rc::clone)
    }

    /// Mirrors `getEncryptedItemsWithoutPasswords()`.
    fn get_encrypted_items_without_passwords(&self) -> SzResult<Vec<Rc<dyn ArchiveItem>>> {
        let mut result = Vec::new();
        for item in &self.items {
            if item.is_encrypted()? && !self.passwords.contains_key(&item.item_index()) {
                result.push(Rc::clone(item));
            }
        }
        Ok(result)
    }

    /// Mirrors `getFileAttributes(GFile, TaskMonitor)`.
    pub fn get_file_attributes(
        &self,
        file: &SzGFile,
        _monitor: &dyn TaskMonitor,
    ) -> FileAttributes {
        let mut result = FileAttributes::new();
        if self.fs_index.get_root_dir().get_path() == file.get_path() {
            result.add(FileAttributeType::NameAttr, Some("/".into()));
            result.add_named(
                "Archive Format",
                self.archive_format.map(|f| f.to_string().into()),
            );
        } else {
            let Some(item) = self.fs_index.get_metadata(file) else {
                return result;
            };

            result.add(
                FileAttributeType::NameAttr,
                Some(base_name_of(&unchecked_get(item.path(), "unknown".to_string())).into()),
            );
            result.add(
                FileAttributeType::FileTypeAttr,
                Some(if unchecked_get(item.is_folder(), false) {
                    FileType::Directory.into()
                } else {
                    FileType::File.into()
                }),
            );
            let encrypted = unchecked_get(item.is_encrypted(), false);
            result.add(FileAttributeType::IsEncryptedAttr, Some(encrypted.into()));
            if encrypted {
                result.add(
                    FileAttributeType::HasGoodPasswordAttr,
                    Some(self.passwords.contains_key(&item.item_index()).into()),
                );
            }
            let comment = unchecked_get(item.comment(), None);
            result.add(
                FileAttributeType::CommentAttr,
                comment
                    .filter(|c| !c.trim().is_empty())
                    .map(FileAttributeValue::Str),
            );
            result.add(
                FileAttributeType::CompressedSizeAttr,
                unchecked_get(item.packed_size(), None).map(FileAttributeValue::Long),
            );
            result.add(
                FileAttributeType::SizeAttr,
                unchecked_get(item.size(), None).map(FileAttributeValue::Long),
            );

            let crc = unchecked_get(item.crc(), None);
            result.add_named("CRC", crc.map(|c| format!("{c:08X}").into()));
            result.add_named(
                "Compression Method",
                unchecked_get(item.method(), None).map(FileAttributeValue::Str),
            );
            result.add(
                FileAttributeType::CreateDateAttr,
                unchecked_get(item.creation_time(), None).map(FileAttributeValue::Date),
            );
            result.add(
                FileAttributeType::ModifiedDateAttr,
                unchecked_get(item.last_write_time(), None).map(FileAttributeValue::Date),
            );
        }
        result
    }

    /// Mirrors `getFileType(GFile, TaskMonitor)`.
    pub fn get_file_type(&self, f: &SzGFile, _monitor: &dyn TaskMonitor) -> FileType {
        let Some(item) = self.fs_index.get_metadata(f) else {
            // Java dereferences the metadata unguarded and would NPE here; an absent entry is
            // reported the same way an unreadable one is.
            return FileType::Unknown;
        };
        match item.is_folder() {
            Ok(true) => FileType::Directory,
            Ok(false) => FileType::File,
            Err(_) => FileType::Unknown,
        }
    }

    /// Mirrors `getByteProvider(GFile, TaskMonitor)`.
    pub fn get_byte_provider(
        &mut self,
        file: &SzGFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GetByteProviderError> {
        let Some(item) = self.fs_index.get_metadata(file).map(Rc::clone) else {
            return Ok(None);
        };

        let item_index = item.item_index();

        let is_folder = item.is_folder().map_err(unwrap_sz_exception_err)?;
        if is_folder {
            return Err(GetByteProviderError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Not a file: {}", file.get_name()),
            )));
        }
        if item.is_encrypted().map_err(unwrap_sz_exception_err)? {
            let file_name = file.get_name().to_string();
            let file_fsrl = file.get_fsrl().clone();
            let password =
                self.get_password_for_file(&file_name, &file_fsrl, item.as_ref(), monitor);
            if password.is_none() {
                let path = item.path().map_err(unwrap_sz_exception_err)?;
                return Err(GetByteProviderError::Crypto(CryptoException::new(format!(
                    "Unable to extract encrypted file, missing password: {path}"
                ))));
            }
        }

        let mut sz_callback = SZExtractCallback::new(
            monitor,
            item_index,
            true,
            &self.items,
            &self.passwords,
            &self.fs_service,
            self.fs_fsrl.get_container().name(),
        );
        {
            let archive = self.archive.as_ref().ok_or_else(|| {
                GetByteProviderError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "7-Zip archive is closed",
                ))
            })?;
            archive
                .extract(&[item_index], false /* extract mode */, &mut sz_callback)
                .map_err(unwrap_sz_exception_err)?;
        }
        let (extract_results, md5_updates) = sz_callback.finish();
        for (file_index, md5) in md5_updates {
            if let Some(g_file) = self.fs_index.get_file_by_index(file_index as i64) {
                if g_file.get_fsrl().md5().is_none() {
                    let new_fsrl = g_file.get_fsrl().with_md5(md5);
                    // `get_file_by_index` borrows the index; re-look-up by path to mutate.
                    let path = g_file.get_path().to_string();
                    if let Some(target) = self.file_by_path(&path) {
                        self.fs_index.update_fsrl(&target, new_fsrl);
                    }
                }
            }
        }

        let Some(result) = extract_results.into_iter().find_map(|(idx, entry)| {
            if idx == item_index {
                Some(entry)
            } else {
                None
            }
        }) else {
            return Err(GetByteProviderError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unable to extract {}", file.get_fsrl().fsrl_path()),
            )));
        };
        Ok(Some(
            result
                .as_byte_provider()
                .map_err(GetByteProviderError::Io)?,
        ))
    }

    /// Rebuilds a detached [`SzGFile`] for `path` so the index can be mutated while the
    /// original borrow is released.
    fn file_by_path(&self, path: &str) -> Option<SzGFile> {
        let root = self.fs_index.get_root_dir();
        let handle = SzFsHandle::new(SzFsrl::new(root.get_path()));
        Some(GFileImpl::from_fsrl(
            handle,
            None,
            SzFsrl::new(path),
            false,
            -1,
        ))
    }
}

/// The failure modes of [`SevenZipFileSystemBase::mount`], mirroring Java's
/// `throws CancelledException, IOException`.
#[derive(Debug)]
pub enum MountError {
    Cancelled(CancelledException),
    Io(io::Error),
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::Cancelled(e) => write!(f, "{e}"),
            MountError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MountError {}

/// The failure modes of [`SevenZipFileSystemBase::get_byte_provider`], mirroring Java's
/// `throws IOException, CancelledException` plus the `CryptoException` it raises for a
/// password-less encrypted entry.
#[derive(Debug)]
pub enum GetByteProviderError {
    Io(io::Error),
    Crypto(CryptoException),
    Cancelled(CancelledException),
}

impl fmt::Display for GetByteProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetByteProviderError::Io(e) => write!(f, "{e}"),
            GetByteProviderError::Crypto(e) => write!(f, "{e}"),
            GetByteProviderError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GetByteProviderError {}

fn unwrap_sz_exception_err(e: SevenZipError) -> GetByteProviderError {
    GetByteProviderError::Io(unwrap_sz_exception(e))
}

// ─── Extract callbacks ────────────────────────────────────────────────────────

/// Implements the SevenZip bulk extract callback.
///
/// For each file in the archive, SZ will call this type's 1) `get_stream`, 2) `prepare_operation`,
/// 3) lots of `write`s, and then 4) `set_operation_result`.
///
/// This type writes the extracted bytes to the file cache.
struct SZExtractCallback<'a, S: SevenZipFsService> {
    monitor: &'a dyn TaskMonitor,
    current_index: i32,
    current_is_folder: bool,
    current_name: String,
    current_cache_entry_builder: Option<FileCacheEntryBuilder>,
    save_results: bool,
    extract_results: Vec<(i32, FileCacheEntry)>,
    /// `(item index, md5)` pairs the owning filesystem should stamp onto its index. The Java
    /// inner class reaches back into the enclosing `fsIndex` directly; collecting them here
    /// keeps the index unborrowed for the duration of the extract.
    md5_updates: Vec<(i32, String)>,
    items: &'a [Rc<dyn ArchiveItem>],
    passwords: &'a HashMap<i32, String>,
    fs_service: &'a S,
    container_name: String,
}

impl<'a, S: SevenZipFsService> SZExtractCallback<'a, S> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        monitor: &'a dyn TaskMonitor,
        inital_index: i32,
        save_results: bool,
        items: &'a [Rc<dyn ArchiveItem>],
        passwords: &'a HashMap<i32, String>,
        fs_service: &'a S,
        container_name: &str,
    ) -> Self {
        SZExtractCallback {
            monitor,
            current_index: inital_index,
            current_is_folder: false,
            current_name: "unknown".to_string(),
            current_cache_entry_builder: None,
            save_results,
            extract_results: Vec::new(),
            md5_updates: Vec::new(),
            items,
            passwords,
            fs_service,
            container_name: container_name.to_string(),
        }
    }

    /// Mirrors `close()` followed by draining `extractResults`.
    fn finish(self) -> (Vec<(i32, FileCacheEntry)>, Vec<(i32, String)>) {
        // Dropping `current_cache_entry_builder` is Java's `close()`: the builder's temp file is
        // discarded when it is never finished.
        (self.extract_results, self.md5_updates)
    }

    /// Mirrors `extractOperationResultToException(ExtractOperationResult)`.
    fn extract_operation_result_to_error(result: ExtractOperationResult) -> Option<io::Error> {
        let message = match result {
            ExtractOperationResult::CrcError => "7-Zip returned CRC error",
            ExtractOperationResult::DataError => "7-Zip returned data error",
            ExtractOperationResult::UnsupportedMethod => {
                "Unexpected: 7-Zip returned unsupported method"
            }
            ExtractOperationResult::UnknownOperationResult => {
                "Unexpected: 7-Zip returned unknown operation result"
            }
            ExtractOperationResult::WrongPassword => "7-Zip wrong password",
            ExtractOperationResult::Ok => return None,
        };
        Some(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

impl<S: SevenZipFsService> ArchiveExtractCallback for SZExtractCallback<'_, S> {
    fn get_stream(&mut self, index: i32, extract_ask_mode: ExtractAskMode) -> SzResult<bool> {
        self.current_index = index;

        // STEP 1: SevenZip calls this method to get an object it can use to write the bytes to.
        // If we return false, SZ treats it as a skip. (except for folders)
        let current_item = self
            .items
            .iter()
            .find(|item| item.item_index() == self.current_index)
            .ok_or_else(|| SevenZipError::new(format!("No such archive item: {index}")))?;
        self.current_name = current_item.path()?;
        self.current_is_folder = current_item.is_folder()?;

        if self.current_is_folder || extract_ask_mode != ExtractAskMode::Extract {
            return Ok(false);
        }

        if current_item.is_encrypted()? && !self.passwords.contains_key(&self.current_index) {
            // if we lack a password for this item, don't try to extract it
            Msg::debug(
                ORIGINATOR,
                &format!(
                    "No password for file[{}] {} of {}, unable to extract.",
                    self.current_index, self.current_name, self.container_name
                ),
            );
            return Ok(false);
        }

        Ok(true)
    }

    fn prepare_operation(&mut self, extract_ask_mode: ExtractAskMode) -> SzResult<()> {
        // STEP 2: SevenZip calls this method to further prepare to operate on the file.
        // In our case, we only handle extract operations.
        if !self.current_is_folder && extract_ask_mode == ExtractAskMode::Extract {
            let size = self
                .items
                .iter()
                .find(|item| item.item_index() == self.current_index)
                .map(|item| item.size())
                .transpose()?
                .flatten()
                .unwrap_or(-1);
            self.current_cache_entry_builder = Some(
                self.fs_service
                    .create_temp_file(size)
                    .map_err(SevenZipError::from_io)?,
            );
            self.monitor.set_message(&format!("Extracting {}", self.current_name));
            self.monitor.initialize(size);
        }
        Ok(())
    }

    fn crypto_get_text_password(&mut self) -> SzResult<String> {
        // STEP 2.5 or 0: SevenZip calls this method to get the password of the file (if
        // encrypted). Sometimes after prepare_operation(), sometimes before get_stream().
        match self.passwords.get(&self.current_index) {
            Some(password) => Ok(password.clone()),
            None => {
                Msg::debug(
                    ORIGINATOR,
                    &format!(
                        "No password for file[{}] {} of {}",
                        self.current_index, self.current_name, self.container_name
                    ),
                );
                // hack, return a non-null bad password.  normally shouldn't get here as
                // encrypted files w/missing password are skipped by get_stream()
                Ok(String::new())
            }
        }
    }

    fn write(&mut self, data: &[u8]) -> SzResult<usize> {
        // STEP 3: SevenZip calls this multiple times for all the bytes in the file.
        // We write them to our temp file.
        let Some(builder) = self.current_cache_entry_builder.as_mut() else {
            return Err(SevenZipError::new(format!(
                "Bad Sevenzip Extract Callback state, {}, {}",
                self.current_index, self.current_name
            )));
        };
        builder.write(data).map_err(SevenZipError::from_io)?;
        self.monitor.increment_progress(data.len() as i64);
        Ok(data.len())
    }

    fn set_operation_result(
        &mut self,
        extract_operation_result: ExtractOperationResult,
    ) -> SzResult<()> {
        // STEP 4: SevenZip calls this to signal that the extract is done for this file.
        let Some(builder) = self.current_cache_entry_builder.take() else {
            return Ok(());
        };
        let outcome = (|| -> SzResult<()> {
            let fce = builder.finish().map_err(SevenZipError::from_io)?;
            if extract_operation_result == ExtractOperationResult::Ok {
                self.md5_updates.push((self.current_index, fce.get_md5().to_string()));
                Msg::debug(
                    ORIGINATOR,
                    &format!(
                        "Wrote file to cache: {}, {}",
                        self.current_name,
                        format_size(fce.length())
                    ),
                );
                if self.save_results {
                    self.extract_results.push((self.current_index, fce));
                }
            } else {
                Msg::warn(
                    ORIGINATOR,
                    &format!(
                        "Failed to push file[{}] {} to cache: {:?}",
                        self.current_index, self.current_name, extract_operation_result
                    ),
                );
                if let Some(e) =
                    Self::extract_operation_result_to_error(extract_operation_result)
                {
                    return Err(SevenZipError::from_io(e));
                }
            }
            Ok(())
        })();

        // hack to advance the current_index for the next file so crypto_get_text_password
        // will have a correct current_index value if it is called before get_stream(),
        // which does happen depending on the phase of the moon or the 7zip library's mood.
        self.current_index += 1;
        outcome
    }
}

/// Has the same layout and hacks re: setting `current_index` as [`SZExtractCallback`], but is
/// specialized to test passwords against the encrypted entries in the file.
struct TestPasswordsCallback<'a> {
    current_index: i32,
    current_password: String,
    success_file_indexes: Vec<i32>,
    monitor: &'a dyn TaskMonitor,
    items: &'a [Rc<dyn ArchiveItem>],
    /// The item indexes the enclosing filesystem already has passwords for. The Java inner
    /// class reads the enclosing `passwords` map directly; a snapshot of its keys is all this
    /// callback needs and it keeps the map unborrowed while `extract` runs.
    known_password_indexes: Vec<i32>,
}

impl<'a> TestPasswordsCallback<'a> {
    fn new(
        current_password: &str,
        initial_index: i32,
        items: &'a [Rc<dyn ArchiveItem>],
        monitor: &'a dyn TaskMonitor,
    ) -> Self {
        TestPasswordsCallback {
            current_index: initial_index,
            current_password: current_password.to_string(),
            success_file_indexes: Vec::new(),
            monitor,
            items,
            known_password_indexes: Vec::new(),
        }
    }

    /// Mirrors `getSuccessFileIndexes()`.
    fn into_success_file_indexes(self) -> Vec<i32> {
        self.success_file_indexes
    }

    fn item_at(&self, index: i32) -> Option<&Rc<dyn ArchiveItem>> {
        self.items.iter().find(|item| item.item_index() == index)
    }
}

impl ArchiveExtractCallback for TestPasswordsCallback<'_> {
    fn get_stream(&mut self, index: i32, _extract_ask_mode: ExtractAskMode) -> SzResult<bool> {
        self.current_index = index;
        if let Some(item) = self.item_at(self.current_index) {
            let path = item.path()?;
            self.monitor.set_message(&format!("Testing password for {path}"));
        }
        Ok(false)
    }

    fn prepare_operation(&mut self, _extract_ask_mode: ExtractAskMode) -> SzResult<()> {
        // nothing
        Ok(())
    }

    fn crypto_get_text_password(&mut self) -> SzResult<String> {
        Ok(self.current_password.clone())
    }

    fn write(&mut self, _data: &[u8]) -> SzResult<usize> {
        // Java's TestPasswordsCallback is not an ISequentialOutStream: getStream() always
        // returns null, so 7-Zip never delivers bytes to it.
        Err(SevenZipError::new(
            "TestPasswordsCallback does not accept extracted bytes",
        ))
    }

    fn set_operation_result(
        &mut self,
        extract_operation_result: ExtractOperationResult,
    ) -> SzResult<()> {
        if let Some(item) = self.item_at(self.current_index) {
            let is_encrypted = item.is_encrypted()?;
            if is_encrypted
                && extract_operation_result == ExtractOperationResult::Ok
                && !self.known_password_indexes.contains(&self.current_index)
                && !self.success_file_indexes.contains(&self.current_index)
            {
                self.success_file_indexes.push(self.current_index);
            }
        }
        self.current_index += 1;
        Ok(())
    }

    fn set_total(&mut self, total: i64) -> SzResult<()> {
        self.monitor.initialize(total);
        Ok(())
    }

    fn set_completed(&mut self, complete: i64) -> SzResult<()> {
        self.monitor.set_progress(complete);
        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Mirrors the `uncheckedGet(SZGetter<T>, T)` helper: swallow a `SevenZipException` and fall
/// back to `default_value`.
fn unchecked_get<T>(result: SzResult<T>, default_value: T) -> T {
    result.unwrap_or(default_value)
}

/// Mirrors `unwrapSZException(SevenZipException)`: descend through nested `SevenZipException`
/// causes and surface the innermost wrapped `IOException`, or wrap the original if there is none.
pub fn unwrap_sz_exception(e: SevenZipError) -> io::Error {
    let original = e.to_string();
    let mut tmp = e;
    loop {
        match tmp.cause.take() {
            Some(cause) => match *cause {
                SevenZipCause::SevenZip(inner) => tmp = inner,
                SevenZipCause::Io(io_error) => return io_error,
            },
            None => break,
        }
    }
    io::Error::new(io::ErrorKind::Other, original)
}

/// Mirrors `FSUtilities.uncheckedClose(Closeable, String)`'s logging arm.
fn unchecked_close_failed(msg: &str, e: &dyn fmt::Display) {
    Msg::warn(ORIGINATOR, &format!("{msg}: {e}"));
}

/// Mirrors `FSUtilities.formatSize(long)`.
fn format_size(length: i64) -> String {
    if length < 0 {
        return "-1".to_string();
    }
    if length < 1024 {
        return format!("{length}B");
    }
    let kb = length as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1}KB");
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{mb:.1}MB");
    }
    format!("{:.1}GB", mb / 1024.0)
}

/// Mirrors `FilenameUtils.getName(String)`: the last path segment, splitting on both `/` and `\`.
fn base_name_of(path: &str) -> &str {
    let start = path
        .rfind(['/', '\\'])
        .map(|i| i + 1)
        .unwrap_or(0);
    &path[start..]
}

/// Mirrors `FilenameUtils.getBaseName(String)`: the last path segment minus its extension.
fn strip_extension(path: &str) -> &str {
    let name = base_name_of(path);
    match name.rfind('.') {
        Some(i) => &name[..i],
        None => name,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::generic::auth::password::Password;
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;

    // ── Test doubles for the 7-Zip seam ──────────────────────────────────────

    #[derive(Clone)]
    struct FakeItem {
        index: i32,
        path: String,
        size: Option<i64>,
        packed_size: Option<i64>,
        folder: bool,
        encrypted: bool,
        comment: Option<String>,
        crc: Option<i32>,
        method: Option<String>,
    }

    impl FakeItem {
        fn file(index: i32, path: &str, size: i64) -> Self {
            FakeItem {
                index,
                path: path.to_string(),
                size: Some(size),
                packed_size: None,
                folder: false,
                encrypted: false,
                comment: None,
                crc: None,
                method: None,
            }
        }

        fn dir(index: i32, path: &str) -> Self {
            FakeItem { folder: true, size: None, ..FakeItem::file(index, path, 0) }
        }

        fn encrypted(mut self) -> Self {
            self.encrypted = true;
            self
        }
    }

    impl ArchiveItem for FakeItem {
        fn item_index(&self) -> i32 {
            self.index
        }
        fn path(&self) -> SzResult<String> {
            Ok(self.path.clone())
        }
        fn size(&self) -> SzResult<Option<i64>> {
            Ok(self.size)
        }
        fn packed_size(&self) -> SzResult<Option<i64>> {
            Ok(self.packed_size)
        }
        fn is_folder(&self) -> SzResult<bool> {
            Ok(self.folder)
        }
        fn is_encrypted(&self) -> SzResult<bool> {
            Ok(self.encrypted)
        }
        fn comment(&self) -> SzResult<Option<String>> {
            Ok(self.comment.clone())
        }
        fn crc(&self) -> SzResult<Option<i32>> {
            Ok(self.crc)
        }
        fn method(&self) -> SzResult<Option<String>> {
            Ok(self.method.clone())
        }
    }

    /// A fake archive whose `extract` drives the callback through the real 7-Zip call order:
    /// `get_stream` -> `prepare_operation` -> `crypto_get_text_password` -> `write`* ->
    /// `set_operation_result`.
    struct FakeArchive {
        format: ArchiveFormat,
        items: Vec<Rc<dyn ArchiveItem>>,
        contents: HashMap<i32, Vec<u8>>,
        /// Password required per item index; extraction fails with `WrongPassword` otherwise.
        required_passwords: HashMap<i32, String>,
    }

    impl FakeArchive {
        fn new(format: ArchiveFormat, items: Vec<FakeItem>) -> Self {
            FakeArchive {
                format,
                items: items
                    .into_iter()
                    .map(|i| Rc::new(i) as Rc<dyn ArchiveItem>)
                    .collect(),
                contents: HashMap::new(),
                required_passwords: HashMap::new(),
            }
        }

        fn with_contents(mut self, index: i32, bytes: &[u8]) -> Self {
            self.contents.insert(index, bytes.to_vec());
            self
        }

        fn with_password(mut self, index: i32, password: &str) -> Self {
            self.required_passwords.insert(index, password.to_string());
            self
        }
    }

    impl InArchive for FakeArchive {
        fn archive_format(&self) -> ArchiveFormat {
            self.format
        }

        fn archive_items(&self) -> SzResult<Vec<Rc<dyn ArchiveItem>>> {
            Ok(self.items.clone())
        }

        fn extract(
            &self,
            indices: &[i32],
            test_mode: bool,
            callback: &mut dyn ArchiveExtractCallback,
        ) -> SzResult<()> {
            callback.set_total(indices.len() as i64)?;
            for (n, &index) in indices.iter().enumerate() {
                let mode = if test_mode {
                    ExtractAskMode::Test
                } else {
                    ExtractAskMode::Extract
                };
                let wants_bytes = callback.get_stream(index, mode)?;
                callback.prepare_operation(mode)?;
                let supplied = callback.crypto_get_text_password()?;
                let ok = match self.required_passwords.get(&index) {
                    Some(expected) => *expected == supplied,
                    None => true,
                };
                if ok && wants_bytes {
                    if let Some(bytes) = self.contents.get(&index) {
                        callback.write(bytes)?;
                    }
                }
                callback.set_operation_result(if ok {
                    ExtractOperationResult::Ok
                } else {
                    ExtractOperationResult::WrongPassword
                })?;
                callback.set_completed(n as i64 + 1)?;
            }
            Ok(())
        }

        fn close(&mut self) -> SzResult<()> {
            Ok(())
        }
    }

    // ── Test double for the FileSystemService seam ───────────────────────────

    struct FakeCryptoSession {
        passwords: Vec<String>,
        accepted: Rc<RefCell<Vec<String>>>,
    }

    impl CryptoSession<SzFsrl> for FakeCryptoSession {
        fn get_passwords_for<'a>(
            &'a self,
            _fsrl: &'a SzFsrl,
            _prompt: &str,
        ) -> Box<dyn Iterator<Item = Password> + 'a> {
            Box::new(
                self.passwords
                    .iter()
                    .map(|p| Password::wrap(p.chars().collect())),
            )
        }

        fn add_successful_password(&mut self, _fsrl: &SzFsrl, password: Password) {
            let chars: String = password.get_password_chars().unwrap_or(&[]).iter().collect();
            self.accepted.borrow_mut().push(chars);
        }

        fn is_closed(&self) -> bool {
            false
        }

        fn close(&mut self) {}
    }

    struct FakeService {
        passwords: Vec<String>,
        accepted: Rc<RefCell<Vec<String>>>,
    }

    impl FakeService {
        fn new(passwords: &[&str]) -> Self {
            FakeService {
                passwords: passwords.iter().map(|s| s.to_string()).collect(),
                accepted: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl SevenZipFsService for FakeService {
        fn new_crypto_session(&self) -> Box<dyn CryptoSession<SzFsrl>> {
            Box::new(FakeCryptoSession {
                passwords: self.passwords.clone(),
                accepted: Rc::clone(&self.accepted),
            })
        }

        fn create_temp_file(&self, size_hint: i64) -> io::Result<FileCacheEntryBuilder> {
            Ok(FileCacheEntryBuilder::new(size_hint))
        }
    }

    /// `Result::unwrap_err` needs the `Ok` type to be `Debug`, which `Box<dyn ByteProvider>`
    /// is not.
    fn expect_err(
        result: Result<Option<Box<dyn ByteProvider>>, GetByteProviderError>,
    ) -> GetByteProviderError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected get_byte_provider to fail"),
        }
    }

    fn fs_for(container: &str) -> SevenZipFileSystemBase<FakeService> {
        SevenZipFileSystemBase::new(
            SzFsrlRoot::new(SzFsrl::new(container)),
            FakeService::new(&[]),
        )
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn file_system_info_matches_the_java_annotation() {
        let fs = fs_for("/tmp/archive.7z");
        assert_eq!(fs.fs_type(), "7zip");
        assert_eq!(fs.description(), "7Zip");
        assert_eq!(fs.priority(), PRIORITY_DEFAULT);
    }

    /// `ZipFileSystem` / `ISO9660FileSystem` override only the `@FileSystemInfo` metadata, which
    /// is exactly what the trait exposes.
    #[test]
    fn subclass_flavour_overrides_only_the_metadata() {
        struct ZipFileSystem(SevenZipFileSystemBase<FakeService>);

        impl SevenZipFileSystem for ZipFileSystem {
            fn fs_type(&self) -> &str {
                "zip"
            }
            fn description(&self) -> &str {
                "ZIP"
            }
            fn priority(&self) -> i32 {
                PRIORITY_HIGH
            }
        }

        let zip = ZipFileSystem(fs_for("/tmp/archive.zip"));
        assert_eq!(zip.fs_type(), "zip");
        assert_eq!(zip.description(), "ZIP");
        assert_eq!(zip.priority(), PRIORITY_HIGH);
        // ...while the inherited behaviour is unchanged.
        assert_eq!(zip.0.get_name(), "archive.zip");
        assert!(zip.0.is_closed());
    }

    #[test]
    fn new_file_system_is_closed_until_mounted() {
        let mut fs = fs_for("/tmp/archive.7z");
        assert!(fs.is_closed());

        let archive = FakeArchive::new(ArchiveFormat::SevenZip, vec![FakeItem::file(0, "a.txt", 3)]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();
        assert!(!fs.is_closed());

        fs.close().unwrap();
        assert!(fs.is_closed());
    }

    #[test]
    fn mount_indexes_every_item_by_its_archive_index() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(
            ArchiveFormat::Zip,
            vec![
                FakeItem::dir(0, "dir"),
                FakeItem::file(1, "dir/hello.txt", 5),
                FakeItem::file(2, "readme.md", 11),
            ],
        );
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let hello = fs.fs_index.get_file_by_index(1).unwrap();
        assert_eq!(hello.get_name(), "hello.txt");
        assert_eq!(hello.get_path(), "/dir/hello.txt");
        assert_eq!(hello.get_length(), 5);
        assert!(!hello.is_directory());

        let dir = fs.fs_index.get_file_by_index(0).unwrap();
        assert!(dir.is_directory());
        // Java stores `Objects.requireNonNullElse(item.getSize(), -1L)`.
        assert_eq!(dir.get_length(), -1);
    }

    /// Java's `fixupItemPath`: a lone unnamed entry is named after the container file minus its
    /// extension.
    #[test]
    fn single_unnamed_item_is_named_after_the_container() {
        let mut fs = fs_for("/tmp/mystery.gz");
        let archive =
            FakeArchive::new(ArchiveFormat::Gzip, vec![FakeItem::file(0, "   ", 42)]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        assert_eq!(fs.fs_index.get_file_by_index(0).unwrap().get_name(), "mystery");
    }

    /// The single-unnamed-item special case only applies when there is exactly one item;
    /// otherwise a blank path becomes `<blank>`.
    #[test]
    fn blank_path_with_multiple_items_becomes_blank_placeholder() {
        let mut fs = fs_for("/tmp/mystery.gz");
        let archive = FakeArchive::new(
            ArchiveFormat::Gzip,
            vec![FakeItem::file(0, "", 42), FakeItem::file(1, "other.txt", 1)],
        );
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        assert_eq!(fs.fs_index.get_file_by_index(0).unwrap().get_name(), "<blank>");
    }

    #[test]
    fn root_dir_attributes_report_the_archive_format() {
        let mut fs = fs_for("/tmp/archive.iso");
        let archive = FakeArchive::new(ArchiveFormat::Iso, vec![FakeItem::file(0, "a.txt", 1)]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let root = fs.get_root_dir().get_path().to_string();
        let root_file = fs.file_by_path(&root).unwrap();
        let attrs = fs.get_file_attributes(&root_file, &DummyMonitor);

        assert_eq!(
            attrs.get(FileAttributeType::NameAttr),
            Some(&FileAttributeValue::Str("/".to_string()))
        );
        assert_eq!(
            attrs.get_named("Archive Format"),
            Some(&FileAttributeValue::Str("Iso".to_string()))
        );
    }

    #[test]
    fn item_attributes_mirror_the_java_field_set() {
        let mut fs = fs_for("/tmp/archive.7z");
        let mut item = FakeItem::file(0, "docs/notes.txt", 100);
        item.packed_size = Some(40);
        item.crc = Some(0x0BAD_F00Du32 as i32);
        item.method = Some("LZMA2".to_string());
        item.comment = Some("  ".to_string()); // blank -> skipped, like Java's isBlank() check
        let archive = FakeArchive::new(ArchiveFormat::SevenZip, vec![item]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let file = fs.fs_index.get_file_by_index(0).unwrap();
        let path = file.get_path().to_string();
        let detached = fs.file_by_path(&path).unwrap();
        let attrs = fs.get_file_attributes(&detached, &DummyMonitor);

        assert_eq!(
            attrs.get(FileAttributeType::NameAttr),
            Some(&FileAttributeValue::Str("notes.txt".to_string()))
        );
        assert_eq!(
            attrs.get(FileAttributeType::FileTypeAttr),
            Some(&FileAttributeValue::FileType(FileType::File))
        );
        assert_eq!(
            attrs.get(FileAttributeType::IsEncryptedAttr),
            Some(&FileAttributeValue::Boolean(false))
        );
        // Not encrypted, so Java never adds HAS_GOOD_PASSWORD_ATTR.
        assert!(!attrs.contains(FileAttributeType::HasGoodPasswordAttr));
        assert!(!attrs.contains(FileAttributeType::CommentAttr));
        assert_eq!(
            attrs.get(FileAttributeType::SizeAttr),
            Some(&FileAttributeValue::Long(100))
        );
        assert_eq!(
            attrs.get(FileAttributeType::CompressedSizeAttr),
            Some(&FileAttributeValue::Long(40))
        );
        assert_eq!(
            attrs.get_named("CRC"),
            Some(&FileAttributeValue::Str("0BADF00D".to_string()))
        );
        assert_eq!(
            attrs.get_named("Compression Method"),
            Some(&FileAttributeValue::Str("LZMA2".to_string()))
        );
    }

    #[test]
    fn get_file_type_distinguishes_files_and_directories() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(
            ArchiveFormat::Tar,
            vec![FakeItem::dir(0, "dir"), FakeItem::file(1, "dir/a.txt", 2)],
        );
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let dir_path = fs.fs_index.get_file_by_index(0).unwrap().get_path().to_string();
        let file_path = fs.fs_index.get_file_by_index(1).unwrap().get_path().to_string();

        assert_eq!(
            fs.get_file_type(&fs.file_by_path(&dir_path).unwrap(), &DummyMonitor),
            FileType::Directory
        );
        assert_eq!(
            fs.get_file_type(&fs.file_by_path(&file_path).unwrap(), &DummyMonitor),
            FileType::File
        );
    }

    #[test]
    fn get_byte_provider_extracts_file_contents() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(ArchiveFormat::SevenZip, vec![FakeItem::file(0, "a.txt", 5)])
            .with_contents(0, b"hello");
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let path = fs.fs_index.get_file_by_index(0).unwrap().get_path().to_string();
        let file = fs.file_by_path(&path).unwrap();
        let mut provider = fs.get_byte_provider(&file, &DummyMonitor).unwrap().unwrap();

        assert_eq!(provider.length().unwrap(), 5);
        assert_eq!(provider.read_bytes(0, 5).unwrap(), b"hello".to_vec());
    }

    #[test]
    fn get_byte_provider_rejects_directories() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(ArchiveFormat::Tar, vec![FakeItem::dir(0, "dir")]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let path = fs.fs_index.get_file_by_index(0).unwrap().get_path().to_string();
        let file = fs.file_by_path(&path).unwrap();
        let err = expect_err(fs.get_byte_provider(&file, &DummyMonitor));
        assert!(matches!(err, GetByteProviderError::Io(_)));
        assert!(err.to_string().starts_with("Not a file: "));
    }

    #[test]
    fn get_byte_provider_returns_none_for_unindexed_file() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(ArchiveFormat::SevenZip, vec![FakeItem::file(0, "a.txt", 1)]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        let stranger = fs.file_by_path("/not/in/the/archive").unwrap();
        assert!(fs.get_byte_provider(&stranger, &DummyMonitor).unwrap().is_none());
    }

    /// Java's `ensurePasswords` tests candidate passwords during `mount` and remembers the ones
    /// that unlock entries.
    #[test]
    fn mount_finds_a_password_for_encrypted_entries() {
        let service = FakeService::new(&["wrong", "s3cret"]);
        let accepted = Rc::clone(&service.accepted);
        let mut fs =
            SevenZipFileSystemBase::new(SzFsrlRoot::new(SzFsrl::new("/tmp/locked.zip")), service);

        let archive = FakeArchive::new(
            ArchiveFormat::Zip,
            vec![FakeItem::file(0, "secret.txt", 6).encrypted()],
        )
        .with_contents(0, b"cipher")
        .with_password(0, "s3cret");
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();

        assert_eq!(fs.passwords.get(&0).map(String::as_str), Some("s3cret"));
        assert_eq!(accepted.borrow().as_slice(), ["s3cret"]);

        let path = fs.fs_index.get_file_by_index(0).unwrap().get_path().to_string();
        let file = fs.file_by_path(&path).unwrap();
        let attrs = fs.get_file_attributes(&file, &DummyMonitor);
        assert_eq!(
            attrs.get(FileAttributeType::IsEncryptedAttr),
            Some(&FileAttributeValue::Boolean(true))
        );
        assert_eq!(
            attrs.get(FileAttributeType::HasGoodPasswordAttr),
            Some(&FileAttributeValue::Boolean(true))
        );
    }

    #[test]
    fn encrypted_entry_without_a_password_fails_with_crypto_error() {
        let mut fs = SevenZipFileSystemBase::new(
            SzFsrlRoot::new(SzFsrl::new("/tmp/locked.zip")),
            FakeService::new(&["nope"]),
        );
        let archive = FakeArchive::new(
            ArchiveFormat::Zip,
            vec![FakeItem::file(0, "secret.txt", 6).encrypted()],
        )
        .with_contents(0, b"cipher")
        .with_password(0, "s3cret");
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();
        assert!(fs.passwords.is_empty());

        let path = fs.fs_index.get_file_by_index(0).unwrap().get_path().to_string();
        let file = fs.file_by_path(&path).unwrap();
        let err = expect_err(fs.get_byte_provider(&file, &DummyMonitor));
        assert!(matches!(err, GetByteProviderError::Crypto(_)));
        assert!(err
            .to_string()
            .contains("Unable to extract encrypted file, missing password"));
    }

    #[test]
    fn close_clears_the_index_and_items() {
        let mut fs = fs_for("/tmp/archive.7z");
        let archive = FakeArchive::new(ArchiveFormat::SevenZip, vec![FakeItem::file(0, "a.txt", 1)]);
        fs.mount(Box::new(archive), &DummyMonitor).unwrap();
        assert!(fs.fs_index.get_file_by_index(0).is_some());

        fs.close().unwrap();
        assert!(fs.fs_index.get_file_by_index(0).is_none());
        assert!(fs.items.is_empty());
    }

    // ── Helper-level tests ───────────────────────────────────────────────────

    #[test]
    fn unwrap_sz_exception_surfaces_the_innermost_io_cause() {
        let inner = SevenZipError::from_io(io::Error::new(io::ErrorKind::NotFound, "gone"));
        let middle = SevenZipError::wrapping("middle", inner);
        let outer = SevenZipError::wrapping("outer", middle);

        let unwrapped = unwrap_sz_exception(outer);
        assert_eq!(unwrapped.kind(), io::ErrorKind::NotFound);
        assert_eq!(unwrapped.to_string(), "gone");
    }

    #[test]
    fn unwrap_sz_exception_wraps_when_there_is_no_io_cause() {
        let e = SevenZipError::wrapping("outer", SevenZipError::new("inner"));
        let unwrapped = unwrap_sz_exception(e);
        assert_eq!(unwrapped.kind(), io::ErrorKind::Other);
        assert_eq!(unwrapped.to_string(), "outer");
    }

    #[test]
    fn archive_format_display_matches_the_java_method_names() {
        assert_eq!(ArchiveFormat::SevenZip.to_string(), "7z");
        assert_eq!(ArchiveFormat::Zip.to_string(), "Zip");
        assert_eq!(ArchiveFormat::Gzip.to_string(), "gzip");
        assert_eq!(ArchiveFormat::Hfs.to_string(), "HFS");
    }

    #[test]
    fn filename_helpers_match_commons_io() {
        assert_eq!(base_name_of("a/b/c.txt"), "c.txt");
        assert_eq!(base_name_of("a\\b\\c.txt"), "c.txt");
        assert_eq!(base_name_of("c.txt"), "c.txt");
        assert_eq!(strip_extension("/tmp/archive.tar.gz"), "archive.tar");
        assert_eq!(strip_extension("/tmp/noext"), "noext");
    }
}
