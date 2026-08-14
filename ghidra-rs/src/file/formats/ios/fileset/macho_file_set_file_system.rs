//! Rust port of `ghidra.file.formats.ios.fileset.MachoFileSetFileSystem`.
//!
//! A `GFileSystem` implementation for Mach-O file set entries: each `LC_FILESET_ENTRY` load
//! command (plus the `__BRANCH_STUBS`/`__BRANCH_GOTS` segments, if present) surfaces as its own
//! file, with dyld chained pointers fixed up ahead of time.
//!
//! # Shape
//!
//! The Java class is a concrete leaf (`AbstractFileSystem<MachoFileSetEntry>`, nothing extends
//! it), so this ports directly to a `struct` + `impl`, mirroring
//! [`DyldCacheFileSystem`](super::super::dyldcache::dyld_cache_file_system::DyldCacheFileSystem)
//! -- the sibling filesystem in this same `ios` package. `AbstractFileSystem`'s inherited state
//! (`fsFSRL`, `fsIndex`) is inlined as fields, and its own narrow `FSRL`/`FSRLRoot` stand-ins are
//! defined locally below, for the same reason `DyldCacheFileSystem` defines its own: the ported
//! `Fsrl`/`FsrlRootLike` seams have no implementer yet.
//!
//! # Unported dependencies
//!
//! `mount`'s Mach-O header/load-command parsing bottoms out in
//! [`MachHeader::parse`](crate::file::seam_stubs::MachHeader::parse) (magic/endianness only) and
//! [`MachHeader::get_segment`](crate::file::seam_stubs::MachHeader::get_segment)/
//! [`file_set_entry_commands`](crate::file::seam_stubs::MachHeader::file_set_entry_commands),
//! neither of which parses real load commands yet; see `crate::file::seam_stubs` (STUBS.tsv) for
//! the placeholders. Because `mount` requires a `__TEXT` segment to be present (mirroring the
//! Java `throw new MachException(...)` when it's missing) and `get_segment` always reports "not
//! found" until real segment parsing lands, a real `mount()` call against this stub always fails
//! today with the same error Java would report for a Mach-O file set that has no `__TEXT`
//! segment -- and will start succeeding the moment the placeholders are replaced, with no change
//! needed here. [`MachoFileSetExtractor`](crate::file::seam_stubs::MachoFileSetExtractor) is
//! similarly unported, so [`get_byte_provider`](MachoFileSetFileSystem::get_byte_provider)
//! always reports "not yet ported" for now.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::rc::Rc;

use crate::file::seam_stubs::{
    ExtractedMacho, FileAttributeValue, FileAttributes, FileSystemIndexHelper, MachHeader,
    MachoFileSetEntry, MachoFileSetExtractor, MessageLog, SegmentCommand,
};
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{
    FsGetListing, FsrlLike as GFileFsrlLike, GFileImpl, HasFsrlRoot,
};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::macho::commands::chained::dyld_chained_fixups::ChainedFixupError;
use crate::format::macho::commands::segment_names;
use crate::format::macho::mach_exception::MachException;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Mirrors `MachoFileSetFileSystem.MACHO_FILESET_FSTYPE`.
pub const MACHO_FILESET_FSTYPE: &str = "machofileset";

// ─── FSRL stand-ins ───────────────────────────────────────────────────────────
//
// Mirrors the same narrow substitution `DyldCacheFileSystem`/`SevenZipFileSystem` make for
// `FSRL`/`FSRLRoot`: the ported `Fsrl`/`FsrlRootLike` seams have no implementer yet, so this
// filesystem parameterizes `GFileImpl`/`FileSystemIndexHelper` with small concrete stand-ins.

/// Stand-in for `ghidra.formats.gfilesystem.FSRL`, used to parameterize [`GFileImpl`] and the
/// index. See
/// [`DyldCacheFileSystem`'s `DyldFsrl`](super::super::dyldcache::dyld_cache_file_system) for the
/// sibling substitution this mirrors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MfsFsrl {
    path: String,
}

impl MfsFsrl {
    /// Creates an FSRL for `path`.
    pub fn new(path: impl Into<String>) -> Self {
        MfsFsrl { path: path.into() }
    }
}

impl GFileFsrlLike for MfsFsrl {
    fn fsrl_name(&self) -> String {
        base_name_of(&self.path).to_string()
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
        MfsFsrl { path }
    }
}

/// Stand-in for `ghidra.formats.gfilesystem.FSRLRoot`, this filesystem's own `fsFSRL`.
///
/// Only `getContainer().getName()` is exercised by this class (via the inherited
/// `AbstractFileSystem.getName()`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MfsFsrlRoot {
    container_name: String,
}

impl MfsFsrlRoot {
    /// Creates a root whose container file is named `container_name`.
    pub fn new(container_name: impl Into<String>) -> Self {
        MfsFsrlRoot { container_name: container_name.into() }
    }

    /// Mirrors `FSRLRoot.getContainer().getName()`.
    pub fn name(&self) -> &str {
        &self.container_name
    }
}

/// Filesystem handle stored inside each [`GFileImpl`] this filesystem hands out.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MfsHandle {
    root: MfsFsrl,
}

impl MfsHandle {
    /// Creates a handle rooted at `root`.
    pub fn new(root: MfsFsrl) -> Self {
        MfsHandle { root }
    }
}

impl HasFsrlRoot<MfsFsrl> for MfsHandle {
    fn root_fsrl(&self) -> &MfsFsrl {
        &self.root
    }
}

impl FsGetListing<MfsHandle, MfsFsrl> for MfsHandle {
    fn fs_get_listing(
        &self,
        _file: &dyn GFile<MfsHandle, MfsFsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<MfsHandle, MfsFsrl>>>> {
        Ok(vec![])
    }
}

/// The concrete [`GFile`] type this filesystem indexes.
pub type MfsGFile = GFileImpl<MfsHandle, MfsFsrl>;

// ─── MachoFileSetFileSystem ─────────────────────────────────────────────────

/// A `GFileSystem` implementation for Mach-O file set entries.
///
/// Mirrors `ghidra.file.formats.ios.fileset.MachoFileSetFileSystem`.
pub struct MachoFileSetFileSystem {
    /// Mirrors the inherited `AbstractFileSystem.fsFSRL`.
    fs_fsrl: MfsFsrlRoot,
    /// Mirrors `provider`. `None` once [`close`](Self::close) has run, matching Java's
    /// `provider == null` after close.
    provider: Option<Rc<RefCell<dyn ByteProvider>>>,
    /// Mirrors `fixedUpProvider`.
    fixed_up_provider: Option<Rc<RefCell<dyn ByteProvider>>>,
    /// Mirrors `header`.
    header: Option<MachHeader>,
    /// Mirrors `entrySegmentMap`.
    entry_segment_map: HashMap<Rc<MachoFileSetEntry>, Vec<SegmentCommand>>,
    /// Mirrors the inherited `AbstractFileSystem.fsIndex`. `AbstractFileSystem.refManager` is
    /// not modeled: this port has no arena-backed `FileSystemRefManager` yet (see
    /// `crate::filesystem::gfilesystem::file_system_ref_manager`'s docs), and nothing in this
    /// class other than `close()`'s `refManager.onClose()` -- itself a no-op absent listeners --
    /// touches it.
    fs_index: FileSystemIndexHelper<MfsHandle, MfsFsrl, Rc<MachoFileSetEntry>>,
}

impl MachoFileSetFileSystem {
    /// Creates a new [`MachoFileSetFileSystem`].
    ///
    /// Mirrors `MachoFileSetFileSystem(FSRLRoot, ByteProvider)`.
    pub fn new(fs_fsrl: MfsFsrlRoot, provider: Rc<RefCell<dyn ByteProvider>>) -> Self {
        let root = MfsFsrl::new("/");
        let fs_index = FileSystemIndexHelper::new(MfsHandle::new(root.clone()), root);
        MachoFileSetFileSystem {
            fs_fsrl,
            provider: Some(provider),
            fixed_up_provider: None,
            header: None,
            entry_segment_map: HashMap::new(),
            fs_index,
        }
    }

    /// Mirrors the inherited `AbstractFileSystem.getFSRL()`.
    pub fn get_fsrl(&self) -> &MfsFsrlRoot {
        &self.fs_fsrl
    }

    /// Mirrors the inherited `AbstractFileSystem.getName()`.
    pub fn get_name(&self) -> &str {
        self.fs_fsrl.name()
    }

    /// Mirrors the inherited `AbstractFileSystem.getRootDir()`.
    pub fn get_root_dir(&self) -> &MfsGFile {
        self.fs_index.get_root_dir()
    }

    /// Mirrors the inherited `AbstractFileSystem.getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        self.fs_index.get_file_count()
    }

    /// Mounts this file system.
    ///
    /// Mirrors `mount(TaskMonitor)`.
    pub fn mount(&mut self, monitor: &dyn TaskMonitor) -> Result<(), MountError> {
        let provider = self.provider.clone().ok_or_else(closed_error)?;
        let log = MessageLog::new();

        monitor.set_message("Opening Mach-O file set...");
        let mut header = MachHeader::from_provider(Rc::clone(&provider));
        header.parse()?;

        let text_segment = header
            .get_segment(segment_names::TEXT)
            .ok_or_else(|| MachException::new(format!("{} not found!", segment_names::TEXT)))?;

        // File set entries
        for cmd in header.file_set_entry_commands() {
            let entry =
                Rc::new(MachoFileSetEntry::new(cmd.get_file_set_entry_id(), cmd.get_file_offset(), false));
            let file_index = self.fs_index.get_file_count() as i64;
            self.fs_index.store_file(entry.id(), file_index, false, -1, Rc::clone(&entry));
            let entry_header = MachHeader::new(Rc::clone(&provider), entry.offset());
            let segments = entry_header.parse_segments()?;
            self.entry_segment_map.insert(entry, segments);
        }

        // BRANCH segments, if present
        if let Some(branch_stubs) = header.get_segment(segment_names::BRANCH_STUBS) {
            let entry = Rc::new(MachoFileSetEntry::new(&segment_names::BRANCH_STUBS[2..], 0, true));
            let file_index = self.fs_index.get_file_count() as i64;
            self.fs_index.store_file(entry.id(), file_index, false, -1, Rc::clone(&entry));
            self.entry_segment_map.insert(entry, vec![branch_stubs]);
        }
        if let Some(branch_gots) = header.get_segment(segment_names::BRANCH_GOTS) {
            let entry = Rc::new(MachoFileSetEntry::new(&segment_names::BRANCH_GOTS[2..], 0, true));
            let file_index = self.fs_index.get_file_count() as i64;
            self.fs_index.store_file(entry.id(), file_index, false, -1, Rc::clone(&entry));
            self.entry_segment_map.insert(entry, vec![branch_gots]);
        }

        monitor.set_message("Getting chained pointers...");
        // Mirrors `getLoadCommands(DyldChainedFixupsCommand.class)`: always empty for now (see
        // `MachHeader::dyld_chained_fixups_commands`'s docs), so there is nothing to iterate.
        // When load-command parsing lands, this loop will also need a real
        // `crate::app::util::bin::binary_reader::BinaryReader` implementation over a
        // `ByteProvider` to pass to `get_chained_fixups` -- only test-only mocks implement that
        // trait anywhere in this crate today.
        let _ = &log;
        let _imagebase = text_segment.vm_address();
        let fixups: Vec<crate::format::macho::dyld::dyld_fixup::DyldFixup> = Vec::new();
        debug_assert!(header.dyld_chained_fixups_commands().is_empty());

        monitor.set_message("Fixing chained pointers...");
        monitor.initialize(fixups.len() as i64);
        let len = provider.borrow_mut().length()?;
        let mut bytes = provider.borrow_mut().read_bytes(0, len as usize)?;
        for fixup in &fixups {
            let Some(value) = fixup.value else { continue };
            let new_bytes = ExtractedMacho::to_bytes(value, fixup.size)?;
            let start = fixup.offset as usize;
            let end = start + new_bytes.len();
            if end <= bytes.len() {
                bytes[start..end].copy_from_slice(&new_bytes);
            }
        }

        self.header = Some(header);
        self.fixed_up_provider =
            Some(Rc::new(RefCell::new(crate::file::seam_stubs::ByteArrayProvider::new(bytes))));
        Ok(())
    }

    /// Mirrors `getByteProvider(GFile, TaskMonitor)`.
    pub fn get_byte_provider(
        &mut self,
        file: &MfsGFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GetByteProviderError> {
        let Some(entry) = self.fs_index.get_metadata(file).map(Rc::clone) else {
            return Ok(None);
        };
        let fixed_up = self.fixed_up_provider.clone().ok_or_else(not_mounted_error)?;
        let fsrl_path = file.get_fsrl().fsrl_path();

        if entry.is_branch_segment() {
            let segment_name = format!("__{}", entry.id());
            let segment = self
                .header
                .as_ref()
                .and_then(|h| h.get_segment(&segment_name))
                .ok_or_else(|| {
                    GetByteProviderError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Invalid Mach-O header detected: segment {segment_name} not found"),
                    ))
                })?;
            return MachoFileSetExtractor::extract_segment(fixed_up, &segment, &fsrl_path, monitor)
                .map(Some)
                .map_err(GetByteProviderError::Io);
        }

        MachoFileSetExtractor::extract_file_set_entry(fixed_up, entry.offset(), &fsrl_path, monitor)
            .map(Some)
            .map_err(GetByteProviderError::Io)
    }

    /// Mirrors `getFileAttributes(GFile, TaskMonitor)`.
    pub fn get_file_attributes(&self, file: &MfsGFile, _monitor: &dyn TaskMonitor) -> FileAttributes {
        let mut result = FileAttributes::new();
        if let Some(entry) = self.fs_index.get_metadata(file) {
            result.add(FileAttributeType::NameAttr, Some(FileAttributeValue::Str(entry.id().to_string())));
            result.add(FileAttributeType::PathAttr, Some(FileAttributeValue::Str(entry.id().to_string())));
        }
        result
    }

    /// Gets the open Mach-O file set [`ByteProvider`]. This is the original `ByteProvider` that
    /// this file system opened.
    ///
    /// Mirrors `getMachoFileSetProvider()`.
    pub fn get_macho_file_set_provider(&self) -> Option<Rc<RefCell<dyn ByteProvider>>> {
        self.provider.clone()
    }

    /// The map of file set entry segments.
    ///
    /// Mirrors `getEntrySegmentMap()`.
    pub fn get_entry_segment_map(&self) -> &HashMap<Rc<MachoFileSetEntry>, Vec<SegmentCommand>> {
        &self.entry_segment_map
    }

    /// Mirrors the inherited `AbstractFileSystem.isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.provider.is_none()
    }

    /// Mirrors `close()`.
    pub fn close(&mut self) {
        // `refManager.onClose()` -- see the `fs_index` field docs for why it is not modeled.
        // `ByteProvider` has no explicit close in this port (see
        // `crate::file::formats::zip::zip_file_system_factory`'s module docs for the same
        // substitution elsewhere in this crate); releasing it is just dropping it.
        self.provider = None;
        self.fixed_up_provider = None;
        self.header = None;
        self.fs_index.clear();
        self.entry_segment_map.clear();
    }
}

fn base_name_of(path: &str) -> &str {
    let start = path.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    &path[start..]
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "MachoFileSetFileSystem is closed")
}

fn not_mounted_error() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "MachoFileSetFileSystem has not been mounted")
}

/// The failure modes of [`MachoFileSetFileSystem::mount`], mirroring Java's `throws IOException,
/// CancelledException` -- `MachException` never escapes `mount()` in Java (it is always caught
/// and rewrapped as `IOException`), so it is collapsed into [`MountError::Io`] here too, rather
/// than kept as a separate variant.
#[derive(Debug)]
pub enum MountError {
    Io(io::Error),
    Cancelled(CancelledException),
}

impl From<io::Error> for MountError {
    fn from(e: io::Error) -> Self {
        MountError::Io(e)
    }
}

impl From<MachException> for MountError {
    fn from(e: MachException) -> Self {
        MountError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

impl From<ChainedFixupError> for MountError {
    fn from(e: ChainedFixupError) -> Self {
        match e {
            ChainedFixupError::Io(e) => MountError::Io(e),
            ChainedFixupError::Cancelled(e) => MountError::Cancelled(e),
        }
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::Io(e) => write!(f, "{e}"),
            MountError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MountError {}

/// The failure modes of [`MachoFileSetFileSystem::get_byte_provider`], mirroring Java's `throws
/// CancelledException, IOException` (collapsed to a single `io::Error`, since the unported
/// `MachoFileSetExtractor` seam doesn't distinguish cancellation from any other failure yet).
#[derive(Debug)]
pub enum GetByteProviderError {
    Io(io::Error),
}

impl From<io::Error> for GetByteProviderError {
    fn from(e: io::Error) -> Self {
        GetByteProviderError::Io(e)
    }
}

impl fmt::Display for GetByteProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetByteProviderError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GetByteProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryByteProvider {
        bytes: Vec<u8>,
    }

    impl ByteProvider for MemoryByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    fn macho_provider() -> Rc<RefCell<dyn ByteProvider>> {
        // MH_MAGIC_64, big-endian on-disk bytes, padded to a plausible header length.
        let mut bytes: Vec<u8> = vec![0xfe, 0xed, 0xfa, 0xcf];
        bytes.resize(64, 0);
        Rc::new(RefCell::new(MemoryByteProvider { bytes }))
    }

    #[test]
    fn fstype_matches_java_constant() {
        assert_eq!(MACHO_FILESET_FSTYPE, "machofileset");
    }

    #[test]
    fn new_filesystem_is_open_with_empty_root() {
        let fs = MachoFileSetFileSystem::new(MfsFsrlRoot::new("kernelcache.fileset"), macho_provider());
        assert!(!fs.is_closed());
        assert_eq!(fs.get_name(), "kernelcache.fileset");
        assert_eq!(fs.get_file_count(), 1); // just the synthetic root dir
    }

    #[test]
    fn mount_fails_without_text_segment_like_java() {
        // Mirrors Java's `throw new MachException(SegmentNames.SEG_TEXT + " not found!")`,
        // wrapped into an IOException -- reachable here because segment parsing is not yet
        // ported (see the module docs), so `__TEXT` is never found.
        let mut fs = MachoFileSetFileSystem::new(MfsFsrlRoot::new("kernelcache.fileset"), macho_provider());
        let monitor = crate::util::task::DummyMonitor;
        let err = fs.mount(&monitor).expect_err("mount should fail without a __TEXT segment");
        match err {
            MountError::Io(e) => assert!(e.to_string().contains("__TEXT not found!"), "{e}"),
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn close_resets_to_closed_state() {
        let mut fs = MachoFileSetFileSystem::new(MfsFsrlRoot::new("kernelcache.fileset"), macho_provider());
        fs.close();
        assert!(fs.is_closed());
        assert!(fs.get_macho_file_set_provider().is_none());
        assert_eq!(fs.get_file_count(), 1);
    }

    #[test]
    fn get_byte_provider_before_mount_reports_not_mounted() {
        let mut fs = MachoFileSetFileSystem::new(MfsFsrlRoot::new("kernelcache.fileset"), macho_provider());
        let root_path = fs.get_root_dir().get_path().to_string();
        let handle = MfsHandle::new(MfsFsrl::new(root_path));
        let file = GFileImpl::from_fsrl(handle, None, MfsFsrl::new("/entry"), false, -1);
        let monitor = crate::util::task::DummyMonitor;
        let err = fs.get_byte_provider(&file, &monitor);
        // No metadata is indexed for an unrecognized path, so this reports `Ok(None)` --
        // mirrors `fsIndex.getMetadata(file) == null` returning `null` in Java.
        assert!(matches!(err, Ok(None)));
    }
}
