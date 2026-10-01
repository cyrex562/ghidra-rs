//! Port of `ghidra.file.formats.ios.fileset.MachoFileSetFileSystem`.
//!
//! A [`GFileSystem`] over a Mach-O file set (kernel collection): each `LC_FILESET_ENTRY` (plus
//! the `__BRANCH_STUBS`/`__BRANCH_GOTS` segments, if present) is a file, extracted with the
//! container's dyld chained pointers fixed up ahead of time.
//!
//! Follows [`CpioFileSystem`](crate::file::formats::cpio::cpio_file_system::CpioFileSystem):
//! the inherited `AbstractFileSystem` state is an embedded [`AbstractFileSystemBase`], and the
//! state `close()` releases sits behind `RefCell`s because the filesystem is shared through
//! [`FsHandle`](crate::filesystem::gfilesystem::g_file_system::FsHandle)s.

use std::cell::{Ref, RefCell};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use super::macho_file_set_entry::MachoFileSetEntry;
use super::macho_file_set_extractor;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::importer::message_log::MessageLog;
use crate::file::formats::ios::extracted_macho;
use crate::filesystem::gfilesystem::abstract_file_system::{AbstractFileSystemBase, AbstractFsHandle};
use crate::filesystem::gfilesystem::annotations::file_system_info::{FileSystemInfo, PRIORITY_DEFAULT};
use crate::filesystem::gfilesystem::file_system_index_helper::copy_file;
use crate::filesystem::gfilesystem::file_system_ref_manager::FileSystemRefManager;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_system::{GFileSystem, GFileSystemError};
use crate::format::macho::commands::chained::dyld_chained_fixups::ChainedFixupError;
use crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand;
use crate::format::macho::commands::file_set_entry_command::FileSetEntryCommand;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::commands::segment_names;
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::util::task::TaskMonitor;

/// Java: `MACHO_FILESET_FSTYPE`.
pub const MACHO_FILESET_FSTYPE: &str = "machofileset";

/// Port of `ghidra.file.formats.ios.fileset.MachoFileSetFileSystem`.
pub struct MachoFileSetFileSystem {
    base: AbstractFileSystemBase<MachoFileSetEntry>,
    provider: RefCell<Option<Rc<dyn ByteProvider>>>,
    fixed_up_provider: RefCell<Option<Rc<dyn ByteProvider>>>,
    header: RefCell<Option<MachHeader>>,
    entry_segment_map: RefCell<HashMap<MachoFileSetEntry, Vec<SegmentCommand>>>,
}

impl MachoFileSetFileSystem {
    /// `@FileSystemInfo(type = "machofileset")`.
    pub const FS_TYPE: &'static str = MACHO_FILESET_FSTYPE;
    /// `@FileSystemInfo(description = "Mach-O file set")`.
    pub const DESCRIPTION: &'static str = "Mach-O file set";
    /// The `@FileSystemInfo` annotation (default priority).
    pub const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, PRIORITY_DEFAULT);

    /// Java `MachoFileSetFileSystem(FSRLRoot, ByteProvider)` (Java takes the service from
    /// `FileSystemService.getInstance()`).
    pub fn new(fs_fsrl: FsrlRoot, provider: Rc<dyn ByteProvider>, fs_service: &FileSystemService) -> Self {
        MachoFileSetFileSystem {
            base: AbstractFileSystemBase::new(fs_fsrl, fs_service),
            provider: RefCell::new(Some(provider)),
            fixed_up_provider: RefCell::new(None),
            header: RefCell::new(None),
            entry_segment_map: RefCell::new(HashMap::new()),
        }
    }

    /// Java `mount(TaskMonitor)`: indexes the file set entries and branch segments, then builds
    /// a copy of the container with every chained pointer fixed up.
    ///
    /// # Errors
    /// I/O errors (a `MachException` is wrapped as one, as in Java) or cancellation.
    pub fn mount(&mut self, monitor: &dyn TaskMonitor) -> Result<(), GFileSystemError> {
        let log = MessageLog::new();
        let provider = self.provider.borrow().clone().ok_or_else(|| io::Error::other("filesystem is closed"))?;
        monitor.set_message("Opening Mach-O file set...");
        let mut header = MachHeader::new(Rc::clone(&provider)).map_err(mach_io)?;
        header.parse().map_err(mach_io)?;
        let text_segment = header
            .get_segment(segment_names::TEXT)
            .ok_or_else(|| mach_io(MachException::new(format!("{} not found!", segment_names::TEXT))))?;
        let imagebase = text_segment.get_vm_address();

        // File set entries
        let mut entry_segment_map = HashMap::new();
        for cmd in header.get_load_commands_of::<FileSetEntryCommand>() {
            let entry = MachoFileSetEntry::new(
                cmd.get_file_set_entry_id().get_string(),
                cmd.get_file_offset(),
                false,
            );
            let index = self.base.fs_index_mut();
            let file_count = index.get_file_count() as i64;
            index.store_file(entry.id(), file_count, false, -1, entry.clone());
            let segments = MachHeader::with_start_index(Rc::clone(&provider), entry.offset() as u64)
                .and_then(|mut h| h.parse_segments())
                .map_err(mach_io)?;
            entry_segment_map.insert(entry, segments);
        }

        // BRANCH segments, if present
        for name in [segment_names::BRANCH_STUBS, segment_names::BRANCH_GOTS] {
            if let Some(segment) = header.get_segment(name) {
                let entry = MachoFileSetEntry::new(&name[2..], 0, true);
                let index = self.base.fs_index_mut();
                let file_count = index.get_file_count() as i64;
                index.store_file(entry.id(), file_count, false, -1, entry.clone());
                entry_segment_map.insert(entry, vec![segment.clone()]);
            }
        }

        monitor.set_message("Getting chained pointers...");
        let reader = BinaryReader::new(Rc::clone(&provider), header.is_little_endian());
        let mut fixups = Vec::new();
        for load_command in header.get_load_commands_of::<DyldChainedFixupsCommand>() {
            match load_command.get_chained_fixups(&reader, imagebase, None, &log, monitor) {
                Ok(f) => fixups.extend(f),
                Err(ChainedFixupError::Io(e)) => return Err(e.into()),
                Err(ChainedFixupError::Cancelled(c)) => return Err(c.into()),
            }
        }
        monitor.initialize(fixups.len() as i64);
        monitor.set_message("Fixing chained pointers...");
        let mut bytes = provider.read_bytes(0, provider.length())?;
        for fixup in &fixups {
            // Bound fixups (the only ones without a value) need a symbol table, which is not
            // supplied here, so `get_chained_fixups` never yields them.
            let Some(value) = fixup.value else { continue };
            let new_bytes = extracted_macho::to_bytes(value, fixup.size as usize)?;
            let start = fixup.offset as usize;
            let dest = bytes.get_mut(start..start + new_bytes.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("fixup at 0x{start:x} out of range"))
            })?;
            dest.copy_from_slice(&new_bytes);
        }

        *self.fixed_up_provider.borrow_mut() = Some(Rc::new(ByteArrayProvider::new(bytes)));
        *self.header.borrow_mut() = Some(header);
        *self.entry_segment_map.borrow_mut() = entry_segment_map;
        Ok(())
    }

    /// Java `getMachoFileSetProvider()`.
    pub fn get_macho_file_set_provider(&self) -> Option<Rc<dyn ByteProvider>> {
        self.provider.borrow().clone()
    }

    /// Java `getEntrySegmentMap()`.
    pub fn get_entry_segment_map(&self) -> Ref<'_, HashMap<MachoFileSetEntry, Vec<SegmentCommand>>> {
        self.entry_segment_map.borrow()
    }

    fn owned(f: &dyn GFile<AbstractFsHandle>) -> Box<dyn GFile<AbstractFsHandle>> {
        Box::new(copy_file(f))
    }
}

/// Java wraps a `MachException` thrown while mounting in an `IOException`.
fn mach_io(e: MachException) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl GFileSystem for MachoFileSetFileSystem {
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

    /// Java `isClosed()`.
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

    /// Java `getByteProvider(GFile, TaskMonitor)`: the extracted entry (a packed Mach-O, or a
    /// branch segment wrapped in a minimal Mach-O), carrying the file's FSRL; `None` if `file`
    /// has no entry.
    fn get_byte_provider(
        &self,
        file: &dyn GFile<AbstractFsHandle>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        let Some(entry) = self.base.fs_index().get_metadata(file).cloned() else {
            return Ok(None);
        };
        let fixed_up = self
            .fixed_up_provider
            .borrow()
            .clone()
            .ok_or_else(|| io::Error::other("Mach-O file set filesystem is not mounted"))?;
        let fsrl = Some(file.get_fsrl().clone());
        let invalid = || io::Error::other(format!("Invalid Mach-O header detected at 0x{:x}", entry.offset()));
        let result = if entry.is_branch_segment() {
            let header = self.header.borrow();
            let segment = header
                .as_ref()
                .and_then(|h| h.get_segment(&format!("__{}", entry.id())))
                .ok_or_else(invalid)?;
            macho_file_set_extractor::extract_segment(fixed_up.as_ref(), segment, fsrl, monitor)
        } else {
            macho_file_set_extractor::extract_file_set_entry(&fixed_up, entry.offset(), fsrl, monitor)
        };
        match result {
            Ok(p) => Ok(Some(Box::new(p))),
            Err(macho_file_set_extractor::FileSetExtractError::Mach(_)) => Err(invalid().into()),
            Err(macho_file_set_extractor::FileSetExtractError::Io(e)) => Err(e.into()),
            Err(macho_file_set_extractor::FileSetExtractError::Extract(e)) => Err(io::Error::from(e).into()),
        }
    }

    fn get_listing(
        &self,
        directory: Option<&dyn GFile<AbstractFsHandle>>,
    ) -> io::Result<Vec<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.get_listing(directory).into_iter().map(|f| Self::owned(f)).collect())
    }

    /// Java `getFileAttributes(GFile, TaskMonitor)`: the entry's id as its name and path.
    fn get_file_attributes(&self, file: &dyn GFile<AbstractFsHandle>, _monitor: &dyn TaskMonitor) -> FileAttributes {
        let mut result = FileAttributes::new();
        if let Some(entry) = self.base.fs_index().get_metadata(file) {
            result.add(FileAttributeType::NameAttr, Some(entry.id().into()));
            result.add(FileAttributeType::PathAttr, Some(entry.id().into()));
        }
        result
    }

    /// Java `close()`.
    fn close(&self) -> io::Result<()> {
        let _ = self.base.get_ref_manager().on_close(self);
        if let Some(mut provider) = self.provider.borrow_mut().take() {
            if let Some(p) = Rc::get_mut(&mut provider) {
                p.close()?;
            }
        }
        self.fixed_up_provider.borrow_mut().take();
        self.header.borrow_mut().take();
        self.base.fs_index().clear();
        self.entry_segment_map.borrow_mut().clear();
        Ok(())
    }
}

impl Deref for MachoFileSetFileSystem {
    type Target = AbstractFileSystemBase<MachoFileSetEntry>;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for MachoFileSetFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::file::formats::ios::extracted_macho::test_support::write_macho;
    use crate::format::macho::commands::load_command_types::{LC_FILESET_ENTRY, LC_SEGMENT_64};
    use crate::format::macho::mach_constants::MH_MAGIC_64;
    use crate::format::macho::mach_header::test_support::Bytes;

    /// A little-endian kernel collection: a container header with `__TEXT` and
    /// `__BRANCH_STUBS` segments and one `LC_FILESET_ENTRY` ("com.example.kext") whose Mach-O
    /// lives at 0x1000.
    pub(crate) fn fileset_image() -> Vec<u8> {
        let mut b = Bytes::new(true);
        let id = "com.example.kext";
        let entry_len = 32 + ((id.len() as u32 + 1 + 7) & !7);
        b.u32(MH_MAGIC_64).u32(0x0100_000c).u32(0).u32(0xc).u32(3).u32(72 * 2 + entry_len).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72).name("__TEXT", 16);
        b.u64(0xffff_fe00_0000_0000).u64(0x1000).u64(0).u64(0x1000).u32(5).u32(5).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72).name("__BRANCH_STUBS", 16);
        b.u64(0xffff_fe00_0000_4000).u64(0x10).u64(0x4000).u64(0x10).u32(5).u32(5).u32(0).u32(0);
        b.u32(LC_FILESET_ENTRY).u32(entry_len).u64(0xffff_fe00_0000_1000).u64(0x1000).u32(32).u32(0);
        b.name(id, (entry_len - 32) as usize);
        write_macho(&mut b, 0x1000, 0xffff_fe00_0000_1000, 0x3000, "_kext_start");
        b.pad_to(0x4000);
        b.raw(b"BRANCHSTUBS_0123");
        b.buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fileset_image;
    use super::*;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::util::task::DummyMonitor;

    struct Fixture {
        _dir: tempfile::TempDir,
        svc: FileSystemService,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        Fixture { _dir: dir, svc }
    }

    fn mount(fx: &Fixture, bytes: Vec<u8>) -> Result<MachoFileSetFileSystem, GFileSystemError> {
        let container = Fsrl::from_string("file:///kernelcache").unwrap();
        let provider: Rc<dyn ByteProvider> = Rc::new(ByteArrayProvider::with_fsrl(bytes, Some(container.clone())));
        let mut fs = MachoFileSetFileSystem::new(container.make_nested(MACHO_FILESET_FSTYPE), provider, &fx.svc);
        fs.mount(&DummyMonitor)?;
        Ok(fs)
    }

    #[test]
    fn mounts_entries_and_branch_segments() {
        let fx = fixture();
        let fs = mount(&fx, fileset_image()).unwrap();
        assert_eq!(fs.get_type(), "machofileset");
        assert_eq!(fs.get_description(), "Mach-O file set");
        let names: Vec<String> =
            GFileSystem::get_listing(&fs, None).unwrap().iter().map(|f| f.get_name().to_owned()).collect();
        assert_eq!(names, ["com.example.kext", "BRANCH_STUBS"]);

        let map = fs.get_entry_segment_map();
        let kext = map.get(&MachoFileSetEntry::new("com.example.kext", 0x1000, false)).unwrap();
        let seg_names: Vec<&str> = kext.iter().map(|s| s.get_segment_name()).collect();
        assert_eq!(seg_names, ["__TEXT", "__LINKEDIT"]);
        assert!(map.contains_key(&MachoFileSetEntry::new("BRANCH_STUBS", 0, true)));
        drop(map);

        let file = GFileSystem::lookup(&fs, Some("/com.example.kext")).unwrap().unwrap();
        let attrs = fs.get_file_attributes(&*file, &DummyMonitor);
        assert!(attrs.get(FileAttributeType::NameAttr).is_some());
    }

    #[test]
    fn extracts_entry_and_branch_segment() {
        let fx = fixture();
        let fs = mount(&fx, fileset_image()).unwrap();

        let kext = GFileSystem::lookup(&fs, Some("/com.example.kext")).unwrap().unwrap();
        let p = fs.get_byte_provider(&*kext, &DummyMonitor).unwrap().unwrap();
        let bytes = p.read_bytes(0, p.length()).unwrap();
        assert!(bytes.ends_with(macho_file_set_extractor::FOOTER_V1));
        assert_eq!(p.get_fsrl(), Some(kext.get_fsrl()));
        let mut h = MachHeader::new(Rc::new(ByteArrayProvider::new(bytes))).unwrap();
        h.parse().unwrap();
        assert_eq!(h.get_segment("__TEXT").unwrap().get_vm_address() as u64, 0xffff_fe00_0000_1000);

        let stubs = GFileSystem::lookup(&fs, Some("/BRANCH_STUBS")).unwrap().unwrap();
        let p = fs.get_byte_provider(&*stubs, &DummyMonitor).unwrap().unwrap();
        let bytes = p.read_bytes(0, p.length()).unwrap();
        assert_eq!(&bytes[32 + 72..32 + 72 + 16], b"BRANCHSTUBS_0123");
    }

    #[test]
    fn missing_text_segment_fails_and_close_releases() {
        let fx = fixture();
        let mut image = fileset_image();
        image[0x28..0x2e].copy_from_slice(b"__NOPE");
        assert!(mount(&fx, image).is_err());

        let fs = mount(&fx, fileset_image()).unwrap();
        assert!(!fs.is_closed());
        GFileSystem::close(&fs).unwrap();
        assert!(fs.is_closed());
        assert_eq!(GFileSystem::get_file_count(&fs), 0);
    }
}
