use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use thiserror::Error;

use crate::app::util::importer::message_log::MessageLog;
use crate::app::seam_stubs::{DyldCacheMappingInfo};
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::StructConverter;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::{Memory, MemoryAccessException};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Port of `DyldCacheSlideInfoCommon.DATA_PAGE_MAP_ENTRY`.
pub const DATA_PAGE_MAP_ENTRY: i32 = 1;
/// Port of `DyldCacheSlideInfoCommon.BYTES_PER_CHAIN_OFFSET`.
pub const BYTES_PER_CHAIN_OFFSET: i32 = 4;
/// Port of `DyldCacheSlideInfoCommon.CHAIN_OFFSET_MASK`.
pub const CHAIN_OFFSET_MASK: i32 = 0x3fff;

/// Error produced by [`DyldCacheSlideInfoCommon::get_slide_fixups`].
///
/// Stands in for the two checked exceptions Java declares (`IOException`, `CancelledException`).
#[derive(Debug, Error)]
pub enum DyldSlideFixupError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Error produced by [`DyldCacheSlideInfoCommon::fixup_slide_pointers`].
///
/// Stands in for the two checked exceptions Java declares (`MemoryAccessException`,
/// `CancelledException`).
#[derive(Debug, Error)]
pub enum DyldFixupSlidePointersError {
    #[error(transparent)]
    Memory(#[from] MemoryAccessException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Slide(#[from] DyldSlideFixupError),
}

/// The shared state (fields) and concrete (non-abstract) instance methods of the
/// `dyld_cache_slide_info` structure family.
///
/// Port of the fields + concrete methods of the abstract Java class
/// `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon`. Per this crate's shape rule
/// for an abstract class with instance fields, the shared state lives here rather than on the
/// [`DyldCacheSlideInfoCommon`] trait (which can only declare behavior); every concrete
/// `dyld_cache_slide_info*` implementor embeds one of these and exposes it via
/// [`DyldCacheSlideInfoCommon::base`].
///
/// This was a `crate::app::seam_stubs::DyldCacheSlideInfoCommon` placeholder (a concrete struct
/// carrying only `version`, standing in for the whole family since
/// [`DyldCacheProgramBuilder`](crate::app::util::opinion::dyld_cache_program_builder::DyldCacheProgramBuilder)
/// never distinguished between slide-info versions) before this class had its own port.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfoCommonBase {
    pub version: i32,
    pub slide_info_offset: i64,
    pub mapping_info: DyldCacheMappingInfo,
}

impl DyldCacheSlideInfoCommonBase {
    /// Reads the common `version` field, mirroring
    /// `DyldCacheSlideInfoCommon(BinaryReader, DyldCacheMappingInfo)`.
    ///
    /// `slide_info_offset` starts at `0` here; [`parse_slide_info`] sets the real value on the
    /// returned info after construction, matching Java's `parseSlideInfo` doing the same via a
    /// direct field write after the version-specific constructor returns.
    pub fn new(reader: &mut dyn BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        Ok(DyldCacheSlideInfoCommonBase {
            version: reader.read_next_int()?,
            slide_info_offset: 0,
            mapping_info,
        })
    }
}

/// A `GByteStore` over a range of program memory starting at a base address, sufficient for
/// [`DyldCacheSlideInfoCommon::fixup_slide_pointers`] to build a `BinaryReader` the way Java's
/// version builds one from a `MemoryByteProvider`.
///
/// `ghidra.app.util.bin.MemoryByteProvider` is not itself ported yet (a much larger, general
/// purpose class), so this is a local, minimal stand-in scoped to sequential reads relative to
/// `base`, mirroring the crate's established pattern for filling this gap (e.g.
/// `ElfInfoItem`'s `ProviderBinaryReader`, `JavaLoader`'s `JavaClassBinaryReader`).
struct MemoryRangeByteProvider {
    memory: Arc<dyn Memory>,
    base: Address,
}

impl MemoryRangeByteProvider {
    fn resolve(&self, index: u64) -> io::Result<Address> {
        self.base
            .add(index as i64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }
}

impl GByteStore for MemoryRangeByteProvider {
    fn length(&mut self) -> io::Result<u64> {
        match self.memory.get_block(&self.base) {
            Some(block) => Ok((block.get_end().subtract(&self.base) as u64) + 1),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "address not mapped in any memory block")),
        }
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        match self.resolve(index) {
            Ok(addr) => self.memory.contains(&addr),
            Err(_) => false,
        }
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        let addr = self.resolve(index)?;
        self.memory
            .get_byte(&addr)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let addr = self.resolve(index)?;
        let mut buf = vec![0u8; length];
        let n = self.memory.get_bytes(&addr, &mut buf);
        if n < length {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(buf)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// A [`BinaryReader`] over a [`MemoryRangeByteProvider`], mirroring the crate's established
/// `GByteStore`-backed reader adapters (see that type's own docs).
struct MemoryRangeBinaryReader {
    provider: Rc<RefCell<dyn GByteStore>>,
    little_endian: bool,
    current_index: u64,
}

impl BinaryReader for MemoryRangeBinaryReader {
    fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }
    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }
    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }
    fn set_pointer_index(&mut self, index: u64) -> u64 {
        let old = self.current_index;
        self.current_index = index;
        old
    }
    fn is_little_endian(&self) -> bool {
        self.little_endian
    }
    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.little_endian = is_little_endian;
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.provider.borrow_mut().read_bytes(index, n_elements)
    }
    fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
        Rc::clone(&self.provider)
    }
    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
        Box::new(MemoryRangeBinaryReader {
            provider: Rc::clone(&self.provider),
            little_endian: self.little_endian,
            current_index: new_index,
        })
    }
}

/// The `dyld_cache_slide_info` structure family, allowing each version-specific implementor to
/// plug in its own page-table-walking logic.
///
/// Port of the abstract class `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon`.
/// Per this crate's shape rule for an abstract Java class with instance fields, this trait
/// declares the abstract `getSlideFixups` plus default implementations of the concrete instance
/// methods (`getVersion`, `getSlideInfoOffset`, `getMappingInfo`, `fixupSlidePointers`), built
/// on [`base`](Self::base)/[`base_mut`](Self::base_mut) accessors that every implementor
/// provides by exposing its embedded [`DyldCacheSlideInfoCommonBase`].
///
/// This was a `crate::app::seam_stubs::DyldCacheSlideInfoCommon` placeholder before this class
/// had its own port; [`DyldCacheHeader`](crate::app::seam_stubs::DyldCacheHeader)'s
/// `slide_infos` field and
/// [`DyldCacheProgramBuilder`](crate::app::util::opinion::dyld_cache_program_builder::DyldCacheProgramBuilder)'s
/// `fixup_slide_pointers` were updated in this same change to use `Box<dyn
/// DyldCacheSlideInfoCommon>` (a trait object) instead of the placeholder struct, since the real
/// Java class is a genuine abstract base with five concrete subclasses
/// (`DyldCacheSlideInfo1..5`), none of which are ported yet.
pub trait DyldCacheSlideInfoCommon: StructConverter {
    /// Access to the shared base state (fields). Every implementor embeds a
    /// [`DyldCacheSlideInfoCommonBase`] and returns a reference to it here.
    fn base(&self) -> &DyldCacheSlideInfoCommonBase;

    /// Mutable access to the shared base state, needed by [`parse_slide_info`] to set
    /// `slide_info_offset` after construction.
    fn base_mut(&mut self) -> &mut DyldCacheSlideInfoCommonBase;

    /// Port of `getVersion()`.
    fn get_version(&self) -> i32 {
        self.base().version
    }

    /// Port of `getSlideInfoOffset()`.
    fn get_slide_info_offset(&self) -> i64 {
        self.base().slide_info_offset
    }

    /// Port of `getMappingInfo()`.
    fn get_mapping_info(&self) -> &DyldCacheMappingInfo {
        &self.base().mapping_info
    }

    /// Walks the slide fixup information and collects the fixups that will need to be applied
    /// to the image.
    ///
    /// Port of the abstract `getSlideFixups(BinaryReader, int, MessageLog, TaskMonitor)`.
    fn get_slide_fixups(
        &self,
        reader: &mut dyn BinaryReader,
        pointer_size: i32,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<DyldFixup>, DyldSlideFixupError>;

    /// Fixes up the program's slide pointers.
    ///
    /// Port of `fixupSlidePointers(Program, boolean, boolean, MessageLog, TaskMonitor)`.
    ///
    /// Markup (`program.getListing().createData(addr, POINTER)`) is not yet performed: it needs
    /// the `POINTER` datatype singleton, which -- like `StructureDataType` elsewhere in this
    /// crate -- is not ported yet. The pointer value write and, when requested, the relocation
    /// table entry are still applied faithfully.
    fn fixup_slide_pointers(
        &self,
        program: &mut dyn Program,
        markup: bool,
        add_relocations: bool,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DyldFixupSlidePointersError> {
        let memory = program
            .get_memory()
            .ok_or_else(|| MemoryAccessException::new("program has no memory"))?;
        let space = program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or_else(|| MemoryAccessException::new("program has no default address space"))?;
        let data_page_addr = Address::new(space, self.base().mapping_info.get_address());

        let provider: Rc<RefCell<dyn GByteStore>> = Rc::new(RefCell::new(MemoryRangeByteProvider {
            memory: Arc::clone(&memory),
            base: data_page_addr.clone(),
        }));
        let mut reader = MemoryRangeBinaryReader {
            provider,
            little_endian: !memory.is_big_endian(),
            current_index: 0,
        };

        let fixups = self.get_slide_fixups(
            &mut reader,
            program.get_default_pointer_size(),
            log,
            monitor,
        )?;

        monitor.initialize(fixups.len() as i64);
        monitor.set_message("Fixing DYLD Cache slide pointers...");
        for fixup in &fixups {
            monitor.increment_progress(1);
            let Some(value) = fixup.value else { continue };
            let addr = data_page_addr
                .add(fixup.offset)
                .map_err(|e| MemoryAccessException::new(e.to_string()))?;
            let bytes: Vec<u8> = if fixup.size == 8 {
                if memory.is_big_endian() { value.to_be_bytes().to_vec() } else { value.to_le_bytes().to_vec() }
            } else {
                let v32 = value as i32;
                if memory.is_big_endian() { v32.to_be_bytes().to_vec() } else { v32.to_le_bytes().to_vec() }
            };
            {
                let memory_mut = program
                    .get_memory_mut()
                    .ok_or_else(|| MemoryAccessException::new("program has no memory"))?;
                memory_mut.set_bytes(&addr, &bytes)?;
            }
        }

        if markup {
            monitor.initialize(fixups.len() as i64);
            monitor.set_message("Marking up DYLD Cache slide pointers...");
            for fixup in &fixups {
                monitor.increment_progress(1);
                let Some(value) = fixup.value else { continue };
                let addr = data_page_addr
                    .add(fixup.offset)
                    .map_err(|e| MemoryAccessException::new(e.to_string()))?;
                if add_relocations {
                    if let Some(table) = program.get_relocation_table() {
                        let _ = table.add_with_byte_length(
                            addr.clone(),
                            RelocationStatus::Applied,
                            self.base().version,
                            vec![value],
                            fixup.size,
                            None,
                        );
                    }
                }
                // See this method's own docs: `createData(addr, POINTER)` is not yet performed
                // (POINTER datatype singleton not ported).
            }
        }

        Ok(())
    }
}

/// Parses the slide info.
///
/// Port of the static `DyldCacheSlideInfoCommon.parseSlideInfo(BinaryReader, long,
/// DyldCacheMappingInfo, MessageLog, TaskMonitor)`.
///
/// None of `DyldCacheSlideInfo{1..5}` (the version-specific subclasses Java's `switch`
/// dispatches to) are ported yet, so every version currently fails to construct, exactly like
/// Java's `default -> throw new IOException()` branch -- this always logs and returns `None`. It
/// still faithfully reads and validates the version field first, matching Java's behavior up to
/// that point.
pub fn parse_slide_info(
    reader: &mut dyn BinaryReader,
    slide_info_offset: i64,
    _mapping_info: &DyldCacheMappingInfo,
    log: &MessageLog,
    monitor: &dyn TaskMonitor,
) -> Option<Box<dyn DyldCacheSlideInfoCommon>> {
    if slide_info_offset == 0 {
        return None;
    }

    monitor.set_message("Parsing DYLD slide info...");
    monitor.initialize(1);
    let mut error_message = String::from("Failed to parse dyld_cache_slide_info");

    reader.set_pointer_index(slide_info_offset as u64);
    let version = match reader.read_int(reader.get_pointer_index()) {
        Ok(v) => v,
        Err(_) => {
            log.append_msg(&error_message);
            return None;
        }
    };
    error_message.push_str(&version.to_string());

    // No DyldCacheSlideInfo{1..5} implementor is ported yet for any version -- see this
    // function's own docs.
    log.append_msg(&error_message);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn base_new_reads_version() {
        let data = 3i32.to_le_bytes().to_vec();
        let mut reader = MockReader::new(data, true);
        let mapping_info = DyldCacheMappingInfo::new(0x1000, 0x2000, 0, true, true, false);
        let base = DyldCacheSlideInfoCommonBase::new(&mut reader, mapping_info).expect("should parse");
        assert_eq!(base.version, 3);
        assert_eq!(base.slide_info_offset, 0);
        assert_eq!(base.mapping_info.get_address(), 0x1000);
    }

    struct NoopMonitor;
    impl TaskMonitor for NoopMonitor {
        fn is_cancelled(&self) -> bool { false }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String { String::new() }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 { 0 }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool { false }
        fn check_cancelled(&self) -> Result<(), CancelledException> { Ok(()) }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 { 0 }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool { true }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn parse_slide_info_zero_offset_returns_none_without_reading() {
        let mut reader = MockReader::new(Vec::new(), true);
        let mapping_info = DyldCacheMappingInfo::new(0, 0, 0, false, false, false);
        let log = MessageLog::new();
        let result = parse_slide_info(&mut reader, 0, &mapping_info, &log, &NoopMonitor);
        assert!(result.is_none());
        assert!(!log.has_messages());
    }

    #[test]
    fn parse_slide_info_logs_version_and_returns_none_for_any_version() {
        // No DyldCacheSlideInfo{1..5} is ported yet, so parsing always fails, matching Java's
        // `default -> throw new IOException()` branch (versions 1-5 all currently hit it too).
        let mut data = vec![0u8; 0x100];
        data.extend_from_slice(&2i32.to_le_bytes());
        let mut reader = MockReader::new(data, true);
        let mapping_info = DyldCacheMappingInfo::new(0, 0, 0, false, false, false);
        let log = MessageLog::new();
        let result = parse_slide_info(&mut reader, 0x100, &mapping_info, &log, &NoopMonitor);
        assert!(result.is_none());
        assert!(log.has_messages());
        assert!(log.messages()[0].ends_with('2'));
    }

    // ---- fixup_slide_pointers ----

    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::reloc::relocation::{Relocation, RelocationStatus};
    use crate::program::model::reloc::relocation_table::RelocationTable;
    use std::sync::{Mutex, RwLock};

    /// A `Memory` handle backed by shared bytes, so a `MockProgram` can hand out both a
    /// `get_memory()` (`Arc<dyn Memory>`) and a `get_memory_mut()` (`&mut dyn Memory`) view of
    /// the same underlying storage -- mirroring `TestMemory`'s "the trait hands out `Arc<dyn
    /// Memory>`, which cannot be mutated through" workaround in
    /// `program::database::code::test_support`.
    struct SharedMemory {
        bytes: Arc<RwLock<Vec<u8>>>,
        big_endian: bool,
    }

    impl Memory for SharedMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let off = addr.offset() as usize;
            self.bytes
                .read()
                .unwrap()
                .get(off)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let off = addr.offset() as usize;
            let buf = self.bytes.read().unwrap();
            if off >= buf.len() {
                return 0;
            }
            let n = (buf.len() - off).min(dest.len());
            dest[..n].copy_from_slice(&buf[off..off + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let off = addr.offset() as usize;
            let mut buf = self.bytes.write().unwrap();
            if off + source.len() > buf.len() {
                buf.resize(off + source.len(), 0);
            }
            buf[off..off + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    struct MockRelocationTable {
        relocations: Vec<Relocation>,
    }

    impl RelocationTable for MockRelocationTable {
        fn add(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            bytes: Option<Vec<u8>>,
            symbol_name: Option<String>,
        ) -> Relocation {
            let reloc = Relocation::new(addr, status, type_, values, bytes, symbol_name);
            self.relocations.push(reloc.clone());
            reloc
        }
        fn add_with_byte_length(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            byte_length: i32,
            symbol_name: Option<String>,
        ) -> Relocation {
            let bytes = if byte_length > 0 { Some(vec![0u8; byte_length as usize]) } else { None };
            self.add(addr, status, type_, values, bytes, symbol_name)
        }
        fn get_relocations(&self, addr: &Address) -> Vec<Relocation> {
            self.relocations.iter().filter(|r| r.address() == addr).cloned().collect()
        }
        fn has_relocation(&self, addr: &Address) -> bool {
            self.relocations.iter().any(|r| r.address() == addr)
        }
        fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(self.relocations.clone().into_iter())
        }
        fn relocation_iter_in(
            &self,
            set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn Iterator<Item = Relocation>> {
            let matches: Vec<Relocation> =
                self.relocations.iter().filter(|r| set.contains(r.address())).cloned().collect();
            Box::new(matches.into_iter())
        }
        fn get_relocation_address_after(&self, addr: &Address) -> Option<Address> {
            self.relocations.iter().map(|r| r.address().clone()).filter(|a| a > addr).min()
        }
        fn get_size(&self) -> i32 {
            self.relocations.len() as i32
        }
        fn is_relocatable(&self) -> bool {
            true
        }
    }

    struct MockProgram {
        memory_shared: Arc<SharedMemory>,
        memory_owned: SharedMemory,
        space: Arc<AddressSpace>,
        relocation_table: MockRelocationTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.dyldcache".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory_shared.clone() as Arc<dyn Memory>)
        }
        fn get_memory_mut(&mut self) -> Option<&mut dyn Memory> {
            Some(&mut self.memory_owned)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(Arc::new(DefaultAddressFactory::new(vec![self.space.clone()])) as Arc<dyn AddressFactory>)
        }
        fn get_default_pointer_size(&self) -> i32 {
            8
        }
        fn get_relocation_table(&mut self) -> Option<&mut dyn RelocationTable> {
            Some(&mut self.relocation_table)
        }
    }

    fn mock_program(initial_len: usize, big_endian: bool) -> MockProgram {
        let bytes = Arc::new(RwLock::new(vec![0u8; initial_len]));
        MockProgram {
            memory_shared: Arc::new(SharedMemory { bytes: Arc::clone(&bytes), big_endian }),
            memory_owned: SharedMemory { bytes, big_endian },
            space: AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0),
            relocation_table: MockRelocationTable { relocations: Vec::new() },
        }
    }

    /// A minimal implementor of [`DyldCacheSlideInfoCommon`] for testing
    /// [`DyldCacheSlideInfoCommon::fixup_slide_pointers`]'s default implementation: its
    /// `get_slide_fixups` just returns canned fixups without touching the reader.
    struct FixedFixupsSlideInfo {
        base: DyldCacheSlideInfoCommonBase,
        fixups: Vec<DyldFixup>,
    }

    impl StructConverter for FixedFixupsSlideInfo {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError>
        {
            Err(crate::app::util::bin::struct_converter::ToDataTypeError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "test stub",
            )))
        }
    }

    impl DyldCacheSlideInfoCommon for FixedFixupsSlideInfo {
        fn base(&self) -> &DyldCacheSlideInfoCommonBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut DyldCacheSlideInfoCommonBase {
            &mut self.base
        }
        fn get_slide_fixups(
            &self,
            _reader: &mut dyn BinaryReader,
            _pointer_size: i32,
            _log: &MessageLog,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<DyldFixup>, DyldSlideFixupError> {
            Ok(self.fixups.clone())
        }
    }

    #[test]
    fn fixup_slide_pointers_writes_pointer_value_into_memory() {
        let mut program = mock_program(16, false);
        let mapping_info = DyldCacheMappingInfo::new(0, 16, 0, true, true, false);
        let info = FixedFixupsSlideInfo {
            base: DyldCacheSlideInfoCommonBase { version: 2, slide_info_offset: 0, mapping_info },
            fixups: vec![DyldFixup::new(0, Some(0x1122_3344_5566_7788u64 as i64), 8, None, None)],
        };
        let log = MessageLog::new();

        info.fixup_slide_pointers(&mut program, false, false, &log, &NoopMonitor)
            .expect("fixup should succeed");

        let bytes = program.memory_owned.bytes.read().unwrap();
        assert_eq!(&bytes[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    }

    #[test]
    fn fixup_slide_pointers_skips_unsupported_fixups() {
        let mut program = mock_program(16, false);
        let mapping_info = DyldCacheMappingInfo::new(0, 16, 0, true, true, false);
        let info = FixedFixupsSlideInfo {
            base: DyldCacheSlideInfoCommonBase { version: 2, slide_info_offset: 0, mapping_info },
            fixups: vec![DyldFixup::new(0, None, 8, None, None)],
        };
        let log = MessageLog::new();

        info.fixup_slide_pointers(&mut program, false, false, &log, &NoopMonitor)
            .expect("fixup should succeed even with an unresolved value");

        let bytes = program.memory_owned.bytes.read().unwrap();
        assert_eq!(&bytes[0..8], &[0u8; 8]);
    }

    #[test]
    fn fixup_slide_pointers_adds_relocation_when_requested() {
        let mut program = mock_program(16, false);
        let mapping_info = DyldCacheMappingInfo::new(0, 16, 0, true, true, false);
        let info = FixedFixupsSlideInfo {
            base: DyldCacheSlideInfoCommonBase { version: 3, slide_info_offset: 0, mapping_info },
            fixups: vec![DyldFixup::new(4, Some(0xAABB_CCDDu32 as i64), 4, None, None)],
        };
        let log = MessageLog::new();

        info.fixup_slide_pointers(&mut program, true, true, &log, &NoopMonitor)
            .expect("fixup should succeed");

        let bytes = program.memory_owned.bytes.read().unwrap();
        assert_eq!(&bytes[4..8], &0xAABB_CCDDu32.to_le_bytes());
        assert_eq!(program.relocation_table.relocations.len(), 1);
        assert_eq!(program.relocation_table.relocations[0].type_(), 3);
    }
}
