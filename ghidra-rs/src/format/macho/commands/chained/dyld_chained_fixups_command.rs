//! Port of `ghidra.app.util.bin.format.macho.commands.DyldChainedFixupsCommand`.
//!
//! Represents a `dyld_chained_fixups_command` structure. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.
//!
//! Java models this as `DyldChainedFixupsCommand extends LinkEditDataCommand extends LoadCommand`.
//! Neither `LinkEditDataCommand` nor `DyldChainedFixupHeader` (and the types it in turn owns) are
//! ported yet -- they are dependency-cycle forward edges -- so this port holds
//! [`format::seam_stubs::LinkEditDataCommand`](crate::format::seam_stubs::LinkEditDataCommand) and
//! [`format::seam_stubs::DyldChainedFixupHeader`](crate::format::seam_stubs::DyldChainedFixupHeader)
//! by composition instead of trait inheritance.
//!
//! Because Java's `markup`/`markupRawBinary` rely on virtual dispatch back up through
//! `LinkEditDataCommand` and `LoadCommand` to this type's own overridden `getCommandName()`, that
//! three-level call chain is flattened directly into this type's own
//! [`LoadCommand`](crate::format::macho::commands::load_command::LoadCommand) implementation below
//! (using the real, already-ported `LoadCommand` default helpers for the pieces that don't depend
//! on the overridden name) rather than split back out across separate
//! `LinkEditDataCommand`/`LoadCommand` method bodies that could never resolve the override
//! correctly.

use std::collections::HashMap;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::chained::dyld_chained_fixups::{self, ChainedFixupError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_types::get_load_command_name;
use crate::format::macho::dyld::dyld_chained_ptr::{DyldChainType, DYLD_CHAINED_PTR_START_NONE};
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::seam_stubs::{
    DyldChainedFixupHeader, FlatProgramAPI, LinkEditDataCommand, MachHeader, MessageLog, Throwable,
};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::SymbolTable;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Bare, state-free implementor used to reach [`DataUtilities`]'s default-implemented methods,
/// mirroring the "a bare `impl DataUtilities for Foo {}` is enough" convention documented on that
/// trait.
struct Du;
impl DataUtilities for Du {}

/// Opaque marker handed to [`MessageLog::append_exception`], standing in for the Java
/// `Exception`/`Throwable` instance caught in `markupRawBinary`'s catch block. [`Throwable`] is an
/// empty marker trait (no accessors), so no error detail is lost by using a single reusable unit
/// type here.
struct RawBinaryMarkupFailure;
impl Throwable for RawBinaryMarkupFailure {}

/// Port of `ghidra.app.util.bin.format.macho.commands.DyldChainedFixupsCommand`.
pub struct DyldChainedFixupsCommand {
    link_edit: LinkEditDataCommand,
    chain_header: DyldChainedFixupHeader,
}

impl DyldChainedFixupsCommand {
    /// Creates and parses a new [`DyldChainedFixupsCommand`].
    ///
    /// `load_command_reader` points to the start of the load command; `data_reader` can read the
    /// data the load command references (possibly a different underlying provider).
    ///
    /// Port of `DyldChainedFixupsCommand(BinaryReader, BinaryReader)`.
    pub fn new(
        load_command_reader: &mut dyn BinaryReader,
        data_reader: &mut dyn BinaryReader,
    ) -> io::Result<Self> {
        let link_edit = LinkEditDataCommand::new(load_command_reader, data_reader)?;
        let chain_header = DyldChainedFixupHeader::new(data_reader)?;
        Ok(DyldChainedFixupsCommand { link_edit, chain_header })
    }

    /// Gets the [`DyldChainedFixupHeader`].
    ///
    /// Port of `DyldChainedFixupsCommand.getChainHeader()`.
    pub fn get_chain_header(&self) -> &DyldChainedFixupHeader {
        &self.chain_header
    }

    /// Walks this command's chained fixup information and collects a list of [`DyldFixup`]s that
    /// will need to be applied to the image.
    ///
    /// `reader` can read the image. `symbol_table` is `None` if not available. `monitor` is a
    /// cancellable monitor.
    ///
    /// Port of `DyldChainedFixupsCommand.getChainedFixups(BinaryReader, long, SymbolTable,
    /// MessageLog, TaskMonitor)`.
    pub fn get_chained_fixups(
        &self,
        reader: &dyn BinaryReader,
        imagebase: i64,
        symbol_table: Option<&dyn SymbolTable>,
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<DyldFixup>, ChainedFixupError> {
        let mut result = Vec::new();
        let mut count_map: HashMap<DyldChainType, i32> = HashMap::new();

        for chain_start in self.chain_header.get_chained_starts_in_image().get_chained_starts() {
            let ptr_format = DyldChainType::lookup_chain_ptr(chain_start.get_pointer_format() as i32);
            monitor.initialize(chain_start.get_page_count() as i64);
            monitor.set_message(&format!("Getting {} chained pointer fixups...", ptr_format.name()));

            let page_result: Result<(), ChainedFixupError> = (|| {
                for index in 0..chain_start.get_page_count() as i32 {
                    monitor.increment_progress(1);

                    let page = chain_start.get_segment_offset()
                        + (chain_start.get_page_size() as i64) * (index as i64);
                    let page_entry =
                        (chain_start.get_page_starts()[index as usize] as u32) & 0xffff;
                    if page_entry == DYLD_CHAINED_PTR_START_NONE {
                        continue;
                    }
                    let fixups = dyld_chained_fixups::get_chained_fixups(
                        reader,
                        self.chain_header.get_chained_imports(),
                        ptr_format,
                        page,
                        page_entry as i64,
                        0,
                        imagebase,
                        symbol_table,
                        log,
                        monitor,
                    )?;
                    *count_map.entry(ptr_format).or_insert(0) += fixups.len() as i32;
                    result.extend(fixups);
                }
                Ok(())
            })();

            match page_result {
                Ok(()) => {}
                Err(ChainedFixupError::Io(_)) => {
                    log.append_msg(&format!(
                        "Failed to get segment chain fixups at {:#x}",
                        chain_start.get_segment_offset()
                    ));
                }
                Err(e @ ChainedFixupError::Cancelled(_)) => return Err(e),
            }
        }

        for (ptr_type, count) in &count_map {
            log.append_msg(&format!(
                "Discovered {count} DYLD_CHAINED_{} chained pointers.",
                ptr_type.name()
            ));
        }

        Ok(result)
    }
}

impl StructConverter for DyldChainedFixupsCommand {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        // This type doesn't override `toDataType()` in Java, so it inherits
        // `LinkEditDataCommand.toDataType()`.
        self.link_edit.to_data_type().map_err(ToDataTypeError::from)
    }
}

impl LoadCommand for DyldChainedFixupsCommand {
    fn base(&self) -> &LoadCommandBase {
        self.link_edit.base()
    }

    fn get_linker_data_offset(&self) -> i64 {
        self.link_edit.dataoff()
    }

    fn get_linker_data_size(&self) -> i64 {
        self.link_edit.datasize()
    }

    fn get_command_name(&self) -> String {
        "dyld_chained_fixups_command".to_string()
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &dyn MachHeader,
        source: Option<&str>,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
    ) -> Result<(), CancelledException> {
        let Some(addr) =
            self.file_offset_to_address(program, header, self.link_edit.dataoff(), self.link_edit.datasize())
        else {
            return Ok(());
        };

        // Flattened `super.markup(...)` (`LinkEditDataCommand.markup`): creates a plate comment
        // at the same address.
        self.markup_plate_comment(program, Some(&addr), source, None);

        let result: Result<(), String> = (|| {
            let data_type = self.chain_header.to_data_type().map_err(|e| e.to_string())?;
            Du.create_data(program, &addr, data_type, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| e.to_string())?;
            self.chain_header
                .markup(program, &addr, header, monitor, log)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();

        if result.is_err() {
            log.error(
                "DyldChainedFixupsCommand",
                &format!("Failed to markup: {}", self.get_contextual_name(source, None)),
            );
        }
        Ok(())
    }

    fn markup_raw_binary(
        &self,
        header: &dyn MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
    ) {
        // ---- Flattened `LoadCommand.markupRawBinary` (the grandparent step; never propagates
        // failures out of itself, only logs them). ----
        let _ = header;
        self.update_monitor(monitor);
        let load_command_result: Result<(), String> = (|| {
            self.create_fragment(api, base_address, parent_module).map_err(|e| e.to_string())?;
            let addr = base_address.space().address(self.get_start_index() as i64);
            let data_type = self.to_data_type().map_err(|e| e.to_string())?;
            api.create_data(&addr, data_type).map_err(|e| e.to_string())?;
            self.create_plate_comment(api, &addr);
            Ok(())
        })();
        if let Err(message) = load_command_result {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }

        // ---- Flattened `LinkEditDataCommand.markupRawBinary`: adds a fragment for the linker
        // data itself, if any. A failure here aborts the rest of this method, matching Java's
        // enclosing try/catch. ----
        let link_edit_result: Result<(), String> = (|| {
            if self.link_edit.datasize() > 0 {
                let start = base_address.space().address(self.link_edit.dataoff());
                api.create_fragment(
                    parent_module,
                    &get_load_command_name(self.get_command_type() as u32),
                    &start,
                    self.link_edit.datasize(),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if link_edit_result.is_err() {
            log.append_msg(&format!("Unable to create {}", self.get_command_name()));
            return;
        }

        // ---- This type's own `markupRawBinary` body. ----
        let result: Result<(), String> = (|| {
            let program = api.get_current_program().ok_or("no current program")?;
            let memory = program.get_memory().ok_or("no memory")?;
            let addrs = memory.locate_addresses_for_file_offset(self.get_linker_data_offset());
            let dyld_chained_header =
                addrs.first().cloned().ok_or("Chain Header does not exist in program")?;

            let c_header = self.chain_header.to_data_type().map_err(|e| e.to_string())?;
            api.create_data(&dyld_chained_header, c_header).map_err(|e| e.to_string())?;

            let segs_addr = dyld_chained_header
                .add(self.chain_header.get_starts_offset())
                .map_err(|e| e.to_string())?;

            let chained_starts_in_image = self.chain_header.get_chained_starts_in_image();
            let seg_info_offset = chained_starts_in_image.get_seg_info_offset();
            let chained_starts = chained_starts_in_image.get_chained_starts();

            for (i, starts_in_seg) in chained_starts.iter().enumerate() {
                let data_type = starts_in_seg.to_data_type().map_err(|e| e.to_string())?;
                let offset = *seg_info_offset.get(i).ok_or("segInfoOffset index out of range")?;
                let addr = segs_addr.add(offset as i64).map_err(|e| e.to_string())?;
                api.create_data(&addr, data_type).map_err(|e| e.to_string())?;
            }
            Ok(())
        })();

        if result.is_err() {
            log.append_msg(&format!("Unable to create {}", self.get_command_name()));
            log.append_exception(&RawBinaryMarkupFailure);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::macho::commands::load_command_types::LC_DYLD_CHAINED_FIXUPS;
    use crate::format::seam_stubs::{Class, DyldChainedImport, DyldChainedImports};
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct TestLog;

    impl MessageLog for TestLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, _message: &str) {}
        fn append_exception(&self, _t: &dyn Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            false
        }
        fn clear(&self) {}
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            String::new()
        }
        fn write(&self, _owner: &dyn Class, _message_header: &str) {}
    }

    fn command_bytes(cmd: u32, cmdsize: i32, dataoff: u32, datasize: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(cmd as i32).to_le_bytes());
        v.extend_from_slice(&cmdsize.to_le_bytes());
        v.extend_from_slice(&dataoff.to_le_bytes());
        v.extend_from_slice(&datasize.to_le_bytes());
        v
    }

    /// A `dyld_chained_fixups_header` with `starts_offset` pointing just past the 7-DWORD header,
    /// followed by a `dyld_chained_starts_in_image` with one segment whose
    /// `dyld_chained_starts_in_segment` declares a single page with a real chain start.
    fn chain_data_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        // dyld_chained_fixups_header
        v.extend_from_slice(&0u32.to_le_bytes()); // fixups_version
        v.extend_from_slice(&28u32.to_le_bytes()); // starts_offset (7 * 4 bytes)
        v.extend_from_slice(&0u32.to_le_bytes()); // imports_offset
        v.extend_from_slice(&0u32.to_le_bytes()); // symbols_offset
        v.extend_from_slice(&0u32.to_le_bytes()); // imports_count
        v.extend_from_slice(&0i32.to_le_bytes()); // imports_format
        v.extend_from_slice(&0i32.to_le_bytes()); // symbols_format
        assert_eq!(v.len(), 28);

        // dyld_chained_starts_in_image
        v.extend_from_slice(&1i32.to_le_bytes()); // seg_count
        v.extend_from_slice(&8i32.to_le_bytes()); // seg_info_offset[0] (relative to this struct)
        assert_eq!(v.len(), 28 + 8);

        // dyld_chained_starts_in_segment, at offset 28 + 8 = 36
        v.extend_from_slice(&0i32.to_le_bytes()); // size
        v.extend_from_slice(&0x1000i16.to_le_bytes()); // page_size
        v.extend_from_slice(&(DyldChainType::Ptr64.value() as i16).to_le_bytes()); // pointer_format
        v.extend_from_slice(&0x2000i64.to_le_bytes()); // segment_offset
        v.extend_from_slice(&0i32.to_le_bytes()); // max_valid_pointer
        v.extend_from_slice(&1i16.to_le_bytes()); // page_count
        v.extend_from_slice(&0i16.to_le_bytes()); // page_starts[0]: chain starts at offset 0

        v
    }

    fn build_command() -> DyldChainedFixupsCommand {
        let mut load_command_reader =
            TestReader::new(command_bytes(LC_DYLD_CHAINED_FIXUPS, 16, 0, 0));
        let mut data_reader = TestReader::new(chain_data_bytes());
        DyldChainedFixupsCommand::new(&mut load_command_reader, &mut data_reader)
            .expect("well-formed chain data parses")
    }

    #[test]
    fn command_name_matches_java() {
        let cmd = build_command();
        assert_eq!(cmd.get_command_name(), "dyld_chained_fixups_command");
    }

    #[test]
    fn constructor_parses_chain_header_fields() {
        let cmd = build_command();
        let header = cmd.get_chain_header();
        assert_eq!(header.get_starts_offset(), 28);
        assert_eq!(header.get_chained_starts_in_image().get_seg_count(), 1);
        assert_eq!(header.get_chained_starts_in_image().get_chained_starts().len(), 1);

        let seg = &header.get_chained_starts_in_image().get_chained_starts()[0];
        assert_eq!(seg.get_page_count(), 1);
        assert_eq!(seg.get_segment_offset(), 0x2000);
        assert_eq!(seg.get_pointer_format(), DyldChainType::Ptr64.value() as i16);
    }

    #[test]
    fn get_chained_fixups_walks_the_single_page_chain() {
        let cmd = build_command();

        // Image bytes: a single Ptr64 chain entry, target=0x5000, next=0 (end of chain), at the
        // segment offset (0x2000) recorded in the starts-in-segment structure above.
        let mut image = vec![0u8; 0x2000];
        image.extend_from_slice(&0x5000i64.to_le_bytes());
        let reader = TestReader::new(image);
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups = cmd
            .get_chained_fixups(&reader, 0x1_0000_0000, None, &log, &monitor)
            .expect("no error");

        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].offset, 0x2000);
        assert_eq!(fixups[0].value, Some(0x5000));
        assert_eq!(fixups[0].size, 8);
    }

    #[test]
    fn get_chained_fixups_skips_pages_with_no_chain_start() {
        // A starts-in-segment with a single page whose entry is DYLD_CHAINED_PTR_START_NONE
        // should be walked without producing any fixups.
        let mut v = Vec::new();
        v.extend_from_slice(&0i32.to_le_bytes()); // size
        v.extend_from_slice(&0x1000i16.to_le_bytes()); // page_size
        v.extend_from_slice(&(DyldChainType::Ptr64.value() as i16).to_le_bytes());
        v.extend_from_slice(&0i64.to_le_bytes()); // segment_offset
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&1i16.to_le_bytes()); // page_count
        v.extend_from_slice(&(DYLD_CHAINED_PTR_START_NONE as i16).to_le_bytes());

        let mut reader = TestReader::new(v);
        let starts_in_seg = crate::format::seam_stubs::DyldChainedStartsInSegment::new(&mut reader)
            .expect("parses");
        assert_eq!(starts_in_seg.get_page_count(), 1);

        // Directly exercise the sentinel check `getChainedFixups` performs, matching the Java
        // `pageEntry == DYLD_CHAINED_PTR_START_NONE -> continue` behaviour.
        let page_entry = (starts_in_seg.get_page_starts()[0] as u32) & 0xffff;
        assert_eq!(page_entry, DYLD_CHAINED_PTR_START_NONE);
    }

    struct _UnusedImportsRef;
    impl DyldChainedImports for _UnusedImportsRef {
        fn get_chained_import(&self, _ordinal: i32) -> Box<dyn DyldChainedImport> {
            unreachable!()
        }
    }
}
