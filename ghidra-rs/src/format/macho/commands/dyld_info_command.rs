//! Port of `ghidra.app.util.bin.format.macho.commands.DyldInfoCommand`.
//!
//! Represents a `dyld_info_command` structure.
//!
//! Java's `DyldInfoCommand extends LoadCommand`; per this crate's composition-over-inheritance
//! convention (see [`LoadCommand`]'s own docs), the inherited state is an embedded
//! [`LoadCommandBase`] rather than a supertrait, mirroring
//! [`DyldChainedFixupsCommand`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand).
//!
//! `RebaseTable`/`BindingTable` (`ghidra.app.util.bin.format.macho.commands.dyld`) are not
//! themselves ported: their real job is to run REBASE/BIND/LAZY_BIND opcode state machines
//! (`AbstractClassicProcessor` and subclasses) over the referenced bytes, none of which are
//! ported. [`crate::format::seam_stubs::RebaseTable`]/[`crate::format::seam_stubs::BindingTable`]
//! are minimal placeholders that read nothing and always report empty
//! [`OpcodeTable`](crate::format::macho::commands::dyld::opcode_table::OpcodeTable) offset lists
//! (see their own docs). Consequently [`DyldInfoCommand::markup`]'s opcode-table markup loops
//! (which would call `DataUtilities.createData` with the `ULEB128`/`SLEB128`/`STRING`/opcode
//! datatype singletons -- also not ported, the same recurring gap as `StructureDataType`
//! elsewhere in this crate) never have anything to iterate; only the real, always-applicable
//! plate-comment markup is performed. `markup_raw_binary`'s fragment creation is unaffected by
//! this gap and is ported in full.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::export_trie::ExportTrie;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::seam_stubs::{BindingTable, FlatProgramAPI, MachHeader, MessageLog, RebaseTable};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A `dyld_info_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DyldInfoCommand`.
pub struct DyldInfoCommand {
    base: LoadCommandBase,
    rebase_off: u64,
    rebase_size: u64,
    bind_off: u64,
    bind_size: u64,
    weak_bind_off: u64,
    weak_bind_size: u64,
    lazy_bind_off: u64,
    lazy_bind_size: u64,
    export_off: u64,
    export_size: u64,
    rebase_table: RebaseTable,
    binding_table: BindingTable,
    weak_binding_table: BindingTable,
    lazy_binding_table: BindingTable,
    export_trie: ExportTrie,
}

impl DyldInfoCommand {
    /// Creates and parses a new `DyldInfoCommand`.
    ///
    /// `load_command_reader` points to the start of the load command; `data_reader` can read the
    /// data the load command references (possibly a different underlying provider).
    ///
    /// Port of `DyldInfoCommand(BinaryReader, BinaryReader, MachHeader)`.
    pub fn new(
        load_command_reader: &mut dyn BinaryReader,
        data_reader: &mut dyn BinaryReader,
        header: &dyn MachHeader,
    ) -> io::Result<Self> {
        let base = LoadCommandBase::new(load_command_reader)?;

        let rebase_off = load_command_reader.read_next_unsigned_int()?;
        let rebase_size = load_command_reader.read_next_unsigned_int()?;
        let bind_off = load_command_reader.read_next_unsigned_int()?;
        let bind_size = load_command_reader.read_next_unsigned_int()?;
        let weak_bind_off = load_command_reader.read_next_unsigned_int()?;
        let weak_bind_size = load_command_reader.read_next_unsigned_int()?;
        let lazy_bind_off = load_command_reader.read_next_unsigned_int()?;
        let lazy_bind_size = load_command_reader.read_next_unsigned_int()?;
        let export_off = load_command_reader.read_next_unsigned_int()?;
        let export_size = load_command_reader.read_next_unsigned_int()?;

        let rebase_table = if rebase_off > 0 && rebase_size > 0 {
            data_reader.set_pointer_index(header.get_start_index() + rebase_off);
            RebaseTable::parse(data_reader, header, rebase_size as i64)?
        } else {
            RebaseTable::new()
        };

        let binding_table = if bind_off > 0 && bind_size > 0 {
            data_reader.set_pointer_index(header.get_start_index() + bind_off);
            BindingTable::parse(data_reader, header, bind_size as i64, false)?
        } else {
            BindingTable::new()
        };

        let weak_binding_table = if weak_bind_off > 0 && weak_bind_size > 0 {
            data_reader.set_pointer_index(header.get_start_index() + weak_bind_off);
            BindingTable::parse(data_reader, header, weak_bind_size as i64, false)?
        } else {
            BindingTable::new()
        };

        let lazy_binding_table = if lazy_bind_off > 0 && lazy_bind_size > 0 {
            data_reader.set_pointer_index(header.get_start_index() + lazy_bind_off);
            BindingTable::parse(data_reader, header, lazy_bind_size as i64, true)?
        } else {
            BindingTable::new()
        };

        let export_trie = if export_off > 0 && export_size > 0 {
            data_reader.set_pointer_index(header.get_start_index() + export_off);
            ExportTrie::from_reader(data_reader)?
        } else {
            ExportTrie::new()
        };

        Ok(DyldInfoCommand {
            base,
            rebase_off,
            rebase_size,
            bind_off,
            bind_size,
            weak_bind_off,
            weak_bind_size,
            lazy_bind_off,
            lazy_bind_size,
            export_off,
            export_size,
            rebase_table,
            binding_table,
            weak_binding_table,
            lazy_binding_table,
            export_trie,
        })
    }

    /// Port of `getRebaseOffset()`.
    pub fn rebase_offset(&self) -> u64 {
        self.rebase_off
    }
    /// Port of `getRebaseSize()`.
    pub fn rebase_size(&self) -> u64 {
        self.rebase_size
    }
    /// Port of `getBindOffset()`.
    pub fn bind_offset(&self) -> u64 {
        self.bind_off
    }
    /// Port of `getBindSize()`.
    pub fn bind_size(&self) -> u64 {
        self.bind_size
    }
    /// Port of `getWeakBindOffset()`.
    pub fn weak_bind_offset(&self) -> u64 {
        self.weak_bind_off
    }
    /// Port of `getWeakBindSize()`.
    pub fn weak_bind_size(&self) -> u64 {
        self.weak_bind_size
    }
    /// Port of `getLazyBindOffset()`.
    pub fn lazy_bind_offset(&self) -> u64 {
        self.lazy_bind_off
    }
    /// Port of `getLazyBindSize()`.
    pub fn lazy_bind_size(&self) -> u64 {
        self.lazy_bind_size
    }
    /// Port of `getExportOffset()`.
    pub fn export_offset(&self) -> u64 {
        self.export_off
    }
    /// Port of `getExportSize()`.
    pub fn export_size(&self) -> u64 {
        self.export_size
    }
    /// Port of `getRebaseTable()`.
    pub fn rebase_table(&self) -> &RebaseTable {
        &self.rebase_table
    }
    /// Port of `getBindingTable()`.
    pub fn binding_table(&self) -> &BindingTable {
        &self.binding_table
    }
    /// Port of `getLazyBindingTable()`.
    pub fn lazy_binding_table(&self) -> &BindingTable {
        &self.lazy_binding_table
    }
    /// Port of `getWeakBindingTable()`.
    pub fn weak_binding_table(&self) -> &BindingTable {
        &self.weak_binding_table
    }
    /// Port of `getExportTrie()`.
    pub fn export_trie(&self) -> &ExportTrie {
        &self.export_trie
    }

    fn markup_rebase_info(&self, program: &mut dyn Program, header: &dyn MachHeader, source: Option<&str>) {
        let addr = self.file_offset_to_address(program, header, self.rebase_off as i64, self.rebase_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("rebase"));
        // See this module's own docs: the opcode-table markup loop is not performed.
    }

    fn markup_bindings(&self, program: &mut dyn Program, header: &dyn MachHeader, source: Option<&str>) {
        let addr = self.file_offset_to_address(program, header, self.bind_off as i64, self.bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("bind"));
    }

    fn markup_weak_bindings(&self, program: &mut dyn Program, header: &dyn MachHeader, source: Option<&str>) {
        let addr =
            self.file_offset_to_address(program, header, self.weak_bind_off as i64, self.weak_bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("weak bind"));
    }

    fn markup_lazy_bindings(&self, program: &mut dyn Program, header: &dyn MachHeader, source: Option<&str>) {
        let addr =
            self.file_offset_to_address(program, header, self.lazy_bind_off as i64, self.lazy_bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("lazy bind"));
    }

    fn markup_export_info(&self, program: &mut dyn Program, header: &dyn MachHeader, source: Option<&str>) {
        let Some(addr) =
            self.file_offset_to_address(program, header, self.export_off as i64, self.export_size as i64)
        else {
            return;
        };
        self.markup_plate_comment(program, Some(&addr), source, Some("export"));
        // See this module's own docs: the ULEB128/STRING markup loop is not performed.
    }
}

impl StructConverter for DyldInfoCommand {
    /// Mirrors `toDataType()`. Not yet buildable: it requires `StructureDataType` (a mutable,
    /// constructible `Structure`), which is not ported yet.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "DyldInfoCommand::to_data_type requires StructureDataType, which is not yet ported",
        )))
    }
}

impl LoadCommand for DyldInfoCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "dyld_info_command".to_string()
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &dyn MachHeader,
        source: Option<&str>,
        _monitor: &dyn TaskMonitor,
        _log: &dyn MessageLog,
    ) -> Result<(), CancelledException> {
        self.markup_rebase_info(program, header, source);
        self.markup_bindings(program, header, source);
        self.markup_weak_bindings(program, header, source);
        self.markup_lazy_bindings(program, header, source);
        self.markup_export_info(program, header, source);
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
        // ---- Flattened `LoadCommand.markupRawBinary` (Java's `super.markupRawBinary(...)`); it
        // has its own internal catch that never propagates a failure out of itself. ----
        let _ = header;
        self.update_monitor(monitor);
        let base_result: Result<(), String> = (|| {
            self.create_fragment(api, base_address, parent_module).map_err(|e| e.to_string())?;
            let addr = base_address.space().address(self.get_start_index() as i64);
            let data_type = self.to_data_type().map_err(|e| e.to_string())?;
            api.create_data(&addr, data_type).map_err(|e| e.to_string())?;
            self.create_plate_comment(api, &addr);
            Ok(())
        })();
        if let Err(message) = base_result {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }

        // ---- `DyldInfoCommand.markupRawBinary`'s own additional fragments. ----
        let extra_result: Result<(), String> = (|| {
            if self.rebase_size > 0 {
                let start = base_address.space().address(self.rebase_off as i64);
                api.create_fragment(parent_module, &format!("{}_REBASE", self.get_command_name()), &start, self.rebase_size as i64)
                    .map_err(|e| e.to_string())?;
            }
            if self.bind_size > 0 {
                let start = base_address.space().address(self.bind_off as i64);
                api.create_fragment(parent_module, &format!("{}_BIND", self.get_command_name()), &start, self.bind_size as i64)
                    .map_err(|e| e.to_string())?;
            }
            if self.weak_bind_size > 0 {
                let start = base_address.space().address(self.weak_bind_off as i64);
                api.create_fragment(parent_module, &format!("{}_WEAK_BIND", self.get_command_name()), &start, self.weak_bind_size as i64)
                    .map_err(|e| e.to_string())?;
            }
            if self.lazy_bind_size > 0 {
                let start = base_address.space().address(self.lazy_bind_off as i64);
                api.create_fragment(parent_module, &format!("{}_LAZY_BIND", self.get_command_name()), &start, self.lazy_bind_size as i64)
                    .map_err(|e| e.to_string())?;
            }
            if self.export_size > 0 {
                let start = base_address.space().address(self.export_off as i64);
                api.create_fragment(parent_module, &format!("{}_EXPORT", self.get_command_name()), &start, self.export_size as i64)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if extra_result.is_err() {
            log.append_msg(&format!("Unable to create {}", self.get_command_name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::macho::commands::dyld::opcode_table::OpcodeTable;
    use crate::format::macho::commands::load_command_types::LC_DYLD_INFO;
    use crate::format::seam_stubs::SegmentCommand;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0.get(start..end).map(|s| s.to_vec()).ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { provider: Rc::new(RefCell::new(VecProvider(data))), little_endian: true, current_index: 0 }
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader { provider: Rc::clone(&self.provider), little_endian: self.little_endian, current_index: new_index })
        }
    }

    struct MockMachHeader;
    impl MachHeader for MockMachHeader {
        fn get_segment(&self, _segment_name: &str) -> Option<Box<dyn SegmentCommand>> {
            None
        }
        fn get_all_segments(&self) -> Vec<Box<dyn SegmentCommand>> {
            Vec::new()
        }
    }

    /// Builds a `dyld_info_command` load-command header (cmd, cmdsize, then the 10 unsigned-int
    /// fields), all little-endian.
    fn command_bytes(
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(LC_DYLD_INFO as i32).to_le_bytes()); // cmd
        data.extend_from_slice(&48i32.to_le_bytes()); // cmdsize
        for v in [
            rebase_off,
            rebase_size,
            bind_off,
            bind_size,
            weak_bind_off,
            weak_bind_size,
            lazy_bind_off,
            lazy_bind_size,
            export_off,
            export_size,
        ] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data
    }

    #[test]
    fn parses_all_offsets_and_sizes_with_zero_tables() {
        let data = command_bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let mut lc_reader = MockReader::new(data);
        let mut data_reader = MockReader::new(Vec::new());
        let header = MockMachHeader;

        let cmd = DyldInfoCommand::new(&mut lc_reader, &mut data_reader, &header).expect("should parse");
        assert_eq!(cmd.rebase_offset(), 0);
        assert_eq!(cmd.rebase_size(), 0);
        assert_eq!(cmd.export_offset(), 0);
        assert_eq!(cmd.export_size(), 0);
        assert_eq!(cmd.get_command_name(), "dyld_info_command");
        assert_eq!(cmd.get_command_type(), LC_DYLD_INFO as i32);
        assert!(cmd.rebase_table().opcode_offsets().is_empty());
    }

    #[test]
    fn parses_nonzero_offsets_and_sizes() {
        let data = command_bytes(100, 10, 110, 20, 130, 5, 135, 15, 150, 8);
        let mut lc_reader = MockReader::new(data);
        // Data reader must be long enough that set_pointer_index'ing to each offset succeeds when
        // the (stub) table parsers touch it; they don't read, but is_valid_index isn't checked by
        // set_pointer_index itself so an empty data reader is fine too. Keep it non-trivial for
        // realism.
        let mut data_reader = MockReader::new(vec![0u8; 200]);
        let header = MockMachHeader;

        let cmd = DyldInfoCommand::new(&mut lc_reader, &mut data_reader, &header).expect("should parse");
        assert_eq!(cmd.rebase_offset(), 100);
        assert_eq!(cmd.rebase_size(), 10);
        assert_eq!(cmd.bind_offset(), 110);
        assert_eq!(cmd.bind_size(), 20);
        assert_eq!(cmd.weak_bind_offset(), 130);
        assert_eq!(cmd.weak_bind_size(), 5);
        assert_eq!(cmd.lazy_bind_offset(), 135);
        assert_eq!(cmd.lazy_bind_size(), 15);
        assert_eq!(cmd.export_offset(), 150);
        assert_eq!(cmd.export_size(), 8);
    }
}
