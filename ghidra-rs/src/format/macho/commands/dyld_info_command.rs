//! Port of `ghidra.app.util.bin.format.macho.commands.DyldInfoCommand`.
//!
//! Represents a `dyld_info_command` structure.
//!
//! Java's `DyldInfoCommand extends LoadCommand`; per this crate's composition-over-inheritance
//! convention (see [`LoadCommand`]'s own docs), the inherited state is an embedded
//! [`LoadCommandBase`] rather than a supertrait, mirroring
//! [`DyldChainedFixupsCommand`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand).
//!
//! The rebase/bind/weak-bind/lazy-bind byte ranges are decoded by the real
//! [`RebaseTable`]/[`BindingTable`] opcode state machines, whose recorded opcode/ULEB128/SLEB128/
//! string offsets drive [`DyldInfoCommand::markup`]'s data markup.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::export_trie::ExportTrie;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::commands::dyld::bind_opcode::BindOpcode;
use crate::format::macho::commands::dyld::binding_table::BindingTable;
use crate::format::macho::commands::dyld::opcode_table::OpcodeTable;
use crate::format::macho::commands::dyld::rebase_opcode::RebaseOpcode;
use crate::format::macho::commands::dyld::rebase_table::RebaseTable;
use crate::format::macho::struct_builder::{fixed_string, sleb128, uleb128, MachStruct};
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

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
        load_command_reader: &mut BinaryReader,
        data_reader: &mut BinaryReader,
        header: &MachHeader,
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

    fn markup_rebase_info(&self, program: &dyn Program, header: &MachHeader, source: Option<&str>, log: &MessageLog) {
        let addr = self.file_offset_to_address(program, header, self.rebase_off as i64, self.rebase_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("rebase"));
        self.markup_opcode_table(program, addr.as_ref(), &self.rebase_table, RebaseOpcode::to_data_type, source, "rebase", log);
    }

    fn markup_bindings(&self, program: &dyn Program, header: &MachHeader, source: Option<&str>, log: &MessageLog) {
        let addr = self.file_offset_to_address(program, header, self.bind_off as i64, self.bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("bind"));
        self.markup_opcode_table(program, addr.as_ref(), &self.binding_table, BindOpcode::to_data_type, source, "bind", log);
    }

    fn markup_weak_bindings(&self, program: &dyn Program, header: &MachHeader, source: Option<&str>, log: &MessageLog) {
        let addr =
            self.file_offset_to_address(program, header, self.weak_bind_off as i64, self.weak_bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("weak bind"));
        self.markup_opcode_table(program, addr.as_ref(), &self.weak_binding_table, BindOpcode::to_data_type, source, "weak bind", log);
    }

    fn markup_lazy_bindings(&self, program: &dyn Program, header: &MachHeader, source: Option<&str>, log: &MessageLog) {
        let addr =
            self.file_offset_to_address(program, header, self.lazy_bind_off as i64, self.lazy_bind_size as i64);
        self.markup_plate_comment(program, addr.as_ref(), source, Some("lazy bind"));
        self.markup_opcode_table(program, addr.as_ref(), &self.lazy_binding_table, BindOpcode::to_data_type, source, "lazy bind", log);
    }

    /// Java `markupOpcodeTable(...)`. `opcode_data_type` builds a fresh instance of the opcode
    /// enum per use (Java shares one `DataType` instance across the loop).
    #[allow(clippy::too_many_arguments)]
    fn markup_opcode_table(
        &self,
        program: &dyn Program,
        addr: Option<&Address>,
        table: &dyn OpcodeTable,
        opcode_data_type: fn() -> Box<dyn DataType>,
        source: Option<&str>,
        additional_description: &str,
        log: &MessageLog,
    ) {
        let Some(addr) = addr else {
            return;
        };
        let result: Result<(), String> = (|| {
            let at = |offset: u64| addr.add(offset as i64).map_err(|e| e.to_string());
            for &offset in table.opcode_offsets() {
                Du.create_data(program, &at(offset)?, opcode_data_type(), -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            for &offset in table.uleb_offsets() {
                Du.create_data(program, &at(offset)?, uleb128().map_err(|e| e.to_string())?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            for &offset in table.sleb_offsets() {
                Du.create_data(program, &at(offset)?, sleb128().map_err(|e| e.to_string())?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            for &offset in table.string_offsets() {
                Du.create_data(program, &at(offset)?, fixed_string().map_err(|e| e.to_string())?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(
                Some("DyldInfoCommand"),
                &format!("Failed to markup: {}", self.get_contextual_name(source, Some(additional_description))),
            );
        }
    }

    fn markup_export_info(&self, program: &dyn Program, header: &MachHeader, source: Option<&str>, log: &MessageLog) {
        let Some(addr) =
            self.file_offset_to_address(program, header, self.export_off as i64, self.export_size as i64)
        else {
            return;
        };
        self.markup_plate_comment(program, Some(&addr), source, Some("export"));
        let result: Result<(), String> = (|| {
            for &offset in self.export_trie.uleb_offsets() {
                let a = addr.add(offset as i64).map_err(|e| e.to_string())?;
                Du.create_data(program, &a, uleb128().map_err(|e| e.to_string())?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            for &offset in self.export_trie.string_offsets() {
                let a = addr.add(offset as i64).map_err(|e| e.to_string())?;
                Du.create_data(program, &a, fixed_string().map_err(|e| e.to_string())?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(
                Some("DyldInfoCommand"),
                &format!("Failed to markup: {}", self.get_contextual_name(source, Some("export"))),
            );
        }
    }
}

impl StructConverter for DyldInfoCommand {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        for (name, comment) in [
            ("rebase_off", "file offset to rebase info"),
            ("rebase_size", "size of rebase info"),
            ("bind_off", "file offset to binding info"),
            ("bind_size", "size of binding info"),
            ("weak_bind_off", "file offset to weak binding info"),
            ("weak_bind_size", "size of weak binding info"),
            ("lazy_bind_off", "file offset to lazy binding info"),
            ("lazy_bind_size", "size of lazy binding info"),
            // (sic) Java reuses the lazy-binding comments for the export fields.
            ("export_off", "file offset to lazy binding info"),
            ("export_size", "size of lazy binding info"),
        ] {
            s.add(crate::format::macho::struct_builder::dword(), name, Some(comment))?;
        }
        Ok(Box::new(s.finish_structure()?))
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
        header: &MachHeader,
        source: Option<&str>,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        self.markup_rebase_info(program, header, source, log);
        self.markup_bindings(program, header, source, log);
        self.markup_weak_bindings(program, header, source, log);
        self.markup_lazy_bindings(program, header, source, log);
        self.markup_export_info(program, header, source, log);
        Ok(())
    }

    fn markup_raw_binary(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
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

    use crate::format::macho::commands::dyld::opcode_table::OpcodeTable;
    use crate::format::macho::commands::load_command_types::LC_DYLD_INFO;
    use crate::format::macho::mach_header::test_support::empty_header64;

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
        let mut lc_reader = BinaryReader::from_bytes(data, true);
        let mut data_reader = BinaryReader::from_bytes(Vec::new(), true);
        let header = empty_header64();

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
        let mut lc_reader = BinaryReader::from_bytes(data, true);
        // Data reader must be long enough that set_pointer_index'ing to each offset succeeds when
        // the (stub) table parsers touch it; they don't read, but is_valid_index isn't checked by
        // set_pointer_index itself so an empty data reader is fine too. Keep it non-trivial for
        // realism.
        let mut data_reader = BinaryReader::from_bytes(vec![0u8; 200], true);
        let header = empty_header64();

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

    #[test]
    fn parses_real_rebase_and_bind_tables() {
        // rebase @0x10: SET_TYPE_IMM(1); SET_SEGMENT_AND_OFFSET_ULEB(2, 0x18); DO_REBASE_IMM_TIMES(2); DONE
        // bind @0x20: SET_DYLIB_ORDINAL_IMM(1); SET_SYMBOL "_f"; SET_SEGMENT_AND_OFFSET_ULEB(2, 8); DO_BIND; DONE
        let mut data = vec![0u8; 0x10];
        data.extend_from_slice(&[0x11, 0x22, 0x18, 0x52, 0x00]);
        data.resize(0x20, 0);
        data.extend_from_slice(&[0x11, 0x40, b'_', b'f', 0, 0x72, 0x08, 0x90, 0x00]);
        data.resize(0x40, 0);
        let mut lc_reader = BinaryReader::from_bytes(command_bytes(0x10, 5, 0x20, 9, 0, 0, 0, 0, 0, 0), true);
        let mut data_reader = BinaryReader::from_bytes(data, true);
        let header = empty_header64();
        let cmd = DyldInfoCommand::new(&mut lc_reader, &mut data_reader, &header).unwrap();

        let rebases: Vec<i64> = cmd.rebase_table().get_rebases().iter().map(|r| r.get_segment_offset()).collect();
        assert_eq!(rebases, vec![0x18, 0x20]);
        assert_eq!(cmd.rebase_table().uleb_offsets(), &[2]);

        let bindings = cmd.binding_table().get_bindings();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].get_symbol_name(), Some("_f"));
        assert_eq!(bindings[0].get_segment_offset(), 8);
        assert_eq!(cmd.binding_table().string_offsets(), &[2]);
        assert!(cmd.lazy_binding_table().get_bindings().is_empty());
    }

    #[test]
    fn to_data_type_is_twelve_dwords() {
        let mut lc_reader = BinaryReader::from_bytes(command_bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0), true);
        let mut data_reader = BinaryReader::from_bytes(Vec::new(), true);
        let cmd = DyldInfoCommand::new(&mut lc_reader, &mut data_reader, &empty_header64()).unwrap();
        let dt = cmd.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "dyld_info_command");
        assert_eq!(dt.get_length(), 48);
        assert_eq!(dt.get_category_path().to_string(), "/MachO");
    }
}
