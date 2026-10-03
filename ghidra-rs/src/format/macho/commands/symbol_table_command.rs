//! Port of `ghidra.app.util.bin.format.macho.commands.SymbolTableCommand`.
//!
//! Represents a `symtab_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::dynamic_symbol_table_constants::{
    INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL,
};
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::n_list::NList;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{fixed_string, MachStruct};
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::ref_type::RefType;
use crate::program::model::symbol::SourceType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// A Mach-O `symtab_command`, with its parsed symbols.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.SymbolTableCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTableCommand {
    base: LoadCommandBase,
    symoff: i64,
    nsyms: i64,
    stroff: i64,
    strsize: i64,
    symbols: Vec<NList>,
}

impl SymbolTableCommand {
    /// Java: `SymbolTableCommand(BinaryReader, BinaryReader, MachHeader)`.
    ///
    /// `load_command_reader` points at the load command; `data_reader` reads the symbol and
    /// string tables it references (possibly in a different provider).
    pub fn new(
        load_command_reader: &mut BinaryReader,
        data_reader: &mut BinaryReader,
        header: &MachHeader,
    ) -> io::Result<Self> {
        let base = LoadCommandBase::new(load_command_reader)?;
        let symoff = load_command_reader.read_next_unsigned_int()? as i64;
        let mut cmd = SymbolTableCommand {
            base,
            symoff,
            nsyms: 0,
            stroff: 0,
            strsize: 0,
            symbols: Vec::new(),
        };
        cmd.nsyms = cmd.check_count(load_command_reader.read_next_unsigned_int()? as i64)?;
        cmd.stroff = load_command_reader.read_next_unsigned_int()? as i64;
        cmd.strsize = load_command_reader.read_next_unsigned_int()? as i64;

        data_reader.set_pointer_index(header.get_start_index().wrapping_add(symoff as u64));
        let mut nlists = Vec::with_capacity(cmd.nsyms as usize);
        for _ in 0..cmd.nsyms {
            nlists.push(NList::new(data_reader, header.is32bit())?);
        }
        // Java initializes the names in string-table order (a stable sort by n_strx) to keep the
        // string reads sequential; the resulting names do not depend on the order.
        let mut order: Vec<usize> = (0..nlists.len()).collect();
        order.sort_by_key(|&i| nlists[i].get_string_table_index());
        for i in order {
            nlists[i].init_string(data_reader, cmd.stroff);
        }
        cmd.symbols = nlists;
        Ok(cmd)
    }

    /// Java: `getSymbolOffset()`.
    pub fn get_symbol_offset(&self) -> i64 {
        self.symoff
    }

    /// Java: `getNumberOfSymbols()`.
    pub fn get_number_of_symbols(&self) -> i64 {
        self.nsyms
    }

    /// Java: `getStringTableOffset()`.
    pub fn get_string_table_offset(&self) -> i64 {
        self.stroff
    }

    /// Java: `getStringTableSize()`.
    pub fn get_string_table_size(&self) -> i64 {
        self.strsize
    }

    /// Java: `getSymbols()`.
    pub fn get_symbols(&self) -> &[NList] {
        &self.symbols
    }

    /// Java: `addSymbols(List<NList>)`. Appends symbols and adjusts the counts/offsets as if
    /// they had been part of the table.
    pub fn add_symbols(&mut self, list: Vec<NList>) {
        let Some(first) = list.first() else {
            return;
        };
        let entry_size = first.get_size() as i64;
        let added = list.len() as i64;
        self.symbols.extend(list);
        self.nsyms += added;
        self.stroff += added * entry_size;
        self.strsize = self.symbols.iter().map(|e| e.get_string().len() as i64 + 1).sum();
    }

    /// Java: `getSymbolAt(int)`. `None` for indirect local/absolute indexes and for indexes past
    /// the end (Java returns `null` for `index > size` and throws for `index == size`).
    pub fn get_symbol_at(&self, index: i32) -> Option<&NList> {
        let bits = index as u32;
        if (bits & INDIRECT_SYMBOL_LOCAL) != 0 || (bits & INDIRECT_SYMBOL_ABS) != 0 {
            return None;
        }
        self.symbols.get(index as usize)
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        for name in ["cmd", "cmdsize", "symoff", "nsyms", "stroff", "strsize"] {
            s.dword(name)?;
        }
        s.finish_structure()
    }

    /// The `try` body of Java's `markup`.
    fn markup_symbols(
        &self,
        program: &dyn Program,
        symbol_table_addr: &Address,
        string_table_addr: Option<&Address>,
    ) -> Result<(), String> {
        let err = |e: &dyn std::fmt::Display| e.to_string();
        for i in 0..self.nsyms {
            let nlist = &self.symbols[i as usize];
            let dt = nlist.to_data_type().map_err(|e| err(&e))?;
            let nlist_addr = symbol_table_addr.add(i * dt.get_length() as i64).map_err(|e| err(&e))?;
            let d = Du
                .create_data(program, &nlist_addr, dt, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| err(&e))?;
            if let Some(string_table_addr) = string_table_addr {
                if nlist.get_string_table_index() != 0 {
                    let str_addr = string_table_addr
                        .add(nlist.get_string_table_index() as i64)
                        .map_err(|e| err(&e))?;
                    Du.create_data(
                        program,
                        &str_addr,
                        fixed_string().map_err(|e| err(&e))?,
                        -1,
                        ClearDataMode::CheckForSpace,
                    )
                    .map_err(|e| err(&e))?;
                    let mut reference_manager =
                        program.get_reference_manager().ok_or("no reference manager")?;
                    let reference = reference_manager.add_memory_reference(
                        d.get_min_address(),
                        str_addr,
                        RefType::Data,
                        SourceType::Imported,
                        0,
                    );
                    reference_manager.set_primary(reference, true);
                }
            }
        }
        Ok(())
    }

    /// The `try` body of Java's `markupRawBinary` after its `super` call.
    fn markup_raw_symbols(
        &self,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), String> {
        let err = |e: &dyn std::fmt::Display| e.to_string();
        let space = base_address.space();
        if self.strsize > 0 {
            let string_table_start = space.address(self.stroff);
            api.create_fragment(parent_module, "string_table", &string_table_start, self.strsize)
                .map_err(|e| err(&e))?;
        }
        let symbol_start_addr = space.address(self.symoff);
        let mut offset = 0i64;
        for (symbol_index, symbol) in self.symbols.iter().enumerate() {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let symbol_dt = symbol.to_data_type().map_err(|e| err(&e))?;
            let symbol_dt_len = symbol_dt.get_length();
            let symbol_addr = symbol_start_addr.add(offset).map_err(|e| err(&e))?;
            let symbol_data = api.create_data(&symbol_addr, symbol_dt).map_err(|e| err(&e))?;
            let string_address = space.address(self.stroff + symbol.get_string_table_index() as i64);
            let string_data = api.create_terminated_ascii_string(&string_address).map_err(|e| err(&e))?;
            let string = crate::program::model::listing::data::Data::get_value(string_data.as_ref())
                .and_then(|v| v.downcast::<String>().ok())
                .map(|s| *s)
                .unwrap_or_default();
            let reference = api
                .create_memory_reference(symbol_data.as_ref(), &string_address, RefType::Data)
                .map_err(|e| err(&e))?;
            api.set_reference_primary(reference, false);
            api.set_plate_comment(
                &symbol_addr,
                &format!(
                    "{string}\nIndex:           0x{:x}\nValue:           0x{:x}\nDescription:     0x{:x}\nLibrary Ordinal: 0x{:x}",
                    symbol_index,
                    symbol.get_value(),
                    symbol.get_description() as i64 & 0xffff,
                    symbol.get_library_ordinal() as i64 & 0xff
                ),
            );
            offset += symbol_dt_len as i64;
        }
        if self.nsyms > 0 {
            api.create_fragment(parent_module, "symbols", &symbol_start_addr, offset)
                .map_err(|e| err(&e))?;
        }
        Ok(())
    }
}

impl StructConverter for SymbolTableCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for SymbolTableCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "symtab_command".to_string()
    }

    fn get_linker_data_offset(&self) -> i64 {
        self.symoff
    }

    fn get_linker_data_size(&self) -> i64 {
        NList::get_total_size(&self.symbols) as i64
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &MachHeader,
        source: Option<&str>,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        let program: &dyn Program = program;
        let Some(symbol_table_addr) = self.file_offset_to_address(program, header, self.symoff, self.nsyms)
        else {
            return Ok(());
        };
        let string_table_addr = self.file_offset_to_address(program, header, self.stroff, self.strsize);
        self.markup_plate_comment(program, Some(&symbol_table_addr), source, Some("symbols"));
        self.markup_plate_comment(program, string_table_addr.as_ref(), source, Some("strings"));
        if self.markup_symbols(program, &symbol_table_addr, string_table_addr.as_ref()).is_err() {
            log.append_msg_from(
                Some("SymbolTableCommand"),
                &format!("Failed to markup: {}", self.get_contextual_name(source, Some("symbols"))),
            );
        }
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
        markup_raw_binary_base(self, header, api, base_address, parent_module, monitor, log);
        if let Err(message) = self.markup_raw_symbols(api, base_address, parent_module, monitor) {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::commands::load_command_types::LC_SYMTAB;
    use crate::format::macho::commands::n_list::test_support::nlist;
    use crate::format::macho::mach_header::test_support::Bytes;

    /// Appends an `LC_SYMTAB` for `names` (all external, section 1, values 0x1000, 0x1010, ...)
    /// to `b`, laying the symbol table at `symoff` and the string table right after it. Returns
    /// the bytes to place at `symoff`.
    pub(crate) fn symtab(b: &mut Bytes, is32bit: bool, symoff: u32, names: &[&str]) -> Vec<u8> {
        let entry = if is32bit { 12 } else { 16 };
        let stroff = symoff + entry * names.len() as u32;
        let mut strings = vec![0u8];
        let mut data = Bytes::new(b.little);
        for (i, name) in names.iter().enumerate() {
            nlist(&mut data, is32bit, strings.len() as u32, 0x0f, 1, 0, 0x1000 + 0x10 * i as u64);
            strings.extend(name.as_bytes());
            strings.push(0);
        }
        b.u32(LC_SYMTAB).u32(24).u32(symoff).u32(names.len() as u32).u32(stroff).u32(strings.len() as u32);
        data.raw(&strings);
        data.buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::symtab;
    use super::*;
    use crate::format::macho::mach_header::test_support::{empty_header64, Bytes};
    use crate::format::macho::struct_builder::test_support::names;

    fn parse(names_: &[&str]) -> SymbolTableCommand {
        let mut b = Bytes::new(true);
        let data = symtab(&mut b, false, 24, names_);
        b.raw(&data);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut dr = lc.clone_reader();
        SymbolTableCommand::new(&mut lc, &mut dr, &empty_header64()).unwrap()
    }

    #[test]
    fn parses_symbols_and_names() {
        let cmd = parse(&["_main", "_helper"]);
        assert_eq!(cmd.get_symbol_offset(), 24);
        assert_eq!(cmd.get_number_of_symbols(), 2);
        assert_eq!(cmd.get_string_table_offset(), 24 + 32);
        assert_eq!(cmd.get_string_table_size(), 1 + 6 + 8);
        let names_: Vec<&str> = cmd.get_symbols().iter().map(NList::get_string).collect();
        assert_eq!(names_, ["_main", "_helper"]);
        assert_eq!(cmd.get_symbols()[1].get_value(), 0x1010);
        assert_eq!(cmd.get_linker_data_offset(), 24);
        assert_eq!(cmd.get_linker_data_size(), 32 + 15);
        assert_eq!(
            names(&cmd.to_structure().unwrap()),
            ["cmd", "cmdsize", "symoff", "nsyms", "stroff", "strsize"]
        );
    }

    #[test]
    fn symbol_at_rejects_indirect_and_out_of_range() {
        let cmd = parse(&["_a"]);
        assert_eq!(cmd.get_symbol_at(0).unwrap().get_string(), "_a");
        assert!(cmd.get_symbol_at(1).is_none());
        assert!(cmd.get_symbol_at(INDIRECT_SYMBOL_LOCAL as i32).is_none());
        assert!(cmd.get_symbol_at(INDIRECT_SYMBOL_ABS as i32).is_none());
    }

    #[test]
    fn add_symbols_updates_counts() {
        let mut cmd = parse(&["_a"]);
        let extra = parse(&["_bb", "_ccc"]).get_symbols().to_vec();
        cmd.add_symbols(extra);
        assert_eq!(cmd.get_number_of_symbols(), 3);
        assert_eq!(cmd.get_string_table_offset(), 24 + 16 + 32);
        assert_eq!(cmd.get_string_table_size(), 3 + 4 + 5);
        cmd.add_symbols(Vec::new());
        assert_eq!(cmd.get_number_of_symbols(), 3);
    }
}
