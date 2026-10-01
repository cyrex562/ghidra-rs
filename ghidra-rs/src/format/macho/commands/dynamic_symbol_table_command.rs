//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicSymbolTableCommand`.
//!
//! Represents a `dysymtab_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::dynamic_library_module::DynamicLibraryModule;
use crate::format::macho::commands::dynamic_library_reference::DynamicLibraryReference;
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::commands::table_of_contents::TableOfContents;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::relocation_info::RelocationInfo;
use crate::format::macho::struct_builder::{dword, MachStruct};
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

type MarkupResult = Result<(), String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// A Mach-O `dysymtab_command`, with the tables it references.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicSymbolTableCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicSymbolTableCommand {
    base: LoadCommandBase,
    ilocalsym: i64,
    nlocalsym: i64,
    iextdefsym: i64,
    nextdefsym: i64,
    iundefsym: i64,
    nundefsym: i64,
    tocoff: i64,
    ntoc: i64,
    modtaboff: i64,
    nmodtab: i64,
    extrefsymoff: i64,
    nextrefsyms: i64,
    indirectsymoff: i64,
    nindirectsyms: i64,
    extreloff: i64,
    nextrel: i64,
    locreloff: i64,
    nlocrel: i64,
    toc_list: Vec<TableOfContents>,
    module_list: Vec<DynamicLibraryModule>,
    referenced_list: Vec<DynamicLibraryReference>,
    indirect_symbols: Vec<i32>,
    external_relocations: Vec<RelocationInfo>,
    local_relocations: Vec<RelocationInfo>,
}

impl DynamicSymbolTableCommand {
    /// Java: `DynamicSymbolTableCommand(BinaryReader, BinaryReader, MachHeader)`. Each table with
    /// a non-zero offset is read from `header.getStartIndex() + offset`.
    pub fn new(
        lc: &mut BinaryReader,
        data_reader: &mut BinaryReader,
        header: &MachHeader,
    ) -> io::Result<Self> {
        let base = LoadCommandBase::new(lc)?;
        let mut cmd = DynamicSymbolTableCommand {
            base,
            ilocalsym: 0, nlocalsym: 0, iextdefsym: 0, nextdefsym: 0, iundefsym: 0, nundefsym: 0, tocoff: 0, ntoc: 0, modtaboff: 0, nmodtab: 0, extrefsymoff: 0, nextrefsyms: 0, indirectsymoff: 0, nindirectsyms: 0, extreloff: 0, nextrel: 0, locreloff: 0, nlocrel: 0,
            toc_list: Vec::new(),
            module_list: Vec::new(),
            referenced_list: Vec::new(),
            indirect_symbols: Vec::new(),
            external_relocations: Vec::new(),
            local_relocations: Vec::new(),
        };
        cmd.ilocalsym = lc.read_next_unsigned_int()? as i64;
        cmd.nlocalsym = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.iextdefsym = lc.read_next_unsigned_int()? as i64;
        cmd.nextdefsym = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.iundefsym = lc.read_next_unsigned_int()? as i64;
        cmd.nundefsym = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.tocoff = lc.read_next_unsigned_int()? as i64;
        cmd.ntoc = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.modtaboff = lc.read_next_unsigned_int()? as i64;
        cmd.nmodtab = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.extrefsymoff = lc.read_next_unsigned_int()? as i64;
        cmd.nextrefsyms = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.indirectsymoff = lc.read_next_unsigned_int()? as i64;
        cmd.nindirectsyms = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.extreloff = lc.read_next_unsigned_int()? as i64;
        cmd.nextrel = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;
        cmd.locreloff = lc.read_next_unsigned_int()? as i64;
        cmd.nlocrel = cmd.check_count(lc.read_next_unsigned_int()? as i64)?;

        let start = header.get_start_index();
        let seek = |r: &mut BinaryReader, off: i64| r.set_pointer_index(start.wrapping_add(off as u64));
        if cmd.tocoff > 0 {
            seek(data_reader, cmd.tocoff);
            for _ in 0..cmd.ntoc {
                cmd.toc_list.push(TableOfContents::new(data_reader)?);
            }
        }
        if cmd.modtaboff > 0 {
            seek(data_reader, cmd.modtaboff);
            for _ in 0..cmd.nmodtab {
                cmd.module_list.push(DynamicLibraryModule::new(data_reader, header)?);
            }
        }
        if cmd.extrefsymoff > 0 {
            seek(data_reader, cmd.extrefsymoff);
            for _ in 0..cmd.nextrefsyms {
                cmd.referenced_list.push(DynamicLibraryReference::new(data_reader)?);
            }
        }
        if cmd.indirectsymoff > 0 {
            seek(data_reader, cmd.indirectsymoff);
            for _ in 0..cmd.nindirectsyms {
                cmd.indirect_symbols.push(data_reader.read_next_int()?);
            }
        }
        if cmd.extreloff > 0 {
            seek(data_reader, cmd.extreloff);
            for _ in 0..cmd.nextrel {
                cmd.external_relocations.push(RelocationInfo::new(data_reader)?);
            }
        }
        if cmd.locreloff > 0 {
            seek(data_reader, cmd.locreloff);
            for _ in 0..cmd.nlocrel {
                cmd.local_relocations.push(RelocationInfo::new(data_reader)?);
            }
        }
        Ok(cmd)
    }

    /// Java: `getLocalSymbolIndex()`.
    pub fn get_local_symbol_index(&self) -> i64 {
        self.ilocalsym
    }

    /// Java: `getLocalSymbolCount()`.
    pub fn get_local_symbol_count(&self) -> i64 {
        self.nlocalsym
    }

    /// Java: `getExternalSymbolIndex()`.
    pub fn get_external_symbol_index(&self) -> i64 {
        self.iextdefsym
    }

    /// Java: `getExternalSymbolCount()`.
    pub fn get_external_symbol_count(&self) -> i64 {
        self.nextdefsym
    }

    /// Java: `getUndefinedSymbolIndex()`.
    pub fn get_undefined_symbol_index(&self) -> i64 {
        self.iundefsym
    }

    /// Java: `getUndefinedSymbolCount()`.
    pub fn get_undefined_symbol_count(&self) -> i64 {
        self.nundefsym
    }

    /// Java: `getTableOfContentsOffset()`.
    pub fn get_table_of_contents_offset(&self) -> i64 {
        self.tocoff
    }

    /// Java: `getTableOfContentsSize()`.
    pub fn get_table_of_contents_size(&self) -> i64 {
        self.ntoc
    }

    /// Java: `getModuleTableOffset()`.
    pub fn get_module_table_offset(&self) -> i64 {
        self.modtaboff
    }

    /// Java: `getModuleTableSize()`.
    pub fn get_module_table_size(&self) -> i64 {
        self.nmodtab
    }

    /// Java: `getReferencedSymbolTableOffset()`.
    pub fn get_referenced_symbol_table_offset(&self) -> i64 {
        self.extrefsymoff
    }

    /// Java: `getReferencedSymbolTableSize()`.
    pub fn get_referenced_symbol_table_size(&self) -> i64 {
        self.nextrefsyms
    }

    /// Java: `getIndirectSymbolTableOffset()`.
    pub fn get_indirect_symbol_table_offset(&self) -> i64 {
        self.indirectsymoff
    }

    /// Java: `getIndirectSymbolTableSize()`.
    pub fn get_indirect_symbol_table_size(&self) -> i64 {
        self.nindirectsyms
    }

    /// Java: `getExternalRelocationOffset()`.
    pub fn get_external_relocation_offset(&self) -> i64 {
        self.extreloff
    }

    /// Java: `getExternalRelocationSize()`.
    pub fn get_external_relocation_size(&self) -> i64 {
        self.nextrel
    }

    /// Java: `getLocalRelocationOffset()`.
    pub fn get_local_relocation_offset(&self) -> i64 {
        self.locreloff
    }

    /// Java: `getLocalRelocationSize()`.
    pub fn get_local_relocation_size(&self) -> i64 {
        self.nlocrel
    }

    /// Java: `getTableOfContentsList()`.
    pub fn get_table_of_contents_list(&self) -> &[TableOfContents] {
        &self.toc_list
    }

    /// Java: `getModuleList()`.
    pub fn get_module_list(&self) -> &[DynamicLibraryModule] {
        &self.module_list
    }

    /// Java: `getReferencedSymbolList()`.
    pub fn get_referenced_symbol_list(&self) -> &[DynamicLibraryReference] {
        &self.referenced_list
    }

    /// Java: `getIndirectSymbols()`.
    pub fn get_indirect_symbols(&self) -> &[i32] {
        &self.indirect_symbols
    }

    /// Java: `getExternalRelocations()`.
    pub fn get_external_relocations(&self) -> &[RelocationInfo] {
        &self.external_relocations
    }

    /// Java: `getLocalRelocations()`.
    pub fn get_local_relocations(&self) -> &[RelocationInfo] {
        &self.local_relocations
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        for name in ["cmd", "cmdsize", "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel"] {
            s.dword(name)?;
        }
        s.finish_structure()
    }

    /// Java: the private `markupIndirectSymbolTable`.
    fn markup_indirect_symbol_table(
        &self,
        program: &dyn Program,
        header: &MachHeader,
        source: Option<&str>,
        log: &MessageLog,
    ) {
        let Some(indirect_addr) =
            self.file_offset_to_address(program, header, self.indirectsymoff, self.nindirectsyms)
        else {
            return;
        };
        self.markup_plate_comment(program, Some(&indirect_addr), source, Some("indirect"));
        let symbol_table = header.get_first_load_command::<SymbolTableCommand>();
        let (symbol_table_addr, string_table_addr) = match symbol_table {
            Some(st) => (
                self.file_offset_to_address(program, header, st.get_symbol_offset(), st.get_number_of_symbols()),
                self.file_offset_to_address(program, header, st.get_string_table_offset(), st.get_string_table_size()),
            ),
            None => (None, None),
        };
        let result: MarkupResult = (|| {
            for i in 0..self.nindirectsyms {
                let nlist_index = self.indirect_symbols[i as usize];
                let data_addr = indirect_addr.add(i * 4).map_err(err)?;
                Du.create_data(program, &data_addr, dword(), -1, ClearDataMode::CheckForSpace).map_err(err)?;
                let (Some(symbol_table_addr), Some(st)) = (&symbol_table_addr, symbol_table) else {
                    continue;
                };
                let Some(nlist) = st.get_symbol_at(nlist_index) else {
                    continue;
                };
                let mut rm = program.get_reference_manager().ok_or("no reference manager")?;
                let target = symbol_table_addr
                    .add(nlist_index as i64 * nlist.get_size() as i64)
                    .map_err(err)?;
                let r = rm.add_memory_reference(data_addr.clone(), target, RefType::Data, SourceType::Imported, 0);
                rm.set_primary(r, true);
                if let Some(string_table_addr) = &string_table_addr {
                    if nlist.get_string_table_index() != 0 {
                        let str_addr =
                            string_table_addr.add(nlist.get_string_table_index() as i64).map_err(err)?;
                        rm.add_memory_reference(data_addr.clone(), str_addr, RefType::Data, SourceType::Imported, 0);
                    }
                }
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(
                Some("DynamicSymbolTableCommand"),
                &format!("Failed to markup: {}", self.get_contextual_name(source, Some("indirect"))),
            );
        }
    }

    fn symtab(header: &MachHeader) -> Result<&SymbolTableCommand, String> {
        header.get_first_load_command::<SymbolTableCommand>().ok_or_else(|| "no symbol table command".to_string())
    }

    /// Java: the private `markupReferencedSymbolTable`.
    fn markup_referenced_symbol_table(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> MarkupResult {
        if self.nextrefsyms == 0 {
            return Ok(());
        }
        let start = base_address.space().address(self.extrefsymoff);
        let mut offset = 0i64;
        for (id, dyref) in self.referenced_list.iter().enumerate() {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let dt = dyref.to_data_type().map_err(err)?;
            let len = dt.get_length();
            api.create_data(&start.add(offset).map_err(err)?, dt).map_err(err)?;
            let sym = Self::symtab(header)?
                .get_symbol_at(dyref.get_symbol_index())
                .ok_or("no symbol for reference")?;
            let module = self.find_module_containing(id as i32)?;
            // Java comments the start address every time (dyrefAddr is never advanced).
            api.set_plate_comment(
                &start,
                &format!("0x{:x} -- {}::{}", id, module.get_module_name(), sym.get_string()),
            );
            offset += len as i64;
        }
        api.create_fragment(parent_module, "REFERENCED_SYMBOLS", &start, offset).map_err(err)?;
        Ok(())
    }

    /// Java: the private `findModuleContaining(int)`.
    fn find_module_containing(&self, symbol_index: i32) -> Result<&DynamicLibraryModule, String> {
        self.module_list
            .iter()
            .find(|m| {
                symbol_index >= m.get_reference_symbol_table_index()
                    && symbol_index < m.get_reference_symbol_table_index() + m.get_reference_symbol_table_count()
            })
            .ok_or_else(|| "no module contains the referenced symbol".to_string())
    }

    /// Java: the private `makupIndirectSymbolTable` (sic).
    fn markup_raw_indirect_symbol_table(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> MarkupResult {
        if self.nindirectsyms == 0 {
            return Ok(());
        }
        let start = base_address.space().address(self.indirectsymoff);
        api.create_fragment(parent_module, "INDIRECT_SYMBOLS", &start, self.nindirectsyms * 4).map_err(err)?;
        for (i, &index) in self.indirect_symbols.iter().enumerate() {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let addr = start.add(i as i64 * 4).map_err(err)?;
            if let Some(symbol) = Self::symtab(header)?.get_symbol_at(index) {
                api.set_eol_comment(&addr, symbol.get_string());
            }
        }
        api.create_dwords(&start, self.nindirectsyms as i32).map_err(err)?;
        Ok(())
    }

    /// Java: the private `markupExternalRelocations`/`markupLocalRelocations`.
    fn markup_relocations(
        relocations: &[RelocationInfo],
        table_offset: i64,
        count: i64,
        fragment: &str,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> MarkupResult {
        if count == 0 {
            return Ok(());
        }
        let start = base_address.space().address(table_offset);
        let mut offset = 0i64;
        for reloc in relocations {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let dt = reloc.to_data_type().map_err(err)?;
            let len = dt.get_length();
            let addr = start.add(offset).map_err(err)?;
            api.create_data(&addr, dt).map_err(err)?;
            api.set_plate_comment(&addr, &reloc.to_string());
            offset += len as i64;
        }
        api.create_fragment(parent_module, fragment, &start, offset).map_err(err)?;
        Ok(())
    }

    /// Java: the private `markupModules`.
    fn markup_modules(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> MarkupResult {
        if self.nmodtab == 0 {
            return Ok(());
        }
        let symtab = Self::symtab(header)?;
        let start = base_address.space().address(self.modtaboff);
        let mut offset = 0i64;
        for (id, module) in self.module_list.iter().enumerate() {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let dt = module.to_data_type().map_err(err)?;
            let len = dt.get_length();
            let module_addr = start.add(offset).map_err(err)?;
            let module_data = api.create_data(&module_addr, dt).map_err(err)?;
            let string_addr = base_address
                .space()
                .address(symtab.get_string_table_offset() + module.get_module_name_index() as i64);
            api.create_memory_reference(module_data.as_ref(), &string_addr, RefType::Data).map_err(err)?;
            api.create_terminated_ascii_string(&string_addr).map_err(err)?;
            api.set_plate_comment(&module_addr, &format!("0x{:x} - {}", id, module.get_module_name()));
            offset += len as i64;
        }
        api.create_fragment(parent_module, "MODULES", &start, offset).map_err(err)?;
        Ok(())
    }

    /// Java: the private `markupTOC`.
    fn markup_toc(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> MarkupResult {
        if self.ntoc == 0 {
            return Ok(());
        }
        let start = base_address.space().address(self.tocoff);
        let mut offset = 0i64;
        for toc in &self.toc_list {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let toc_addr = start.add(offset).map_err(err)?;
            let module = self.module_list.get(toc.get_module_index() as usize).ok_or("bad module index")?;
            let symbol = Self::symtab(header)?.get_symbol_at(toc.get_symbol_index()).ok_or("bad symbol index")?;
            api.set_plate_comment(
                &toc_addr,
                &format!("Module: {}\nSymbol: {}", module.get_module_name(), symbol.get_string()),
            );
            let dt = toc.to_data_type().map_err(err)?;
            let len = dt.get_length();
            api.create_data(&toc_addr, dt).map_err(err)?;
            offset += len as i64;
        }
        api.create_fragment(parent_module, "TOC", &start, offset).map_err(err)?;
        Ok(())
    }
}

impl StructConverter for DynamicSymbolTableCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for DynamicSymbolTableCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "dysymtab_command".to_string()
    }

    fn get_linker_data_offset(&self) -> i64 {
        self.indirectsymoff
    }

    fn get_linker_data_size(&self) -> i64 {
        self.nindirectsyms * 4
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &MachHeader,
        source: Option<&str>,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        self.markup_indirect_symbol_table(program, header, source, log);
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
        let result: MarkupResult = (|| {
            self.markup_toc(header, api, base_address, parent_module, monitor)?;
            self.markup_modules(header, api, base_address, parent_module, monitor)?;
            self.markup_referenced_symbol_table(header, api, base_address, parent_module, monitor)?;
            self.markup_raw_indirect_symbol_table(header, api, base_address, parent_module, monitor)?;
            Self::markup_relocations(
                &self.external_relocations, self.extreloff, self.nextrel, "EXTERNAL_RELOCATIONS",
                api, base_address, parent_module, monitor,
            )?;
            Self::markup_relocations(
                &self.local_relocations, self.locreloff, self.nlocrel, "LOCAL_RELOCATIONS",
                api, base_address, parent_module, monitor,
            )
        })();
        if let Err(message) = result {
            log.append_msg(&format!("Unable to create {}", self.get_command_name()));
            log.append_exception(&io::Error::other(message), &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_DYSYMTAB;
    use crate::format::macho::commands::symbol_table_command::test_support::symtab;
    use crate::format::macho::cpu_types::CPU_TYPE_X86_64;
    use crate::format::macho::mach_constants::MH_CIGAM_64;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::format::macho::struct_builder::test_support::names;

    /// A 64-bit image with LC_SYMTAB (`_a`, `_b`) and LC_DYSYMTAB whose indirect table is
    /// `[1, 0x80000000]`, one module named by string index 1 (`_a`), one TOC entry, one external
    /// reference and one local relocation.
    fn image() -> Vec<u8> {
        let mut b = Bytes::new(true);
        let cmds = 24 + 80;
        b.u32(MH_CIGAM_64.swap_bytes()).u32(CPU_TYPE_X86_64 as u32).u32(3).u32(2).u32(2);
        b.u32(cmds).u32(0).u32(0);
        let symoff = 0x100u32;
        let data = symtab(&mut b, false, symoff, &["_a", "_b"]);
        let (toc, modt, extref, indirect, locrel) = (0x200u32, 0x210, 0x260, 0x270, 0x280);
        b.u32(LC_DYSYMTAB).u32(80);
        for v in [0, 1, 1, 1, 2, 0, toc, 1, modt, 1, extref, 1, indirect, 2, 0, 0, locrel, 1] {
            b.u32(v);
        }
        b.pad_to(symoff as usize).raw(&data).pad_to(toc as usize);
        b.u32(0).u32(0); // toc: symbol 0, module 0
        b.pad_to(modt as usize);
        b.u32(1); // module_name -> "_a"
        for v in [0u32, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0] {
            b.u32(v);
        }
        b.u64(0x1000);
        b.pad_to(extref as usize).u32(0x0100_0001);
        b.pad_to(indirect as usize).u32(1).u32(0x8000_0000);
        b.pad_to(locrel as usize).u32(0x10).u32(0x0500_0001);
        b.pad_to(0x300);
        b.buf
    }

    #[test]
    fn parses_all_tables() {
        let mut h = MachHeader::new(provider(image())).unwrap();
        h.parse().unwrap();
        let d = h.get_first_load_command::<DynamicSymbolTableCommand>().expect("parsed dysymtab");
        assert_eq!(d.get_local_symbol_count(), 1);
        assert_eq!(d.get_undefined_symbol_index(), 2);
        assert_eq!(d.get_table_of_contents_list().len(), 1);
        let m = &d.get_module_list()[0];
        assert_eq!(m.get_module_name(), "_a");
        assert_eq!(m.get_reference_symbol_table_count(), 1);
        assert_eq!(m.get_objc_module_info_address(), 0x1000);
        assert_eq!(d.get_referenced_symbol_list()[0].get_symbol_index(), 1);
        assert_eq!(d.get_referenced_symbol_list()[0].get_flags(), 1);
        assert_eq!(d.get_indirect_symbols(), [1, 0x8000_0000u32 as i32]);
        assert!(d.get_external_relocations().is_empty());
        assert_eq!(d.get_local_relocations()[0].get_address(), 0x10);
        assert_eq!(d.get_linker_data_offset(), 0x270);
        assert_eq!(d.get_linker_data_size(), 8);
        let s = d.to_structure().unwrap();
        assert_eq!(s.get_length(), 80);
        assert_eq!(names(&s)[19], "nlocrel");
        assert_eq!(m.to_structure().unwrap().get_length(), 56);
    }
}
