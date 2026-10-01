//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryModule`.
//!
//! Represents a `dylib_module` / `dylib_module_64` structure. See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{dword, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `dylib_module` entry.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryModule`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicLibraryModule {
    module_name: i32,
    iextdefsym: i32,
    nextdefsym: i32,
    irefsym: i32,
    nrefsym: i32,
    ilocalsym: i32,
    nlocalsym: i32,
    iextrel: i32,
    nextrel: i32,
    iinit_iterm: i32,
    ninit_nterm: i32,
    objc_module_info_size: i32,
    objc_module_info_addr: i64,
    is32bit: bool,
    module_name_string: String,
}

impl DynamicLibraryModule {
    /// Java: `DynamicLibraryModule(BinaryReader, MachHeader)`. The module name is read from the
    /// string table of `header`'s symbol table command, which must already have been parsed
    /// (Java throws `NullPointerException` otherwise; this port reports invalid data).
    pub fn new(reader: &mut BinaryReader, header: &MachHeader) -> io::Result<Self> {
        let is32bit = header.is32bit();
        let module_name = reader.read_next_int()?;
        let iextdefsym = reader.read_next_int()?;
        let nextdefsym = reader.read_next_int()?;
        let irefsym = reader.read_next_int()?;
        let nrefsym = reader.read_next_int()?;
        let ilocalsym = reader.read_next_int()?;
        let nlocalsym = reader.read_next_int()?;
        let iextrel = reader.read_next_int()?;
        let nextrel = reader.read_next_int()?;
        let iinit_iterm = reader.read_next_int()?;
        let ninit_nterm = reader.read_next_int()?;
        let (objc_module_info_addr, objc_module_info_size) = if is32bit {
            let addr = reader.read_next_unsigned_int()? as i64;
            (addr, reader.read_next_int()?)
        } else {
            let size = reader.read_next_int()?;
            (reader.read_next_long()?, size)
        };
        let stc = header.get_first_load_command::<SymbolTableCommand>().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "dylib_module needs a symbol table command")
        })?;
        let name_index = stc.get_string_table_offset().wrapping_add(module_name as i64);
        let module_name_string = reader.read_ascii_string(name_index as u64)?;
        Ok(DynamicLibraryModule {
            module_name, iextdefsym, nextdefsym, irefsym, nrefsym, ilocalsym, nlocalsym, iextrel, nextrel, iinit_iterm, ninit_nterm,
            objc_module_info_size,
            objc_module_info_addr,
            is32bit,
            module_name_string,
        })
    }

    /// Java: `getModuleName()`.
    pub fn get_module_name(&self) -> &str {
        &self.module_name_string
    }

    /// Java: `getModuleNameIndex()`.
    pub fn get_module_name_index(&self) -> i32 {
        self.module_name
    }

    /// Java: `getExtDefSymIndex()`.
    pub fn get_ext_def_sym_index(&self) -> i32 {
        self.iextdefsym
    }

    /// Java: `getExtDefSymCount()`.
    pub fn get_ext_def_sym_count(&self) -> i32 {
        self.nextdefsym
    }

    /// Java: `getReferenceSymbolTableIndex()`.
    pub fn get_reference_symbol_table_index(&self) -> i32 {
        self.irefsym
    }

    /// Java: `getReferenceSymbolTableCount()`.
    pub fn get_reference_symbol_table_count(&self) -> i32 {
        self.nrefsym
    }

    /// Java: `getLocalSymbolIndex()`.
    pub fn get_local_symbol_index(&self) -> i32 {
        self.ilocalsym
    }

    /// Java: `getLocalSymbolCount()`.
    pub fn get_local_symbol_count(&self) -> i32 {
        self.nlocalsym
    }

    /// Java: `getExternalRelocationIndex()`.
    pub fn get_external_relocation_index(&self) -> i32 {
        self.iextrel
    }

    /// Java: `getExternalRelocationCount()`.
    pub fn get_external_relocation_count(&self) -> i32 {
        self.nextrel
    }

    /// Java: `getInitTermIndex()`.
    pub fn get_init_term_index(&self) -> i32 {
        self.iinit_iterm
    }

    /// Java: `getInitTermCount()`.
    pub fn get_init_term_count(&self) -> i32 {
        self.ninit_nterm
    }

    /// Java: `getObjcModuleInfoSize()`.
    pub fn get_objc_module_info_size(&self) -> i32 {
        self.objc_module_info_size
    }

    /// Java: `getObjcModuleInfoAddress()`.
    pub fn get_objc_module_info_address(&self) -> i64 {
        self.objc_module_info_addr
    }

    /// Java: `toDataType()`, returning the concrete structure. (Java's 32-bit field comments are
    /// swapped relative to the field names; kept as-is.)
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dylib_module");
        s.add(dword(), "module_name", Some("the module name (index into string table)"))?;
        s.add(dword(), "iextdefsym", Some("index into externally defined symbols"))?;
        s.add(dword(), "nextdefsym", Some("number of externally defined symbols"))?;
        s.add(dword(), "irefsym", Some("index into reference symbol table"))?;
        s.add(dword(), "nrefsym", Some("number of reference symbol table entries"))?;
        s.add(dword(), "ilocalsym", Some("index into symbols for local symbols"))?;
        s.add(dword(), "nlocalsym", Some("number of local symbols"))?;
        s.add(dword(), "iextrel", Some("index into external relocation entries"))?;
        s.add(dword(), "nextrel", Some("number of external relocation entries"))?;
        s.add(dword(), "iinit_iterm", Some("low 16 bits are the index into the init section, high 16 bits are the index into the term section"))?;
        s.add(dword(), "ninit_nterm", Some("low 16 bits are the number of init section entries, high 16 bits are the number of term section entries"))?;
        if self.is32bit {
            s.add(dword(), "objc_module_info_addr", Some("module size"))?;
            s.add(dword(), "objc_module_info_size", Some("module start address"))?;
        } else {
            s.add(dword(), "objc_module_info_size", Some("module size"))?;
            s.add(qword(), "objc_module_info_addr", Some("module start address"))?;
        }
        s.finish_structure()
    }
}

impl StructConverter for DynamicLibraryModule {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}
