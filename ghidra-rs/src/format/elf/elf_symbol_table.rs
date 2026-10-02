//! Port of `ghidra.app.util.bin.format.elf.ElfSymbolTable`.
//!
//! A container class to hold ELF symbols. The table owns its [`ElfSymbol`]s (which, unlike
//! Java's, hold no back-pointer to the table) and a copy of its associated [`ElfStringTable`];
//! the optional section it came from is identified by its index in the header's section list.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::elf::elf_file_section::ElfFileSection;
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_section_header_constants::SHN_XINDEX;
use crate::format::elf::elf_string_table::ElfStringTable;
use crate::format::elf::elf_structs::{array, byte, dword, qword, word, ElfStruct};
use crate::format::elf::elf_symbol::{ElfSymbol, FORMATTED_NO_NAME, STB_GLOBAL, STT_FILE};
use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::data_type::DataType;

/// An ELF symbol table (`SHT_SYMTAB`/`SHT_DYNSYM` section or the dynamic `DT_SYMTAB` table).
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfSymbolTable`.
#[derive(Debug, Clone)]
pub struct ElfSymbolTable {
    string_table: Option<ElfStringTable>,
    /// Index of the section this table came from (may be `None` for the dynamic table).
    symbol_table_section: Option<usize>,
    symbol_section_index_table: Option<Vec<i32>>,
    file_offset: i64,
    addr_offset: i64,
    length: i64,
    entry_size: i64,
    symbol_count: i32,
    is_32bit: bool,
    is_dynamic: bool,
    symbols: Vec<ElfSymbol>,
}

impl ElfSymbolTable {
    /// Construct and parse an ELF symbol table. Mirrors
    /// `ElfSymbolTable(BinaryReader, ElfHeader, ElfSectionHeader, long, long, long, long,
    /// ElfStringTable, int[], boolean)`.
    ///
    /// * `reader` - byte reader (the reader is not retained; its position is unaffected)
    /// * `header` - ELF header
    /// * `symbol_table_section` - index of the symbol table section (may be `None`)
    /// * `file_offset` / `addr_offset` - table file offset and (pre-link adjusted) address
    /// * `length` / `entry_size` - table length and entry size in bytes
    /// * `string_table` - associated string table
    /// * `symbol_section_index_table` - extended symbol section index table (may be `None`, used
    ///   when a symbol's `st_shndx == SHN_XINDEX`)
    /// * `is_dynamic` - true if the symbol table is the dynamic symbol table
    ///
    /// # Errors
    /// Fails on an IO error, or (Java's `ArithmeticException`) a zero `entry_size` with a
    /// non-zero `length`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: &BinaryReader,
        header: &ElfHeader,
        symbol_table_section: Option<usize>,
        file_offset: i64,
        addr_offset: i64,
        length: i64,
        entry_size: i64,
        string_table: Option<ElfStringTable>,
        symbol_section_index_table: Option<Vec<i32>>,
        is_dynamic: bool,
    ) -> io::Result<Self> {
        let mut sym_table_reader = reader.clone_at(file_offset as u64);

        if entry_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "/ by zero"));
        }
        let symbol_count = (length / entry_size) as i32;

        // load all the symbol entries first, don't initialize the string name; that will be
        // done later to help localize memory access
        let mut symbols: Vec<ElfSymbol> = Vec::with_capacity(symbol_count.max(0) as usize);
        let mut entry_pos = file_offset;
        for i in 0..symbol_count.max(0) {
            // Reposition reader to start of symbol element since ElfSymbol object may not
            // consume all symbol element data
            sym_table_reader.set_pointer_index(entry_pos as u64);
            let sym = ElfSymbol::parse(&mut sym_table_reader, i as u32, header)?;
            symbols.push(sym);
            entry_pos = entry_pos.wrapping_add(entry_size);
        }

        // sort the entries by the index in the string table, so don't jump around reading
        let mut order: Vec<usize> = (0..symbols.len()).collect();
        // Java compares `getName()` as a signed int; a stable sort keeps equal names in order.
        order.sort_by_key(|&i| symbols[i].get_name() as i32);

        // initialize the Symbol string names from string table
        if let Some(st) = &string_table {
            let log = |msg: &str| header.log_error(msg);
            for i in order {
                symbols[i].init_symbol_name(&sym_table_reader, st, &log);
            }
        }

        Ok(ElfSymbolTable {
            string_table,
            symbol_table_section,
            symbol_section_index_table,
            file_offset,
            addr_offset,
            length,
            entry_size,
            symbol_count,
            is_32bit: header.is32_bit(),
            is_dynamic,
            symbols,
        })
    }

    /// A table over already-parsed `symbols` (test fixtures only; no file backing).
    #[cfg(test)]
    pub(crate) fn from_symbols(symbols: Vec<ElfSymbol>, is_32bit: bool) -> Self {
        let entry_size = if is_32bit { 16 } else { 24 };
        ElfSymbolTable {
            string_table: None,
            symbol_table_section: None,
            symbol_section_index_table: None,
            file_offset: 0,
            addr_offset: 0,
            length: symbols.len() as i64 * entry_size,
            entry_size,
            symbol_count: symbols.len() as i32,
            is_32bit,
            is_dynamic: false,
            symbols,
        }
    }

    /// Replaces the extended (`SHT_SYMTAB_SHNDX`) index table (test fixtures only).
    #[cfg(test)]
    pub(crate) fn with_symbol_section_index_table(mut self, table: Vec<i32>) -> Self {
        self.symbol_section_index_table = Some(table);
        self
    }

    /// True if this is the dynamic symbol table.
    pub fn is_dynamic(&self) -> bool {
        self.is_dynamic
    }

    /// The associated string table.
    pub fn get_string_table(&self) -> Option<&ElfStringTable> {
        self.string_table.as_ref()
    }

    /// The number of symbols contained in this symbol table.
    pub fn get_symbol_count(&self) -> i32 {
        self.symbol_count
    }

    /// All the symbols contained in this symbol table.
    pub fn get_symbols(&self) -> &[ElfSymbol] {
        &self.symbols
    }

    /// The section index for `sym` from the associated `SHT_SYMTAB_SHNDX` table, or 0 if not
    /// supported or the symbol's `st_shndx` is not `SHN_XINDEX`.
    pub fn get_extended_section_index(&self, sym: &ElfSymbol) -> i32 {
        if sym.get_section_header_index() == SHN_XINDEX {
            if let Some(table) = &self.symbol_section_index_table {
                let symbol_table_index = sym.get_symbol_table_index() as usize;
                if symbol_table_index < table.len() {
                    return table[symbol_table_index];
                }
            }
        }
        0
    }

    /// The index of `symbol` within this table, or `-1`.
    pub fn get_symbol_index(&self, symbol: &ElfSymbol) -> i32 {
        self.symbols.iter().position(|s| s == symbol).map_or(-1, |i| i as i32)
    }

    /// The first symbol whose value equals `addr`, or `None`.
    pub fn get_symbol_at(&self, addr: i64) -> Option<&ElfSymbol> {
        self.symbols.iter().find(|s| s.get_value() as i64 == addr)
    }

    /// The symbol at `symbol_index`, or `None` if out of range.
    pub fn get_symbol(&self, symbol_index: i32) -> Option<&ElfSymbol> {
        if symbol_index < 0 {
            return None;
        }
        self.symbols.get(symbol_index as usize)
    }

    /// The name of the symbol at `symbol_index`, or `None` if out of range (or unnamed).
    pub fn get_symbol_name(&self, symbol_index: i32) -> Option<String> {
        self.get_symbol(symbol_index)
            .and_then(|s| s.get_name_as_string().map(str::to_string))
    }

    /// The formatted name of the symbol at `symbol_index`, or `"<no name>"`.
    pub fn get_formatted_symbol_name(&self, symbol_index: i32) -> String {
        match self.get_symbol(symbol_index) {
            Some(s) => s.get_formatted_name().to_string(),
            None => FORMATTED_NO_NAME.to_string(),
        }
    }

    /// All the global (`STB_GLOBAL`) symbols.
    pub fn get_global_symbols(&self) -> Vec<&ElfSymbol> {
        self.symbols.iter().filter(|s| s.get_bind() == STB_GLOBAL).collect()
    }

    /// The names of all `STT_FILE` symbols (source files).
    pub fn get_source_files(&self) -> Vec<String> {
        self.symbols
            .iter()
            .filter(|s| s.get_type() == STT_FILE)
            .filter_map(|s| s.get_name_as_string().map(str::to_string))
            .collect()
    }

    /// Index of the section header for this symbol table, or `None` for a dynamic table found
    /// only through the dynamic table.
    pub fn get_table_section_header(&self) -> Option<usize> {
        self.symbol_table_section
    }
}

impl ElfFileSection for ElfSymbolTable {
    fn get_address_offset(&self) -> i64 {
        self.addr_offset
    }

    fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    fn get_length(&self) -> i64 {
        self.length
    }

    fn get_entry_size(&self) -> i32 {
        self.entry_size as i32
    }
}

impl StructConverter for ElfSymbolTable {
    /// An array of `Elf32_Sym`/`Elf64_Sym`, padded with an `st_unknown` byte array when the
    /// entry size exceeds the standard structure.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let name = if self.is_32bit { "Elf32_Sym" } else { "Elf64_Sym" };
        let mut s = ElfStruct::new(name);
        s.add(dword(), "st_name")?;
        if self.is_32bit {
            s.add(dword(), "st_value")?;
            s.add(dword(), "st_size")?;
            s.add(byte(), "st_info")?;
            s.add(byte(), "st_other")?;
            s.add(word(), "st_shndx")?;
        } else {
            s.add(byte(), "st_info")?;
            s.add(byte(), "st_other")?;
            s.add(word(), "st_shndx")?;
            s.add(qword(), "st_value")?;
            s.add(qword(), "st_size")?;
        }
        let size_remaining = self.get_entry_size() - s.length();
        if size_remaining > 0 {
            s.add(array(Box::new(ByteDataType::new(None)), size_remaining, 1)?, "st_unknown")?;
        }
        array(s.finish(), (self.length / self.entry_size) as i32, self.entry_size as i32)
    }
}
