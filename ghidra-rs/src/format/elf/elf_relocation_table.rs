//! Port of `ghidra.app.util.bin.format.elf.ElfRelocationTable`.
//!
//! A container class to hold ELF relocations, parsed from a standard `REL`/`RELA` table, a
//! `RELR` (relative-only, bitmap-compressed) table, or an Android `APS2` packed table.
//!
//! Java keeps references to its header, its own section, the section being relocated and its
//! symbol table. The header owns all of those, so the port identifies the two sections by their
//! index in the header's section list (resolve them with
//! [`get_section_to_be_relocated`](ElfRelocationTable::get_section_to_be_relocated) /
//! [`get_table_section_header`](ElfRelocationTable::get_table_section_header)), shares the
//! symbol table as `Arc<ElfSymbolTable>`, and takes the header at call time where Java consults
//! it after construction.
//!
//! `toDataType()` for `RELR` and Android tables builds `ElfRelrRelocationTableDataType` /
//! `AndroidElfRelocationTableDataType`, which are not ported yet; for those formats
//! [`to_data_type`](ElfRelocationTable::to_data_type) reports an error instead.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::elf::android_elf_relocation_group::AndroidElfRelocationGroup;
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_relocation::ElfRelocation;
use crate::format::elf::elf_section_header::ElfSectionHeader;
use crate::format::elf::elf_structs::array;
use crate::format::elf::elf_symbol_table::ElfSymbolTable;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::leb128::Leb128;

/// `ElfRelocationTable.TableFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableFormat {
    Default,
    Android,
    Relr,
}

/// A parsed ELF relocation table.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfRelocationTable`.
#[derive(Debug, Clone)]
pub struct ElfRelocationTable {
    format: TableFormat,
    /// Index of the section the relocations apply to (`None` for a dynamic table).
    section_to_be_relocated: Option<usize>,
    symbol_table: Option<Arc<ElfSymbolTable>>,
    /// Index of the relocation table's own section (`None` for a dynamic table).
    reloc_table_section: Option<usize>,
    /// `sh_link` of the table's own section (Java reads it from the section on demand).
    reloc_table_section_link: i32,
    file_offset: i64,
    addr_offset: i64,
    length: i64,
    entry_size: i64,
    addend_type_reloc: bool,
    relocs: Vec<ElfRelocation>,
}

impl ElfRelocationTable {
    /// Construct and parse an ELF relocation table. Mirrors `ElfRelocationTable(BinaryReader,
    /// ElfHeader, ElfSectionHeader, long, long, long, long, boolean, ElfSymbolTable,
    /// ElfSectionHeader, TableFormat)`.
    ///
    /// * `reloc_table_section` - index of the relocation table section (`None` if not section
    ///   based)
    /// * `entry_size` - table entry size; `<= 0` selects the standard size for a `Default` table
    /// * `section_to_be_relocated` - index of the section the relocations apply to (`None` for a
    ///   dynamic table)
    ///
    /// # Errors
    /// An IO error while reading, or (Android) an unsupported table identifier.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: &BinaryReader,
        header: &ElfHeader,
        reloc_table_section: Option<usize>,
        file_offset: i64,
        addr_offset: i64,
        length: i64,
        entry_size: i64,
        addend_type_reloc: bool,
        symbol_table: Option<Arc<ElfSymbolTable>>,
        section_to_be_relocated: Option<usize>,
        format: TableFormat,
    ) -> io::Result<Self> {
        let entry_size = if format == TableFormat::Default && entry_size <= 0 {
            ElfRelocation::get_standard_relocation_entry_size(header.is64_bit(), addend_type_reloc)
                as i64
        } else {
            entry_size
        };
        let reloc_table_section_link = reloc_table_section
            .and_then(|i| header.get_sections().get(i))
            .map_or(0, ElfSectionHeader::get_link);

        let mut table = ElfRelocationTable {
            format,
            section_to_be_relocated,
            symbol_table,
            reloc_table_section,
            reloc_table_section_link,
            file_offset,
            addr_offset,
            length,
            entry_size,
            addend_type_reloc,
            relocs: Vec::new(),
        };

        let mut reloc_reader = reader.clone_at(file_offset as u64);
        table.relocs = match format {
            TableFormat::Relr => table.parse_relr_relocations(&mut reloc_reader, header)?,
            TableFormat::Android => table.parse_android_relocations(&mut reloc_reader, header)?,
            TableFormat::Default => table.parse_standard_relocations(&mut reloc_reader, header)?,
        };
        Ok(table)
    }

    /// Determine if the required symbol table is missing: a dynamic table (no section) always
    /// needs one, a section-based table needs one when its `sh_link != 0`.
    pub fn is_missing_required_symbol_table(&self) -> bool {
        if self.symbol_table.is_none() {
            // relocTableSection may only be null for dynamic relocation table which must have a
            // symbol table. All other section-based relocation tables require a symbol table if
            // link != 0.
            return self.reloc_table_section.is_none() || self.reloc_table_section_link != 0;
        }
        false
    }

    fn parse_standard_relocations(
        &self,
        reader: &mut BinaryReader,
        header: &ElfHeader,
    ) -> io::Result<Vec<ElfRelocation>> {
        if self.entry_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "/ by zero"));
        }
        let n_relocs = (self.length / self.entry_size) as i32;
        let mut relocations = Vec::with_capacity(n_relocs.max(0) as usize);
        for relocation_index in 0..n_relocs.max(0) {
            relocations.push(ElfRelocation::create_elf_relocation(
                reader,
                header,
                relocation_index,
                self.addend_type_reloc,
            )?);
        }
        Ok(relocations)
    }

    fn read_next_relr_entry(&self, reader: &mut BinaryReader) -> io::Result<i64> {
        if self.entry_size == 8 {
            reader.read_next_long()
        } else {
            Ok(reader.read_next_unsigned_int()? as i64)
        }
    }

    fn add_relr_entry(
        &self,
        offset: i64,
        reloc_list: &mut Vec<ElfRelocation>,
        header: &ElfHeader,
    ) -> i64 {
        reloc_list.push(ElfRelocation::create_elf_relocation_from_values(
            header,
            reloc_list.len() as i32,
            self.addend_type_reloc,
            offset,
            0,
            0,
        ));
        offset.wrapping_add(self.entry_size)
    }

    fn add_relr_entries(
        &self,
        base_offset: i64,
        entry: i64,
        reloc_list: &mut Vec<ElfRelocation>,
        header: &ElfHeader,
    ) -> i64 {
        let mut offset = base_offset;
        let mut entry = entry as u64;
        while entry != 0 {
            entry >>= 1;
            if (entry & 1) != 0 {
                reloc_list.push(ElfRelocation::create_elf_relocation_from_values(
                    header,
                    reloc_list.len() as i32,
                    self.addend_type_reloc,
                    offset,
                    0,
                    0,
                ));
            }
            offset = offset.wrapping_add(self.entry_size);
        }
        let n_bits = self.entry_size * 8 - 1;
        base_offset.wrapping_add(n_bits.wrapping_mul(self.entry_size))
    }

    /// NOTE: supports an entry size of 8 or 4.
    fn parse_relr_relocations(
        &self,
        reader: &mut BinaryReader,
        header: &ElfHeader,
    ) -> io::Result<Vec<ElfRelocation>> {
        let mut reloc_list = Vec::new();
        // limit to number of bytes specified for RELR table
        let mut remaining = self.length;
        let mut offset = self.read_next_relr_entry(reader)?;
        offset = self.add_relr_entry(offset, &mut reloc_list, header);
        remaining -= self.entry_size;
        while remaining > 0 {
            let next_value = self.read_next_relr_entry(reader)?;
            if (next_value & 1) == 1 {
                offset = self.add_relr_entries(offset, next_value, &mut reloc_list, header);
            } else {
                offset = self.add_relr_entry(next_value, &mut reloc_list, header);
            }
            remaining -= self.entry_size;
        }
        Ok(reloc_list)
    }

    fn parse_android_relocations(
        &self,
        reader: &mut BinaryReader,
        header: &ElfHeader,
    ) -> io::Result<Vec<ElfRelocation>> {
        let identifier = reader.read_next_ascii_string_fixed(4)?;
        if identifier != "APS2" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported Android relocation table format",
            ));
        }

        let mut relocations = Vec::new();
        let result = (|| -> io::Result<()> {
            let leb = |r: &mut BinaryReader| Leb128::signed(&mut r.get_input_stream());
            let mut relocation_index = 0i32;
            let mut remaining_relocations = leb(reader)?; // reloc_count
            let mut offset = leb(reader)?; // reloc_baseOffset
            let mut addend = 0i64;

            while remaining_relocations > 0 {
                // start new group - read group header (size and flags)

                // group_size
                let group_size = leb(reader)?;
                if group_size > remaining_relocations {
                    header.log_error(&format!(
                        "Group relocation count {group_size} exceeded total count {remaining_relocations}"
                    ));
                    break;
                }

                // group_flags
                let group_flags = leb(reader)?;
                let grouped_by_info =
                    (group_flags & AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
                let grouped_by_delta = (group_flags
                    & AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG)
                    != 0;
                let grouped_by_addend = (group_flags
                    & AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_ADDEND_FLAG)
                    != 0;
                let group_has_addend = (group_flags
                    & AndroidElfRelocationGroup::RELOCATION_GROUP_HAS_ADDEND_FLAG)
                    != 0;

                // group_offsetDelta (optional)
                let group_offset_delta = if grouped_by_delta { leb(reader)? } else { 0 };

                // group_info (optional)
                let group_r_info = if grouped_by_info { leb(reader)? } else { 0 };

                if group_has_addend && grouped_by_addend {
                    if !self.addend_type_reloc {
                        header.log_error(
                            "ELF Android Relocation processing failed.  Unexpected r_addend in android.rel section",
                        );
                        relocations.clear();
                        return Ok(());
                    }
                    // group_addend (optional)
                    addend = addend.wrapping_add(leb(reader)?);
                } else if !group_has_addend {
                    addend = 0;
                }

                // Process all group entries
                for _ in 0..group_size {
                    // reloc_offset (optional)
                    offset = offset.wrapping_add(if grouped_by_delta {
                        group_offset_delta
                    } else {
                        leb(reader)?
                    });

                    // reloc_info (optional)
                    let info = if grouped_by_info { group_r_info } else { leb(reader)? };

                    let mut r_addend = 0;
                    if self.addend_type_reloc && group_has_addend {
                        if !grouped_by_addend {
                            // reloc_addend (optional)
                            addend = addend.wrapping_add(leb(reader)?);
                        }
                        r_addend = addend;
                    }

                    relocations.push(ElfRelocation::create_elf_relocation_from_values(
                        header,
                        relocation_index,
                        self.addend_type_reloc,
                        offset,
                        info,
                        r_addend,
                    ));
                    relocation_index += 1;
                }

                remaining_relocations -= group_size;
            }
            Ok(())
        })();
        // Java logs ("Error reading relocations.") and keeps what it had parsed.
        let _ = result;
        Ok(relocations)
    }

    /// True if this table's relocations carry addends (`RELA`).
    pub fn has_addend_relocations(&self) -> bool {
        self.addend_type_reloc
    }

    /// Index of the section the relocations apply to, or `None` (dynamic table).
    pub fn get_section_to_be_relocated_index(&self) -> Option<usize> {
        self.section_to_be_relocated
    }

    /// The section the relocations apply to, resolved against `header`, or `None` (dynamic
    /// table). Mirrors `getSectionToBeRelocated()`.
    pub fn get_section_to_be_relocated<'a>(
        &self,
        header: &'a ElfHeader,
    ) -> Option<&'a ElfSectionHeader> {
        header.get_sections().get(self.section_to_be_relocated?)
    }

    /// The relocations defined in this table.
    pub fn get_relocations(&self) -> &[ElfRelocation] {
        &self.relocs
    }

    /// The number of relocations defined in this table.
    pub fn get_relocation_count(&self) -> i32 {
        self.relocs.len() as i32
    }

    /// The associated symbol table, or `None`. A relocation table is not required to link to a
    /// symbol table (e.g., `SHT_RELR`).
    pub fn get_associated_symbol_table(&self) -> Option<&Arc<ElfSymbolTable>> {
        self.symbol_table.as_ref()
    }

    /// Length of the table in bytes.
    pub fn get_length(&self) -> i64 {
        self.length
    }

    /// Memory address offset of the table.
    pub fn get_address_offset(&self) -> i64 {
        self.addr_offset
    }

    /// Index of the table's own section, or `None` if not section based.
    pub fn get_table_section_header_index(&self) -> Option<usize> {
        self.reloc_table_section
    }

    /// The table's own section resolved against `header`, or `None`. Mirrors
    /// `getTableSectionHeader()`.
    pub fn get_table_section_header<'a>(&self, header: &'a ElfHeader) -> Option<&'a ElfSectionHeader> {
        header.get_sections().get(self.reloc_table_section?)
    }

    /// True if this is a `RELR` table.
    pub fn is_relr_table(&self) -> bool {
        self.format == TableFormat::Relr
    }

    /// The table's format.
    pub fn get_format(&self) -> TableFormat {
        self.format
    }

    /// File offset of the table.
    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    /// Entry size in bytes.
    pub fn get_entry_size(&self) -> i32 {
        self.entry_size as i32
    }

    /// An array of the table's relocation structure. Mirrors `toDataType()` (see the module
    /// docs for the `RELR`/Android gap).
    pub fn to_data_type(&self, header: &ElfHeader) -> Result<Box<dyn DataType>, ToDataTypeError> {
        match self.format {
            TableFormat::Relr => Err(unported("ElfRelrRelocationTableDataType")),
            TableFormat::Android => Err(unported("AndroidElfRelocationTableDataType")),
            TableFormat::Default => {
                let representative = ElfRelocation::create_elf_relocation_from_values(
                    header,
                    -1,
                    self.addend_type_reloc,
                    0,
                    0,
                    0,
                );
                let entry = representative.to_data_type()?;
                array(entry, (self.length / self.entry_size) as i32, self.entry_size as i32)
            }
        }
    }

    /// A table over already-built `relocs` (test fixtures only; no file backing).
    #[cfg(test)]
    pub(crate) fn from_relocations(
        relocs: Vec<ElfRelocation>,
        addend_type_reloc: bool,
        symbol_table: Option<Arc<ElfSymbolTable>>,
        section_to_be_relocated: Option<usize>,
    ) -> Self {
        ElfRelocationTable {
            format: TableFormat::Default,
            section_to_be_relocated,
            symbol_table,
            reloc_table_section: None,
            reloc_table_section_link: 0,
            file_offset: 0,
            addr_offset: 0,
            length: 0,
            entry_size: 8,
            addend_type_reloc,
            relocs,
        }
    }
}

fn unported(what: &str) -> ToDataTypeError {
    ToDataTypeError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not ported yet"),
    ))
}
