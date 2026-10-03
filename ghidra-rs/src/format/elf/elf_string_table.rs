//! Port of `ghidra.app.util.bin.format.elf.ElfStringTable`.
//!
//! Java keeps a back-pointer to the owning `ElfHeader`, used for the pre-link address adjustment
//! and for logging read errors. The port carries the header's immutable [`ElfHeaderContext`]
//! for the former and takes an error sink at call time for the latter; the optional section the
//! table came from is identified by its index in the header's section list rather than by
//! reference.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::elf::elf_file_section::ElfFileSection;
use crate::format::elf::elf_header::ElfHeaderContext;
use crate::program::model::data::data_type::DataType;

/// An ELF string table (a `SHT_STRTAB` section, or the dynamic `DT_STRTAB` table).
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfStringTable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfStringTable {
    ctx: ElfHeaderContext,
    /// Index of the section this table was parsed from, in the header's section list (may be
    /// `None` for a table found only through the dynamic table).
    string_table_section: Option<usize>,
    file_offset: i64,
    addr_offset: i64,
    length: i64,
}

impl ElfStringTable {
    /// Construct and parse an ELF string table. Mirrors
    /// `ElfStringTable(ElfHeader, ElfSectionHeader, long, long, long)`.
    ///
    /// * `string_table_section` - index of the string table section header (may be `None` for
    ///   dynamic string table)
    /// * `file_offset` - string table file offset
    /// * `addr_offset` - memory address of string table (should already be adjusted for
    ///   pre-link)
    /// * `length` - length of string table in bytes
    pub fn new(
        ctx: ElfHeaderContext,
        string_table_section: Option<usize>,
        file_offset: i64,
        addr_offset: i64,
        length: i64,
    ) -> Self {
        ElfStringTable { ctx, string_table_section, file_offset, addr_offset, length }
    }

    /// Read a null-terminated UTF-8 string at `string_offset` within this table, trimmed.
    ///
    /// Returns `None` when the table has no file data (`file_offset < 0`) or the read fails; a
    /// failed read is reported through `log_error` (Java's `header.logError`).
    pub fn read_string(
        &self,
        reader: &BinaryReader,
        string_offset: i64,
        log_error: &dyn Fn(&str),
    ) -> Option<String> {
        if self.file_offset < 0 {
            return None;
        }
        let result = (|| -> io::Result<String> {
            if string_offset >= self.length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "String read beyond table bounds",
                ));
            }
            let s = reader.read_utf8_string(self.file_offset.wrapping_add(string_offset) as u64)?;
            Ok(java_trim(&s).to_string())
        })();
        match result {
            Ok(s) => Some(s),
            Err(_) => {
                log_error(&format!(
                    "Failed to read Elf String at offset 0x{:x} within String Table at offset 0x{:x}",
                    string_offset, self.file_offset
                ));
                None
            }
        }
    }

    /// Index of the section header for this string table, or `None` if it was not defined by a
    /// section. Mirrors `getTableSectionHeader()`.
    pub fn get_table_section_header(&self) -> Option<usize> {
        self.string_table_section
    }
}

/// Java's `String.trim()`: strips leading/trailing chars `<= ' '`.
pub(crate) fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

impl ElfFileSection for ElfStringTable {
    fn get_address_offset(&self) -> i64 {
        self.ctx.adjust_address_for_prelink(self.addr_offset)
    }

    fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    fn get_length(&self) -> i64 {
        self.length
    }

    fn get_entry_size(&self) -> i32 {
        -1
    }
}

impl StructConverter for ElfStringTable {
    /// Java returns `null`: there is no uniform structure to apply. There is no null
    /// `Box<dyn DataType>`, so this reports the absence as an error the caller can skip.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "no uniform structure to be applied to an ELF string table",
        )))
    }
}
