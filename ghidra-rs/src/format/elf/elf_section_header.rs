//! Port of `ghidra.app.util.bin.format.elf.ElfSectionHeader`.
//!
//! ```text
//! typedef struct {                    typedef struct {
//!     Elf32_Word   sh_name;               Elf64_Word   sh_name;
//!     Elf32_Word   sh_type;               Elf64_Word   sh_type;
//!     Elf32_Word   sh_flags;              Elf64_Xword  sh_flags;
//!     Elf32_Addr   sh_addr;               Elf64_Addr   sh_addr;
//!     Elf32_Off    sh_offset;             Elf64_Off    sh_offset;
//!     Elf32_Word   sh_size;               Elf64_Xword  sh_size;
//!     Elf32_Word   sh_link;               Elf64_Word   sh_link;
//!     Elf32_Word   sh_info;               Elf64_Word   sh_info;
//!     Elf32_Word   sh_addralign;          Elf64_Xword  sh_addralign;
//!     Elf32_Word   sh_entsize;            Elf64_Xword  sh_entsize;
//! } Elf32_Shdr;                       } Elf64_Shdr;
//! ```
//!
//! # Departures from the Java class
//!
//! * No back-pointer to the owning `ElfHeader` (the header owns its sections). Each section
//!   carries the immutable [`ElfHeaderContext`] it needs; `getElfHeader()` is gone, and the
//!   operations that need the header's type registry or section list take it as a call-time
//!   argument ([`get_type_as_string`](ElfSectionHeader::get_type_as_string),
//!   [`update_name`](ElfSectionHeader::update_name), `to_data_type`).
//! * Java's `name` is lazily set by `updateName()`, called by the header after all sections are
//!   read; here `update_name` *computes* the name and the header stores it.
//! * A compressed (`SHF_COMPRESSED`) section's data is decompressed eagerly into memory by
//!   [`get_filtered_load_input_stream`](MemoryLoadable::get_filtered_load_input_stream) using
//!   `flate2`, which stands in for Java's `InflaterInputStream` + `FaultTolerantInputStream`
//!   (decompression errors are reported through the error consumer and the remainder zero-filled).

use std::io::{self, Read};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::elf::elf_compressed_section_header::{
    ElfCompressedSectionHeader, ELFCOMPRESS_ZLIB,
};
use crate::format::elf::elf_constants::ELF32_INVALID_OFFSET;
use crate::format::elf::elf_header::{ElfHeader, ElfHeaderContext};
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_section_header_constants::{
    SHF_ALLOC, SHF_COMPRESSED, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS,
};
use crate::format::elf::elf_structs::{dword, enum_type, qword, ElfStruct};
use crate::format::memory_loadable::MemoryLoadable;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::util::string_utilities::StringUtilities;

/// One ELF section header table entry.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfSectionHeader`.
#[derive(Debug, Clone)]
pub struct ElfSectionHeader {
    ctx: ElfHeaderContext,
    reader: BinaryReader,

    sh_name: i32,
    sh_type: i32,
    sh_flags: i64,
    /// May be altered after instantiation (see [`set_address`](Self::set_address)).
    sh_addr: i64,
    sh_offset: i64,
    sh_size: i64,
    sh_link: i32,
    sh_info: i32,
    sh_addralign: i64,
    sh_entsize: i64,

    /// Delayed initialization: set by the owning header once all sections are read.
    name: Option<String>,
    compressed_header: Option<ElfCompressedSectionHeader>,
}

impl ElfSectionHeader {
    /// Reads a section header from the reader's current position. Mirrors
    /// `ElfSectionHeader(BinaryReader, ElfHeader)`. The reader is retained.
    pub fn new(mut reader: BinaryReader, header: &ElfHeader) -> io::Result<Self> {
        Self::read(&mut reader, header.context(), &|msg| header.log_error(msg))
    }

    pub(crate) fn read(
        reader: &mut BinaryReader,
        ctx: ElfHeaderContext,
        warn: &dyn Fn(&str),
    ) -> io::Result<Self> {
        let sh_name = reader.read_next_int()?;
        let sh_type = reader.read_next_int()?;
        let (sh_flags, sh_addr, sh_offset, sh_size);
        if !ctx.is_32_bit {
            sh_flags = reader.read_next_long()?;
            sh_addr = reader.read_next_long()?;
            sh_offset = reader.read_next_long()?;
            sh_size = reader.read_next_long()?;
        } else {
            sh_flags = reader.read_next_unsigned_int()? as i64;
            sh_addr = reader.read_next_unsigned_int()? as i64;
            sh_offset = reader.read_next_unsigned_int()? as i64;
            sh_size = reader.read_next_unsigned_int()? as i64;
        }
        let sh_link = reader.read_next_int()?;
        let sh_info = reader.read_next_int()?;
        let (sh_addralign, sh_entsize);
        if !ctx.is_32_bit {
            sh_addralign = reader.read_next_long()?;
            sh_entsize = reader.read_next_long()?;
        } else {
            sh_addralign = reader.read_next_unsigned_int()? as i64;
            sh_entsize = reader.read_next_unsigned_int()? as i64;
        }

        let mut section = ElfSectionHeader {
            ctx,
            reader: reader.clone(),
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
            name: None,
            compressed_header: None,
        };
        if (sh_flags & SHF_COMPRESSED as i64) != 0 {
            section.compressed_header = section.read_compressed_section_header(warn);
        }
        Ok(section)
    }

    /// Java logs a warning (`Msg.warn`) and leaves the section uncompressed on failure.
    fn read_compressed_section_header(
        &self,
        warn: &dyn Fn(&str),
    ) -> Option<ElfCompressedSectionHeader> {
        let result = (|| -> io::Result<ElfCompressedSectionHeader> {
            let stream_length = self.reader.length()?;
            if !self.is_valid_for_compressed(stream_length as i64) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid compressed section: {}", self.name_or_null()),
                ));
            }
            let mut raw = self.get_raw_section_reader()?;
            let result = ElfCompressedSectionHeader::read_for_class(&mut raw, self.ctx.is_32_bit)?;
            if !is_supported_compression_type(result.get_ch_type()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Unknown ELF section compression type 0x{:x} for section {}",
                        result.get_ch_type(),
                        self.name_or_null()
                    ),
                ));
            }
            Ok(result)
        })();
        match result {
            Ok(h) => Some(h),
            Err(e) => {
                warn(&format!("Error reading compressed section information: {e}"));
                None
            }
        }
    }

    fn name_or_null(&self) -> &str {
        self.name.as_deref().unwrap_or("null")
    }

    fn is_valid_for_compressed(&self, stream_length: i64) -> bool {
        let end_offset = self.sh_offset.wrapping_add(self.sh_size);
        !self.is_alloc()
            && self.sh_offset >= 0
            && self.sh_size > 0
            && end_offset > 0
            && end_offset <= stream_length
    }

    /// The header-wide facts this section was read with (word size, pre-link base, load
    /// adapter, `e_type`). Replaces Java's `getElfHeader()` for the questions consumers ask.
    pub fn header_context(&self) -> &ElfHeaderContext {
        &self.ctx
    }

    /// `sh_addr`, pre-link adjusted: the address at which the section's first byte should reside
    /// in memory, or 0.
    pub fn get_address(&self) -> i64 {
        self.ctx.adjust_address_for_prelink(self.sh_addr)
    }

    /// `sh_addralign`, or the compressed header's `ch_addralign` for a compressed section.
    pub fn get_address_alignment(&self) -> i64 {
        match &self.compressed_header {
            None => self.sh_addralign,
            Some(c) => c.get_ch_addralign(),
        }
    }

    /// `sh_entsize`: the size of each fixed-size table entry, or 0.
    pub fn get_entry_size(&self) -> i64 {
        self.sh_entsize
    }

    /// `sh_flags` (`SHF_*`).
    pub fn get_flags(&self) -> i64 {
        self.sh_flags
    }

    /// True if this section is writable (per the load adapter).
    pub fn is_writable(&self) -> bool {
        self.ctx
            .load_adapter
            .is_section_writable(self)
            .unwrap_or((self.sh_flags & SHF_WRITE as i64) != 0)
    }

    /// True if this section is executable (per the load adapter).
    pub fn is_executable(&self) -> bool {
        self.ctx
            .load_adapter
            .is_section_executable(self)
            .unwrap_or((self.sh_flags & SHF_EXECINSTR as i64) != 0)
    }

    /// True if this section is allocated (per the load adapter).
    pub fn is_alloc(&self) -> bool {
        self.ctx
            .load_adapter
            .is_section_allocated(self)
            .unwrap_or((self.sh_flags & SHF_ALLOC as i64) != 0)
    }

    /// True if this section is compressed in a supported manner.
    pub fn is_compressed(&self) -> bool {
        self.compressed_header.is_some()
    }

    fn is_no_bits(&self) -> bool {
        self.sh_type == SHT_NOBITS as i32
    }

    /// `sh_info`: extra information whose interpretation depends on the section type.
    pub fn get_info(&self) -> i32 {
        self.sh_info
    }

    /// `sh_link`: a section header table index link, interpreted per section type.
    pub fn get_link(&self) -> i32 {
        self.sh_link
    }

    /// `sh_name`: the index into the section header string table of this section's name.
    pub fn get_name(&self) -> i32 {
        self.sh_name
    }

    /// Computes this section's name, as Java's `updateName()` does: read from the
    /// `e_shstrndx` string table section, or `"SECTION<index>"` (`"NO-NAME"` if this section is
    /// not in `sections`) when it cannot be read or is empty.
    ///
    /// `sections` is the header's section list and `e_shstrndx` its string table index.
    pub(crate) fn compute_name(&self, sections: &[ElfSectionHeader], e_shstrndx: i32) -> String {
        let mut name: Option<String> = None;
        if self.sh_name >= 0 && e_shstrndx > 0 && (e_shstrndx as usize) < sections.len() {
            let strtab = &sections[e_shstrndx as usize];
            if !strtab.is_invalid_offset() {
                let string_table_offset = strtab.get_offset();
                let offset = string_table_offset.wrapping_add(self.sh_name as i64);
                if let Ok(len) = self.reader.length() {
                    if offset < len as i64 {
                        if let Ok(s) = self.reader.read_utf8_string(offset as u64) {
                            if !s.is_empty() {
                                name = Some(s);
                            }
                        }
                    }
                }
            }
        }
        name.unwrap_or_else(|| {
            match sections.iter().position(|s| std::ptr::eq(s, self)) {
                Some(i) => format!("SECTION{i}"),
                None => "NO-NAME".to_string(),
            }
        })
    }

    /// Recomputes this section's name against `header`'s sections. Mirrors the package-private
    /// `updateName()`.
    pub fn update_name(&mut self, header: &ElfHeader) {
        let name = self.compute_name(header.get_sections(), header.e_shstrndx());
        self.name = Some(name);
    }

    pub(crate) fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    /// The actual string name of this section, as resolved by the header. Java returns `null`
    /// before `updateName()` runs; every section the header hands out has been named, and an
    /// unnamed one renders as `"null"` (Java's string concatenation of `null`).
    pub fn get_name_as_string(&self) -> String {
        self.name.clone().unwrap_or_else(|| "null".to_string())
    }

    /// `sh_offset`: the file offset of the section's first byte. A `SHT_NOBITS` section occupies
    /// no file space; its offset is only conceptual.
    pub fn get_offset(&self) -> i64 {
        self.sh_offset
    }

    /// True if `sh_offset` is negative or the 32-bit `-1` sentinel.
    pub fn is_invalid_offset(&self) -> bool {
        self.sh_offset < 0 || (self.ctx.is_32_bit && self.sh_offset as u64 == ELF32_INVALID_OFFSET)
    }

    /// `sh_size`: the section's size in bytes in the file (or in memory for `SHT_NOBITS`).
    pub fn get_size(&self) -> i64 {
        self.sh_size
    }

    /// The logical (uncompressed) size: `ch_size` for a compressed section, `sh_size` otherwise.
    pub fn get_logical_size(&self) -> i64 {
        match &self.compressed_header {
            None => self.sh_size,
            Some(c) => c.get_ch_size(),
        }
    }

    /// `sh_type` (`SHT_*`).
    pub fn get_type(&self) -> i32 {
        self.sh_type
    }

    /// The type as a string (e.g. `"SHT_PROGBITS"`), or `SHT_0x<hex>` if unknown to `header`'s
    /// type registry.
    pub fn get_type_as_string(&self, header: &ElfHeader) -> String {
        match header.get_section_header_type(self.sh_type) {
            Some(t) => t.name.clone(),
            None => format!("SHT_0x{}", format!("{:x}", self.sh_type as u32).pad('0', 8)),
        }
    }

    fn get_raw_section_bytes(&self) -> io::Result<Vec<u8>> {
        if self.is_no_bits() || self.sh_size <= 0 {
            return Ok(Vec::new());
        }
        self.reader
            .get_byte_provider()
            .read_bytes(self.sh_offset as u64, self.sh_size as u64)
    }

    fn get_raw_section_reader(&self) -> io::Result<BinaryReader> {
        Ok(BinaryReader::from_bytes(self.get_raw_section_bytes()?, self.reader.is_little_endian()))
    }

    fn get_decompressed_data_stream(
        &self,
        data_length: i64,
        error_consumer: Option<&dyn Fn(&str, &dyn std::error::Error)>,
    ) -> io::Result<Box<dyn Read>> {
        let compressed = match &self.compressed_header {
            Some(c) if data_length == c.get_ch_size() => c,
            _ => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "UnsupportedOperation"));
            }
        };
        let raw = self.get_raw_section_bytes()?;
        let skip = (compressed.get_header_size() as usize).min(raw.len());
        match compressed.get_ch_type() {
            ELFCOMPRESS_ZLIB => {
                let expected = compressed.get_ch_size().max(0) as usize;
                let mut out = Vec::with_capacity(expected);
                let mut decoder = flate2::read::ZlibDecoder::new(&raw[skip..]);
                if let Err(e) = decoder.read_to_end(&mut out) {
                    if let Some(consumer) = error_consumer {
                        consumer("Error decompressing ELF section data", &e);
                    }
                }
                // FaultTolerantInputStream: exactly ch_size bytes, zero-filled past an error.
                out.resize(expected, 0);
                Ok(Box::new(io::Cursor::new(out)))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Unknown ELF section compression type 0x{other:x} for section {}",
                    self.name_or_null()
                ),
            )),
        }
    }

    /// The reader this section header was read with.
    pub fn get_reader(&self) -> &BinaryReader {
        &self.reader
    }

    /// Sets the (pre-link adjusted) start address of the section. Mirrors `setAddress(long)`.
    ///
    /// # Errors
    /// Java's `RuntimeException` when placing a non-loaded section of a non-relocatable image.
    pub fn set_address(&mut self, addr: i64) -> Result<(), String> {
        if !self.ctx.is_relocatable && self.sh_addr == 0 {
            return Err(format!(
                "Attempting to place non-loaded section into memory :{}",
                self.name_or_null()
            ));
        }
        self.sh_addr = self.ctx.unadjust_address_for_prelink(addr);
        Ok(())
    }

    /// The `Elf32_Shdr`/`Elf64_Shdr` structure. Mirrors `toDataType()`.
    pub fn to_data_type(&self, header: &ElfHeader) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let name = if self.ctx.is_32_bit { "Elf32_Shdr" } else { "Elf64_Shdr" };
        let word = if self.ctx.is_32_bit { dword } else { qword };
        let mut s = ElfStruct::new(name);
        s.add(dword(), "sh_name")?;
        s.add(self.get_type_data_type(header), "sh_type")?;
        for f in ["sh_flags", "sh_addr", "sh_offset", "sh_size"] {
            s.add(word(), f)?;
        }
        s.add(dword(), "sh_link")?;
        s.add(dword(), "sh_info")?;
        s.add(word(), "sh_addralign")?;
        s.add(word(), "sh_entsize")?;
        Ok(s.finish())
    }

    fn get_type_data_type(&self, header: &ElfHeader) -> Box<dyn DataType> {
        match header.get_section_header_type_map() {
            None => dword(),
            Some(map) => {
                let mut name = "Elf_SectionHeaderType".to_string();
                if let Some(suffix) = header.get_type_suffix() {
                    name.push_str(&suffix);
                }
                enum_type(&name, 4, map.values().map(|t| (t.name.as_str(), t.value as i64)))
            }
        }
    }
}

fn is_supported_compression_type(compression_type: i32) -> bool {
    compression_type == ELFCOMPRESS_ZLIB
}

impl MemoryLoadable for ElfSectionHeader {
    fn has_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
    ) -> bool {
        self.is_compressed()
            || self.ctx.load_adapter.has_filtered_load_input_stream(elf_load_helper, self, &start)
    }

    fn get_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
        data_length: i64,
        error_consumer: Option<&dyn Fn(&str, &dyn std::error::Error)>,
    ) -> io::Result<Box<dyn Read>> {
        let is = if self.is_compressed() {
            self.get_decompressed_data_stream(data_length, error_consumer)?
        } else {
            self.get_raw_input_stream()?
        };
        self.ctx.load_adapter.get_filtered_load_input_stream(
            elf_load_helper,
            self,
            &start,
            data_length,
            is,
        )
    }

    /// The section's raw file bytes; a `SHT_NOBITS` section yields an empty stream.
    fn get_raw_input_stream(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(io::Cursor::new(self.get_raw_section_bytes()?)))
    }
}

/// Mirrors `ElfSectionHeader.equals`: the ten raw fields.
impl PartialEq for ElfSectionHeader {
    fn eq(&self, other: &Self) -> bool {
        self.sh_name == other.sh_name
            && self.sh_type == other.sh_type
            && self.sh_flags == other.sh_flags
            && self.sh_addr == other.sh_addr
            && self.sh_offset == other.sh_offset
            && self.sh_size == other.sh_size
            && self.sh_link == other.sh_link
            && self.sh_info == other.sh_info
            && self.sh_addralign == other.sh_addralign
            && self.sh_entsize == other.sh_entsize
    }
}

impl Eq for ElfSectionHeader {}

/// Mirrors `ElfSectionHeader.hashCode` (`Objects.hash(sh_offset)`).
impl std::hash::Hash for ElfSectionHeader {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sh_offset.hash(state);
    }
}

/// Mirrors `ElfSectionHeader.toString()`.
impl std::fmt::Display for ElfSectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - 0x{:x}:0x{:x} - 0x{:x}  - 0x{:x}",
            self.name_or_null(),
            self.sh_addr,
            self.sh_addr.wrapping_add(self.sh_size).wrapping_sub(1),
            self.sh_size,
            self.sh_offset
        )
    }
}
