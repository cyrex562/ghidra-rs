//! Port of `ghidra.app.util.bin.format.elf.ElfProgramHeader`.
//!
//! An executable or shared object file's program header table is an array of structures, each
//! describing a segment or other information the system needs to prepare the program for
//! execution.
//!
//! ```text
//! typedef struct {                    typedef struct {
//!     Elf32_Word   p_type;                Elf64_Word   p_type;
//!     Elf32_Off    p_offset;              Elf64_Word   p_flags;
//!     Elf32_Addr   p_vaddr;               Elf64_Off    p_offset;
//!     Elf32_Addr   p_paddr;               Elf64_Addr   p_vaddr;
//!     Elf32_Word   p_filesz;              Elf64_Addr   p_paddr;
//!     Elf32_Word   p_memsz;               Elf64_Xword  p_filesz;
//!     Elf32_Word   p_flags;               Elf64_Xword  p_memsz;
//!     Elf32_Word   p_align;               Elf64_Xword  p_align;
//! } Elf32_Phdr;                       } Elf64_Phdr;
//! ```
//!
//! # Departures from the Java class
//!
//! * Java keeps a back-pointer to the owning `ElfHeader`. The header owns its program headers, so
//!   a back-pointer would be a reference cycle; instead each program header carries the small,
//!   immutable [`ElfHeaderContext`] it needs (word size, pre-link base and load adapter) and the
//!   two operations that need the header's type registry ([`get_type_as_string`] /
//!   [`get_description`] / [`get_comment`] / `to_data_type`) take the header as a call-time
//!   argument.
//! * The `MemoryLoadable` raw stream copies the segment's file bytes out of the shared provider
//!   (Java wraps the provider in a `ByteProviderWrapper`).
//!
//! [`get_type_as_string`]: ElfProgramHeader::get_type_as_string
//! [`get_description`]: ElfProgramHeader::get_description
//! [`get_comment`]: ElfProgramHeader::get_comment

use std::cmp::Ordering;
use std::io::{self, Read};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::elf::elf_constants::ELF32_INVALID_OFFSET;
use crate::format::elf::elf_header::{ElfHeader, ElfHeaderContext};
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_program_header_constants::{PF_R, PF_W, PF_X, PT_LOAD};
use crate::format::memory_loadable::MemoryLoadable;
use crate::format::elf::elf_structs::{dword, enum_type, qword, ElfStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::util::string_utilities::StringUtilities;

/// One ELF program header (segment) table entry.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfProgramHeader`.
#[derive(Debug, Clone)]
pub struct ElfProgramHeader {
    ctx: ElfHeaderContext,
    reader: BinaryReader,

    p_type: i32,
    p_flags: i32,
    /// May be altered after instantiation (see `ElfHeader`'s malformed-file adjustment).
    p_offset: i64,
    p_vaddr: i64,
    p_paddr: i64,
    p_filesz: i64,
    p_memsz: i64,
    p_align: i64,
}

impl ElfProgramHeader {
    /// Reads a program header from the reader's current position.
    ///
    /// Mirrors `ElfProgramHeader(BinaryReader, ElfHeader)`. The reader is retained (Java keeps it
    /// for the segment's raw input stream).
    pub fn new(mut reader: BinaryReader, header: &ElfHeader) -> io::Result<Self> {
        Self::read(&mut reader, header.context())
    }

    pub(crate) fn read(reader: &mut BinaryReader, ctx: ElfHeaderContext) -> io::Result<Self> {
        let (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align);
        if !ctx.is_32_bit {
            p_type = reader.read_next_int()?;
            p_flags = reader.read_next_int()?;
            p_offset = reader.read_next_long()?;
            p_vaddr = reader.read_next_long()?;
            p_paddr = reader.read_next_long()?;
            p_filesz = reader.read_next_long()?;
            p_memsz = reader.read_next_long()?;
            p_align = reader.read_next_long()?;
        } else {
            p_type = reader.read_next_int()?;
            p_offset = reader.read_next_unsigned_int()? as i64;
            p_vaddr = reader.read_next_unsigned_int()? as i64;
            p_paddr = reader.read_next_unsigned_int()? as i64;
            p_filesz = reader.read_next_unsigned_int()? as i64;
            p_memsz = reader.read_next_unsigned_int()? as i64;
            p_flags = reader.read_next_int()?;
            p_align = reader.read_next_unsigned_int()? as i64;
        }
        // Java notes (without acting on it) that p_memsz > p_filesz occurs when a data segment
        // has both initialized and uninitialized sections (e.g. ".data" + ".bss").
        Ok(ElfProgramHeader {
            ctx,
            reader: reader.clone(),
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        })
    }

    /// The type of this segment as a string (e.g. `"PT_LOAD"`), or `PT_0x<hex>` if the type is
    /// unknown to `header`'s type registry. Mirrors `getTypeAsString()`.
    pub fn get_type_as_string(&self, header: &ElfHeader) -> String {
        match header.get_program_header_type(self.p_type) {
            Some(t) => t.name.clone(),
            None => format!("PT_0x{}", format!("{:x}", self.p_type as u32).pad('0', 8)),
        }
    }

    /// Description of this program header type, or `None`. Mirrors `getDescription()`.
    pub fn get_description(&self, header: &ElfHeader) -> Option<String> {
        header
            .get_program_header_type(self.p_type)
            .map(|t| t.description.clone())
            .filter(|d| !d.is_empty())
    }

    /// Type string, plus `" - " + description` when one exists. Mirrors `getComment()`.
    pub fn get_comment(&self, header: &ElfHeader) -> String {
        match self.get_description(header) {
            Some(d) => format!("{} - {}", self.get_type_as_string(header), d),
            None => self.get_type_as_string(header),
        }
    }

    /// `p_align`: the value to which segments are aligned in memory and in the file.
    pub fn get_align(&self) -> i64 {
        self.p_align
    }

    /// `p_filesz`: the number of bytes in the file image of the segment (may be zero).
    pub fn get_file_size(&self) -> i64 {
        self.p_filesz
    }

    /// `p_flags`: the flags relevant to the segment (`PF_*`).
    pub fn get_flags(&self) -> i32 {
        self.p_flags
    }

    /// True if this segment is readable when loaded (per the load adapter).
    pub fn is_read(&self) -> bool {
        self.ctx.load_adapter.is_segment_readable(self).unwrap_or(self.p_flags & PF_R as i32 != 0)
    }

    /// True if this segment is writable when loaded (per the load adapter).
    pub fn is_write(&self) -> bool {
        self.ctx.load_adapter.is_segment_writable(self).unwrap_or(self.p_flags & PF_W as i32 != 0)
    }

    /// True if this segment is executable when loaded (per the load adapter).
    pub fn is_execute(&self) -> bool {
        self.ctx.load_adapter.is_segment_executable(self).unwrap_or(self.p_flags & PF_X as i32 != 0)
    }

    /// `p_memsz`: the number of bytes in the memory image of the segment (may be zero).
    pub fn get_memory_size(&self) -> i64 {
        self.p_memsz
    }

    /// The adjusted memory size in bytes, which may differ from `p_memsz` when an extension
    /// filters the segment's bytes. Mirrors `getAdjustedMemorySize()`.
    pub fn get_adjusted_memory_size(&self) -> i64 {
        self.ctx.load_adapter.get_adjusted_memory_size(self)
    }

    /// The adjusted file load size (bytes loaded from the file), which may differ from `p_filesz`
    /// when an extension filters the segment's bytes. Mirrors `getAdjustedLoadSize()`.
    pub fn get_adjusted_load_size(&self) -> i64 {
        self.ctx.load_adapter.get_adjusted_load_size(self)
    }

    /// The reader this header was read with. Mirrors `getReader()`.
    pub fn get_reader(&self) -> &BinaryReader {
        &self.reader
    }

    /// `p_offset`: the offset from the beginning of the file at which the first byte of the
    /// segment resides.
    pub fn get_offset(&self) -> i64 {
        self.p_offset
    }

    /// True if `p_offset` is negative or the 32-bit `-1` sentinel. Mirrors `isInvalidOffset()`.
    pub fn is_invalid_offset(&self) -> bool {
        self.p_offset < 0 || (self.ctx.is_32_bit && self.p_offset as u64 == ELF32_INVALID_OFFSET)
    }

    /// Computes the file offset of `virtual_address` within this `PT_LOAD` segment. Mirrors
    /// `getOffset(long)`.
    ///
    /// # Errors
    /// Java's `UnsupportedOperationException` (the address is not loaded by this segment, or the
    /// segment is a filtered load) becomes `Err(String)`.
    pub fn get_offset_of(&self, virtual_address: i64) -> Result<i64, String> {
        if self.p_type != PT_LOAD as i32 || self.p_filesz == 0 || self.p_memsz == 0 {
            return Err("virtualAddress not loaded by this segment".to_string());
        }
        if self.get_memory_size() != self.get_adjusted_memory_size() {
            return Err("unsupported use of filtered load segment".to_string());
        }
        let addressable_unit_size = self.p_filesz / self.get_adjusted_load_size();
        Ok(addressable_unit_size * virtual_address.wrapping_sub(self.get_virtual_address())
            + self.p_offset)
    }

    /// Sets `p_offset`. Mirrors the package-private `setOffset(long)`.
    pub(crate) fn set_offset(&mut self, offset: i64) {
        self.p_offset = offset;
    }

    /// `p_paddr`, pre-link adjusted.
    pub fn get_physical_address(&self) -> i64 {
        self.ctx.adjust_address_for_prelink(self.p_paddr)
    }

    /// `p_type`: what kind of segment this is (`PT_*`).
    pub fn get_type(&self) -> i32 {
        self.p_type
    }

    /// `p_vaddr`, pre-link adjusted: the virtual address at which the first byte of the segment
    /// resides in memory.
    pub fn get_virtual_address(&self) -> i64 {
        self.ctx.adjust_address_for_prelink(self.p_vaddr)
    }

    /// The `Elf32_Phdr`/`Elf64_Phdr` structure. Mirrors `toDataType()`; the type registry comes
    /// from `header` at call time.
    pub fn to_data_type(&self, header: &ElfHeader) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let name = if self.ctx.is_32_bit { "Elf32_Phdr" } else { "Elf64_Phdr" };
        let mut s = ElfStruct::new(name);
        let type_dt = self.get_type_data_type(header);
        if self.ctx.is_32_bit {
            s.add(type_dt, "p_type")?;
            for f in ["p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align"]
            {
                s.add(dword(), f)?;
            }
        } else {
            s.add(type_dt, "p_type")?;
            s.add(dword(), "p_flags")?;
            for f in ["p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align"] {
                s.add(qword(), f)?;
            }
        }
        Ok(s.finish())
    }

    fn get_type_data_type(&self, header: &ElfHeader) -> Box<dyn DataType> {
        match header.get_program_header_type_map() {
            None => dword(),
            Some(map) => {
                let mut name = "Elf_ProgramHeaderType".to_string();
                if let Some(suffix) = header.get_type_suffix() {
                    name.push_str(&suffix);
                }
                enum_type(&name, 4, map.values().map(|t| (t.name.as_str(), t.value as i64)))
            }
        }
    }
}

impl MemoryLoadable for ElfProgramHeader {
    fn has_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
    ) -> bool {
        self.ctx.load_adapter.has_filtered_load_input_stream(elf_load_helper, self, &start)
    }

    fn get_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
        data_length: i64,
        _error_consumer: Option<&dyn Fn(&str, &dyn std::error::Error)>,
    ) -> io::Result<Box<dyn Read>> {
        let raw = self.get_raw_input_stream()?;
        self.ctx.load_adapter.get_filtered_load_input_stream(
            elf_load_helper,
            self,
            &start,
            data_length,
            raw,
        )
    }

    /// The segment's raw file bytes (`p_filesz` bytes at `p_offset`); an empty segment yields an
    /// empty stream (Java's `EMPTY_BYTEPROVIDER`).
    fn get_raw_input_stream(&self) -> io::Result<Box<dyn Read>> {
        if self.p_filesz <= 0 {
            return Ok(Box::new(io::empty()));
        }
        let bytes = self
            .reader
            .get_byte_provider()
            .read_bytes(self.p_offset as u64, self.p_filesz as u64)?;
        Ok(Box::new(io::Cursor::new(bytes)))
    }
}

/// Mirrors `ElfProgramHeader.compareTo`: `PT_LOAD` headers order by `p_vaddr`, with the
/// `0xffffffff` sentinel address sorted last; everything else compares equal.
impl ElfProgramHeader {
    pub fn compare_to(&self, that: &ElfProgramHeader) -> Ordering {
        if self.p_type == PT_LOAD as i32 {
            if self.p_vaddr < that.p_vaddr {
                if self.p_vaddr == 0xffff_ffff {
                    return Ordering::Greater;
                }
                return Ordering::Less;
            } else if self.p_vaddr > that.p_vaddr {
                if that.p_vaddr == 0xffff_ffff {
                    return Ordering::Less;
                }
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }
}

/// Mirrors `ElfProgramHeader.equals`: all eight raw fields.
impl PartialEq for ElfProgramHeader {
    fn eq(&self, other: &Self) -> bool {
        self.p_type == other.p_type
            && self.p_flags == other.p_flags
            && self.p_offset == other.p_offset
            && self.p_vaddr == other.p_vaddr
            && self.p_paddr == other.p_paddr
            && self.p_filesz == other.p_filesz
            && self.p_memsz == other.p_memsz
            && self.p_align == other.p_align
    }
}

impl Eq for ElfProgramHeader {}

/// Mirrors `ElfProgramHeader.hashCode` (`Objects.hash(p_offset)`).
impl std::hash::Hash for ElfProgramHeader {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.p_offset.hash(state);
    }
}
