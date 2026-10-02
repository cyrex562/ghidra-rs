//! Port of `ghidra.app.util.bin.format.elf.ElfRelocation`.
//!
//! A class to represent the `Elf32_Rel`/`Elf32_Rela`/`Elf64_Rel`/`Elf64_Rela` data structures:
//!
//! ```text
//! typedef struct {                       typedef struct {
//!     Elf32_Addr   r_offset;                 Elf64_Addr   r_offset;
//!     Elf32_Word   r_info;                   Elf64_Xword  r_info;
//!     Elf32_Sword  r_addend; // Rela only    Elf64_Sxword r_addend; // Rela only
//! } Elf32_Rela;                          } Elf64_Rela;
//! ```
//!
//! # Subclassing
//!
//! Java lets an `ElfLoadAdapter` substitute a subclass (`getRelocationClass`), instantiated
//! reflectively, whose `initElfRelocation` override re-decodes `r_info` -- its single subclass is
//! `MIPS_Elf64Relocation`, which splits the ELF64 MIPS `r_info` into a symbol index, a special
//! symbol index (`r_ssym`) and up to three packed types. The port keeps one struct: an adapter's
//! [`ElfRelocationFactory`](crate::format::elf::extend::elf_load_adapter::ElfRelocationFactory)
//! is a post-initialization hook that may call [`ElfRelocation::set_decoded_info`] to install the
//! re-decoded fields, which the getters then answer (Java's overridden `getSymbolIndex`/`getType`/
//! `getSpecialSymbolIndex`).

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_structs::{dword, qword, ElfStruct};
use crate::program::model::data::data_type::DataType;

pub const R_OFFSET_COMMENT: &str = "location to apply the relocation action";
pub const R_INFO_COMMENT: &str = "the symbol table index and the type of relocation";
pub const R_ADDEND_COMMENT: &str = "a constant addend used to compute the relocatable field value";

const BYTE_MASK: i64 = 0xFF;
const INT_MASK: i64 = 0xFFFF_FFFF;

/// Fields a relocation subclass decodes from `r_info` in place of the standard encoding (see the
/// [module documentation](self)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecodedRelocationInfo {
    pub symbol_index: i32,
    pub special_symbol_index: i32,
    pub type_: i32,
}

/// One ELF relocation entry.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfRelocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ElfRelocation {
    r_offset: i64,
    r_info: i64,
    /// signed-value
    r_addend: i64,
    has_addend: bool,
    is32bit: bool,
    relocation_index: i32,
    decoded: Option<DecodedRelocationInfo>,
}

impl ElfRelocation {
    /// Reads a relocation entry from `reader`'s current position (advancing it). Mirrors the
    /// package-private static `createElfRelocation(BinaryReader, ElfHeader, int, boolean)`.
    pub fn create_elf_relocation(
        reader: &mut BinaryReader,
        elf_header: &ElfHeader,
        relocation_index: i32,
        with_addend: bool,
    ) -> io::Result<Self> {
        let mut r = ElfRelocation {
            is32bit: elf_header.is32_bit(),
            relocation_index,
            has_addend: with_addend,
            ..Default::default()
        };
        r.read_entry_data(reader)?;
        Ok(Self::apply_relocation_class(r, elf_header))
    }

    /// Constructs a relocation entry from values. Mirrors the package-private static
    /// `createElfRelocation(ElfHeader, int, boolean, long, long, long)`. For ELF32 `offset` and
    /// `info` are truncated to their unsigned 32-bit values; `addend` is kept only for an
    /// addend-type relocation.
    pub fn create_elf_relocation_from_values(
        elf_header: &ElfHeader,
        relocation_index: i32,
        with_addend: bool,
        offset: i64,
        info: i64,
        addend: i64,
    ) -> Self {
        let r = Self::from_values(
            elf_header.is32_bit(),
            relocation_index,
            with_addend,
            offset,
            info,
            addend,
        );
        Self::apply_relocation_class(r, elf_header)
    }

    /// [`create_elf_relocation_from_values`](Self::create_elf_relocation_from_values) given only
    /// the image's word size and without an adapter hook.
    pub fn from_values(
        is32bit: bool,
        relocation_index: i32,
        with_addend: bool,
        offset: i64,
        info: i64,
        addend: i64,
    ) -> Self {
        let (r_offset, r_info) = if is32bit {
            (offset as i32 as u32 as i64, info as i32 as u32 as i64)
        } else {
            (offset, info)
        };
        ElfRelocation {
            r_offset,
            r_info,
            r_addend: if with_addend { addend } else { 0 },
            has_addend: with_addend,
            is32bit,
            relocation_index,
            decoded: None,
        }
    }

    /// `getElfRelocationClass` + the subclass's `initElfRelocation` override.
    fn apply_relocation_class(r: Self, elf_header: &ElfHeader) -> Self {
        match elf_header.get_load_adapter().get_relocation_class(elf_header) {
            Some(factory) => factory(r, elf_header),
            None => r,
        }
    }

    fn read_entry_data(&mut self, reader: &mut BinaryReader) -> io::Result<()> {
        if self.is32bit {
            self.r_offset = reader.read_next_unsigned_int()? as i64;
            self.r_info = reader.read_next_unsigned_int()? as i64;
            if self.has_addend {
                self.r_addend = reader.read_next_int()? as i64;
            }
        } else {
            self.r_offset = reader.read_next_long()?;
            self.r_info = reader.read_next_long()?;
            if self.has_addend {
                self.r_addend = reader.read_next_long()?;
            }
        }
        Ok(())
    }

    /// Installs a subclass's re-decoded `r_info` fields (see the [module documentation](self)).
    pub fn set_decoded_info(&mut self, decoded: DecodedRelocationInfo) {
        self.decoded = Some(decoded);
    }

    /// This relocation's index within its table.
    pub fn get_relocation_index(&self) -> i32 {
        self.relocation_index
    }

    /// True for an ELF32 relocation entry.
    pub fn is32_bit(&self) -> bool {
        self.is32bit
    }

    /// `r_offset`: the location at which to apply the relocation action.
    pub fn get_offset(&self) -> i64 {
        self.r_offset
    }

    /// The symbol table index encoded in `r_info` (`r_info >> 8` for ELF32, `>> 32` for ELF64).
    pub fn get_symbol_index(&self) -> i32 {
        if let Some(d) = &self.decoded {
            return d.symbol_index;
        }
        (if self.is32bit { self.r_info >> 8 } else { ((self.r_info as u64) >> 32) as i64 }) as i32
    }

    /// The special symbol index (`r_ssym`) of a MIPS ELF64 relocation; 0 for every other entry.
    /// Mirrors `MIPS_Elf64Relocation.getSpecialSymbolIndex()`.
    pub fn get_special_symbol_index(&self) -> i32 {
        self.decoded.map_or(0, |d| d.special_symbol_index)
    }

    /// The relocation type encoded in `r_info` (low byte for ELF32, low 32 bits for ELF64).
    pub fn get_type(&self) -> i32 {
        if let Some(d) = &self.decoded {
            return d.type_;
        }
        (if self.is32bit { self.r_info & BYTE_MASK } else { self.r_info & INT_MASK }) as i32
    }

    /// Replaces the type bits of `r_info`.
    pub fn set_type(&mut self, type_id: i64) {
        let mask = if self.is32bit { BYTE_MASK } else { INT_MASK };
        self.r_info = (self.r_info & !mask).wrapping_add(type_id & mask);
    }

    /// `r_info`: the symbol table index and the type of relocation.
    pub fn get_relocation_info(&self) -> i64 {
        self.r_info
    }

    /// `r_addend` (0 when [`has_addend`](Self::has_addend) is false).
    pub fn get_addend(&self) -> i64 {
        self.r_addend
    }

    /// True if this is an addend-type (`Rela`) relocation.
    pub fn has_addend(&self) -> bool {
        self.has_addend
    }

    /// `Elf32_Rel`/`Elf32_Rela`/`Elf64_Rel`/`Elf64_Rela`. Mirrors `toDataType()`.
    pub fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut name = if self.is32bit { "Elf32_Rel" } else { "Elf64_Rel" }.to_string();
        if self.has_addend {
            name.push('a');
        }
        let field = if self.is32bit { dword } else { qword };
        let mut s = ElfStruct::new(&name);
        s.add_with_comment(field(), "r_offset", R_OFFSET_COMMENT)?;
        s.add_with_comment(field(), "r_info", R_INFO_COMMENT)?;
        if self.has_addend {
            s.add_with_comment(field(), "r_addend", R_ADDEND_COMMENT)?;
        }
        Ok(s.finish())
    }

    /// The standard entry size: 8/12 bytes (ELF32 Rel/Rela), 16/24 bytes (ELF64 Rel/Rela).
    pub fn get_standard_relocation_entry_size(is64bit: bool, has_addend: bool) -> i32 {
        if is64bit {
            return if has_addend { 24 } else { 16 };
        }
        if has_addend {
            12
        } else {
            8
        }
    }

    /// This entry's size in bytes. Mirrors the protected `sizeof()`.
    pub fn sizeof(&self) -> i32 {
        Self::get_standard_relocation_entry_size(!self.is32bit, self.has_addend)
    }
}

/// Mirrors `ElfRelocation.toString()`.
impl fmt::Display for ElfRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Offset: 0x{:x} - Type: 0x{:x} - Symbol: 0x{:x}",
            self.get_offset(),
            self.get_type() as i64,
            self.get_symbol_index() as i64
        )?;
        if self.has_addend {
            write!(f, " - Addend: 0x{:x}", self.get_addend())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::elf::elf_test_image::minimal_header;

    #[test]
    fn elf32_info_splits_into_symbol_and_byte_type() {
        let mut reader = BinaryReader::from_bytes(
            [0x10u32.to_le_bytes(), 0x0000_0305u32.to_le_bytes(), (-8i32).to_le_bytes()].concat(),
            true,
        );
        let elf = minimal_header(false, true, 1);
        let r = ElfRelocation::create_elf_relocation(&mut reader, &elf, 3, true).unwrap();
        assert_eq!(reader.get_pointer_index(), 12);
        assert_eq!((r.get_offset(), r.get_symbol_index(), r.get_type()), (0x10, 3, 5));
        assert_eq!((r.get_addend(), r.get_relocation_index(), r.sizeof()), (-8, 3, 12));
        assert!(r.is32_bit() && r.has_addend());
        assert_eq!(r.get_special_symbol_index(), 0);
    }

    #[test]
    fn elf64_rel_has_no_addend_and_splits_at_32_bits() {
        let mut reader = BinaryReader::from_bytes(
            [0x4000u64.to_be_bytes(), 0x0000_0007_0000_0012u64.to_be_bytes()].concat(),
            false,
        );
        let elf = minimal_header(true, false, 1);
        let r = ElfRelocation::create_elf_relocation(&mut reader, &elf, 0, false).unwrap();
        assert_eq!((r.get_offset(), r.get_symbol_index(), r.get_type()), (0x4000, 7, 0x12));
        assert_eq!((r.get_addend(), r.sizeof()), (0, 16));
        assert_eq!(r.to_string(), "Offset: 0x4000 - Type: 0x12 - Symbol: 0x7");
    }

    #[test]
    fn values_are_truncated_for_elf32_and_addend_dropped_for_rel() {
        let elf = minimal_header(false, true, 1);
        let r = ElfRelocation::create_elf_relocation_from_values(&elf, 1, false, -1, 0x1_0000_0102, 9);
        assert_eq!(r.get_offset(), 0xffff_ffff);
        assert_eq!(r.get_relocation_info(), 0x102);
        assert_eq!(r.get_addend(), 0);
        assert_eq!((r.get_symbol_index(), r.get_type()), (1, 2));
    }

    #[test]
    fn set_type_replaces_only_the_type_bits() {
        let mut r32 = ElfRelocation::from_values(true, 0, false, 0, 0x0000_0305, 0);
        r32.set_type(0x1ff);
        assert_eq!((r32.get_symbol_index(), r32.get_type()), (3, 0xff));
        let mut r64 = ElfRelocation::from_values(false, 0, false, 0, (9 << 32) | 4, 0);
        r64.set_type(0x22);
        assert_eq!((r64.get_symbol_index(), r64.get_type()), (9, 0x22));
    }

    #[test]
    fn decoded_info_overrides_the_standard_encoding() {
        let mut r = ElfRelocation::from_values(false, 0, false, 0, (9 << 32) | 4, 0);
        r.set_decoded_info(DecodedRelocationInfo { symbol_index: 1, special_symbol_index: 2, type_: 3 });
        assert_eq!((r.get_symbol_index(), r.get_special_symbol_index(), r.get_type()), (1, 2, 3));
    }

    #[test]
    fn standard_entry_sizes_and_data_types() {
        assert_eq!(ElfRelocation::get_standard_relocation_entry_size(false, false), 8);
        assert_eq!(ElfRelocation::get_standard_relocation_entry_size(false, true), 12);
        assert_eq!(ElfRelocation::get_standard_relocation_entry_size(true, false), 16);
        assert_eq!(ElfRelocation::get_standard_relocation_entry_size(true, true), 24);
        let dt = ElfRelocation::from_values(true, 0, true, 0, 0, 0).to_data_type().unwrap();
        assert_eq!((dt.get_name(), dt.get_length()), ("Elf32_Rela".to_string(), 12));
        let dt = ElfRelocation::from_values(false, 0, false, 0, 0, 0).to_data_type().unwrap();
        assert_eq!((dt.get_name(), dt.get_length()), ("Elf64_Rel".to_string(), 16));
    }
}
