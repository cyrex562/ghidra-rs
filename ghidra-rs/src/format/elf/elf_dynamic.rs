//! Port of `ghidra.app.util.bin.format.elf.ElfDynamic`.
//!
//! Represents an `Elf32_Dyn`/`Elf64_Dyn` entry:
//!
//! ```text
//! typedef  int32_t  Elf32_Sword;
//! typedef uint32_t  Elf32_Word;
//! typedef uint32_t  Elf32_Addr;
//!
//!  typedef struct {
//!      Elf32_Sword     d_tag;
//!      union {
//!          Elf32_Word  d_val;
//!          Elf32_Addr  d_ptr;
//!      } d_un;
//!  } Elf32_Dyn;
//!
//! typedef   int64_t  Elf64_Sxword;
//! typedef  uint64_t  Elf64_Xword;
//! typedef  uint64_t  Elf64_Addr;
//!
//! typedef struct {
//!     Elf64_Sxword    d_tag;     //Dynamic entry type
//!     union {
//!         Elf64_Xword d_val;     //Integer value
//!         Elf64_Addr  d_ptr;     //Address value
//!     } d_un;
//! } Elf64_Dyn;
//! ```
//!
//! Java keeps a back-pointer to the owning `ElfHeader`, used for the entry size and for
//! looking up the tag's [`ElfDynamicType`]. The header owns its dynamic table, so the port records
//! the word size at parse time and takes the header as a call-time argument in
//! [`get_tag_type`](ElfDynamic::get_tag_type) / [`get_tag_as_string`](ElfDynamic::get_tag_as_string).

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::elf::elf_dynamic_type::ElfDynamicType;
use crate::format::elf::elf_header::ElfHeader;
use crate::util::string_utilities::StringUtilities;

/// One `Elf32_Dyn`/`Elf64_Dyn` entry.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfDynamic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfDynamic {
    is_32bit: bool,

    d_tag: i32,
    d_val: u64,
}

impl ElfDynamic {
    /// Reads an entry from the reader's current position. Mirrors
    /// `ElfDynamic(BinaryReader, ElfHeader)`.
    pub fn parse(reader: &mut BinaryReader, elf: &ElfHeader) -> io::Result<Self> {
        Self::parse_for_class(reader, elf.is32_bit())
    }

    /// [`parse`](Self::parse) given only the header's word size.
    pub fn parse_for_class(reader: &mut BinaryReader, is_32bit: bool) -> io::Result<Self> {
        let (d_tag, d_val) = if is_32bit {
            let d_tag = reader.read_next_int()?;
            let d_val = reader.read_next_unsigned_int()?;
            (d_tag, d_val)
        } else {
            let d_tag = reader.read_next_long()? as i32;
            let d_val = reader.read_next_long()? as u64;
            (d_tag, d_val)
        };

        Ok(ElfDynamic { is_32bit, d_tag, d_val })
    }

    /// Mirrors `ElfDynamic(int, long, ElfHeader)`.
    pub fn new(tag: i32, value: u64, elf: &ElfHeader) -> Self {
        ElfDynamic { is_32bit: elf.is32_bit(), d_tag: tag, d_val: value }
    }

    /// Mirrors `ElfDynamic(ElfDynamicType, long, ElfHeader)`.
    pub fn with_type(tag: &ElfDynamicType, value: u64, elf: &ElfHeader) -> Self {
        Self::new(tag.value, value, elf)
    }

    /// The value that controls the interpretation of `d_val`/`d_ptr`.
    pub fn get_tag(&self) -> i32 {
        self.d_tag
    }

    /// The enum-like type of this entry's tag in `elf`'s dynamic type registry, or `None` if
    /// unknown (or the registry is not built yet).
    pub fn get_tag_type<'a>(&self, elf: &'a ElfHeader) -> Option<&'a ElfDynamicType> {
        elf.get_dynamic_type(self.d_tag)
    }

    /// `d_val`/`d_ptr`.
    pub fn get_value(&self) -> u64 {
        self.d_val
    }

    /// The tag's name, or `DT_0x<hex>` if unknown to `elf`'s registry. Mirrors
    /// `getTagAsString()`.
    pub fn get_tag_as_string(&self, elf: &ElfHeader) -> String {
        match self.get_tag_type(elf) {
            Some(tag_type) => tag_type.name.clone(),
            None => format!("DT_0x{}", format!("{:x}", self.d_tag as u32).pad('0', 8)),
        }
    }

    /// The entry's size in bytes: 8 (ELF32) or 16 (ELF64).
    pub fn sizeof(&self) -> i32 {
        if self.is_32bit { 8 } else { 16 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::elf::elf_dynamic_type;
    use crate::format::elf::elf_test_image::minimal_header;

    /// `Elf32_Dyn`: d_tag, d_val.
    fn dyn32(tag: i32, val: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&tag.to_le_bytes());
        data.extend_from_slice(&val.to_le_bytes());
        data
    }

    /// `Elf64_Dyn`: d_tag, d_val.
    fn dyn64(tag: i64, val: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&tag.to_le_bytes());
        data.extend_from_slice(&val.to_le_bytes());
        data
    }

    #[test]
    fn parses_elf32_entry_field_order() {
        let mut reader = BinaryReader::from_bytes(dyn32(6, 0x8048_400), true);
        let header = minimal_header(false, true, 2);
        let dynamic = ElfDynamic::parse(&mut reader, &header).unwrap();

        assert_eq!(dynamic.get_tag(), 6);
        assert_eq!(dynamic.get_value(), 0x8048_400);
        assert_eq!(dynamic.sizeof(), 8);
        // 8 bytes consumed: 4 + 4
        assert_eq!(reader.get_pointer_index(), 8);
    }

    #[test]
    fn parses_elf64_entry_field_order() {
        let mut reader = BinaryReader::from_bytes(dyn64(7, 0xdead_beef), true);
        let header = minimal_header(true, true, 2);
        let dynamic = ElfDynamic::parse(&mut reader, &header).unwrap();

        assert_eq!(dynamic.get_tag(), 7);
        assert_eq!(dynamic.get_value(), 0xdead_beef);
        assert_eq!(dynamic.sizeof(), 16);
        // 16 bytes consumed: 8 + 8
        assert_eq!(reader.get_pointer_index(), 16);
    }

    #[test]
    fn tag_as_string_uses_known_type_name() {
        let header = minimal_header(false, true, 2);
        let dynamic = ElfDynamic::new(6, 0, &header);

        assert_eq!(dynamic.get_tag_as_string(&header), "DT_SYMTAB");
        assert_eq!(dynamic.get_tag_type(&header).unwrap().value, 6);
    }

    #[test]
    fn tag_as_string_falls_back_to_hex_for_unknown_tag() {
        let header = minimal_header(false, true, 2);
        // 0x7ffffffd is DT_AUXILIARY in the real registry; 0x7fff0000 is unassigned.
        let dynamic = ElfDynamic::new(0x7fff_0000, 0, &header);

        // Integer.toHexString(0x7fff0000) == "7fff0000", zero-padded to 8 chars (already 8).
        assert_eq!(dynamic.get_tag_as_string(&header), "DT_0x7fff0000");
        assert!(dynamic.get_tag_type(&header).is_none());
    }

    #[test]
    fn tag_as_string_pads_short_hex_values() {
        let header = minimal_header(false, true, 2);
        let dynamic = ElfDynamic::new(0x2a, 0, &header);

        assert_eq!(dynamic.get_tag_as_string(&header), "DT_0x0000002a");
    }

    #[test]
    fn with_type_uses_the_enum_tag_value() {
        let header = minimal_header(false, true, 2);
        let dynamic = ElfDynamic::with_type(&elf_dynamic_type::dt_symtab(), 0x1000, &header);

        assert_eq!(dynamic.get_tag(), 6);
        assert_eq!(dynamic.get_value(), 0x1000);
    }
}
