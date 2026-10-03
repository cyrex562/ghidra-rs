//! Port of `ghidra.app.util.bin.format.macho.commands.NList`.
//!
//! Represents an `nlist` / `nlist_64` symbol table entry. See
//! `EXTERNAL_HEADERS/mach-o/nlist.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::n_list_constants::{
    DESC_N_ARM_THUMB_DEF, MASK_N_EXT, MASK_N_PEXT, MASK_N_STAB, MASK_N_TYPE, NO_SECT, REFERENCE_TYPE,
    TYPE_N_ABS, TYPE_N_INDR, TYPE_N_PBUD, TYPE_N_UNDF,
};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `nlist` (32-bit) or `nlist_64` entry.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.NList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NList {
    n_strx: i32,
    n_type: i8,
    n_sect: i8,
    n_desc: i16,
    n_value: i64,
    /// `None` until [`init_string`](NList::init_string) is called (Java's `null`).
    string: Option<String>,
    is32bit: bool,
}

impl NList {
    /// Java: `NList(BinaryReader, boolean)`.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        let n_strx = reader.read_next_int()?;
        let n_type = reader.read_next_byte()? as i8;
        let n_sect = reader.read_next_byte()? as i8;
        let n_desc = reader.read_next_short()?;
        let n_value = if is32bit {
            reader.read_next_unsigned_int()? as i64
        } else {
            reader.read_next_long()?
        };
        Ok(NList { n_strx, n_type, n_sect, n_desc, n_value, string: None, is32bit })
    }

    /// Java: `initString(BinaryReader, long)`. Initializes the string name from the string table
    /// at `string_table_offset`; any read failure leaves it empty, as in Java.
    pub fn init_string(&mut self, reader: &BinaryReader, string_table_offset: i64) {
        let mut string = String::new();
        if self.n_strx != 0 {
            let index = string_table_offset.wrapping_add(self.n_strx as i64);
            if let Ok(s) = reader.read_ascii_string(index as u64) {
                string = s;
            }
        }
        self.string = Some(string);
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("nlist");
        s.dword("n_strx")?.byte("n_type")?.byte("n_sect")?.word("n_desc")?;
        if self.is32bit {
            s.dword("n_value")?;
        } else {
            s.qword("n_value")?;
        }
        s.finish_structure()
    }

    /// Java: `getString()`.
    ///
    /// # Panics
    /// Panics (Java: `AssertException`) if [`init_string`](Self::init_string) was not called
    /// first.
    pub fn get_string(&self) -> &str {
        self.string.as_deref().expect("initString must be called first")
    }

    /// Java: `getStringTableIndex()`.
    pub fn get_string_table_index(&self) -> i32 {
        self.n_strx
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> i8 {
        self.n_type
    }

    fn masked_type(&self) -> u8 {
        (self.n_type as u8 as u32 & MASK_N_TYPE) as u8
    }

    fn no_sect(&self) -> bool {
        self.n_sect as u8 == NO_SECT
    }

    /// Java: `isTypeUndefined()`.
    pub fn is_type_undefined(&self) -> bool {
        self.no_sect() && self.masked_type() == TYPE_N_UNDF
    }

    /// Java: `isTypeAbsolute()`.
    pub fn is_type_absolute(&self) -> bool {
        self.no_sect() && self.masked_type() == TYPE_N_ABS
    }

    /// Java: `isTypePreboundUndefined()`.
    pub fn is_type_prebound_undefined(&self) -> bool {
        self.no_sect() && self.masked_type() == TYPE_N_PBUD
    }

    /// Java: `isIndirect()`.
    pub fn is_indirect(&self) -> bool {
        self.no_sect() && self.masked_type() == TYPE_N_INDR
    }

    /// Java: `isSymbolicDebugging()`.
    pub fn is_symbolic_debugging(&self) -> bool {
        (self.n_type as u8 as u32 & MASK_N_STAB) != 0
    }

    /// Java: `isPrivateExternal()`.
    pub fn is_private_external(&self) -> bool {
        (self.n_type as u8 as u32 & MASK_N_PEXT) != 0
    }

    /// Java: `isExternal()`.
    pub fn is_external(&self) -> bool {
        (self.n_type as u8 as u32 & MASK_N_EXT) != 0
    }

    /// Java: `isLazyBind()`.
    pub fn is_lazy_bind(&self) -> bool {
        (self.n_desc as i32 & REFERENCE_TYPE as i32) != 0
    }

    /// Java: `isThumbSymbol()`.
    pub fn is_thumb_symbol(&self) -> bool {
        (self.n_desc as i32 & DESC_N_ARM_THUMB_DEF as i32) != 0
    }

    /// Java: `getSection()`.
    pub fn get_section(&self) -> i8 {
        self.n_sect
    }

    /// Java: `getDescription()`.
    pub fn get_description(&self) -> i16 {
        self.n_desc
    }

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i64 {
        self.n_value
    }

    /// Java: `getLibraryOrdinal()`.
    pub fn get_library_ordinal(&self) -> i32 {
        ((self.n_desc as i32) >> 8) & 0xff
    }

    /// Java: `is32bit()`.
    pub fn is32bit(&self) -> bool {
        self.is32bit
    }

    /// Java: `getSize()`, the entry's size in bytes.
    pub fn get_size(&self) -> i32 {
        if self.is32bit {
            12
        } else {
            16
        }
    }

    /// Java: the static `getSize(List<NList>)`: the size in bytes of the entries plus their string
    /// table (a leading 0 byte and each NUL-terminated name).
    pub fn get_total_size(nlists: &[NList]) -> i32 {
        match nlists.first() {
            None => 0,
            Some(first) => {
                let strings: i32 = 1 + nlists.iter().map(|n| n.get_string().len() as i32 + 1).sum::<i32>();
                nlists.len() as i32 * first.get_size() + strings
            }
        }
    }
}

impl StructConverter for NList {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl fmt::Display for NList {
    /// Java: `toString()`, the name (Java prints `null` before `initString`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.string.as_deref().unwrap_or("null"))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::mach_header::test_support::Bytes;

    /// Appends one nlist entry to `b`.
    pub(crate) fn nlist(b: &mut Bytes, is32bit: bool, strx: u32, n_type: u8, sect: u8, desc: u16, value: u64) {
        b.u32(strx).u8(n_type).u8(sect).u16(desc);
        if is32bit {
            b.u32(value as u32);
        } else {
            b.u64(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::nlist;
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::fields;

    #[test]
    fn parses_64_bit_entry_and_flags() {
        let mut b = Bytes::new(true);
        nlist(&mut b, false, 4, 0x0f, 1, 0x0208, 0x1_0000_3f40);
        b.raw(b"\0\0\0\0_main\0");
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let mut n = NList::new(&mut r, false).unwrap();
        assert_eq!(r.get_pointer_index(), 16);
        n.init_string(&r, 16);
        assert_eq!(n.get_string(), "_main");
        assert_eq!(n.get_value(), 0x1_0000_3f40);
        assert!(n.is_external());
        assert!(!n.is_private_external());
        assert!(!n.is_symbolic_debugging());
        assert!(!n.is_type_undefined(), "n_sect != NO_SECT");
        assert!(n.is_thumb_symbol());
        assert_eq!(n.get_library_ordinal(), 2);
        assert_eq!(n.get_size(), 16);
        let s = n.to_structure().unwrap();
        assert_eq!(s.get_length(), 16);
        assert_eq!(fields(&s)[3], ("n_desc".to_string(), 6, 2));
    }

    #[test]
    fn parses_32_bit_big_endian_undefined_entry() {
        let mut b = Bytes::new(false);
        nlist(&mut b, true, 0, 0x01, 0, 0x0101, 0xffff_fff0);
        let mut n = NList::new(&mut BinaryReader::from_bytes(b.buf, false), true).unwrap();
        assert_eq!(n.get_value(), 0xffff_fff0, "unsigned");
        assert!(n.is_type_undefined());
        assert!(n.is_lazy_bind());
        assert_eq!(n.to_string(), "null");
        n.init_string(&BinaryReader::from_bytes(vec![], false), 0);
        assert_eq!(n.get_string(), "", "strx 0 means empty name");
        assert_eq!(n.to_structure().unwrap().get_length(), 12);
    }

    #[test]
    fn type_predicates() {
        let mk = |t: u8| {
            let mut b = Bytes::new(true);
            nlist(&mut b, true, 0, t, 0, 0, 0);
            NList::new(&mut BinaryReader::from_bytes(b.buf, true), true).unwrap()
        };
        assert!(mk(0x02).is_type_absolute());
        assert!(mk(0x0c).is_type_prebound_undefined());
        assert!(mk(0x0a).is_indirect());
        assert!(mk(0x20).is_symbolic_debugging());
        assert!(mk(0x10).is_private_external());
    }

    #[test]
    fn total_size_counts_strings() {
        let mut b = Bytes::new(true);
        nlist(&mut b, true, 1, 0, 0, 0, 0);
        nlist(&mut b, true, 4, 0, 0, 0, 0);
        b.raw(b"\0ab\0cde\0");
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let mut v = vec![NList::new(&mut r, true).unwrap(), NList::new(&mut r, true).unwrap()];
        for n in &mut v {
            n.init_string(&r, 24);
        }
        assert_eq!(NList::get_total_size(&v), 2 * 12 + 1 + 3 + 4);
        assert_eq!(NList::get_total_size(&[]), 0);
    }
}
