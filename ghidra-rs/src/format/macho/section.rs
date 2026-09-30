//! Port of `ghidra.app.util.bin.format.macho.Section`.
//!
//! Represents a `section` / `section_64` structure. See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.
//!
//! Java's `Section` keeps the `BinaryReader` it was parsed from, solely so that
//! `getDataStream(MachHeader)` can reach the underlying `ByteProvider`. Every `Section` is parsed
//! (via `SegmentCommand`) from its owning [`MachHeader`]'s own reader, so this port keeps no reader
//! and [`Section::get_data_stream`] takes the provider from the header instead. That keeps
//! `Section` a plain, `Send + Sync` value type.

use std::fmt;
use std::io::{self, Read};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::segment_names;
use crate::format::macho::mach_constants::NAME_LENGTH;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::mach_header_file_types::MH_EXECUTE;
use crate::format::macho::relocation_info::RelocationInfo;
use crate::format::macho::section_attributes::{
    get_attribute_names, SECTION_ATTRIBUTES_MASK, S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS,
};
use crate::format::macho::section_names;
use crate::format::macho::section_types::{get_type_name, SECTION_TYPE_MASK, S_ZEROFILL};
use crate::format::macho::struct_builder::{fixed_string, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `section` (32-bit) or `section_64` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.Section`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    sectname: String,
    segname: String,
    addr: i64,
    size: i64,
    offset: i32,
    align: i32,
    reloff: i32,
    nrelocs: i32,
    flags: i32,
    reserved1: i32,
    reserved2: i32,
    reserved3: i32,
    is32bit: bool,
    relocations: Vec<RelocationInfo>,
}

impl Section {
    /// Java: `Section(BinaryReader, boolean)`. Reads the section header at the reader's position,
    /// then its `nrelocs` relocation entries from `reloff`, restoring the reader's position
    /// afterwards.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        let sectname = reader.read_next_ascii_string_fixed(NAME_LENGTH)?;
        let segname = reader.read_next_ascii_string_fixed(NAME_LENGTH)?;
        let (addr, size) = if is32bit {
            (reader.read_next_unsigned_int()? as i64, reader.read_next_unsigned_int()? as i64)
        } else {
            (reader.read_next_long()?, reader.read_next_long()?)
        };
        let offset = reader.read_next_int()?;
        let align = reader.read_next_int()?;
        let reloff = reader.read_next_int()?;
        let nrelocs = reader.read_next_int()?;
        let flags = reader.read_next_int()?;
        let reserved1 = reader.read_next_int()?;
        let reserved2 = reader.read_next_int()?;
        let reserved3 = if is32bit { 0 } else { reader.read_next_int()? };

        let index = reader.get_pointer_index();
        // Java: reader.setPointerIndex(reloff) -- an int, sign-extended to long.
        reader.set_pointer_index(reloff as i64 as u64);
        let mut relocations = Vec::new();
        let mut result = Ok(());
        for _ in 0..nrelocs.max(0) {
            match RelocationInfo::new(reader) {
                Ok(r) => relocations.push(r),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        reader.set_pointer_index(index);
        result?;

        Ok(Section {
            sectname,
            segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nrelocs,
            flags,
            reserved1,
            reserved2,
            reserved3,
            is32bit,
            relocations,
        })
    }

    /// Java: `getRelocations()`.
    pub fn get_relocations(&self) -> &[RelocationInfo] {
        &self.relocations
    }

    /// Java: `isRead()`. All sections appear to be readable.
    pub fn is_read(&self) -> bool {
        true
    }

    /// Java: `isWrite()`.
    pub fn is_write(&self) -> bool {
        if self.sectname.starts_with(section_names::SECT_GOT) {
            // Assume the GOT section is read_only. This is not true, but it helps with analysis.
            return true;
        }
        segment_names::TEXT != self.segname
            && segment_names::TEXT_EXEC != self.segname
            && segment_names::PRELINK_TEXT != self.segname
            && section_names::DATA_CONST != self.sectname
    }

    /// Java: `isExecute()`.
    pub fn is_execute(&self) -> bool {
        if section_names::TEXT == self.sectname || segment_names::TEXT_EXEC == self.segname {
            return true;
        }
        let attrs = self.get_attributes() as u32;
        (attrs & S_ATTR_PURE_INSTRUCTIONS) != 0 || (attrs & S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// Java: `getDataStream(MachHeader)`. A stream over this section's bytes: `size` zero bytes
    /// for a zero-fill section, `size` `0xf4` bytes for an executable's `__jump_table`, otherwise
    /// the provider's bytes starting at `header.getStartIndex() + offset`.
    pub fn get_data_stream(&self, header: &MachHeader) -> io::Result<Box<dyn Read>> {
        if self.get_type() as u32 == S_ZEROFILL {
            return Ok(Box::new(io::repeat(0).take(self.size as u64)));
        }
        if self.sectname == section_names::IMPORT_JUMP_TABLE
            && header.get_file_type() as u32 == MH_EXECUTE
        {
            return Ok(Box::new(io::repeat(0xf4).take(self.size as u64)));
        }
        let start = (header.get_start_index() as i64).wrapping_add(self.offset as i64);
        header.get_byte_provider().get_input_stream(start as u64)
    }

    /// Java: `getSectionName()`.
    pub fn get_section_name(&self) -> &str {
        &self.sectname
    }

    /// Java: `setSectionName(String)`.
    pub fn set_section_name(&mut self, name: impl Into<String>) {
        self.sectname = name.into();
    }

    /// Java: `getSegmentName()`.
    pub fn get_segment_name(&self) -> &str {
        &self.segname
    }

    /// Java: `setSegmentName(String)`.
    pub fn set_segment_name(&mut self, name: impl Into<String>) {
        self.segname = name.into();
    }

    /// Java: `getAddress()`. Masks off a possible chained fixup found in kernelcache section
    /// addresses.
    pub fn get_address(&self) -> i64 {
        if (self.addr & 0xfff0_0000_0000) == 0xfff0_0000_0000 {
            return self.addr | 0xffff_0000_0000_0000u64 as i64;
        }
        self.addr
    }

    /// Java: `getSize()`.
    pub fn get_size(&self) -> i64 {
        self.size
    }

    /// Java: `getOffset()`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Java: `getAlign()`.
    pub fn get_align(&self) -> i32 {
        self.align
    }

    /// Java: `getRelocationOffset()`.
    pub fn get_relocation_offset(&self) -> i32 {
        self.reloff
    }

    /// Java: `getNumberOfRelocations()`.
    pub fn get_number_of_relocations(&self) -> i32 {
        self.nrelocs
    }

    /// Java: `getFlags()`.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> i32 {
        self.flags & SECTION_TYPE_MASK as i32
    }

    /// Java: `getAttributes()`.
    pub fn get_attributes(&self) -> i32 {
        self.flags & SECTION_ATTRIBUTES_MASK as i32
    }

    /// Java: `getReserved1()`.
    pub fn get_reserved1(&self) -> i32 {
        self.reserved1
    }

    /// Java: `getReserved2()`.
    pub fn get_reserved2(&self) -> i32 {
        self.reserved2
    }

    /// Java: `getReserved3()`.
    pub fn get_reserved3(&self) -> i32 {
        self.reserved3
    }

    /// Java: `contains(long)`, an unsigned comparison against the raw (unmasked) address.
    pub fn contains(&self, address: i64) -> bool {
        (address as u64) >= (self.addr as u64)
            && (address as u64) < (self.addr.wrapping_add(self.size) as u64)
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("section");
        s.add_len(fixed_string()?, NAME_LENGTH as i32, "sectname", None)?;
        s.add_len(fixed_string()?, NAME_LENGTH as i32, "segname", None)?;
        if self.is32bit {
            s.dword("addr")?.dword("size")?;
        } else {
            s.qword("addr")?.qword("size")?;
        }
        s.dword("offset")?
            .dword("align")?
            .dword("reloff")?
            .dword("nrelocs")?
            .dword("flags")?
            .dword("reserved1")?
            .dword("reserved2")?;
        if !self.is32bit {
            s.dword("reserved3")?;
        }
        s.finish_structure()
    }
}

impl StructConverter for Section {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl fmt::Display for Section {
    /// Java: `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "      Name: {}", self.sectname)?;
        writeln!(f, "   Address: 0x{:x}", self.addr)?;
        writeln!(f, "    Length: 0x{:x}", self.size)?;
        writeln!(
            f,
            "      Type: 0x{:x} ({})",
            self.get_type(),
            get_type_name(self.get_type() as u32)
        )?;
        writeln!(f, "    Offset: 0x{:x}", self.offset as i64)?;
        writeln!(f, "Attributes: {:x}", self.get_attributes())?;
        for attr in get_attribute_names(self.get_attributes() as u32) {
            writeln!(f, "            {attr}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Builders for synthetic `section`/`section_64` bytes.

    /// Encodes a section header. `name`/`seg` are NUL-padded to 16 bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn section_bytes(
        is32bit: bool,
        little: bool,
        name: &str,
        seg: &str,
        addr: u64,
        size: u64,
        offset: u32,
        reloff: u32,
        nrelocs: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        let pad = |s: &str| {
            let mut v = s.as_bytes().to_vec();
            v.resize(16, 0);
            v
        };
        let u32b = |v: u32| if little { v.to_le_bytes() } else { v.to_be_bytes() };
        let u64b = |v: u64| if little { v.to_le_bytes() } else { v.to_be_bytes() };
        b.extend(pad(name));
        b.extend(pad(seg));
        if is32bit {
            b.extend(u32b(addr as u32));
            b.extend(u32b(size as u32));
        } else {
            b.extend(u64b(addr));
            b.extend(u64b(size));
        }
        for v in [offset, 2, reloff, nrelocs, flags, 0x11, 0x22] {
            b.extend(u32b(v));
        }
        if !is32bit {
            b.extend(u32b(0x33));
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::section_bytes;
    use super::*;
    use crate::format::macho::section_types::S_REGULAR;

    #[test]
    fn parses_64_bit_little_endian_section() {
        let bytes = section_bytes(
            false, true, "__text", "__TEXT", 0x1_0000_1000, 0x200, 0x1000, 0, 0,
            S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
        );
        let mut r = BinaryReader::from_bytes(bytes, true);
        let s = Section::new(&mut r, false).unwrap();
        assert_eq!(r.get_pointer_index(), 80);
        assert_eq!(s.get_section_name(), "__text");
        assert_eq!(s.get_segment_name(), "__TEXT");
        assert_eq!(s.get_address(), 0x1_0000_1000);
        assert_eq!(s.get_size(), 0x200);
        assert_eq!(s.get_offset(), 0x1000);
        assert_eq!(s.get_align(), 2);
        assert_eq!(s.get_type() as u32, S_REGULAR);
        assert_eq!(s.get_attributes() as u32, S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS);
        assert_eq!(s.get_reserved1(), 0x11);
        assert_eq!(s.get_reserved2(), 0x22);
        assert_eq!(s.get_reserved3(), 0x33);
        assert!(s.is_execute());
        assert!(!s.is_write());
        assert!(s.is_read());
    }

    #[test]
    fn parses_32_bit_big_endian_section_with_relocations() {
        let mut bytes = section_bytes(true, false, "__data", "__DATA", 0x2000, 0x10, 0x100, 68, 2, 0);
        assert_eq!(bytes.len(), 68);
        for (a, b) in [(0x10u32, 0x0800_0003u32), (0x14, 0x0800_0004)] {
            bytes.extend(a.to_be_bytes());
            bytes.extend(b.to_be_bytes());
        }
        let mut r = BinaryReader::from_bytes(bytes, false);
        let s = Section::new(&mut r, true).unwrap();
        assert_eq!(r.get_pointer_index(), 68, "reader restored after reading relocations");
        assert_eq!(s.get_address(), 0x2000);
        assert_eq!(s.get_reserved3(), 0);
        assert_eq!(s.get_number_of_relocations(), 2);
        assert_eq!(s.get_relocations()[0].get_address(), 0x10);
        assert_eq!(s.get_relocations()[1].get_value(), 4);
        assert!(s.get_relocations()[1].is_external());
        assert!(s.is_write());
        assert!(!s.is_execute());
    }

    #[test]
    fn write_and_execute_rules() {
        let mk = |sect: &str, seg: &str| {
            let b = section_bytes(false, true, sect, seg, 0, 0, 0, 0, 0, 0);
            Section::new(&mut BinaryReader::from_bytes(b, true), false).unwrap()
        };
        assert!(mk("__got", "__TEXT").is_write(), "GOT is always writable");
        assert!(!mk("__const", "__DATA").is_write(), "DATA_CONST name is read-only");
        assert!(!mk("__stubs", "__TEXT_EXEC").is_write());
        assert!(mk("__stubs", "__TEXT_EXEC").is_execute());
        assert!(!mk("__init", "__PRELINK_TEXT").is_write());
    }

    #[test]
    fn kernelcache_address_is_sign_extended() {
        let b = section_bytes(false, true, "__text", "__TEXT", 0xfff0_0000_1000, 0x10, 0, 0, 0, 0);
        let s = Section::new(&mut BinaryReader::from_bytes(b, true), false).unwrap();
        assert_eq!(s.get_address() as u64, 0xffff_fff0_0000_1000);
        assert!(s.contains(0xfff0_0000_1008));
        assert!(!s.contains(0xfff0_0000_1010));
    }

    #[test]
    fn display_matches_java_to_string() {
        let b = section_bytes(
            false, true, "__text", "__TEXT", 0x1000, 0x20, 0x400, 0, 0,
            S_ATTR_PURE_INSTRUCTIONS,
        );
        let s = Section::new(&mut BinaryReader::from_bytes(b, true), false).unwrap();
        assert_eq!(
            s.to_string(),
            "      Name: __text\n   Address: 0x1000\n    Length: 0x20\n      Type: 0x0 (REGULAR)\n    \
             Offset: 0x400\nAttributes: 80000000\n            PURE_INSTRUCTIONS\n"
        );
    }
}
