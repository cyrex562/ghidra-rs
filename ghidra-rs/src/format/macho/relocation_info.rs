//! Port of `ghidra.app.util.bin.format.macho.RelocationInfo`.
//!
//! Represents a `relocation_info` / `scattered_relocation_info` structure. See
//! `EXTERNAL_HEADERS/mach-o/reloc.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

const R_SCATTERED_LE: i32 = 0x8000_0000u32 as i32;
const R_SCATTERED_BE: i32 = 0x0000_0001;

/// A Mach-O relocation entry.
///
/// Port of `ghidra.app.util.bin.format.macho.RelocationInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelocationInfo {
    r_scattered: i32,
    r_address: i32,
    r_value: i32,
    r_pcrel: i32,
    r_length: i32,
    r_extern: i32,
    r_type: i32,
}

impl RelocationInfo {
    /// Java: `RelocationInfo(BinaryReader)`. Reads the two 32-bit words and decodes them as a
    /// scattered or plain relocation according to the reader's endianness.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let i1 = reader.read_next_int()?;
        let i2 = reader.read_next_int()?;
        Ok(Self::decode(i1, i2, reader.is_big_endian()))
    }

    /// The decoding half of [`new`](Self::new), for already-read words.
    pub fn decode(i1: i32, i2: i32, big_endian: bool) -> Self {
        if big_endian && (i1 & R_SCATTERED_BE) != 0 {
            RelocationInfo {
                r_scattered: 1,
                r_pcrel: (i1 >> 1) & 0x1,
                r_length: (i1 >> 2) & 0x3,
                r_type: (i1 >> 4) & 0xf,
                r_address: (i1 >> 8) & 0xffffff,
                r_extern: 1,
                r_value: i2,
            }
        } else if (i1 & R_SCATTERED_LE) != 0 {
            RelocationInfo {
                r_scattered: 1,
                r_extern: 1,
                r_address: i1 & 0xffffff,
                r_type: (i1 >> 24) & 0xf,
                r_length: (i1 >> 28) & 0x3,
                r_pcrel: (i1 >> 30) & 0x1,
                r_value: i2,
            }
        } else {
            RelocationInfo {
                r_scattered: 0,
                r_address: i1,
                r_value: i2 & 0xffffff,
                r_pcrel: (i2 >> 24) & 0x1,
                r_length: (i2 >> 25) & 0x3,
                r_extern: (i2 >> 27) & 0x1,
                r_type: (i2 >> 28) & 0xf,
            }
        }
    }

    /// Java: `getAddress()`.
    pub fn get_address(&self) -> i32 {
        self.r_address
    }

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        self.r_value
    }

    /// Java: `isPcRelocated()`.
    pub fn is_pc_relocated(&self) -> bool {
        self.r_pcrel == 1
    }

    /// Java: `getLength()`.
    pub fn get_length(&self) -> i32 {
        self.r_length
    }

    /// Java: `isExternal()`.
    pub fn is_external(&self) -> bool {
        self.r_extern == 1
    }

    /// Java: `isScattered()`.
    pub fn is_scattered(&self) -> bool {
        self.r_scattered == 1
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> i32 {
        self.r_type
    }

    /// Java: `toValues()`. The leading 0 indicates a non-scattered relocation (Java always emits
    /// 0 here, even for scattered ones).
    pub fn to_values(&self) -> [i64; 7] {
        let u = |v: i32| (v as u32) as i64;
        [
            0,
            u(self.r_address),
            u(self.r_value),
            u(self.r_pcrel),
            u(self.r_length),
            u(self.r_extern),
            u(self.r_type),
        ]
    }

    fn length_string(&self) -> &'static str {
        match self.r_length {
            0 => " (1 byte)",
            1 => " (2 bytes)",
            2 => " (4 bytes)",
            3 => " (8 bytes)",
            _ => "",
        }
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let dword_len = 4;
        let mut s;
        if self.is_scattered() {
            s = MachStruct::new("scattered_relocation_info");
            let bits: Result<(), String> = (|| {
                s.insert_bit_field_at(0, dword_len, 0, dword(), 24, "r_address", "")?;
                s.insert_bit_field_at(0, dword_len, 24, dword(), 4, "r_type", "")?;
                s.insert_bit_field_at(0, dword_len, 28, dword(), 2, "r_length", "")?;
                s.insert_bit_field_at(0, dword_len, 30, dword(), 1, "r_pcrel", "")?;
                s.insert_bit_field_at(0, dword_len, 31, dword(), 1, "r_scattered", "")
            })();
            if bits.is_err() {
                s.add(dword(), "r_mask", Some("{r_address,r_type,r_length,r_pcrel,r_scattered}"))?;
            }
            s.dword("r_value")?;
        } else {
            s = MachStruct::new("relocation_info");
            s.dword("r_address")?;
            let bits: Result<(), String> = (|| {
                s.insert_bit_field_at(4, dword_len, 0, dword(), 24, "r_symbolnum", "")?;
                s.insert_bit_field_at(4, dword_len, 24, dword(), 1, "r_pcrel", "")?;
                s.insert_bit_field_at(4, dword_len, 25, dword(), 2, "r_length", "")?;
                s.insert_bit_field_at(4, dword_len, 27, dword(), 1, "r_extern", "")?;
                s.insert_bit_field_at(4, dword_len, 28, dword(), 4, "r_type", "")
            })();
            if bits.is_err() {
                s.add(dword(), "r_mask", Some("{r_symbolnum,r_pcrel,r_length,r_extern,r_type}"))?;
            }
        }
        s.finish_structure()
    }
}

impl fmt::Display for RelocationInfo {
    /// Java: `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Address:      {:x}", self.r_address as i64)?;
        writeln!(f, "Value:        {:x}", self.r_value)?;
        writeln!(f, "Scattered:    {}", self.is_scattered())?;
        writeln!(f, "PC Relocated: {}", self.is_pc_relocated())?;
        writeln!(f, "Length:       {:x}{}", self.r_length, self.length_string())?;
        writeln!(f, "External:     {}", self.is_external())?;
        writeln!(f, "Type:         {:x}", self.r_type)
    }
}

impl StructConverter for RelocationInfo {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::struct_builder::test_support::names;

    fn reader(i1: u32, i2: u32, little: bool) -> BinaryReader {
        let mut b = Vec::new();
        if little {
            b.extend_from_slice(&i1.to_le_bytes());
            b.extend_from_slice(&i2.to_le_bytes());
        } else {
            b.extend_from_slice(&i1.to_be_bytes());
            b.extend_from_slice(&i2.to_be_bytes());
        }
        BinaryReader::from_bytes(b, little)
    }

    #[test]
    fn plain_relocation_decodes_second_word_bitfields() {
        // r_symbolnum=0x123456, pcrel=1, length=2, extern=1, type=5
        let i2 = 0x123456 | (1 << 24) | (2 << 25) | (1 << 27) | (5 << 28);
        let r = RelocationInfo::new(&mut reader(0x1000, i2, true)).unwrap();
        assert!(!r.is_scattered());
        assert_eq!(r.get_address(), 0x1000);
        assert_eq!(r.get_value(), 0x123456);
        assert!(r.is_pc_relocated());
        assert_eq!(r.get_length(), 2);
        assert!(r.is_external());
        assert_eq!(r.get_type(), 5);
        assert_eq!(r.to_values(), [0, 0x1000, 0x123456, 1, 2, 1, 5]);
    }

    #[test]
    fn little_endian_scattered_relocation() {
        // scattered bit | pcrel(30) | length 3 (28) | type 0xa (24) | address 0xabcdef
        let i1 = 0x8000_0000 | (1 << 30) | (3 << 28) | (0xa << 24) | 0xabcdef;
        let r = RelocationInfo::new(&mut reader(i1, 0xdead_beef, true)).unwrap();
        assert!(r.is_scattered());
        assert!(r.is_external());
        assert_eq!(r.get_address(), 0xabcdef);
        assert_eq!(r.get_type(), 0xa);
        assert_eq!(r.get_length(), 3);
        assert!(r.is_pc_relocated());
        assert_eq!(r.get_value(), 0xdead_beefu32 as i32);
    }

    #[test]
    fn big_endian_scattered_relocation_uses_low_bit() {
        // low scattered bit | pcrel (1) | length 1 (2) | type 3 (4) | address 0x42 (8)
        let i1 = 1 | (1 << 1) | (1 << 2) | (3 << 4) | (0x42 << 8);
        let r = RelocationInfo::new(&mut reader(i1, 7, false)).unwrap();
        assert!(r.is_scattered());
        assert!(r.is_pc_relocated());
        assert_eq!(r.get_length(), 1);
        assert_eq!(r.get_type(), 3);
        assert_eq!(r.get_address(), 0x42);
        assert_eq!(r.get_value(), 7);
    }

    #[test]
    fn little_endian_low_bit_is_not_scattered() {
        let r = RelocationInfo::new(&mut reader(1, 0, true)).unwrap();
        assert!(!r.is_scattered());
        assert_eq!(r.get_address(), 1);
    }

    #[test]
    fn display_matches_java_to_string() {
        let r = RelocationInfo::decode(0x10, 0x5 | (2 << 25), false);
        assert_eq!(
            r.to_string(),
            "Address:      10\nValue:        5\nScattered:    false\nPC Relocated: false\n\
             Length:       2 (4 bytes)\nExternal:     false\nType:         0\n"
        );
    }

    #[test]
    fn data_types_match_java_layouts() {
        let plain = RelocationInfo::decode(0, 0, true).to_structure().unwrap();
        assert_eq!(plain.get_name(), "relocation_info");
        assert_eq!(plain.get_length(), 8);
        assert_eq!(
            names(&plain),
            ["r_address", "r_symbolnum", "r_pcrel", "r_length", "r_extern", "r_type"]
        );
        let scattered = RelocationInfo::decode(0x8000_0000u32 as i32, 0, true).to_structure().unwrap();
        assert_eq!(scattered.get_name(), "scattered_relocation_info");
        assert_eq!(scattered.get_length(), 8);
        assert_eq!(
            names(&scattered),
            ["r_address", "r_type", "r_length", "r_pcrel", "r_scattered", "r_value"]
        );
    }
}
