//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateHeader`.
//!
//! The `flavor`/`count` pair that precedes a thread state in a `thread_command`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadStateHeader {
    flavor: i32,
    count: i64,
}

impl ThreadStateHeader {
    /// Java: `ThreadStateHeader(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let flavor = reader.read_next_int()?;
        let count = reader.read_next_unsigned_int()? as i64;
        Ok(ThreadStateHeader { flavor, count })
    }

    /// Java: `getFlavor()`.
    pub fn get_flavor(&self) -> i32 {
        self.flavor
    }

    /// Java: `getCount()`, the state's size in 32-bit words.
    pub fn get_count(&self) -> i64 {
        self.count
    }

    /// Java: `toDataType()`, returning the concrete structure. Java does not set the `/MachO`
    /// category on this one; neither does this port.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("thread_state_hdr");
        s.dword("flavor")?.dword("count")?;
        Ok(s.into_structure())
    }
}

impl StructConverter for ThreadStateHeader {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_flavor_and_unsigned_count() {
        let mut b = 6u32.to_be_bytes().to_vec();
        b.extend(0xffff_fffeu32.to_be_bytes());
        let h = ThreadStateHeader::new(&mut BinaryReader::from_bytes(b, false)).unwrap();
        assert_eq!(h.get_flavor(), 6);
        assert_eq!(h.get_count(), 0xffff_fffe);
        let s = h.to_structure().unwrap();
        assert_eq!(s.get_length(), 8);
        assert_eq!(s.get_category_path().to_string(), "/");
    }
}
