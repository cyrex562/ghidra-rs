//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldChainedStartsOffsets`.
//!
//! Represents a `dyld_chained_starts_offsets` structure. See
//! `include/mach-o/fixup-chains.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::dyld::dyld_chained_ptr::DyldChainType;
use crate::format::macho::struct_builder::{array_with_element_length, dword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::ibo32_data_type::IBO32DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `dyld_chained_starts_offsets`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldChainedStartsOffsets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldChainedStartsOffsets {
    pointer_format: i32,
    starts_count: i32,
    chain_starts: Vec<i32>,
}

impl DyldChainedStartsOffsets {
    /// Java: `DyldChainedStartsOffsets(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let pointer_format = reader.read_next_int()?;
        let starts_count = reader.read_next_int()?;
        let chain_starts = reader.read_next_int_array(starts_count.max(0) as usize)?;
        Ok(DyldChainedStartsOffsets { pointer_format, starts_count, chain_starts })
    }

    /// Java: `getPointerFormat()`.
    pub fn get_pointer_format(&self) -> DyldChainType {
        DyldChainType::lookup_chain_ptr(self.pointer_format)
    }

    /// Java: `getStartsCount()`.
    pub fn get_starts_count(&self) -> i32 {
        self.starts_count
    }

    /// Java: `getChainStartOffsets()`.
    pub fn get_chain_start_offsets(&self) -> &[i32] {
        &self.chain_starts
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_chained_starts_offset");
        s.add(dword(), "pointer_format", Some("DYLD_CHAINED_PTR_*"))?;
        s.add(dword(), "starts_count", Some("number of starts in array"))?;
        s.add(
            array_with_element_length(Box::new(IBO32DataType::new()), self.starts_count, 1)?,
            "chain_starts",
            Some("array chain start offsets"),
        )?;
        s.finish_structure()
    }
}

impl StructConverter for DyldChainedStartsOffsets {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_starts() {
        let mut b = Vec::new();
        for v in [5u32, 2, 0x10, 0x20] {
            b.extend(v.to_le_bytes());
        }
        let s = DyldChainedStartsOffsets::new(&mut BinaryReader::from_bytes(b, true)).unwrap();
        assert_eq!(s.get_pointer_format(), DyldChainType::lookup_chain_ptr(5));
        assert_eq!(s.get_chain_start_offsets(), [0x10, 0x20]);
        assert_eq!(s.to_structure().unwrap().get_length(), 16);
    }
}
