//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheAcceleratorInitializer`.
//!
//! Represents a `dyld_cache_accelerator_initializer` structure. See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheAcceleratorInitializer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldCacheAcceleratorInitializer {
    functions_offset: i32,
    image_index: i32,
}

impl DyldCacheAcceleratorInitializer {
    /// Java: `DyldCacheAcceleratorInitializer(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let functions_offset = reader.read_next_int()?;
        let image_index = reader.read_next_int()?;
        Ok(DyldCacheAcceleratorInitializer { functions_offset, image_index })
    }

    /// Java: `getFunctionsOffset()`.
    pub fn get_functions_offset(&self) -> i32 {
        self.functions_offset
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_accelerator_initializer");
        s.add(dword(), "functionsOffset", Some(""))?;
        s.add(dword(), "imageIndex", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheAcceleratorInitializer {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::fields;

    #[test]
    fn parses_in_order_and_lays_out_structure() {
        let mut b = Bytes::new(true);
        b.u32(1);
        b.u32(2);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let v = DyldCacheAcceleratorInitializer::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 8);
        assert_eq!(v.functions_offset, 1);
        assert_eq!(v.image_index, 2);
        let s = v.to_structure().unwrap();
        assert_eq!(s.get_length(), 8);
        assert_eq!(fields(&s)[0].0, "functionsOffset");
    }
}
