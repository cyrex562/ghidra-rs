//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageInfoExtra`.
//!
//! Represents a `dyld_cache_image_info_extra` structure. See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageInfoExtra`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldCacheImageInfoExtra {
    exports_trie_addr: i64,
    weak_bindings_addr: i64,
    exports_trie_size: i32,
    weak_bindings_size: i32,
    dependents_start_array_index: i32,
    re_exports_start_array_index: i32,
}

impl DyldCacheImageInfoExtra {
    /// Java: `DyldCacheImageInfoExtra(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let exports_trie_addr = reader.read_next_long()?;
        let weak_bindings_addr = reader.read_next_long()?;
        let exports_trie_size = reader.read_next_int()?;
        let weak_bindings_size = reader.read_next_int()?;
        let dependents_start_array_index = reader.read_next_int()?;
        let re_exports_start_array_index = reader.read_next_int()?;
        Ok(DyldCacheImageInfoExtra { exports_trie_addr, weak_bindings_addr, exports_trie_size, weak_bindings_size, dependents_start_array_index, re_exports_start_array_index })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_image_info_extra");
        s.add(qword(), "exportsTrieAddr", Some(""))?;
        s.add(qword(), "weakBindingsAddr", Some(""))?;
        s.add(dword(), "exportsTrieSize", Some(""))?;
        s.add(dword(), "weakBindingsSize", Some(""))?;
        s.add(dword(), "dependentsStartArrayIndex", Some(""))?;
        s.add(dword(), "reExportsStartArrayIndex", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheImageInfoExtra {
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
        b.u64(1);
        b.u64(2);
        b.u32(3);
        b.u32(4);
        b.u32(5);
        b.u32(6);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let v = DyldCacheImageInfoExtra::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 32);
        assert_eq!(v.exports_trie_addr, 1);
        assert_eq!(v.re_exports_start_array_index, 6);
        let s = v.to_structure().unwrap();
        assert_eq!(s.get_length(), 32);
        assert_eq!(fields(&s)[0].0, "exportsTrieAddr");
    }
}
