//! Port of `ghidra.app.util.bin.format.macos.rm.ReferenceListEntry`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::format::macos::rm::resource_map::ResourceMap;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// One entry of a resource type's reference list: a single resource's ID, name, attributes and
/// the location of its data.
///
/// Port of `ghidra.app.util.bin.format.macos.rm.ReferenceListEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceListEntry {
    id: i16,
    name_offset: i16,
    attributes: i8,
    data_offset: i32,
    handle: i32,
    name: Option<String>,
}

impl ReferenceListEntry {
    /// Reads a 12-byte reference list entry and resolves its name through `map`'s name list.
    ///
    /// Port of the package-private `ReferenceListEntry(BinaryReader, ResourceMap)` constructor.
    pub fn new(reader: &mut dyn BinaryReader, map: &ResourceMap) -> io::Result<Self> {
        let id = reader.read_next_short()?;
        let name_offset = reader.read_next_short()?;
        let attributes = reader.read_next_byte()? as i8;
        let data_offset = read_3_byte_value(reader)?;
        let handle = reader.read_next_int()?;
        let name = map.get_string_at(name_offset).map(str::to_string);
        Ok(Self { id, name_offset, attributes, data_offset, handle, name })
    }

    /// Returns the resource ID.
    pub fn get_id(&self) -> i16 {
        self.id
    }

    /// Returns the resource's name, or `None` when it has none (a name offset of -1) or the offset
    /// does not match a name-list entry.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the offset from the beginning of the resource name list to the resource name.
    pub fn get_name_offset(&self) -> i16 {
        self.name_offset
    }

    /// Returns the resource attributes.
    pub fn get_attributes(&self) -> i8 {
        self.attributes
    }

    /// Returns the offset from the beginning of the resource data to the data for this resource.
    pub fn get_data_offset(&self) -> i32 {
        self.data_offset
    }

    /// Returns the resource handle. This field is reserved.
    pub fn get_handle(&self) -> i32 {
        self.handle
    }
}

/// Reads an unsigned 24-bit value in the reader's byte order.
///
/// Port of the private `read3ByteValue(BinaryReader)`.
fn read_3_byte_value(reader: &mut dyn BinaryReader) -> io::Result<i32> {
    let value1 = i32::from(reader.read_next_byte()?);
    let value2 = i32::from(reader.read_next_byte()?);
    let value3 = i32::from(reader.read_next_byte()?);
    if reader.is_little_endian() {
        return Ok((value3 << 16) | (value2 << 8) | value1);
    }
    Ok((value1 << 16) | (value2 << 8) | value3)
}

impl StructConverter for ReferenceListEntry {
    /// Port of `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("ReferenceListEntry", 0);
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("id".to_string()), None)?;
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("nameOffset".to_string()), None)?;
        s.add_with_name(PrimitiveDt::BYTE.boxed(), Some("attributes".to_string()), None)?;
        s.add_with_name(PrimitiveDt::UINT3.boxed(), Some("dataOffset".to_string()), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), Some("handle".to_string()), None)?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;

    #[test]
    fn three_byte_value_honours_byte_order() {
        let mut be = VecReader::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(read_3_byte_value(&mut be).unwrap(), 0x010203);
        let mut le = VecReader::little_endian(vec![0x01, 0x02, 0x03]);
        assert_eq!(read_3_byte_value(&mut le).unwrap(), 0x030201);
        let mut high = VecReader::new(vec![0xff, 0xfe, 0xfd]);
        assert_eq!(read_3_byte_value(&mut high).unwrap(), 0x00fffefd);
    }

    #[test]
    fn to_data_type_is_twelve_bytes() {
        let e = ReferenceListEntry {
            id: 0,
            name_offset: -1,
            attributes: 0,
            data_offset: 0,
            handle: 0,
            name: None,
        };
        let dt = e.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ReferenceListEntry");
        assert_eq!(dt.get_length(), 12);
    }
}
