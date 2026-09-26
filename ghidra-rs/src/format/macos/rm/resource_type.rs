//! Port of `ghidra.app.util.bin.format.macos.rm.ResourceType`.
//!
//! Not to be confused with the unrelated NE-format
//! [`ResourceType`](crate::format::ne::resource_type::ResourceType).

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::cfm::c_frag_resource::CFragResource;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::format::macos::rm::reference_list_entry::ReferenceListEntry;
use crate::format::macos::rm::resource_header::ResourceHeader;
use crate::format::macos::rm::resource_map::ResourceMap;
use crate::format::macos::rm::resource_type_factory;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// One entry of a resource map's type list: a four-character resource type, the resources of
/// that type, and (for types this crate understands) the parsed resource object.
///
/// Port of `ghidra.app.util.bin.format.macos.rm.ResourceType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceType {
    type_: i32,
    type_bytes: Vec<u8>,
    /// Number of resources of this type in the map, minus 1.
    number_of_resources: i16,
    offset_to_reference_list: i16,
    reference_list: Vec<ReferenceListEntry>,
    resource_object: Option<CFragResource>,
}

impl ResourceType {
    /// Reads an 8-byte type-list entry, then the type's reference list (located through `map`),
    /// then the resource object via [`resource_type_factory::get_resource_object`]. The reader is
    /// left just past the 8-byte entry.
    ///
    /// Port of the package-private `ResourceType(BinaryReader, ResourceHeader, ResourceMap, long)`
    /// constructor. Its trailing `resourceTypeListStartIndex` argument is unused in Java too, so
    /// it is not taken here.
    pub fn new(
        reader: &mut dyn BinaryReader,
        header: &ResourceHeader,
        map: &ResourceMap,
    ) -> io::Result<Self> {
        let type_ = reader.peek_next_int()?;
        let type_bytes = reader.read_next_byte_array(4)?;
        let number_of_resources = reader.read_next_short()?;
        let offset_to_reference_list = reader.read_next_short()?;

        let mut resource_type = Self {
            type_,
            type_bytes,
            number_of_resources,
            offset_to_reference_list,
            reference_list: Vec::new(),
            resource_object: None,
        };
        resource_type.reference_list = resource_type.parse_reference_list(reader, map)?;
        resource_type.resource_object =
            resource_type_factory::get_resource_object(reader, header, &resource_type)?;
        Ok(resource_type)
    }

    /// Port of the private `parseReferenceList(BinaryReader, ResourceMap)`: reads
    /// `numberOfResources + 1` entries from the reference list, restoring the reader afterwards.
    fn parse_reference_list(
        &self,
        reader: &mut dyn BinaryReader,
        map: &ResourceMap,
    ) -> io::Result<Vec<ReferenceListEntry>> {
        let start = map.get_map_start_index() as i64
            + i64::from(map.get_resource_type_list_offset())
            + i64::from(self.offset_to_reference_list);

        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(start as u64);
        let count = i32::from(self.number_of_resources) + 1;
        let result = (0..count.max(0))
            .map(|_| ReferenceListEntry::new(reader, map))
            .collect::<io::Result<Vec<_>>>();
        reader.set_pointer_index(old_index);
        result
    }

    /// Returns the parsed resource object, if this resource type is one this crate understands.
    ///
    /// Port of `getResourceObject()`. Java types it as `Object`; the only object
    /// `ResourceTypeFactory` ever builds is a [`CFragResource`] (for `'cfrg'`).
    pub fn get_resource_object(&self) -> Option<&CFragResource> {
        self.resource_object.as_ref()
    }

    /// Returns the resource type.
    pub fn get_type(&self) -> i32 {
        self.type_
    }

    /// Returns the resource type as its four characters when they are all printable ASCII,
    /// otherwise as `0x` followed by lower-case hex digits.
    ///
    /// Port of `getTypeAsString()`.
    pub fn get_type_as_string(&self) -> String {
        if self.is_ascii() {
            return self.type_bytes.iter().map(|&b| char::from(b)).collect();
        }
        format!("0x{:x}", self.type_ as u32)
    }

    /// Returns the number of resources of this type in map minus 1.
    pub fn get_number_of_resources(&self) -> i16 {
        self.number_of_resources
    }

    /// Returns the offset from the beginning of the resource type list to reference list for this
    /// type.
    pub fn get_offset_to_reference_list(&self) -> i16 {
        self.offset_to_reference_list
    }

    /// Returns this type's reference list.
    pub fn get_reference_list(&self) -> &[ReferenceListEntry] {
        &self.reference_list
    }

    /// Port of the private `isAscii()`: every type byte is in `' '..=126`. (Java's signed `byte`
    /// makes bytes >= 0x80 negative, so they fail the `< ' '` test.)
    fn is_ascii(&self) -> bool {
        self.type_bytes.iter().all(|&b| (b' '..=126).contains(&b))
    }
}

impl StructConverter for ResourceType {
    /// Port of `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("ResourceType", 0);
        if self.is_ascii() {
            s.add_with_length_and_name(PrimitiveDt::STRING.boxed(), 4, Some("type".to_string()), None)?;
        } else {
            s.add_with_name(PrimitiveDt::DWORD.boxed(), Some("type".to_string()), None)?;
        }
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("numberOfResources".to_string()), None)?;
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("offsetToReferenceList".to_string()), None)?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_type(bytes: [u8; 4]) -> ResourceType {
        ResourceType {
            type_: i32::from_be_bytes(bytes),
            type_bytes: bytes.to_vec(),
            number_of_resources: 0,
            offset_to_reference_list: 0,
            reference_list: Vec::new(),
            resource_object: None,
        }
    }

    #[test]
    fn printable_type_renders_as_characters() {
        assert_eq!(with_type(*b"cfrg").get_type_as_string(), "cfrg");
        assert_eq!(with_type(*b"STR ").get_type_as_string(), "STR ");
    }

    #[test]
    fn non_printable_type_renders_as_unpadded_hex() {
        assert_eq!(with_type([0x00, 0x00, 0x12, 0x34]).get_type_as_string(), "0x1234");
        assert_eq!(with_type([0x80, 0x41, 0x42, 0x43]).get_type_as_string(), "0x80414243");
        assert_eq!(with_type([b'a', b'b', b'c', 0x7f]).get_type_as_string(), "0x6162637f");
    }

    #[test]
    fn to_data_type_uses_string_for_ascii_types() {
        let ascii = with_type(*b"cfrg").to_data_type().unwrap();
        assert_eq!(ascii.get_name(), "ResourceType");
        assert_eq!(ascii.get_length(), 8);

        let binary = with_type([0, 0, 0, 1]).to_data_type().unwrap();
        assert_eq!(binary.get_length(), 8);
    }
}
