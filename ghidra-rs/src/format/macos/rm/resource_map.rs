//! Port of `ghidra.app.util.bin.format.macos.rm.ResourceMap`.

use std::collections::HashMap;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::asd::entry::Entry;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::format::macos::rm::reference_list_entry::ReferenceListEntry;
use crate::format::macos::rm::resource_header::ResourceHeader;
use crate::format::macos::rm::resource_type::ResourceType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The resource map of a resource fork: a copy of the fork header, the resource type list, and
/// the resource name list.
///
/// Port of `ghidra.app.util.bin.format.macos.rm.ResourceMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMap {
    copy: ResourceHeader,
    handle_to_next_resource_map: i32,
    file_reference_number: i16,
    resource_fork_attributes: i16,
    /// From the beginning of the map.
    resource_type_list_offset: i16,
    /// From the beginning of the map.
    resource_name_list_offset: i16,
    /// Number of types, minus 1.
    number_of_types: i16,

    map_start_index: u64,
    resource_type_list: Vec<ResourceType>,
    reference_entry_list: Vec<ReferenceListEntry>,
    resource_name_map: HashMap<i16, String>,
}

impl ResourceMap {
    /// Reads the resource map starting at the reader's current position, then its name list and
    /// type list. The reader is left just past the map's fixed 30-byte header.
    ///
    /// Port of the package-private `ResourceMap(BinaryReader, ResourceHeader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader, header: &ResourceHeader) -> io::Result<Self> {
        let map_start_index = reader.get_pointer_index();

        let copy =
            ResourceHeader::read(reader, header.get_entry_descriptor().clone(), true)?;

        let handle_to_next_resource_map = reader.read_next_int()?;
        let file_reference_number = reader.read_next_short()?;
        let resource_fork_attributes = reader.read_next_short()?;
        let resource_type_list_offset = reader.read_next_short()?;
        let resource_name_list_offset = reader.read_next_short()?;
        let number_of_types = reader.read_next_short()?;

        let mut map = Self {
            copy,
            handle_to_next_resource_map,
            file_reference_number,
            resource_fork_attributes,
            resource_type_list_offset,
            resource_name_list_offset,
            number_of_types,
            map_start_index,
            resource_type_list: Vec::new(),
            reference_entry_list: Vec::new(),
            resource_name_map: HashMap::new(),
        };

        let old_index = reader.get_pointer_index();
        let parsed = map.parse_resource_name_list(reader).and_then(|names| {
            map.resource_name_map = names;
            map.parse_resource_type_list(reader, header)
        });
        reader.set_pointer_index(old_index);
        map.resource_type_list = parsed?;
        Ok(map)
    }

    /// Port of the private `parseResourceTypeList(BinaryReader, ResourceHeader)`: reads
    /// `numberOfTypes + 1` type entries starting two bytes past the type list offset (the list is
    /// prefixed by its own count).
    fn parse_resource_type_list(
        &self,
        reader: &mut dyn BinaryReader,
        header: &ResourceHeader,
    ) -> io::Result<Vec<ResourceType>> {
        let start = self.map_start_index as i64 + i64::from(self.resource_type_list_offset) + 2;
        reader.set_pointer_index(start as u64);
        let count = i32::from(self.number_of_types) + 1;
        (0..count.max(0)).map(|_| ResourceType::new(reader, header, self)).collect()
    }

    /// Port of the private `parseResourceNameList(BinaryReader)`: reads length-prefixed ASCII
    /// names until the end of the input, keyed by their offset from the start of the name list.
    fn parse_resource_name_list(
        &self,
        reader: &mut dyn BinaryReader,
    ) -> io::Result<HashMap<i16, String>> {
        let start = self.map_start_index as i64 + i64::from(self.resource_name_list_offset);
        reader.set_pointer_index(start as u64);
        let mut names = HashMap::new();
        while reader.has_next() {
            let offset = reader.get_pointer_index() as i64;
            let length = usize::from(reader.read_next_byte()?);
            let name = reader.read_next_ascii_string_fixed(length)?;
            // Java: `(short)(offset - start)`.
            names.insert((offset - start) as i16, name);
        }
        Ok(names)
    }

    /// Returns the copy of the resource fork header stored at the start of the map (read without
    /// its own map).
    pub fn get_copy(&self) -> &ResourceHeader {
        &self.copy
    }

    /// Returns the (reserved) handle to the next resource map.
    pub fn get_handle_to_next_resource_map(&self) -> i32 {
        self.handle_to_next_resource_map
    }

    /// Returns the (reserved) file reference number.
    pub fn get_file_reference_number(&self) -> i16 {
        self.file_reference_number
    }

    /// Returns the resource fork attributes.
    pub fn get_resource_fork_attributes(&self) -> i16 {
        self.resource_fork_attributes
    }

    /// Returns the offset from the beginning of the map to the resource type list.
    pub fn get_resource_type_list_offset(&self) -> i16 {
        self.resource_type_list_offset
    }

    /// Returns the offset from the beginning of the map to the resource name list.
    pub fn get_resource_name_list_offset(&self) -> i16 {
        self.resource_name_list_offset
    }

    /// Returns the number of resource types in the map, minus 1.
    pub fn get_number_of_types(&self) -> i16 {
        self.number_of_types
    }

    /// Returns the parsed resource types.
    pub fn get_resource_type_list(&self) -> &[ResourceType] {
        &self.resource_type_list
    }

    /// Returns the reference entry list. Java never populates it, so it is always empty.
    pub fn get_reference_entry_list(&self) -> &[ReferenceListEntry] {
        &self.reference_entry_list
    }

    /// Returns the resource name at `offset` from the start of the name list, or `None` for an
    /// offset of -1 (no name) or one that does not start a name.
    ///
    /// Port of `getStringAt(short)`.
    pub fn get_string_at(&self, offset: i16) -> Option<&str> {
        if offset == -1 {
            return None;
        }
        self.resource_name_map.get(&offset).map(String::as_str)
    }

    /// Returns the reader index at which this map starts.
    pub fn get_map_start_index(&self) -> u64 {
        self.map_start_index
    }
}

impl StructConverter for ResourceMap {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: one component
    /// per private non-underscore field, the `copy` header becoming a nested structure.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("ResourceMap", 0);
        s.add_with_name(self.copy.to_data_type()?, Some("copy".to_string()), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), Some("handleToNextResourceMap".to_string()), None)?;
        for field in [
            "fileReferenceNumber",
            "resourceForkAttributes",
            "resourceTypeListOffset",
            "resourceNameListOffset",
            "numberOfTypes",
        ] {
            s.add_with_name(PrimitiveDt::WORD.boxed(), Some(field.to_string()), None)?;
        }
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::asd::entry_descriptor::EntryDescriptor;
    use crate::format::macos::test_support::{resource_fork_fixture, VecReader};

    fn shallow_header(reader: &mut VecReader) -> ResourceHeader {
        let d = EntryDescriptor::new(2, 0, reader.length().unwrap() as i32);
        ResourceHeader::read(reader, d, true).unwrap()
    }

    #[test]
    fn parses_fixed_fields_names_and_types() {
        let mut reader = VecReader::new(resource_fork_fixture());
        let header = shallow_header(&mut reader);
        reader.set_pointer_index(0x20);

        let map = ResourceMap::new(&mut reader, &header).unwrap();
        // Left just past the 30-byte map header.
        assert_eq!(reader.get_pointer_index(), 0x20 + 30);
        assert_eq!(map.get_map_start_index(), 0x20);
        assert_eq!(map.get_copy().get_resource_map_offset(), 0x20);
        assert!(map.get_copy().get_map().is_none());
        assert_eq!(map.get_handle_to_next_resource_map(), 0xdead_beef_u32 as i32);
        assert_eq!(map.get_file_reference_number(), 7);
        assert_eq!(map.get_resource_fork_attributes(), 0x80);
        assert_eq!(map.get_resource_type_list_offset(), 0x1e);
        assert_eq!(map.get_resource_name_list_offset(), 0x54);
        assert_eq!(map.get_number_of_types(), 1);

        assert_eq!(map.get_string_at(0), Some("hello"));
        assert_eq!(map.get_string_at(6), Some("icn"));
        assert_eq!(map.get_string_at(1), None);
        assert_eq!(map.get_string_at(-1), None);
        assert!(map.get_reference_entry_list().is_empty());

        let types = map.get_resource_type_list();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].get_type_as_string(), "STR ");
        assert_eq!(types[1].get_type_as_string(), "ICN#");
        let str_refs = types[0].get_reference_list();
        assert_eq!(str_refs.len(), 1);
        assert_eq!(str_refs[0].get_id(), 128);
        assert_eq!(str_refs[0].get_name(), Some("hello"));
        assert_eq!(str_refs[0].get_attributes(), 0x20);
        assert_eq!(str_refs[0].get_data_offset(), 0x10);
        let icn_refs = types[1].get_reference_list();
        assert_eq!(icn_refs.len(), 2);
        assert_eq!((icn_refs[0].get_id(), icn_refs[0].get_name()), (129, None));
        assert_eq!((icn_refs[1].get_id(), icn_refs[1].get_name()), (130, Some("icn")));
        assert_eq!(icn_refs[1].get_data_offset(), 0x010000);
        assert!(types.iter().all(|t| t.get_resource_object().is_none()));
    }

    #[test]
    fn truncated_name_list_is_an_error_and_restores_position() {
        let mut bytes = resource_fork_fixture();
        // A name whose length byte promises more than remains.
        bytes.push(0x10);
        let mut reader = VecReader::new(bytes);
        let header = shallow_header(&mut reader);
        reader.set_pointer_index(0x20);
        assert!(ResourceMap::new(&mut reader, &header).is_err());
        assert_eq!(reader.get_pointer_index(), 0x20 + 30);
    }

    #[test]
    fn to_data_type_nests_the_header_copy() {
        let mut reader = VecReader::new(resource_fork_fixture());
        let header = shallow_header(&mut reader);
        reader.set_pointer_index(0x20);
        let map = ResourceMap::new(&mut reader, &header).unwrap();
        let dt = map.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ResourceMap");
        assert_eq!(dt.get_length(), 16 + 4 + 5 * 2);
    }
}
