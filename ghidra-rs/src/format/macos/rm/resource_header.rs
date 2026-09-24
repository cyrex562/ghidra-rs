//! Port of `ghidra.app.util.bin.format.macos.rm.ResourceHeader`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::asd::entry::{Entry, EntryBase};
use crate::format::macos::asd::entry_descriptor::EntryDescriptor;
use crate::format::macos::asd::entry_descriptor_id::ENTRY_RESOURCE_FORK;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::format::macos::rm::resource_map::ResourceMap;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The header of a Macintosh resource fork, and (unless read shallowly) the fork's parsed
/// [`ResourceMap`].
///
/// Port of `ghidra.app.util.bin.format.macos.rm.ResourceHeader`. Java's `extends Entry` becomes
/// composition over [`EntryBase`] plus an [`Entry`] impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHeader {
    entry: EntryBase,
    resource_data_offset: i32,
    resource_map_offset: i32,
    resource_data_length: i32,
    resource_map_length: i32,
    map: Option<Box<ResourceMap>>,
}

impl ResourceHeader {
    /// Reads a resource fork that makes up the whole input, starting at index 0 in big-endian
    /// order, described by an `ENTRY_RESOURCE_FORK` descriptor spanning the input.
    ///
    /// Port of `ResourceHeader(ByteProvider)`, which wraps the provider in a fresh big-endian
    /// `BinaryReader`. Here the caller passes the reader over the provider; it is switched to
    /// big-endian and repositioned to 0 to match.
    pub fn from_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        reader.set_little_endian(false);
        reader.set_pointer_index(0);
        let length = reader.length()? as i32;
        Self::new(reader, EntryDescriptor::new(ENTRY_RESOURCE_FORK as i32, 0, length))
    }

    /// Reads the 16-byte fork header at the reader's current position, then the resource map it
    /// points to. The reader is left just past the 16-byte header.
    ///
    /// Port of `ResourceHeader(BinaryReader, EntryDescriptor)`.
    pub fn new(reader: &mut dyn BinaryReader, entry: EntryDescriptor) -> io::Result<Self> {
        Self::read(reader, entry, false)
    }

    /// Reads the 16-byte fork header; unless `only_do_shallow_parsing`, also parses the resource
    /// map at `start + resourceMapOffset`, restoring the reader afterwards.
    ///
    /// Port of the package-private `ResourceHeader(BinaryReader, EntryDescriptor, boolean)`
    /// constructor (the shallow form is what a [`ResourceMap`] uses for its header copy).
    pub(crate) fn read(
        reader: &mut dyn BinaryReader,
        entry: EntryDescriptor,
        only_do_shallow_parsing: bool,
    ) -> io::Result<Self> {
        let beginning_of_resource_fork = reader.get_pointer_index();

        let mut header = Self {
            entry: EntryBase::new(entry),
            resource_data_offset: reader.read_next_int()?,
            resource_map_offset: reader.read_next_int()?,
            resource_data_length: reader.read_next_int()?,
            resource_map_length: reader.read_next_int()?,
            map: None,
        };

        if only_do_shallow_parsing {
            return Ok(header);
        }

        let old_index = reader.get_pointer_index();
        let map_start =
            beginning_of_resource_fork as i64 + i64::from(header.resource_map_offset);
        reader.set_pointer_index(map_start as u64);
        let map = ResourceMap::new(reader, &header);
        reader.set_pointer_index(old_index);
        header.map = Some(Box::new(map?));
        Ok(header)
    }

    /// Returns the offset from the beginning of the resource fork to the resource map.
    pub fn get_resource_map_offset(&self) -> i32 {
        self.resource_map_offset
    }

    /// Returns the length of the resource map.
    pub fn get_resource_map_length(&self) -> i32 {
        self.resource_map_length
    }

    /// Returns the offset from the beginning of the resource fork to the resource data.
    pub fn get_resource_data_offset(&self) -> i32 {
        self.resource_data_offset
    }

    /// Returns the length of the resource data.
    pub fn get_resource_data_length(&self) -> i32 {
        self.resource_data_length
    }

    /// Returns the parsed resource map, or `None` for a header read shallowly (the copy stored
    /// inside a [`ResourceMap`]).
    pub fn get_map(&self) -> Option<&ResourceMap> {
        self.map.as_deref()
    }
}

impl Entry for ResourceHeader {
    fn entry_base(&self) -> &EntryBase {
        &self.entry
    }
}

impl StructConverter for ResourceHeader {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: the four
    /// `int` fields (the inherited `_entryDescriptor` and the `_map` field are skipped for their
    /// leading underscore).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("ResourceHeader", 0);
        for field in
            ["resourceDataOffset", "resourceMapOffset", "resourceDataLength", "resourceMapLength"]
        {
            s.add_with_name(PrimitiveDt::DWORD.boxed(), Some(field.to_string()), None)?;
        }
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::{resource_fork_fixture, VecReader};

    #[test]
    fn from_reader_parses_whole_fork_big_endian() {
        let bytes = resource_fork_fixture();
        let len = bytes.len() as i32;
        let mut reader = VecReader::little_endian(bytes);
        reader.set_pointer_index(9);

        let header = ResourceHeader::from_reader(&mut reader).unwrap();
        assert!(!reader.is_little_endian());
        assert_eq!(reader.get_pointer_index(), 16);
        assert_eq!(header.get_resource_data_offset(), 0x100);
        assert_eq!(header.get_resource_map_offset(), 0x20);
        assert_eq!(header.get_resource_data_length(), 0x40);
        assert_eq!(header.get_resource_map_length(), 0x5e);
        let d = header.get_entry_descriptor();
        assert_eq!(
            (d.get_entry_id(), d.get_offset(), d.get_length()),
            (ENTRY_RESOURCE_FORK as i32, 0, len)
        );
        let map = header.get_map().expect("map");
        assert_eq!(map.get_resource_type_list().len(), 2);
        assert_eq!(map.get_copy().get_resource_data_offset(), 0x100);
    }

    #[test]
    fn shallow_read_skips_the_map() {
        let mut reader = VecReader::new(resource_fork_fixture());
        let header =
            ResourceHeader::read(&mut reader, EntryDescriptor::new(2, 0, 0), true).unwrap();
        assert!(header.get_map().is_none());
        assert_eq!(reader.get_pointer_index(), 16);
    }

    #[test]
    fn map_offset_is_relative_to_fork_start() {
        let mut bytes = vec![0xaa; 5];
        bytes.extend(resource_fork_fixture());
        let mut reader = VecReader::new(bytes);
        reader.set_pointer_index(5);
        // The fixture's map-relative offsets are all relative to the map start, so the whole fork
        // parses the same when shifted.
        let header = ResourceHeader::new(&mut reader, EntryDescriptor::new(2, 5, 0)).unwrap();
        assert_eq!(reader.get_pointer_index(), 5 + 16);
        let map = header.get_map().unwrap();
        assert_eq!(map.get_map_start_index(), 5 + 0x20);
        assert_eq!(map.get_string_at(6), Some("icn"));
    }

    #[test]
    fn bad_map_offset_is_an_error_and_restores_position() {
        let mut bytes = resource_fork_fixture();
        bytes[4..8].copy_from_slice(&0x1000u32.to_be_bytes());
        let mut reader = VecReader::new(bytes);
        assert!(ResourceHeader::new(&mut reader, EntryDescriptor::new(2, 0, 0)).is_err());
        assert_eq!(reader.get_pointer_index(), 16);
    }

    #[test]
    fn to_data_type_is_four_dwords() {
        let mut reader = VecReader::new(resource_fork_fixture());
        let header =
            ResourceHeader::read(&mut reader, EntryDescriptor::new(2, 0, 0), true).unwrap();
        let dt = header.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ResourceHeader");
        assert_eq!(dt.get_length(), 16);
    }
}
