//! Port of `ghidra.app.util.bin.format.macos.asd.EntryDescriptor`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::asd::entry_factory;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::format::macos::rm::resource_header::ResourceHeader;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// One entry of an AppleSingle/AppleDouble header: which kind of entry it is and where its data
/// lives in the file.
///
/// Port of `ghidra.app.util.bin.format.macos.asd.EntryDescriptor`.
///
/// Java stores the parsed entry in an `Object _entry` field filled in by `EntryFactory`. The only
/// entry kind `EntryFactory` ever builds is a [`ResourceHeader`], so the Rust field is typed as
/// that (boxed, since a `ResourceHeader` in turn carries its own descriptor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDescriptor {
    entry_id: i32,
    offset: i32,
    length: i32,
    entry: Option<Box<ResourceHeader>>,
}

impl EntryDescriptor {
    /// Reads a descriptor (entry ID, offset, length) and then the entry it describes, via
    /// [`entry_factory::get_entry`]. The reader is left just past the 12-byte descriptor.
    ///
    /// Port of the package-private `EntryDescriptor(BinaryReader)` constructor.
    ///
    /// Java's `EntryFactory` hands the descriptor under construction itself to the entry it
    /// builds; here the entry receives a copy of the descriptor's ID/offset/length, whose own
    /// `entry` is empty (a value cannot contain itself).
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let entry_id = reader.read_next_int()?;
        let offset = reader.read_next_int()?;
        let length = reader.read_next_int()?;
        let mut descriptor = Self::new(entry_id, offset, length);
        descriptor.entry = entry_factory::get_entry(reader, &descriptor)?.map(Box::new);
        Ok(descriptor)
    }

    /// Creates a descriptor with no parsed entry.
    ///
    /// Port of the public `EntryDescriptor(int, int, int)` constructor.
    pub fn new(entry_id: i32, offset: i32, length: i32) -> Self {
        Self { entry_id, offset, length, entry: None }
    }

    /// Returns the entry's ID. Note: 0 is invalid. See
    /// [`entry_descriptor_id`](crate::format::macos::asd::entry_descriptor_id).
    pub fn get_entry_id(&self) -> i32 {
        self.entry_id
    }

    /// The offset from the beginning of the file to the beginning of the entry's data.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Returns the length of the entry's data. The length can be zero (0).
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Returns the parsed entry, if the entry kind is one `EntryFactory` understands.
    ///
    /// Port of `getEntry()`.
    pub fn get_entry(&self) -> Option<&ResourceHeader> {
        self.entry.as_deref()
    }
}

impl StructConverter for EntryDescriptor {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: one component
    /// per private non-underscore field (`entryID`, `offset`, `length`, all `int` -> DWORD).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("EntryDescriptor", 0);
        for field in ["entryID", "offset", "length"] {
            s.add_with_name(PrimitiveDt::DWORD.boxed(), Some(field.to_string()), None)?;
        }
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::asd::entry::Entry;
    use crate::format::macos::asd::entry_descriptor_id::{ENTRY_REAL_NAME, ENTRY_RESOURCE_FORK};
    use crate::format::macos::test_support::{Image, VecReader};

    #[test]
    fn read_non_resource_entry_has_no_parsed_entry() {
        let mut img = Image::default();
        img.u32(ENTRY_REAL_NAME).u32(0x40).u32(7);
        let mut reader = VecReader::new(img.0);

        let d = EntryDescriptor::read(&mut reader).unwrap();
        assert_eq!(d.get_entry_id(), ENTRY_REAL_NAME as i32);
        assert_eq!(d.get_offset(), 0x40);
        assert_eq!(d.get_length(), 7);
        assert!(d.get_entry().is_none());
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn read_resource_fork_entry_parses_resource_header_and_restores_position() {
        // Descriptor at 0 pointing at a resource fork at 0x10 whose map lies at fork+0x10.
        let mut img = Image::default();
        img.u32(ENTRY_RESOURCE_FORK).u32(0x10).u32(0x40);
        img.pad_to(0x10);
        // Resource fork header: data offset, map offset, data length, map length.
        img.u32(0x100).u32(0x10).u32(0).u32(0x1e);
        // Map (at 0x20): copy of header, handle, file ref, attrs, type list off, name list off,
        // numberOfTypes = -1 (no types).
        img.u32(0x100).u32(0x10).u32(0).u32(0x1e);
        img.u32(0).u16(0).u16(0).u16(0x1c).u16(0x1e).u16(0xffff);
        let mut reader = VecReader::new(img.0);

        let d = EntryDescriptor::read(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 12);
        let header = d.get_entry().expect("resource header");
        assert_eq!(header.get_resource_data_offset(), 0x100);
        assert_eq!(header.get_resource_map_offset(), 0x10);
        assert_eq!(header.get_entry_descriptor().get_offset(), 0x10);
        assert!(header.get_entry_descriptor().get_entry().is_none());
        let map = header.get_map().expect("map");
        assert_eq!(map.get_map_start_index(), 0x20);
        assert!(map.get_resource_type_list().is_empty());
    }

    #[test]
    fn to_data_type_has_three_dwords() {
        let dt = EntryDescriptor::new(1, 2, 3).to_data_type().unwrap();
        assert_eq!(dt.get_name(), "EntryDescriptor");
        assert_eq!(dt.get_length(), 12);
    }
}
