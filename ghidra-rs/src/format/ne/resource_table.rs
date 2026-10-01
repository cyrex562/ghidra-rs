use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::resource_type::ResourceType;
use std::io;

use super::resource_name::ResourceName;

/// Stores the new-executable (NE) resource table.
///
/// A resource table contains all of the supported types of resources.
///
/// Mirrors `ResourceTable` from the original Ghidra Java source.
pub struct ResourceTable {
    index: u64,
    alignment_shift_count: i16,
    types: Vec<ResourceType>,
    names: Vec<ResourceName>,
}

impl ResourceTable {
    /// Constructs a new resource table.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `index` - the byte index where the Resource Table begins, relative to the beginning of
    ///   the file
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader, index: u64) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let alignment_shift_count = reader.read_next_short()?;

        let mut types = Vec::new();
        loop {
            let rt = ResourceType::new(reader, alignment_shift_count)?;
            if rt.get_type_id() == 0 {
                break;
            }
            types.push(rt);
        }

        let mut names = Vec::new();
        loop {
            let rn = ResourceName::new(reader)?;
            if rn.length() == 0 {
                break;
            }
            names.push(rn);
        }

        reader.set_pointer_index(old_index);

        Ok(ResourceTable {
            index,
            alignment_shift_count,
            types,
            names,
        })
    }

    /// Returns the alignment shift count.
    /// Some resources offsets and lengths are stored bit shifted.
    pub fn get_alignment_shift_count(&self) -> i16 {
        self.alignment_shift_count
    }

    /// Returns the array of resource types.
    pub fn get_resource_types(&self) -> &[ResourceType] {
        &self.types
    }

    /// Returns the array of resources names.
    pub fn get_resource_names(&self) -> &[ResourceName] {
        &self.names
    }

    /// Returns the byte index where the resource table begins, relative to the beginning of the
    /// file.
    pub fn get_index(&self) -> u64 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_empty_table() {
        // alignment shift count = 0, then a sentinel type id (0) and a sentinel name length (0).
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(data, true);

        let table = ResourceTable::new(&mut reader, 0).unwrap();

        assert_eq!(table.get_index(), 0);
        assert_eq!(table.get_alignment_shift_count(), 0);
        assert!(table.get_resource_types().is_empty());
        assert!(table.get_resource_names().is_empty());
    }

    #[test]
    fn reads_one_resource_type_and_name() {
        let data = vec![
            0x04, 0x00, // alignment shift count = 4
            // ResourceType: typeID=0x8002 (RT_BITMAP|0x8000), count=1, reserved=0
            //
            // Note: deliberately not RT_STRING here (unlike RT_BITMAP, RT_STRING entries parse
            // as a `ResourceStringTable` that reads additional string bytes from an absolute,
            // alignment-shifted file offset -- see `resource_type::tests` for that dedicated
            // scenario). This test only exercises the plain-`Resource` path.
            0x02, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Resource: fileOffset, fileLength, flagword, resourceID, handle, usage
            0x10, 0x00, 0x20, 0x00, 0x40, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00,
            // sentinel ResourceType (typeID=0)
            0x00, 0x00,
            // ResourceName: length=3, "abc"
            0x03, b'a', b'b', b'c',
            // sentinel ResourceName (length=0)
            0x00,
        ];
        let mut reader = BinaryReader::from_bytes(data, true);

        let table = ResourceTable::new(&mut reader, 0).unwrap();

        assert_eq!(table.get_alignment_shift_count(), 4);

        let types = table.get_resource_types();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].get_type_id(), 0x8002u16 as i16);
        assert_eq!(types[0].get_count(), 1);
        let resources = types[0].get_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].resource().get_file_offset(), 0x0010);
        assert_eq!(resources[0].resource().get_file_offset_shifted(), 0x0010 << 4);

        let names = table.get_resource_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name(), "abc");
    }

    #[test]
    fn restores_reader_position_after_construction() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(data, true);
        reader.set_pointer_index(2);

        let _ = ResourceTable::new(&mut reader, 0).unwrap();

        assert_eq!(reader.get_pointer_index(), 2);
    }
}
