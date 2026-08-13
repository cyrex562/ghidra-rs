use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::ResourceType;
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
    pub fn new(reader: &mut dyn BinaryReader, index: u64) -> io::Result<Self> {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn reads_empty_table() {
        // alignment shift count = 0, then a sentinel type id (0) and a sentinel name length (0).
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = MockReader::new(data);

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
            // ResourceType: typeID=0x8006 (RT_STRING|0x8000), count=1, reserved=0
            0x06, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Resource: fileOffset, fileLength, flagword, resourceID, handle, usage
            0x10, 0x00, 0x20, 0x00, 0x40, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00,
            // sentinel ResourceType (typeID=0)
            0x00, 0x00,
            // ResourceName: length=3, "abc"
            0x03, b'a', b'b', b'c',
            // sentinel ResourceName (length=0)
            0x00,
        ];
        let mut reader = MockReader::new(data);

        let table = ResourceTable::new(&mut reader, 0).unwrap();

        assert_eq!(table.get_alignment_shift_count(), 4);

        let types = table.get_resource_types();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].get_type_id(), 0x8006u16 as i16);
        assert_eq!(types[0].get_count(), 1);
        let resources = types[0].get_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].get_file_offset(), 0x0010);
        assert_eq!(resources[0].get_file_offset_shifted(), 0x0010 << 4);

        let names = table.get_resource_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name(), "abc");
    }

    #[test]
    fn restores_reader_position_after_construction() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(2);

        let _ = ResourceTable::new(&mut reader, 0).unwrap();

        assert_eq!(reader.get_pointer_index(), 2);
    }
}
