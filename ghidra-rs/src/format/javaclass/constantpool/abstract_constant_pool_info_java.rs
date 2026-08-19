//! Base class for constant pool entries in Java class files.
//!
//! Ported from `ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Base class for all constant pool entries in Java class files.
///
/// Java virtual machine instructions do not rely on the runtime layout of classes,
/// interfaces, class instances, or arrays. Instead, instructions refer to symbolic
/// information in the constant_pool table.
///
/// All constant_pool table entries have the following general format:
/// ```text
/// cp_info {
///     u1 tag;
///     u1 info[];
/// }
/// ```
///
/// Each item in the constant_pool table must begin with a 1-byte tag indicating
/// the kind of cp_info entry. The contents of the info array vary with the value of
/// tag. The valid tags and their values are listed in the Java class file specification.
/// Each tag byte must be followed by two or more bytes giving information about the specific
/// constant. The format of the additional information varies with the tag value.
pub struct AbstractConstantPoolInfoJava {
    offset: u64,
    tag: u8,
}

impl AbstractConstantPoolInfoJava {
    /// Creates a new constant pool entry by reading from the provided binary reader.
    ///
    /// Captures the current pointer index as the offset and reads the tag byte.
    ///
    /// # Arguments
    /// * `reader` - The binary reader positioned at the start of the constant pool entry.
    ///
    /// # Returns
    /// A new `AbstractConstantPoolInfoJava` instance.
    ///
    /// # Errors
    /// Returns an IO error if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let offset = reader.get_pointer_index();
        let tag = reader.read_next_byte()?;
        Ok(AbstractConstantPoolInfoJava { offset, tag })
    }

    /// Returns the offset (file position) where this constant pool entry begins.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// Returns the tag byte that identifies the type of this constant pool entry.
    pub fn get_tag(&self) -> u8 {
        self.tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReader {
        data: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { data, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            index < self.data.len() as u64
        }

        fn get_pointer_index(&self) -> u64 {
            self.pos
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.pos;
            self.pos = index;
            prev
        }

        fn is_little_endian(&self) -> bool {
            false
        }

        fn set_little_endian(&mut self, _is_little_endian: bool) {}

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            if index >= self.data.len() as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "index out of bounds",
                ));
            }
            Ok(self.data[index as usize])
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            if index as usize + n_elements > self.data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "not enough data",
                ));
            }
            Ok(self.data[index as usize..index as usize + n_elements].to_vec())
        }

        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            unimplemented!()
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            let mut clone = MockReader {
                data: self.data.clone(),
                pos: new_index,
            };
            Box::new(clone)
        }
    }

    #[test]
    fn new_reads_tag_and_captures_offset() {
        let data = vec![0x07u8]; // CONSTANT_CLASS tag value
        let mut reader = MockReader::new(data);

        let entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry");

        assert_eq!(entry.get_offset(), 0);
        assert_eq!(entry.get_tag(), 0x07);
    }

    #[test]
    fn new_advances_reader_position() {
        let data = vec![0x09u8, 0x0Au8]; // CONSTANT_FIELDREF and CONSTANT_METHODREF
        let mut reader = MockReader::new(data);

        let _entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry");

        assert_eq!(reader.get_pointer_index(), 1);
    }

    #[test]
    fn new_captures_offset_before_reading() {
        let mut data = vec![0u8; 6];
        data[5] = 0x01u8;
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(5);

        let entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry");

        assert_eq!(entry.get_offset(), 5);
        assert_eq!(entry.get_tag(), 0x01);
        assert_eq!(reader.get_pointer_index(), 6);
    }

    #[test]
    fn get_offset_returns_stored_offset() {
        let mut data = vec![0u8; 101];
        data[100] = 0x03u8;
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(100);

        let entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry");

        assert_eq!(entry.get_offset(), 100);
    }

    #[test]
    fn get_tag_returns_stored_tag() {
        let data = vec![0x12u8];
        let mut reader = MockReader::new(data);

        let entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry");

        assert_eq!(entry.get_tag(), 0x12);
    }

    #[test]
    fn get_tag_returns_various_tag_values() {
        for tag_value in [0x01u8, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A] {
            let data = vec![tag_value];
            let mut reader = MockReader::new(data);

            let entry = AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create");
            assert_eq!(entry.get_tag(), tag_value);
        }
    }

    #[test]
    fn new_returns_error_when_no_data_available() {
        let data: Vec<u8> = vec![];
        let mut reader = MockReader::new(data);

        let result = AbstractConstantPoolInfoJava::new(&mut reader);

        assert!(result.is_err());
    }

    #[test]
    fn multiple_entries_track_offsets_correctly() {
        let data = vec![0x07u8, 0x09u8, 0x0Au8];
        let mut reader = MockReader::new(data);

        let entry1 =
            AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry1");
        let entry2 =
            AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry2");
        let entry3 =
            AbstractConstantPoolInfoJava::new(&mut reader).expect("failed to create entry3");

        assert_eq!(entry1.get_offset(), 0);
        assert_eq!(entry1.get_tag(), 0x07);

        assert_eq!(entry2.get_offset(), 1);
        assert_eq!(entry2.get_tag(), 0x09);

        assert_eq!(entry3.get_offset(), 2);
        assert_eq!(entry3.get_tag(), 0x0A);
    }
}
