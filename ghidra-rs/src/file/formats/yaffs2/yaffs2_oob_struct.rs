use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents the data YAFFS2 puts in the OOB (out-of-band) area of a page.
///
/// See the yaffs_guts.h for yaffs_tags or yaffs_ext_tags.
/// The layout of data in the OOB area can vary depending on the version, size,
/// and MTD-vs-yaffs option used in mkyaffs.
///
/// This implementation reads the `yaffs2_ext_tag` format, extracting the sequence number
/// and object ID from the OOB data.
///
/// Mirrors `ghidra.file.formats.yaffs2.YAFFS2OOBStruct`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Yaffs2OobStruct {
    sequence_number: u64,
    object_id: u64,
}

impl Yaffs2OobStruct {
    /// Reads a yaffs2_ext_tag-formatted OOB data area.
    ///
    /// # Arguments
    /// * `reader` - A mutable binary reader positioned at the start of the OOB data.
    /// * `oob_size` - Size of the OOB data in bytes. The reader is advanced to
    ///   `start + oob_size` after this call.
    ///
    /// # Errors
    /// Returns `io::Error` if reading from the underlying data source fails.
    ///
    /// # Algorithm
    /// 1. Records the starting position.
    /// 2. Reads the sequence number as an unsigned 32-bit integer.
    /// 3. Reads the object ID as an unsigned 32-bit integer.
    /// 4. Advances the reader to the starting position plus `oob_size`.
    pub fn read(reader: &mut GBinaryReader, oob_size: usize) -> io::Result<Self> {
        let start = reader.get_pointer_index();
        let sequence_number = reader.read_next_int()? as u32 as u64;
        let object_id = reader.read_next_int()? as u32 as u64;
        reader.set_pointer_index(start + (oob_size as u64));
        Ok(Yaffs2OobStruct {
            sequence_number,
            object_id,
        })
    }

    /// Returns the object ID.
    pub fn get_object_id(&self) -> u64 {
        self.object_id
    }

    /// Returns the sequence number.
    pub fn get_sequence_number(&self) -> u64 {
        self.sequence_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestProvider(Vec<u8>);

    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for TestProvider {
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
            }
            Ok(self.0[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[idx] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "write past end"));
            }
            self.0[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    fn test_reader(data: Vec<u8>, little_endian: bool) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(TestProvider(data))), little_endian)
    }

    #[test]
    fn reads_sequence_number_and_object_id() {
        // 4 bytes for sequence_number + 4 bytes for object_id
        let data = vec![0x01_u8, 0x00, 0x00, 0x00, 0x42_u8, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(oob.get_sequence_number(), 1);
        assert_eq!(oob.get_object_id(), 0x42);
    }

    #[test]
    fn sequence_number_big_endian() {
        let data = vec![0x00_u8, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, false);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(oob.get_sequence_number(), 10);
    }

    #[test]
    fn object_id_little_endian() {
        let data = vec![0x00_u8, 0x00, 0x00, 0x00, 0x34_u8, 0x12, 0x00, 0x00];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(oob.get_object_id(), 0x1234);
    }

    #[test]
    fn advances_reader_to_oob_size() {
        let data = vec![0x01_u8, 0x00, 0x00, 0x00, 0x02_u8, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let mut reader = test_reader(data, true);
        Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(reader.get_pointer_index(), 8);
    }

    #[test]
    fn advances_reader_with_larger_oob_size() {
        let data = vec![0x01_u8, 0x00, 0x00, 0x00, 0x02_u8, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = test_reader(data, true);
        Yaffs2OobStruct::read(&mut reader, 12).unwrap();
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn reads_max_unsigned_values() {
        let data = vec![0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF_u8, 0xFF, 0xFF, 0xFF];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(oob.get_sequence_number(), 0xFFFFFFFF);
        assert_eq!(oob.get_object_id(), 0xFFFFFFFF);
    }

    #[test]
    fn zero_values() {
        let data = vec![0x00_u8; 8];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        assert_eq!(oob.get_sequence_number(), 0);
        assert_eq!(oob.get_object_id(), 0);
    }

    #[test]
    fn struct_is_copy() {
        let data = vec![0x01_u8, 0x00, 0x00, 0x00, 0x02_u8, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        let oob2 = oob;
        assert_eq!(oob, oob2);
    }

    #[test]
    fn struct_debug_impl() {
        let data = vec![0x01_u8, 0x00, 0x00, 0x00, 0x02_u8, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, true);
        let oob = Yaffs2OobStruct::read(&mut reader, 8).unwrap();
        let debug_str = format!("{:?}", oob);
        assert!(debug_str.contains("Yaffs2OobStruct"));
    }
}
