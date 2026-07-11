use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents an entry in the SquashFS directory table.
///
/// Mirrors `ghidra.file.formats.squashfs.SquashDirectoryTableEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashDirectoryTableEntry {
    /// Offset into the uncompressed directory table where this entry is.
    address_offset: u32,
    /// Stores the basic inode type (e.g. an "extended file" inode is stored as "basic file" here).
    inode_type: u32,
    /// The result of adding the base inode to the offset stored in this entry.
    inode_number: i32,
    /// Upon creation, this is just the name of this sub-entry, but may be expanded to the full path.
    path: String,
}

impl SquashDirectoryTableEntry {
    /// Reads a directory table entry from the given binary reader.
    ///
    /// # Arguments
    /// * `reader` - A binary reader positioned at the start of the entry data
    /// * `base_inode` - The base inode number used to calculate the current entry's inode number
    ///
    /// # Errors
    /// Returns `io::Error` if any read operation fails.
    pub fn read(reader: &mut GBinaryReader, base_inode: i64) -> io::Result<Self> {
        let address_offset = reader.read_next_short()? as u16 as u32;
        let inode_number_offset = reader.read_next_short()?; // NOTE: Signed
        let inode_type = reader.read_next_short()? as u16 as u32;
        let name_size = reader.read_next_short()? as u16 as u32;

        // The stored filename doesn't include the terminating null byte
        // Note: Though technically 16 bits, Linux caps name size at 256 chars
        let name_bytes = reader.read_next_byte_array((name_size + 1) as usize)?;
        let path = String::from_utf8_lossy(&name_bytes).into_owned();

        // Find the inode number using the base in the table entry header and the offset
        let inode_number = (base_inode + inode_number_offset as i64) as i32;

        Ok(SquashDirectoryTableEntry {
            address_offset,
            inode_type,
            inode_number,
            path,
        })
    }

    pub fn get_address_offset(&self) -> u32 {
        self.address_offset
    }

    pub fn get_inode_type(&self) -> u32 {
        self.inode_type
    }

    /// Extracts the filename from the path.
    pub fn get_file_name(&self) -> &str {
        match self.path.rfind('/') {
            Some(slash_index) => &self.path[slash_index..],
            None => &self.path,
        }
    }

    pub fn get_inode_number(&self) -> i32 {
        self.inode_number
    }

    pub fn get_path(&self) -> &str {
        &self.path
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

    /// Builds the byte layout for one entry: address_offset, inode_number_offset, inode_type,
    /// name_size, followed by `name_size + 1` bytes for the name.
    fn entry_bytes(
        address_offset: u16,
        inode_number_offset: i16,
        inode_type: u16,
        name: &str,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&address_offset.to_le_bytes());
        data.extend_from_slice(&inode_number_offset.to_le_bytes());
        data.extend_from_slice(&inode_type.to_le_bytes());
        data.extend_from_slice(&((name.len() - 1) as u16).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data
    }

    #[test]
    fn reads_basic_entry() {
        let data = entry_bytes(0x10, 5, 2, "test.txt");
        let mut reader = test_reader(data, true);
        let entry = SquashDirectoryTableEntry::read(&mut reader, 100).unwrap();

        assert_eq!(entry.get_address_offset(), 0x10);
        assert_eq!(entry.get_inode_type(), 2);
        assert_eq!(entry.get_path(), "test.txt");
        assert_eq!(entry.get_inode_number(), 105);
    }

    #[test]
    fn negative_inode_number_offset_subtracts_from_base() {
        let data = entry_bytes(0, -1, 0, "a");
        let mut reader = test_reader(data, true);
        let entry = SquashDirectoryTableEntry::read(&mut reader, 100).unwrap();

        assert_eq!(entry.get_inode_number(), 99);
    }

    #[test]
    fn inode_number_truncates_to_32_bits() {
        let data = entry_bytes(0, 0, 0, "a");
        let mut reader = test_reader(data, true);
        // base_inode + offset overflows a 32 bit int; the Java source narrows via `(int)`.
        let entry = SquashDirectoryTableEntry::read(&mut reader, 0x1_0000_0000).unwrap();

        assert_eq!(entry.get_inode_number(), 0);
    }

    #[test]
    fn get_file_name_with_no_slash_returns_whole_path() {
        let data = entry_bytes(0, 0, 0, "somefile");
        let mut reader = test_reader(data, true);
        let entry = SquashDirectoryTableEntry::read(&mut reader, 0).unwrap();

        assert_eq!(entry.get_file_name(), "somefile");
    }

    #[test]
    fn get_file_name_with_slash_includes_the_slash() {
        let data = entry_bytes(0, 0, 0, "dir/sub");
        let mut reader = test_reader(data, true);
        let entry = SquashDirectoryTableEntry::read(&mut reader, 0).unwrap();

        // Mirrors the Java source's `path.substring(slashIndex)`, which keeps the slash.
        assert_eq!(entry.get_file_name(), "/sub");
    }

    #[test]
    fn big_endian() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0010u16.to_be_bytes());
        data.extend_from_slice(&5i16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&7u16.to_be_bytes());
        data.extend_from_slice(b"test.txt");
        let mut reader = test_reader(data, false);
        let entry = SquashDirectoryTableEntry::read(&mut reader, 100).unwrap();

        assert_eq!(entry.get_address_offset(), 0x10);
        assert_eq!(entry.get_path(), "test.txt");
        assert_eq!(entry.get_inode_number(), 105);
    }
}
