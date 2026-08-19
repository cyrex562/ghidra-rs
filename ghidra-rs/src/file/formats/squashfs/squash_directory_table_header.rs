use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;
use crate::util::task::TaskMonitor;

use super::squash_directory_table_entry::SquashDirectoryTableEntry;

/// Represents a header in the SquashFS directory table.
///
/// Mirrors `ghidra.file.formats.squashfs.SquashDirectoryTableHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashDirectoryTableHeader {
    /// The number of sub-entries (off by 1, so a "0" really means there is one sub-entry)
    number_of_entries: u32,
    /// Relative to the inode table start, this is the byte offset where the corresponding inode is
    directory_inode_offset: u32,
    /// The base inode number. Sub-entries will store their inodes as an offset to this one (+/-)
    base_inode: u32,
    /// A list of sub-entries
    entries: Vec<SquashDirectoryTableEntry>,
}

impl SquashDirectoryTableHeader {
    /// Reads a directory table header from the given binary reader.
    ///
    /// # Arguments
    /// * `reader` - A binary reader with pointer index at the start of the header data
    /// * `monitor` - Monitor to allow the user to cancel the load
    ///
    /// # Errors
    /// Returns `io::Error` if any read operation fails, or `CancelledException` if the load was cancelled.
    pub fn read(
        reader: &mut GBinaryReader,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let number_of_entries = reader.read_next_int()? as u32;
        let directory_inode_offset = reader.read_next_int()? as u32;
        let base_inode = reader.read_next_int()? as u32;

        let mut entries = Vec::new();
        for _ in 0..=number_of_entries {
            monitor.check_cancelled()?;
            let entry = SquashDirectoryTableEntry::read(reader, base_inode as i64)?;
            entries.push(entry);
        }

        Ok(SquashDirectoryTableHeader {
            number_of_entries,
            directory_inode_offset,
            base_inode,
            entries,
        })
    }

    /// Returns the list of directory table entries.
    pub fn get_entries(&self) -> &[SquashDirectoryTableEntry] {
        &self.entries
    }

    /// Returns the base inode number.
    pub fn get_base_inode_number(&self) -> u32 {
        self.base_inode
    }

    /// Returns the directory inode offset.
    pub fn get_directory_inode_offset(&self) -> u32 {
        self.directory_inode_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use std::cell::RefCell;
    use std::io;
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
            if index as usize + length > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            Ok(self.0[index as usize..index as usize + length].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            match self.0.get_mut(index as usize) {
                Some(slot) => {
                    *slot = value;
                    Ok(())
                }
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range")),
            }
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            if start + values.len() > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    struct TestMonitor;

    impl TaskMonitor for TestMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn test_read_header_with_single_entry() {
        // Create test data: 3 unsigned ints (12 bytes) + 1 entry data
        // Entry: addressOffset (u16), inodeNumberOffset (i16), inodeType (u16), nameSize (u16), name bytes
        let mut data = Vec::new();

        // Header: numberOfEntries=0 (means 1 entry), directoryInodeOffset=256, baseInode=1000
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&256u32.to_le_bytes());
        data.extend_from_slice(&1000u32.to_le_bytes());

        // Entry: addressOffset=100, inodeNumberOffset=5, inodeType=2, nameSize=3, name="test"
        data.extend_from_slice(&(100u16).to_le_bytes());
        data.extend_from_slice(&(5i16).to_le_bytes());
        data.extend_from_slice(&(2u16).to_le_bytes());
        data.extend_from_slice(&(3u16).to_le_bytes());
        data.extend_from_slice(b"test");

        let provider = TestProvider(data);
        let mut reader = GBinaryReader::new(Rc::new(RefCell::new(provider)), true);
        let monitor = TestMonitor;

        let result = SquashDirectoryTableHeader::read(&mut reader, &monitor);
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.number_of_entries, 0);
        assert_eq!(header.directory_inode_offset, 256);
        assert_eq!(header.base_inode, 1000);
        assert_eq!(header.entries.len(), 1);
        assert_eq!(header.get_base_inode_number(), 1000);
        assert_eq!(header.get_directory_inode_offset(), 256);
    }

    #[test]
    fn test_read_header_with_multiple_entries() {
        let mut data = Vec::new();

        // Header: numberOfEntries=1 (means 2 entries), directoryInodeOffset=512, baseInode=2000
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&512u32.to_le_bytes());
        data.extend_from_slice(&2000u32.to_le_bytes());

        // First entry
        data.extend_from_slice(&(50u16).to_le_bytes());
        data.extend_from_slice(&(10i16).to_le_bytes());
        data.extend_from_slice(&(1u16).to_le_bytes());
        data.extend_from_slice(&(2u16).to_le_bytes());
        data.extend_from_slice(b"abc");

        // Second entry
        data.extend_from_slice(&(75u16).to_le_bytes());
        data.extend_from_slice(&(20i16).to_le_bytes());
        data.extend_from_slice(&(3u16).to_le_bytes());
        data.extend_from_slice(&(2u16).to_le_bytes());
        data.extend_from_slice(b"def");

        let provider = TestProvider(data);
        let mut reader = GBinaryReader::new(Rc::new(RefCell::new(provider)), true);
        let monitor = TestMonitor;

        let result = SquashDirectoryTableHeader::read(&mut reader, &monitor);
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.number_of_entries, 1);
        assert_eq!(header.directory_inode_offset, 512);
        assert_eq!(header.base_inode, 2000);
        assert_eq!(header.entries.len(), 2);
    }

    #[test]
    fn test_get_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&500u32.to_le_bytes());

        // One entry
        data.extend_from_slice(&(10u16).to_le_bytes());
        data.extend_from_slice(&(1i16).to_le_bytes());
        data.extend_from_slice(&(4u16).to_le_bytes());
        data.extend_from_slice(&(0u16).to_le_bytes()); // nameSize = len-1, so 0 => 1-byte name "x"
        data.extend_from_slice(b"x");

        let provider = TestProvider(data);
        let mut reader = GBinaryReader::new(Rc::new(RefCell::new(provider)), true);
        let monitor = TestMonitor;

        let header = SquashDirectoryTableHeader::read(&mut reader, &monitor).unwrap();
        let entries = header.get_entries();
        assert_eq!(entries.len(), 1);
    }
}
