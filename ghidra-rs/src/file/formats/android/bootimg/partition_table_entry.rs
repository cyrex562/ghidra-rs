use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Represents an entry in a partition table.
///
/// Port of `ghidra.file.formats.android.bootimg.PartitionTableEntry`.
#[derive(Debug, Clone)]
pub struct PartitionTableEntry {
    name: Vec<u8>,
    start: i32,
    length: i32,
    flags: i32,
}

impl PartitionTableEntry {
    /// Creates a new `PartitionTableEntry` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let name = reader.read_next_byte_array(16)?;
        let start = reader.read_next_int()?;
        let length = reader.read_next_int()?;
        let flags = reader.read_next_int()?;
        Ok(Self {
            name,
            start,
            length,
            flags,
        })
    }

    /// Returns the name as a string.
    pub fn get_name(&self) -> String {
        String::from_utf8_lossy(&self.name).to_string()
    }

    /// Returns the start offset.
    pub fn get_start(&self) -> i32 {
        self.start
    }

    /// Returns the length.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Returns the flags.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_reads_correct_data() {
        let mut data = vec![0u8; 28];

        // Set the name to "testpart"
        let name_bytes = b"testpart\0\0\0\0\0\0\0\0";
        data[0..16].copy_from_slice(&name_bytes[..16]);

        // Set start = 0x1000 (4096 in little-endian)
        data[16..20].copy_from_slice(&4096i32.to_le_bytes());
        // Set length = 0x2000 (8192 in little-endian)
        data[20..24].copy_from_slice(&8192i32.to_le_bytes());
        // Set flags = 1
        data[24..28].copy_from_slice(&1i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).expect("Failed to create entry");

        assert_eq!(entry.get_name().trim_end_matches('\0'), "testpart");
        assert_eq!(entry.get_start(), 4096);
        assert_eq!(entry.get_length(), 8192);
        assert_eq!(entry.get_flags(), 1);
    }

    #[test]
    fn test_get_name_returns_correct_value() {
        let mut data = vec![0u8; 28];
        let name_bytes = b"partition\0\0\0\0\0\0\0";
        data[0..16].copy_from_slice(&name_bytes[..16]);

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();

        assert_eq!(entry.get_name().trim_end_matches('\0'), "partition");
    }

    #[test]
    fn test_get_start_returns_correct_value() {
        let mut data = vec![0u8; 28];
        data[16..20].copy_from_slice(&1000i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();

        assert_eq!(entry.get_start(), 1000);
    }

    #[test]
    fn test_get_length_returns_correct_value() {
        let mut data = vec![0u8; 28];
        data[20..24].copy_from_slice(&2000i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();

        assert_eq!(entry.get_length(), 2000);
    }

    #[test]
    fn test_get_flags_returns_correct_value() {
        let mut data = vec![0u8; 28];
        data[24..28].copy_from_slice(&5i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();

        assert_eq!(entry.get_flags(), 5);
    }

    #[test]
    fn test_all_fields_with_large_values() {
        let mut data = vec![0u8; 28];

        // Name with special characters
        let name_bytes = b"large\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
        data[0..16].copy_from_slice(&name_bytes[..16]);

        // Large values
        data[16..20].copy_from_slice(&i32::MAX.to_le_bytes());
        data[20..24].copy_from_slice(&i32::MIN.to_le_bytes());
        data[24..28].copy_from_slice(&0x12345678i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();

        assert_eq!(entry.get_start(), i32::MAX);
        assert_eq!(entry.get_length(), i32::MIN);
        assert_eq!(entry.get_flags(), 0x12345678i32);
    }

    #[test]
    fn test_insufficient_data_error() {
        let data = vec![0u8; 27]; // One byte too short
        let mut reader = BinaryReader::from_bytes(data, true);

        let result = PartitionTableEntry::new(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_reader_position_advances() {
        let mut data = vec![0u8; 28];
        data[16..20].copy_from_slice(&100i32.to_le_bytes());
        data[20..24].copy_from_slice(&200i32.to_le_bytes());
        data[24..28].copy_from_slice(&300i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        assert_eq!(reader.get_pointer_index(), 0);

        let _ = PartitionTableEntry::new(&mut reader);
        assert_eq!(reader.get_pointer_index(), 28);
    }

    #[test]
    fn test_multiple_entries_sequential_read() {
        let mut data = vec![0u8; 56]; // Two entries worth of data

        // First entry
        let name1 = b"entry1\0\0\0\0\0\0\0\0\0\0";
        data[0..16].copy_from_slice(&name1[..16]);
        data[16..20].copy_from_slice(&1000i32.to_le_bytes());
        data[20..24].copy_from_slice(&2000i32.to_le_bytes());
        data[24..28].copy_from_slice(&1i32.to_le_bytes());

        // Second entry
        let name2 = b"entry2\0\0\0\0\0\0\0\0\0\0";
        data[28..44].copy_from_slice(&name2[..16]);
        data[44..48].copy_from_slice(&3000i32.to_le_bytes());
        data[48..52].copy_from_slice(&4000i32.to_le_bytes());
        data[52..56].copy_from_slice(&2i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);

        let entry1 = PartitionTableEntry::new(&mut reader).unwrap();
        assert_eq!(entry1.get_start(), 1000);

        let entry2 = PartitionTableEntry::new(&mut reader).unwrap();
        assert_eq!(entry2.get_start(), 3000);
    }

    #[test]
    fn test_clone_preserves_data() {
        let mut data = vec![0u8; 28];
        let name_bytes = b"clonetest\0\0\0\0\0\0\0";
        data[0..16].copy_from_slice(&name_bytes[..16]);
        data[16..20].copy_from_slice(&500i32.to_le_bytes());
        data[20..24].copy_from_slice(&600i32.to_le_bytes());
        data[24..28].copy_from_slice(&7i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let entry = PartitionTableEntry::new(&mut reader).unwrap();
        let entry_clone = entry.clone();

        assert_eq!(entry.get_name(), entry_clone.get_name());
        assert_eq!(entry.get_start(), entry_clone.get_start());
        assert_eq!(entry.get_length(), entry_clone.get_length());
        assert_eq!(entry.get_flags(), entry_clone.get_flags());
    }
}
