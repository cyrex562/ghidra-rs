use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Represents a SOM DLT (Dynamic Link Table) entry.
///
/// Mirrors `ghidra.app.util.bin.format.som.SomDltEntry`.
///
/// Reference: The 32-bit PA-RISC Run-time Architecture Document (rad_11_0_32.pdf)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomDltEntry {
    value: i32,
}

impl SomDltEntry {
    /// The size of a SomDltEntry in bytes.
    pub const SIZE: u64 = 4;

    /// Creates a new `SomDltEntry` by reading from the given binary reader.
    ///
    /// Reads a single 32-bit integer from the reader at the current position.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_int()?;
        Ok(SomDltEntry { value })
    }

    /// Returns the value of the DLT entry.
    pub fn value(&self) -> i32 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn size_constant() {
        assert_eq!(SomDltEntry::SIZE, 4);
    }

    #[test]
    fn reads_positive_value() {
        let data = (0x12345678i32).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0x12345678);
    }

    #[test]
    fn reads_zero() {
        let data = (0i32).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0);
    }

    #[test]
    fn reads_negative_value() {
        let data = (-1i32).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), -1);
    }

    #[test]
    fn reads_max_value() {
        let data = (i32::MAX).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), i32::MAX);
    }

    #[test]
    fn reads_min_value() {
        let data = (i32::MIN).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), i32::MIN);
    }

    #[test]
    fn advances_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(42i32).to_le_bytes());
        data.push(0x99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = SomDltEntry::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_offset() {
        let mut data = vec![0u8; 2];
        data.extend_from_slice(&(0xDEADBEEFu32 as i32).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(2);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0xDEADBEEFu32 as i32);
    }

    #[test]
    fn copy_and_equality() {
        let data = (123i32).to_le_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data.clone(), true);
        let entry1 = SomDltEntry::new(&mut r).unwrap();
        let entry2 = entry1;

        assert_eq!(entry1, entry2);
        assert_eq!(entry1.value(), entry2.value());
    }

    #[test]
    fn big_endian_reads() {
        let data = (0xABCDEF00u32 as i32).to_be_bytes().to_vec();
        let mut r = BinaryReader::from_bytes(data, true);
        r.set_little_endian(false);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0xABCDEF00u32 as i32);
    }
}
