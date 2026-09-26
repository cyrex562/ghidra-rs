use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::util::task::TaskMonitor;

/// Bit masks for each of the 32 bit positions within a dense integer array element, indexed by
/// `val & 0x1f`. Mirrors the Java source's `bitMask` table verbatim, including its duplicate
/// entries at indices 10/14 and 11/15.
const BIT_MASK: [i32; 32] = [
    0x0000_0001,
    0x0000_0002,
    0x0000_0004,
    0x0000_0008,
    0x0000_0010,
    0x0000_0020,
    0x0000_0040,
    0x0000_0080,
    0x0000_0100,
    0x0000_0200,
    0x0000_4000,
    0x0000_8000,
    0x0000_1000,
    0x0000_2000,
    0x0000_4000,
    0x0000_8000,
    0x0001_0000,
    0x0002_0000,
    0x0004_0000,
    0x0008_0000,
    0x0010_0000,
    0x0020_0000,
    0x0040_0000,
    0x0080_0000,
    0x0100_0000u32 as i32,
    0x0200_0000u32 as i32,
    0x0400_0000u32 as i32,
    0x0800_0000u32 as i32,
    0x1000_0000u32 as i32,
    0x2000_0000u32 as i32,
    0x4000_0000u32 as i32,
    0x8000_0000u32 as i32,
];

/// This struct represents the Dense Integer Array component of a PDB file. This struct is only
/// suitable for reading; not for writing or modifying a PDB.
///
/// We have intended to implement according to the Microsoft PDB API (source); see the API for
/// truth.
#[derive(Debug, Clone, Default)]
pub struct DenseIntegerArray {
    array: Vec<i32>,
}

impl DenseIntegerArray {
    /// Creates a new, empty `DenseIntegerArray`.
    pub fn new() -> Self {
        DenseIntegerArray::default()
    }

    /// Deserializes this `DenseIntegerArray`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse, or upon user cancellation.
    pub fn parse(
        &mut self,
        reader: &mut PdbByteReader,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), PdbException> {
        self.array.clear();
        let array_size = reader.parse_int()?;
        for _ in 0..array_size {
            monitor.check_cancelled().map_err(|e| PdbException::new(e.0))?;
            let val = reader.parse_int()?;
            self.array.push(val);
        }
        Ok(())
    }

    /// Returns whether the dense integer array contains the argument val.
    pub fn contains(&self, val: i32) -> bool {
        if val <= 0 {
            return false;
        }
        let index = (val >> 5) as usize;
        let bit = (val & 0x1f) as usize;
        index < self.array.len() && (self.array[index] & BIT_MASK[bit]) != 0
    }

    /// Returns the maximum value allowed in the array. Minimum value is zero.
    pub fn get_max_possible(&self) -> i64 {
        32i64 * self.array.len() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn new_array_is_empty() {
        let array = DenseIntegerArray::new();
        assert_eq!(array.get_max_possible(), 0);
        assert!(!array.contains(1));
    }

    #[test]
    fn parse_reads_declared_number_of_ints() {
        let bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // arraySize = 2
            0x01, 0x00, 0x00, 0x00, // array[0] = 1 (bit 1 set)
            0x00, 0x00, 0x00, 0x00, // array[1] = 0
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let mut array = DenseIntegerArray::new();
        array.parse(&mut reader, &monitor).unwrap();
        assert_eq!(array.get_max_possible(), 64);
    }

    #[test]
    fn parse_clears_previous_contents() {
        let mut array = DenseIntegerArray::new();
        let first_bytes: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(first_bytes);
        let monitor = DummyMonitor;
        array.parse(&mut reader, &monitor).unwrap();
        assert_eq!(array.get_max_possible(), 32);

        let second_bytes: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(second_bytes);
        array.parse(&mut reader, &monitor).unwrap();
        assert_eq!(array.get_max_possible(), 0);
    }

    #[test]
    fn parse_insufficient_data_returns_error() {
        let bytes: Vec<u8> = vec![0x05, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let mut array = DenseIntegerArray::new();
        assert!(array.parse(&mut reader, &monitor).is_err());
    }

    #[test]
    fn contains_rejects_non_positive_values() {
        let array = DenseIntegerArray::new();
        assert!(!array.contains(0));
        assert!(!array.contains(-1));
    }

    #[test]
    fn contains_checks_bit_within_word() {
        // val = 33 -> index 1, bit 1 -> BIT_MASK[1] = 0x2
        let bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // arraySize = 2
            0x00, 0x00, 0x00, 0x00, // array[0] = 0
            0x02, 0x00, 0x00, 0x00, // array[1] = 0x2 (bit 1 set)
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let mut array = DenseIntegerArray::new();
        array.parse(&mut reader, &monitor).unwrap();
        assert!(array.contains(33));
        assert!(!array.contains(32));
        assert!(!array.contains(34));
    }

    #[test]
    fn contains_out_of_bounds_index_is_false() {
        let bytes: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let mut array = DenseIntegerArray::new();
        array.parse(&mut reader, &monitor).unwrap();
        assert!(!array.contains(1));
    }

    #[test]
    fn contains_high_bit_value() {
        // val = 31 -> index 0, bit 31 -> BIT_MASK[31] = 0x8000_0000 (as i32)
        let bytes: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x00, // arraySize = 1
            0x00, 0x00, 0x00, 0x80, // array[0] = 0x80000000
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let mut array = DenseIntegerArray::new();
        array.parse(&mut reader, &monitor).unwrap();
        assert!(array.contains(31));
    }
}
