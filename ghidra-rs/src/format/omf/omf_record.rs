use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// The common data held by every OMF record.
///
/// Mirrors Ghidra's `OmfRecord` abstract class. Ghidra's `parseData()` and `toDataType()`
/// abstract methods are type-specific and are implemented by the concrete OMF record types
/// that build on top of this struct.
pub struct OmfRecord {
    record_type: i32,
    record_length: i32,
    data: Vec<u8>,
    check_sum: i8,
    record_offset: u64,
    data_reader: Option<Box<dyn BinaryReader>>,
    data_end: u64,
}

impl OmfRecord {
    /// Creates a new [`OmfRecord`] by reading its common fields from `reader`, which must be
    /// positioned at the start of the record.
    ///
    /// # Errors
    /// Returns `Err` if there was an IO-related error.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let record_offset = reader.get_pointer_index();

        let record_type = reader.read_next_unsigned_byte()? as i32;
        let record_length = reader.read_next_unsigned_short()? as i32;
        let data = reader.read_next_byte_array((record_length - 1) as usize)?;
        let check_sum = reader.read_next_byte()? as i8;

        let data_reader = reader.clone_at(record_offset + 3);
        let data_end = record_offset + 3 + record_length as u64 - 1;

        Ok(Self {
            record_type,
            record_length,
            data,
            check_sum,
            record_offset,
            data_reader: Some(data_reader),
            data_end,
        })
    }

    /// Returns the record type.
    pub fn record_type(&self) -> i32 {
        self.record_type
    }

    /// Returns the record length.
    pub fn record_length(&self) -> i32 {
        self.record_length
    }

    /// Returns the record offset.
    pub fn record_offset(&self) -> u64 {
        self.record_offset
    }

    /// Returns the record checksum.
    pub fn record_checksum(&self) -> i8 {
        self.check_sum
    }

    /// Returns the record data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a reader positioned at the start of the record's type-specific data, if one is
    /// set.
    pub fn data_reader_mut(&mut self) -> Option<&mut (dyn BinaryReader + 'static)> {
        self.data_reader.as_deref_mut()
    }

    /// Returns the offset immediately following the record's type-specific data.
    pub fn data_end(&self) -> u64 {
        self.data_end
    }

    /// Computes the record's checksum.
    pub fn calc_check_sum(&self) -> i8 {
        let mut sum = self.record_type as i8;
        sum = sum
            .wrapping_add(self.record_length as i8)
            .wrapping_add((self.record_length >> 8) as i8);
        for &b in &self.data {
            sum = sum.wrapping_add(b as i8);
        }
        sum.wrapping_add(self.check_sum)
    }

    /// Returns true if the record's checksum is valid; otherwise, false.
    pub fn valid_check_sum(&self) -> bool {
        if self.check_sum == 0 {
            // Some compilers just set this to zero
            return true;
        }
        self.calc_check_sum() == 0
    }

    /// Returns true if this record has big fields; otherwise, false.
    pub fn has_big_fields(&self) -> bool {
        (self.record_type & 1) != 0
    }
}

impl Default for OmfRecord {
    fn default() -> Self {
        Self {
            record_type: 0,
            record_length: 0,
            data: Vec::new(),
            check_sum: 0,
            record_offset: 0,
            data_reader: None,
            data_end: 0,
        }
    }
}

impl fmt::Display for OmfRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "type: 0x{:x}, offset: 0x{:x}, length: 0x{:x}",
            self.record_type, self.record_offset, self.record_length
        )
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

    fn build_record_bytes(record_type: u8, payload: &[u8], check_sum: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(record_type);
        let record_length = (payload.len() + 1) as u16;
        bytes.extend_from_slice(&record_length.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.push(check_sum);
        bytes
    }

    #[test]
    fn new_reads_common_fields() {
        let bytes = build_record_bytes(0x80, &[0xDE, 0xAD, 0xBE, 0xEF], 0x00);
        let mut r = MockReader::new(bytes);

        let record = OmfRecord::new(&mut r).unwrap();

        assert_eq!(record.record_type(), 0x80);
        assert_eq!(record.record_length(), 5);
        assert_eq!(record.record_offset(), 0);
        assert_eq!(record.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(record.record_checksum(), 0);
        assert_eq!(record.data_end(), 3 + 5 - 1);
    }

    #[test]
    fn new_reads_from_nonzero_offset() {
        let mut bytes = vec![0xFF, 0xFF, 0xFF]; // leading padding
        bytes.extend(build_record_bytes(0x01, &[0x42], 0x00));
        let mut r = MockReader::new(bytes);
        r.set_pointer_index(3);

        let record = OmfRecord::new(&mut r).unwrap();

        assert_eq!(record.record_offset(), 3);
        assert_eq!(record.record_type(), 0x01);
        assert_eq!(record.data(), &[0x42]);
        assert_eq!(record.data_end(), 3 + 3 + 2 - 1);
    }

    #[test]
    fn data_reader_is_positioned_after_header() {
        let bytes = build_record_bytes(0x80, &[0xAA, 0xBB], 0x00);
        let mut r = MockReader::new(bytes);

        let mut record = OmfRecord::new(&mut r).unwrap();
        let data_reader = record.data_reader_mut().unwrap();

        assert_eq!(data_reader.get_pointer_index(), 3);
        assert_eq!(data_reader.read_next_byte().unwrap(), 0xAA);
    }

    #[test]
    fn valid_check_sum_true_when_zero() {
        let bytes = build_record_bytes(0x80, &[0x01, 0x02], 0x00);
        let mut r = MockReader::new(bytes);
        let record = OmfRecord::new(&mut r).unwrap();
        assert!(record.valid_check_sum());
    }

    #[test]
    fn valid_check_sum_matches_calculated_checksum() {
        let mut r = MockReader::new(build_record_bytes(0x80, &[0x01, 0x02], 0x00));
        let record = OmfRecord::new(&mut r).unwrap();
        let calc = record.calc_check_sum();

        let checksum_byte = (0u8.wrapping_sub(calc as u8)) as i8;
        let mut r2 = MockReader::new(build_record_bytes(0x80, &[0x01, 0x02], checksum_byte as u8));
        let record2 = OmfRecord::new(&mut r2).unwrap();

        assert!(record2.valid_check_sum());
    }

    #[test]
    fn invalid_check_sum_detected() {
        let mut r = MockReader::new(build_record_bytes(0x80, &[0x01, 0x02], 0x05));
        let record = OmfRecord::new(&mut r).unwrap();
        assert!(!record.valid_check_sum());
    }

    #[test]
    fn has_big_fields_checks_low_bit() {
        let mut r = MockReader::new(build_record_bytes(0x01, &[], 0x00));
        let record = OmfRecord::new(&mut r).unwrap();
        assert!(record.has_big_fields());

        let mut r2 = MockReader::new(build_record_bytes(0x02, &[], 0x00));
        let record2 = OmfRecord::new(&mut r2).unwrap();
        assert!(!record2.has_big_fields());
    }

    #[test]
    fn display_formats_type_offset_length() {
        let mut r = MockReader::new(build_record_bytes(0x0A, &[0x01], 0x00));
        let record = OmfRecord::new(&mut r).unwrap();
        assert_eq!(record.to_string(), "type: 0xa, offset: 0x0, length: 0x2");
    }

    #[test]
    fn default_yields_zeroed_record() {
        let record = OmfRecord::default();
        assert_eq!(record.record_type(), 0);
        assert_eq!(record.record_length(), 0);
        assert_eq!(record.record_offset(), 0);
        assert_eq!(record.record_checksum(), 0);
        assert!(record.data().is_empty());
        assert_eq!(record.data_end(), 0);
        assert!(record.valid_check_sum());
    }
}
