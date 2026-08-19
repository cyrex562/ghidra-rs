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
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
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
    fn size_constant() {
        assert_eq!(SomDltEntry::SIZE, 4);
    }

    #[test]
    fn reads_positive_value() {
        let data = (0x12345678i32).to_le_bytes().to_vec();
        let mut r = MockReader::new(data);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0x12345678);
    }

    #[test]
    fn reads_zero() {
        let data = (0i32).to_le_bytes().to_vec();
        let mut r = MockReader::new(data);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0);
    }

    #[test]
    fn reads_negative_value() {
        let data = (-1i32).to_le_bytes().to_vec();
        let mut r = MockReader::new(data);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), -1);
    }

    #[test]
    fn reads_max_value() {
        let data = (i32::MAX).to_le_bytes().to_vec();
        let mut r = MockReader::new(data);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), i32::MAX);
    }

    #[test]
    fn reads_min_value() {
        let data = (i32::MIN).to_le_bytes().to_vec();
        let mut r = MockReader::new(data);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), i32::MIN);
    }

    #[test]
    fn advances_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(42i32).to_le_bytes());
        data.push(0x99);

        let mut r = MockReader::new(data);
        let _ = SomDltEntry::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_offset() {
        let mut data = vec![0u8; 2];
        data.extend_from_slice(&(0xDEADBEEFu32 as i32).to_le_bytes());

        let mut r = MockReader::new(data);
        r.set_pointer_index(2);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0xDEADBEEFu32 as i32);
    }

    #[test]
    fn copy_and_equality() {
        let data = (123i32).to_le_bytes().to_vec();
        let mut r = MockReader::new(data.clone());
        let entry1 = SomDltEntry::new(&mut r).unwrap();
        let entry2 = entry1;

        assert_eq!(entry1, entry2);
        assert_eq!(entry1.value(), entry2.value());
    }

    #[test]
    fn big_endian_reads() {
        let data = (0xABCDEF00u32 as i32).to_be_bytes().to_vec();
        let mut r = MockReader::new(data);
        r.set_little_endian(false);
        let entry = SomDltEntry::new(&mut r).unwrap();

        assert_eq!(entry.value(), 0xABCDEF00u32 as i32);
    }
}
