use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents a User Data Record.
///
/// See: <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>
pub struct BTreeUserDataRecord {
    unused: Vec<u8>,
}

impl BTreeUserDataRecord {
    pub(crate) fn new(reader: &mut GBinaryReader) -> io::Result<Self> {
        Ok(BTreeUserDataRecord {
            unused: reader.read_next_byte_array(128)?,
        })
    }

    pub fn get_unused(&self) -> &[u8] {
        &self.unused
    }
}

#[cfg(test)]
mod tests {
    use super::BTreeUserDataRecord;
    use crate::filesystem::ghidra::g_binary_reader::{ByteProvider, GBinaryReader};
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

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

    fn reader(data: Vec<u8>) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecProvider(data))), false)
    }

    #[test]
    fn reads_128_byte_unused_field() {
        let data = vec![42u8; 128];
        let mut r = reader(data.clone());
        let record = BTreeUserDataRecord::new(&mut r).unwrap();

        assert_eq!(record.get_unused(), &data[..]);
    }

    #[test]
    fn errors_on_truncated_input() {
        let data = vec![42u8; 64];
        let mut r = reader(data);

        assert!(BTreeUserDataRecord::new(&mut r).is_err());
    }

    #[test]
    fn reads_exact_128_bytes() {
        let mut data = vec![42u8; 128];
        data.push(99); // extra byte that should not be read
        let mut r = reader(data);
        let record = BTreeUserDataRecord::new(&mut r).unwrap();

        assert_eq!(record.get_unused().len(), 128);
        assert_eq!(record.get_unused()[0], 42);
    }
}
