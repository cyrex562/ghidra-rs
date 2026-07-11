use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) alignment symbol.
///
/// Mirrors the `OMFAlignSym` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfAlignSym {
    /// The alignment padding length.
    length: i16,
    /// The alignment padding bytes.
    pad: Vec<u8>,
}

impl OmfAlignSym {
    /// Creates a new `OmfAlignSym` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `index` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, index: u64) -> io::Result<Self> {
        let length = reader.read_short(index)? as i16;
        let pad = reader.read_byte_array(index + 2, length as usize)?;

        Ok(OmfAlignSym { length, pad })
    }

    /// Returns the alignment padding bytes.
    pub fn pad(&self) -> &[u8] {
        &self.pad
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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
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
    fn read_structure_little_endian() {
        let data = vec![
            0x03, 0x00, // length = 3 (little endian)
            0xAA, 0xBB, 0xCC, // pad = [0xAA, 0xBB, 0xCC]
        ];

        let reader = MockReader::new(data, true);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 3);
        assert_eq!(align_sym.pad(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x02, // length = 2 (big endian)
            0x11, 0x22, // pad = [0x11, 0x22]
        ];

        let reader = MockReader::new(data, false);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 2);
        assert_eq!(align_sym.pad(), &[0x11, 0x22]);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x02, 0x00,             // length = 2 at offset 4
            0x55, 0x66,             // pad at offset 6
        ];

        let reader = MockReader::new(data, true);
        let align_sym = OmfAlignSym::new(&reader, 4).expect("failed to read");

        assert_eq!(align_sym.length, 2);
        assert_eq!(align_sym.pad(), &[0x55, 0x66]);
    }

    #[test]
    fn zero_length_padding() {
        let data = vec![
            0x00, 0x00, // length = 0
        ];

        let reader = MockReader::new(data, true);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 0);
        assert!(align_sym.pad().is_empty());
    }

    #[test]
    fn clone_equality() {
        let data = vec![
            0x02, 0x00,
            0xDE, 0xAD,
        ];

        let reader = MockReader::new(data, true);
        let align_sym1 = OmfAlignSym::new(&reader, 0).expect("failed to read");
        let align_sym2 = align_sym1.clone();

        assert_eq!(align_sym1, align_sym2);
    }
}
