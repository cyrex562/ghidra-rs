use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents a FIXUP debug directory element.
///
/// Mirrors the `DebugFixupElement` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// A possible implementation of the FIXUP debug directory elements.
/// It may be inaccurate and/or incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugFixupElement {
    /// The FIXUP element type.
    type_val: u32,
    /// The first address of this FIXUP element.
    addr1: u32,
    /// The second address of this FIXUP element.
    addr2: u32,
}

impl DebugFixupElement {
    /// The size of a FIXUP element, in bytes.
    pub const SIZEOF: usize = 12;

    /// Creates a new `DebugFixupElement` by reading from the given binary reader at the
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
        let type_val = reader.read_int(index)? as u32;
        let addr1 = reader.read_int(index + 4)? as u32;
        let addr2 = reader.read_int(index + 8)? as u32;

        Ok(DebugFixupElement {
            type_val,
            addr1,
            addr2,
        })
    }

    /// Returns the FIXUP element type.
    pub fn type_val(&self) -> u32 {
        self.type_val
    }

    /// Returns the first address of this FIXUP element.
    pub fn addr1(&self) -> u32 {
        self.addr1
    }

    /// Returns the second address of this FIXUP element.
    pub fn addr2(&self) -> u32 {
        self.addr2
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
            0x01, 0x02, 0x03, 0x04, // type: 0x04030201 (LE)
            0x11, 0x12, 0x13, 0x14, // addr1: 0x14131211 (LE)
            0x21, 0x22, 0x23, 0x24, // addr2: 0x24232221 (LE)
        ];

        let reader = MockReader::new(data, true);
        let elem = DebugFixupElement::new(&reader, 0).expect("failed to read");

        assert_eq!(elem.type_val(), 0x04030201);
        assert_eq!(elem.addr1(), 0x14131211);
        assert_eq!(elem.addr2(), 0x24232221);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x01, 0x02, 0x03, 0x04, // type: 0x01020304 (BE)
            0x11, 0x12, 0x13, 0x14, // addr1: 0x11121314 (BE)
            0x21, 0x22, 0x23, 0x24, // addr2: 0x21222324 (BE)
        ];

        let reader = MockReader::new(data, false);
        let elem = DebugFixupElement::new(&reader, 0).expect("failed to read");

        assert_eq!(elem.type_val(), 0x01020304);
        assert_eq!(elem.addr1(), 0x11121314);
        assert_eq!(elem.addr2(), 0x21222324);
    }

    #[test]
    fn structure_size_is_12_bytes() {
        assert_eq!(DebugFixupElement::SIZEOF, 12);
    }

    #[test]
    fn zero_values() {
        let data = vec![0; 12];
        let reader = MockReader::new(data, true);
        let elem = DebugFixupElement::new(&reader, 0).expect("failed to read");

        assert_eq!(elem.type_val(), 0);
        assert_eq!(elem.addr1(), 0);
        assert_eq!(elem.addr2(), 0);
    }

    #[test]
    fn max_values() {
        let data = vec![0xFF; 12];
        let reader = MockReader::new(data, true);
        let elem = DebugFixupElement::new(&reader, 0).expect("failed to read");

        assert_eq!(elem.type_val(), 0xFFFFFFFF);
        assert_eq!(elem.addr1(), 0xFFFFFFFF);
        assert_eq!(elem.addr2(), 0xFFFFFFFF);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0xAA, 0xBB, 0xCC, 0xDD,             // type at offset 6
            0x11, 0x22, 0x33, 0x44,             // addr1 at offset 10
            0x55, 0x66, 0x77, 0x88,             // addr2 at offset 14
        ];

        let reader = MockReader::new(data, true);
        let elem = DebugFixupElement::new(&reader, 6).expect("failed to read");

        assert_eq!(elem.type_val(), 0xDDCCBBAA);
        assert_eq!(elem.addr1(), 0x44332211);
        assert_eq!(elem.addr2(), 0x88776655);
    }

    #[test]
    fn clone_equality() {
        let data = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let reader = MockReader::new(data, true);
        let elem1 = DebugFixupElement::new(&reader, 0).expect("failed to read");
        let elem2 = elem1.clone();

        assert_eq!(elem1, elem2);
    }

    #[test]
    fn independent_clones_equal() {
        let data = vec![
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
        ];
        let reader = MockReader::new(data.clone(), true);
        let elem1 = DebugFixupElement::new(&reader, 0).expect("failed to read");

        let reader2 = MockReader::new(data, true);
        let elem2 = DebugFixupElement::new(&reader2, 0).expect("failed to read");

        assert_eq!(elem1, elem2);
    }
}
