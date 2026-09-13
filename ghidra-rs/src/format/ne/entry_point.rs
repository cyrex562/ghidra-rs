use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Represents a new-executable (NE) entry point.
///
/// Mirrors `EntryPoint` from the original Ghidra Java source.
///
/// The Java constructor takes a back-reference to the owning
/// [`EntryTableBundle`](super::entry_table_bundle::EntryTableBundle) solely to query
/// `isMoveable()`, which is fixed by the time any `EntryPoint` is constructed. This port takes
/// that flag directly instead of an owning back-reference, avoiding an ownership cycle with
/// `EntryTableBundle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    flagword: i8,
    instruction: i16,
    segment: i8,
    offset: i16,
    is_moveable: bool,
}

impl EntryPoint {
    /// Exported entry point flag.
    pub const EXPORTED: i8 = 0x01;
    /// Global entry point flag.
    pub const GLOBAL: i8 = 0x02;

    /// Constructs a new entry point given a binary reader and whether the owning entry table
    /// bundle is moveable.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader, is_moveable: bool) -> io::Result<Self> {
        let flagword = reader.read_next_byte()? as i8;

        let mut instruction = 0i16;
        let mut segment = 0i8;
        if is_moveable {
            instruction = reader.read_next_short()?;
            segment = reader.read_next_byte()? as i8;
        }

        let offset = reader.read_next_short()?;

        Ok(EntryPoint {
            flagword,
            instruction,
            segment,
            offset,
            is_moveable,
        })
    }

    /// Returns the flagword.
    pub fn get_flagword(&self) -> i8 {
        self.flagword
    }

    /// Returns the instruction.
    ///
    /// # Panics
    /// Panics if this entry point is not moveable, mirroring the Java
    /// `RuntimeException("Entry point is not moveable!")`.
    pub fn get_instruction(&self) -> i16 {
        assert!(self.is_moveable, "Entry point is not moveable!");
        self.instruction
    }

    /// Returns the segment.
    ///
    /// # Panics
    /// Panics if this entry point is not moveable, mirroring the Java
    /// `RuntimeException("Entry point is not moveable!")`.
    pub fn get_segment(&self) -> i8 {
        assert!(self.is_moveable, "Entry point is not moveable!");
        self.segment
    }

    /// Returns the offset.
    pub fn get_offset(&self) -> i16 {
        self.offset
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
    fn reads_non_moveable_entry_point() {
        // flagword=0x01 (EXPORTED), offset=0x1234; no instruction/segment for non-moveable.
        let data = vec![0x01, 0x34, 0x12];
        let mut reader = MockReader::new(data);

        let ep = EntryPoint::new(&mut reader, false).unwrap();

        assert_eq!(ep.get_flagword(), EntryPoint::EXPORTED);
        assert_eq!(ep.get_offset(), 0x1234);
        assert_eq!(reader.get_pointer_index(), 3);
    }

    #[test]
    fn reads_moveable_entry_point() {
        // flagword=0x02 (GLOBAL), instruction=0xBEEF, segment=0x05, offset=0x0010.
        let data = vec![0x02, 0xEF, 0xBE, 0x05, 0x10, 0x00];
        let mut reader = MockReader::new(data);

        let ep = EntryPoint::new(&mut reader, true).unwrap();

        assert_eq!(ep.get_flagword(), EntryPoint::GLOBAL);
        assert_eq!(ep.get_instruction(), i16::from_le_bytes([0xEF, 0xBE]));
        assert_eq!(ep.get_segment(), 5);
        assert_eq!(ep.get_offset(), 0x0010);
        assert_eq!(reader.get_pointer_index(), 6);
    }

    #[test]
    #[should_panic(expected = "Entry point is not moveable!")]
    fn get_instruction_panics_when_not_moveable() {
        let data = vec![0x00, 0x00, 0x00];
        let mut reader = MockReader::new(data);
        let ep = EntryPoint::new(&mut reader, false).unwrap();
        let _ = ep.get_instruction();
    }

    #[test]
    #[should_panic(expected = "Entry point is not moveable!")]
    fn get_segment_panics_when_not_moveable() {
        let data = vec![0x00, 0x00, 0x00];
        let mut reader = MockReader::new(data);
        let ep = EntryPoint::new(&mut reader, false).unwrap();
        let _ = ep.get_segment();
    }

    #[test]
    fn errors_on_truncated_data() {
        let data = vec![0x01]; // missing offset bytes
        let mut reader = MockReader::new(data);
        assert!(EntryPoint::new(&mut reader, false).is_err());
    }
}
