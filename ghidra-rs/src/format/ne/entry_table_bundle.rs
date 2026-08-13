use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::EntryPoint;
use std::io;

/// Marker denoting an unused entry table bundle.
pub const UNUSED: i8 = 0x00;
/// Segment is moveable.
pub const MOVEABLE: i8 = 0xffu8 as i8;
/// Refers to a constant defined in module.
pub const CONSTANT: i8 = 0xfeu8 as i8;

/// Represents a new-executable (NE) entry table bundle.
///
/// Mirrors `EntryTableBundle` from the original Ghidra Java source.
pub struct EntryTableBundle {
    count: i8,
    r#type: i8,
    /// `None` mirrors the Java `null` left in place when the bundle is unused (`count == 0`) or
    /// the type byte itself is unused (`type == 0`).
    entry_points: Option<Vec<EntryPoint>>,
}

impl EntryTableBundle {
    /// Constructs a new entry table bundle by reading it from `reader`.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let count = reader.read_next_byte()? as i8;
        if count == 0 {
            // do not read anymore data...
            return Ok(EntryTableBundle {
                count,
                r#type: 0,
                entry_points: None,
            });
        }

        let r#type = reader.read_next_byte()? as i8;
        if r#type == 0 {
            // unused bundle...
            return Ok(EntryTableBundle {
                count,
                r#type,
                entry_points: None,
            });
        }

        let count_int = count as u8 as usize;
        let is_moveable = r#type == MOVEABLE;

        let mut entry_points = Vec::with_capacity(count_int);
        for _ in 0..count_int {
            entry_points.push(EntryPoint::new(reader, is_moveable)?);
        }

        Ok(EntryTableBundle {
            count,
            r#type,
            entry_points: Some(entry_points),
        })
    }

    /// Returns true if this bundle is moveable.
    pub fn is_moveable(&self) -> bool {
        self.r#type == MOVEABLE
    }

    /// Returns true if this bundle is constant.
    pub fn is_constant(&self) -> bool {
        self.r#type == CONSTANT
    }

    /// Returns the number of entries in bundle.
    pub fn get_count(&self) -> i8 {
        self.count
    }

    /// Returns the type of the bundle. For example, MOVEABLE, CONSTANT, or segment index.
    pub fn get_type(&self) -> i8 {
        self.r#type
    }

    /// Returns the entry points in this bundle, or `None` if the bundle is unused.
    pub fn get_entry_points(&self) -> Option<&[EntryPoint]> {
        self.entry_points.as_deref()
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
    fn unused_bundle_stops_after_count_byte() {
        let data = vec![0x00u8];
        let mut reader = MockReader::new(data);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 0);
        assert_eq!(bundle.get_type(), 0);
        assert!(bundle.get_entry_points().is_none());
        assert!(!bundle.is_moveable());
        assert!(!bundle.is_constant());
    }

    #[test]
    fn unused_type_stops_after_type_byte() {
        let data = vec![0x02u8, 0x00u8];
        let mut reader = MockReader::new(data);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 2);
        assert_eq!(bundle.get_type(), 0);
        assert!(bundle.get_entry_points().is_none());
    }

    #[test]
    fn reads_constant_bundle_entry_points() {
        // count = 2, type = CONSTANT (0xfe); non-moveable entries only have flagword + offset.
        let data = vec![
            0x02, 0xfe, // count, type
            0x01, 0x10, 0x00, // entry 1: flagword=1, offset=0x0010
            0x02, 0x20, 0x00, // entry 2: flagword=2, offset=0x0020
        ];
        let mut reader = MockReader::new(data);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 2);
        assert_eq!(bundle.get_type(), CONSTANT);
        assert!(bundle.is_constant());
        assert!(!bundle.is_moveable());

        let entries = bundle.get_entry_points().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get_flagword(), 1);
        assert_eq!(entries[0].get_offset(), 0x0010);
        assert_eq!(entries[1].get_flagword(), 2);
        assert_eq!(entries[1].get_offset(), 0x0020);
    }

    #[test]
    fn reads_moveable_bundle_entry_points() {
        // count = 1, type = MOVEABLE (0xff); moveable entries also read instruction + segment.
        let data = vec![
            0x01, 0xff, // count, type
            0x03, 0xAA, 0xBB, 0x05, 0x30, 0x00, // flagword, instruction, segment, offset
        ];
        let mut reader = MockReader::new(data);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert!(bundle.is_moveable());
        let entries = bundle.get_entry_points().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get_flagword(), 3);
        assert_eq!(entries[0].get_instruction(), i16::from_le_bytes([0xAA, 0xBB]));
        assert_eq!(entries[0].get_segment(), 5);
        assert_eq!(entries[0].get_offset(), 0x0030);
    }
}
