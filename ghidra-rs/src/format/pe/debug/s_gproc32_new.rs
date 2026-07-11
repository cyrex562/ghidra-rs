use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a global procedure start symbol (S_GPROC32_NEW) in CodeView format.
///
/// Mirrors the `S_GPROC32_NEW` Java class in `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGproc32New {
    base: DebugSymbolBase,
    parent: i32,
    end: i32,
    next: i32,
    proc_len: i32,
    debug_start: i32,
    debug_end: i32,
    proc_offset: i32,
    proc_type: i16,
}

impl SGproc32New {
    /// Creates a new `SGproc32New` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `length` - The record length.
    /// * `symbol_type` - The record type.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(
        reader: &dyn BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        let mut offset = ptr;

        let parent = reader.read_int(offset)?;
        offset += 4;

        let end = reader.read_int(offset)?;
        offset += 4;

        let next = reader.read_int(offset)?;
        offset += 4;

        let proc_len = reader.read_int(offset)?;
        offset += 4;

        let debug_start = reader.read_int(offset)?;
        offset += 4;

        let debug_end = reader.read_int(offset)?;
        offset += 4;

        base.offset = reader.read_int(offset)?;
        offset += 4;

        let proc_offset = reader.read_int(offset)?;
        offset += 4;

        base.section = reader.read_short(offset)?;
        offset += 2;

        let proc_type = reader.read_short(offset)?;
        offset += 2;

        base.name = reader.read_ascii_string(offset)?;

        Ok(SGproc32New {
            base,
            parent,
            end,
            next,
            proc_len,
            debug_start,
            debug_end,
            proc_offset,
            proc_type,
        })
    }

    /// Returns the parent offset.
    pub fn parent(&self) -> i32 {
        self.parent
    }

    /// Returns the end offset.
    pub fn end(&self) -> i32 {
        self.end
    }

    /// Returns the next offset.
    pub fn next(&self) -> i32 {
        self.next
    }

    /// Returns the debug start offset.
    pub fn debug_start(&self) -> i32 {
        self.debug_start
    }

    /// Returns the debug end offset.
    pub fn debug_end(&self) -> i32 {
        self.debug_end
    }

    /// Returns the procedure length.
    pub fn proc_len(&self) -> i32 {
        self.proc_len
    }

    /// Returns the procedure type.
    pub fn proc_type(&self) -> i16 {
        self.proc_type
    }

    /// Returns the procedure offset.
    pub fn proc_offset(&self) -> i32 {
        self.proc_offset
    }
}

impl DebugSymbol for SGproc32New {
    fn length(&self) -> i16 {
        self.base.length()
    }

    fn symbol_type(&self) -> i16 {
        self.base.symbol_type()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    fn section(&self) -> i16 {
        self.base.section()
    }

    fn offset(&self) -> i32 {
        self.base.offset()
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
            let prev = self.current_index;
            self.current_index = index;
            prev
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

    fn build_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&1i32.to_le_bytes()); // parent
        data.extend_from_slice(&2i32.to_le_bytes()); // end
        data.extend_from_slice(&3i32.to_le_bytes()); // next
        data.extend_from_slice(&4i32.to_le_bytes()); // proc_len
        data.extend_from_slice(&5i32.to_le_bytes()); // debug_start
        data.extend_from_slice(&6i32.to_le_bytes()); // debug_end
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes()); // offset
        data.extend_from_slice(&7i32.to_le_bytes()); // proc_offset
        data.extend_from_slice(&8i16.to_le_bytes()); // section
        data.extend_from_slice(&9i16.to_le_bytes()); // proc_type
        data.extend_from_slice(b"main\0"); // name
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let reader = MockReader::new(build_data(), true);
        let sym = SGproc32New::new(&reader, 40, 0x0022, 0).unwrap();

        assert_eq!(sym.length(), 40);
        assert_eq!(sym.symbol_type(), 0x0022);
        assert_eq!(sym.parent(), 1);
        assert_eq!(sym.end(), 2);
        assert_eq!(sym.next(), 3);
        assert_eq!(sym.proc_len(), 4);
        assert_eq!(sym.debug_start(), 5);
        assert_eq!(sym.debug_end(), 6);
        assert_eq!(sym.offset(), 0x1000_0000);
        assert_eq!(sym.proc_offset(), 7);
        assert_eq!(sym.section(), 8);
        assert_eq!(sym.proc_type(), 9);
        assert_eq!(sym.name(), "main");
    }

    #[test]
    fn name_is_read_as_null_terminated_string() {
        let mut data = build_data();
        data.extend_from_slice(b"extra"); // extra data that shouldn't be read

        let reader = MockReader::new(data, true);
        let sym = SGproc32New::new(&reader, 40, 0x0022, 0).unwrap();

        assert_eq!(sym.name(), "main");
    }

    #[test]
    fn trait_object_dispatch() {
        let reader = MockReader::new(build_data(), true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SGproc32New::new(&reader, 40, 0x0022, 0).unwrap());

        assert_eq!(sym.length(), 40);
        assert_eq!(sym.symbol_type(), 0x0022);
        assert_eq!(sym.offset(), 0x1000_0000);
        assert_eq!(sym.section(), 8);
        assert_eq!(sym.name(), "main");
    }

    #[test]
    fn clone_equality() {
        let reader = MockReader::new(build_data(), true);
        let sym = SGproc32New::new(&reader, 40, 0x0022, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_offset_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&(-1i32).to_le_bytes()); // offset
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let reader = MockReader::new(data, true);
        let sym = SGproc32New::new(&reader, 10, 0, 0).unwrap();

        assert_eq!(sym.offset(), -1);
        assert_eq!(sym.name(), "");
    }
}
