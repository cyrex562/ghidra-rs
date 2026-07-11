use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::DebugSymbol;
use super::debug_symbol_selector::select_symbol;

/// Represents the Object Module Format (OMF) Global data structure.
///
/// Mirrors the `OMFGlobal` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
pub struct OmfGlobal {
    sym_hash: i16,
    addr_hash: i16,
    cb_symbol: i32,
    cb_sym_hash: i32,
    cb_addr_hash: i32,
    symbols: Vec<Box<dyn DebugSymbol>>,
}

impl OmfGlobal {
    /// Creates a new `OmfGlobal` by reading from the given binary reader at the
    /// specified pointer, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, ptr: u64) -> io::Result<Self> {
        let mut index = ptr;

        let sym_hash = reader.read_short(index)?;
        index += 2; // Advance by SIZEOF_SHORT
        let addr_hash = reader.read_short(index)?;
        index += 2; // Advance by SIZEOF_SHORT
        let cb_symbol = reader.read_int(index)?;
        index += 4; // Advance by SIZEOF_INT
        let cb_sym_hash = reader.read_int(index)?;
        index += 4; // Advance by SIZEOF_INT
        let cb_addr_hash = reader.read_int(index)?;
        index += 4; // Advance by SIZEOF_INT

        let mut bytes_left = cb_symbol;
        let mut symbols: Vec<Box<dyn DebugSymbol>> = Vec::new();

        while bytes_left > 0 {
            let sym = select_symbol(reader, index)?;

            index += 4; // Advance by 2 * SIZEOF_SHORT
            bytes_left -= 4;

            if let Some(sym) = sym {
                // Mirrors `Short.toUnsignedInt(sym.getLength())`.
                let rec_len = (sym.length() as u16) as i32;
                symbols.push(sym);

                bytes_left -= rec_len;
                index = index.wrapping_add((rec_len - 2) as u64);
            }
        }

        Ok(OmfGlobal {
            sym_hash,
            addr_hash,
            cb_symbol,
            cb_sym_hash,
            cb_addr_hash,
            symbols,
        })
    }

    /// Returns the address hash value.
    pub fn addr_hash(&self) -> i16 {
        self.addr_hash
    }

    /// Returns the address hash byte count.
    pub fn cb_addr_hash(&self) -> i32 {
        self.cb_addr_hash
    }

    /// Returns the symbol byte count.
    pub fn cb_symbol(&self) -> i32 {
        self.cb_symbol
    }

    /// Returns the symbol hash byte count.
    pub fn cb_sym_hash(&self) -> i32 {
        self.cb_sym_hash
    }

    /// Returns the symbol hash value.
    pub fn sym_hash(&self) -> i16 {
        self.sym_hash
    }

    /// Returns the debug symbols in this OMF Global.
    pub fn symbols(&self) -> &[Box<dyn DebugSymbol>] {
        &self.symbols
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
    fn read_header_with_no_symbols() {
        let data = vec![
            0x01, 0x00, // symHash = 1
            0x02, 0x00, // addrHash = 2
            0x00, 0x00, 0x00, 0x00, // cbSymbol = 0
            0x03, 0x00, 0x00, 0x00, // cbSymHash = 3
            0x04, 0x00, 0x00, 0x00, // cbAddrHash = 4
        ];

        let reader = MockReader::new(data, true);
        let global = OmfGlobal::new(&reader, 0).expect("failed to read");

        assert_eq!(global.sym_hash(), 1);
        assert_eq!(global.addr_hash(), 2);
        assert_eq!(global.cb_symbol(), 0);
        assert_eq!(global.cb_sym_hash(), 3);
        assert_eq!(global.cb_addr_hash(), 4);
        assert!(global.symbols().is_empty());
    }

    #[test]
    fn read_header_with_one_symbol() {
        // S_COMPILE record: length=4, type=0x0001, followed by no extra payload.
        let mut data = vec![
            0x00, 0x00, // symHash = 0
            0x00, 0x00, // addrHash = 0
            0x04, 0x00, 0x00, 0x00, // cbSymbol = 4
            0x00, 0x00, 0x00, 0x00, // cbSymHash = 0
            0x00, 0x00, 0x00, 0x00, // cbAddrHash = 0
        ];
        data.extend_from_slice(&[0x04, 0x00, 0x01, 0x00]); // S_COMPILE record

        let reader = MockReader::new(data, true);
        let global = OmfGlobal::new(&reader, 0).expect("failed to read");

        assert_eq!(global.cb_symbol(), 4);
        assert_eq!(global.symbols().len(), 1);
        assert_eq!(global.symbols()[0].length(), 4);
        assert_eq!(global.symbols()[0].symbol_type(), 0x0001);
    }

    #[test]
    fn read_header_at_non_zero_offset() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&[
            0x05, 0x00, // symHash = 5
            0x06, 0x00, // addrHash = 6
            0x00, 0x00, 0x00, 0x00, // cbSymbol = 0
            0x00, 0x00, 0x00, 0x00, // cbSymHash = 0
            0x00, 0x00, 0x00, 0x00, // cbAddrHash = 0
        ]);

        let reader = MockReader::new(data, true);
        let global = OmfGlobal::new(&reader, 4).expect("failed to read");

        assert_eq!(global.sym_hash(), 5);
        assert_eq!(global.addr_hash(), 6);
        assert!(global.symbols().is_empty());
    }

    #[test]
    fn read_header_skips_invalid_symbol_record() {
        // A record with length == 0 is skipped by select_symbol, but the loop still
        // advances by 2 * SIZEOF_SHORT and decrements bytesLeft accordingly.
        let mut data = vec![
            0x00, 0x00, // symHash = 0
            0x00, 0x00, // addrHash = 0
            0x04, 0x00, 0x00, 0x00, // cbSymbol = 4
            0x00, 0x00, 0x00, 0x00, // cbSymHash = 0
            0x00, 0x00, 0x00, 0x00, // cbAddrHash = 0
        ];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // length = 0, type = 0

        let reader = MockReader::new(data, true);
        let global = OmfGlobal::new(&reader, 0).expect("failed to read");

        assert!(global.symbols().is_empty());
    }
}
