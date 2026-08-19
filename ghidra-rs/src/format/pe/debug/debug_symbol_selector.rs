use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::data_sym32::DataSym32;
use super::data_sym32_new::DataSym32New;
use super::debug_code_view_constants;
use super::debug_symbol::DebugSymbol;
use super::s_align::SAlign;
use super::s_block32::SBlock32;
use super::s_bprel32_new::SBprel32New;
use super::s_compile::SCompile;
use super::s_constant32::SConstant32;
use super::s_dataref::SDataref;
use super::s_end::SEnd;
use super::s_gdata32_new::SGdata32New;
use super::s_gproc32_new::SGproc32New;
use super::s_label32::SLabel32;
use super::s_ldata32_new::SLdata32New;
use super::s_objname::SObjname;
use super::s_procref::SProcref;
use super::s_udt32::SUdt32;
use super::unknown_symbol::UnknownSymbol;

/// Selects and constructs the appropriate debug symbol type based on symbol type code.
///
/// Mirrors the static `selectSymbol` method of the `DebugSymbolSelector` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// This function reads the symbol record header (length and type) from the reader at the
/// given pointer, validates it, and instantiates the appropriate concrete symbol type.
///
/// # Arguments
///
/// * `reader` - A binary reader positioned to read the symbol data.
/// * `ptr` - The byte offset at which to start reading the symbol header.
///
/// # Returns
///
/// `Ok(Some(symbol))` if a valid symbol was read and constructed.
/// `Ok(None)` if the symbol is invalid (length == 0 or type < 0).
/// `Err` if reading from the reader fails.
pub fn select_symbol(
    reader: &dyn BinaryReader,
    ptr: u64,
) -> io::Result<Option<Box<dyn DebugSymbol>>> {
    let length = reader.read_short(ptr)?;
    let ptr = ptr + 2; // Advance by SIZEOF_SHORT
    let symbol_type = reader.read_short(ptr)?;

    if length == 0 || symbol_type < 0 {
        return Ok(None);
    }

    let sym: Box<dyn DebugSymbol> = match symbol_type as u32 {
        debug_code_view_constants::S_LDATA32
        | debug_code_view_constants::S_GDATA32
        | debug_code_view_constants::S_PUB32 => {
            Box::new(DataSym32::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_PUBSYM32_NEW => {
            Box::new(DataSym32New::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_PROCREF | debug_code_view_constants::S_LPROCREF => {
            Box::new(SProcref::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_DATAREF => {
            Box::new(SDataref::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_ALIGN => Box::new(SAlign::new(reader, length, symbol_type, ptr)?),
        debug_code_view_constants::S_UDT32 => {
            Box::new(SUdt32::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_LDATA32_NEW => {
            Box::new(SLdata32New::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_LPROC32_NEW | debug_code_view_constants::S_GPROC32_NEW => {
            Box::new(SGproc32New::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_BPREL32_NEW => {
            Box::new(SBprel32New::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_END => Box::new(SEnd::new(length, symbol_type)),
        debug_code_view_constants::S_BLOCK32 => Box::new(SBlock32::new(length, symbol_type)),
        debug_code_view_constants::S_COMPILE => Box::new(SCompile::new(length, symbol_type)),
        debug_code_view_constants::S_OBJNAME => {
            Box::new(SObjname::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_CONSTANT32 => {
            Box::new(SConstant32::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_GDATA32_NEW => {
            Box::new(SGdata32New::new(reader, length, symbol_type, ptr)?)
        }
        debug_code_view_constants::S_LABEL32 => {
            Box::new(SLabel32::new(reader, length, symbol_type, ptr)?)
        }
        _ => Box::new(UnknownSymbol::new(reader, length, symbol_type, ptr)?),
    };

    Ok(Some(sym))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
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
            Ok(self.0[index as usize])
        }

        fn read_bytes(&mut self, index: u64, count: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = (index as usize) + count;
            if end <= self.0.len() {
                Ok(self.0[start..end].to_vec())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Index out of bounds",
                ))
            }
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// Minimal little-endian [`BinaryReader`] over a `VecProvider`, mirroring the mock reader
    /// used in `binary_reader.rs`'s own tests.
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
    fn select_symbol_with_zero_length_returns_none() {
        let reader = MockReader::new(vec![0x00, 0x00, 0x07, 0x02]);

        let result = select_symbol(&reader, 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn select_symbol_with_negative_type_returns_none() {
        let reader = MockReader::new(vec![0x10, 0x00, 0xFF, 0xFF]);

        let result = select_symbol(&reader, 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn select_symbol_s_block32() {
        let reader = MockReader::new(vec![0x08, 0x00, 0x07, 0x02]);

        let result = select_symbol(&reader, 0);
        assert!(result.is_ok());
        let symbol = result.unwrap();
        assert!(symbol.is_some());
        let sym = symbol.unwrap();
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 0x0207);
    }

    #[test]
    fn select_symbol_s_compile() {
        let reader = MockReader::new(vec![0x04, 0x00, 0x01, 0x00]);

        let result = select_symbol(&reader, 0);
        assert!(result.is_ok());
        let symbol = result.unwrap();
        assert!(symbol.is_some());
        let sym = symbol.unwrap();
        assert_eq!(sym.length(), 4);
        assert_eq!(sym.symbol_type(), 0x0001);
    }

    #[test]
    fn select_symbol_unknown_type() {
        // 0x7000 is a positive i16 not matching any known CodeView symbol type,
        // so select_symbol falls through to UnknownSymbol. (A negative type such
        // as 0xCDAB would be rejected as None -- see select_symbol_with_negative_type_returns_none.)
        let mut data = vec![0x10, 0x00, 0x00, 0x70];
        data.resize(18, 0); // UnknownSymbol reads `length` (16) bytes from ptr=2, so needs 2+16 bytes
        let reader = MockReader::new(data);

        let result = select_symbol(&reader, 0);
        assert!(result.is_ok());
        let symbol = result.unwrap();
        assert!(symbol.is_some());
        let sym = symbol.unwrap();
        assert_eq!(sym.length(), 16);
        assert_eq!(sym.symbol_type(), 0x7000);
    }

    #[test]
    fn select_symbol_with_offset() {
        let reader = MockReader::new(vec![0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x07, 0x02]);

        let result = select_symbol(&reader, 4);
        assert!(result.is_ok());
        let symbol = result.unwrap();
        assert!(symbol.is_some());
        let sym = symbol.unwrap();
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 0x0207);
    }
}
