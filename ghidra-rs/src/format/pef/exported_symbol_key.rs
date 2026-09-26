//! Port of `ghidra.app.util.bin.format.pef.ExportedSymbolKey`.
//!
//! See Apple's PEFBinaryFormat.h:
//! ```text
//! struct PEFExportedSymbolKey {
//!     union {
//!         UInt32            fullHashWord;
//!         PEFSplitHashWord  splitHashWord;
//!     } u;
//! };
//! struct PEFSplitHashWord {
//!     UInt16  nameLength;
//!     UInt16  hashValue;
//! };
//! ```
//!
//! Java's `toDataType()` returns `new TypedefDataType("ExportedSymbolKey", DWORD)`. `DWORD` (the
//! `StructConverter.DWORD` singleton) is not ported yet -- [`DWordDataType`
//! (`crate::program::model::data::dword_data_type`)] is currently a trait with no concrete
//! production instance -- so, following the precedent already set by this package's other
//! `StructConverter` implementors
//! ([`LoaderInfoHeader`](crate::format::pef::loader_info_header),
//! [`LoaderRelocationHeader`](crate::format::pef::loader_relocation_header)), this port uses the
//! [`StructConverterUtilDataType`](crate::format::seam_stubs::StructConverterUtilDataType)
//! placeholder instead.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::StructConverterUtilDataType;
use crate::program::model::data::data_type::DataType;

/// Fixed size, in bytes, of the on-disk `PEFExportedSymbolKey` structure.
pub const SIZEOF: i32 = 4;

/// A PEF exported-symbol hash key: a 4-byte word that, depending on interpretation, is either
/// the full 32-bit hash word or a split `(nameLength, hashValue)` pair.
///
/// Port of `ghidra.app.util.bin.format.pef.ExportedSymbolKey`.
pub struct ExportedSymbolKey {
    full_hash_word: i32,
    name_length: i16,
    hash_value: i16,
}

impl ExportedSymbolKey {
    /// Reads an [`ExportedSymbolKey`] from `reader`.
    ///
    /// Port of `ExportedSymbolKey(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_int()?;

        Ok(ExportedSymbolKey {
            full_hash_word: value,
            name_length: (value >> 16) as i16,
            hash_value: (value & 0xffff) as i16,
        })
    }

    /// Port of `ExportedSymbolKey.getFullHashWord()`.
    pub fn full_hash_word(&self) -> i32 {
        self.full_hash_word
    }

    /// Port of `ExportedSymbolKey.getNameLength()`.
    pub fn name_length(&self) -> i16 {
        self.name_length
    }

    /// Port of `ExportedSymbolKey.getHashValue()`.
    pub fn hash_value(&self) -> i16 {
        self.hash_value
    }
}

impl StructConverter for ExportedSymbolKey {
    /// Port of `ExportedSymbolKey.toDataType()`. See the module docs for why this returns a
    /// [`StructConverterUtilDataType`] placeholder rather than a real `TypedefDataType`-wrapping-
    /// `DWORD`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(StructConverterUtilDataType::to_data_type("ExportedSymbolKey", SIZEOF)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Minimal in-memory [`BinaryReader`] sufficient for this module's tests: sequential
    /// big-endian 32-bit reads.
    struct MockReader {
        bytes: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockReader { bytes, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            self.pos
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pos;
            self.pos = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            false
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn get_byte_provider(
            &self,
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::GByteStore>> {
            unimplemented!("not needed by ExportedSymbolKey tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by ExportedSymbolKey tests")
        }
    }

    fn write_i32_be(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn splits_full_word_into_name_length_and_hash_value() {
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0x0005_0002);
        let mut reader = MockReader::new(buf);

        let key = ExportedSymbolKey::new(&mut reader).unwrap();

        assert_eq!(key.full_hash_word(), 0x0005_0002);
        assert_eq!(key.name_length(), 5);
        assert_eq!(key.hash_value(), 2);
    }

    #[test]
    fn advances_reader_by_four_bytes() {
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0x0001_0002);
        let mut reader = MockReader::new(buf);

        ExportedSymbolKey::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 4);

        let second = ExportedSymbolKey::new(&mut reader).unwrap();
        assert_eq!(second.name_length(), 1);
        assert_eq!(second.hash_value(), 2);
    }

    #[test]
    fn name_length_sign_extends_like_java_short_cast() {
        // value >> 16 in Java is an *arithmetic* shift on a 32-bit int, so a high word with its
        // top bit set sign-extends before being narrowed to a short. 0x8001_0002 -> upper 16
        // bits 0x8001, which as a signed 16-bit short is -32767.
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0x8001_0002u32 as i32);
        let mut reader = MockReader::new(buf);

        let key = ExportedSymbolKey::new(&mut reader).unwrap();

        assert_eq!(key.name_length(), -32767);
        assert_eq!(key.hash_value(), 2);
    }

    #[test]
    fn to_data_type_reports_fixed_length() {
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0);
        let mut reader = MockReader::new(buf);
        let key = ExportedSymbolKey::new(&mut reader).unwrap();

        let dt = key.to_data_type().unwrap();
        assert_eq!(dt.get_length(), SIZEOF);
        assert_eq!(dt.get_name(), "ExportedSymbolKey");
    }
}
