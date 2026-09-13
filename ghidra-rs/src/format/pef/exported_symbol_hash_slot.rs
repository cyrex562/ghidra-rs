//! Port of `ghidra.app.util.bin.format.pef.ExportedSymbolHashSlot`.
//!
//! See Apple's PEFBinaryFormat.h:
//! ```text
//! struct PEFExportedSymbolHashSlot {
//!     UInt32              countAndStart;
//! };
//! ```
//!
//! See [`exported_symbol_key`](crate::format::pef::exported_symbol_key)'s module docs for why
//! `to_data_type()` returns a [`StructConverterUtilDataType`] placeholder instead of a real
//! `TypedefDataType`-wrapping-`DWORD`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::StructConverterUtilDataType;
use crate::program::model::data::data_type::DataType;

/// Fixed size, in bytes, of the on-disk `PEFExportedSymbolHashSlot` structure.
pub const SIZEOF: i32 = 4;

/// A PEF exported-symbol hash slot: an entry in the export hash table naming how many exported
/// symbols hash to this slot, and where their keys begin in the exported-symbol-key table.
///
/// Port of `ghidra.app.util.bin.format.pef.ExportedSymbolHashSlot`.
pub struct ExportedSymbolHashSlot {
    symbol_count: i32,
    index_of_first_export_key: i32,
}

impl ExportedSymbolHashSlot {
    /// Reads an [`ExportedSymbolHashSlot`] from `reader`.
    ///
    /// Port of `ExportedSymbolHashSlot(BinaryReader)`.
    ///
    /// Faithfully reproduces a real bug in the Java source: `indexOfFirstExportKey` is computed
    /// as `countAndStart & 0x12` instead of a proper low-bits mask (the real PEF format packs a
    /// 14-bit count in the high bits and an 18-bit start index in the low bits, i.e. the mask
    /// should be `0x3FFFF`). `0x12` is exactly `18` written as a hex literal instead of decimal --
    /// it looks like the shift amount used for `symbolCount` (`>> 18`) was mistakenly reused as
    /// the hex mask for `indexOfFirstExportKey` instead. The upshot: `getIndexOfFirstExportKey()`
    /// returns 0 for the vast majority of real `countAndStart` values (only bits 1 and 4 of the
    /// mask survive), so this accessor is effectively unusable in the original Ghidra too.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let count_and_start = reader.read_next_int()?;

        Ok(ExportedSymbolHashSlot {
            symbol_count: count_and_start >> 18,
            // BUG (preserved from Java): should be `count_and_start & 0x3FFFF`.
            index_of_first_export_key: count_and_start & 0x12,
        })
    }

    /// Port of `ExportedSymbolHashSlot.getSymbolCount()`.
    pub fn symbol_count(&self) -> i32 {
        self.symbol_count
    }

    /// Port of `ExportedSymbolHashSlot.getIndexOfFirstExportKey()`. See [`Self::new`] for the
    /// faithfully-preserved `& 0x12` masking bug that makes this return 0 for most real inputs.
    pub fn index_of_first_export_key(&self) -> i32 {
        self.index_of_first_export_key
    }
}

impl StructConverter for ExportedSymbolHashSlot {
    /// Port of `ExportedSymbolHashSlot.toDataType()`. See the module docs for why this returns a
    /// [`StructConverterUtilDataType`] placeholder rather than a real `TypedefDataType`-wrapping-
    /// `DWORD`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(StructConverterUtilDataType::to_data_type("ExportedSymbolHashSlot", SIZEOF)))
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
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            unimplemented!("not needed by ExportedSymbolHashSlot tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by ExportedSymbolHashSlot tests")
        }
    }

    fn write_i32_be(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn extracts_symbol_count_from_top_bits() {
        // symbolCount = 3, packed into bits >> 18.
        let count_and_start = 3i32 << 18;
        let mut buf = Vec::new();
        write_i32_be(&mut buf, count_and_start);
        let mut reader = MockReader::new(buf);

        let slot = ExportedSymbolHashSlot::new(&mut reader).unwrap();

        assert_eq!(slot.symbol_count(), 3);
    }

    #[test]
    fn index_of_first_export_key_reproduces_the_0x12_masking_bug() {
        // A "start index" of 0x3FFFF (all 18 low bits set, the value the real mask *should*
        // extract) still only survives the buggy `& 0x12` as `0x12` itself, not 0x3FFFF.
        let count_and_start = 0x3_FFFF;
        let mut buf = Vec::new();
        write_i32_be(&mut buf, count_and_start);
        let mut reader = MockReader::new(buf);

        let slot = ExportedSymbolHashSlot::new(&mut reader).unwrap();

        assert_eq!(slot.index_of_first_export_key(), 0x12);
    }

    #[test]
    fn index_of_first_export_key_is_zero_for_most_start_values() {
        // A "start index" of 5 (0b101) has no overlap with the 0x12 (0b10010) mask, so the buggy
        // accessor reports 0 even though a real start index was encoded.
        let count_and_start = 5;
        let mut buf = Vec::new();
        write_i32_be(&mut buf, count_and_start);
        let mut reader = MockReader::new(buf);

        let slot = ExportedSymbolHashSlot::new(&mut reader).unwrap();

        assert_eq!(slot.index_of_first_export_key(), 0);
    }

    #[test]
    fn to_data_type_reports_fixed_length() {
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0);
        let mut reader = MockReader::new(buf);
        let slot = ExportedSymbolHashSlot::new(&mut reader).unwrap();

        let dt = slot.to_data_type().unwrap();
        assert_eq!(dt.get_length(), SIZEOF);
        assert_eq!(dt.get_name(), "ExportedSymbolHashSlot");
    }
}
