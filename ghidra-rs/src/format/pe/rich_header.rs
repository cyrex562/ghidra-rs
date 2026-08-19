use std::io::Write;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::rich::comp_id::CompId;
use crate::format::pe::rich_table::RichTable;
use crate::format::seam_stubs::RichHeaderRecord;
use crate::format::writeable::Writeable;
use crate::program::model::data::data_type::DataType;
use crate::util::data_converter::DataConverter;

/// The "Rich" header contains encoded metadata about the tool chain used to generate the binary.
/// This type decodes and writes the Rich header (if it exists).
///
/// Mirrors `ghidra.app.util.bin.format.pe.RichHeader`.
pub struct RichHeader {
    table: RichTable,
}

impl RichHeader {
    /// "Rich"
    pub const IMAGE_RICH_SIGNATURE: i32 = 0x68636952;
    /// "DanS"
    pub const IMAGE_DANS_SIGNATURE: i32 = 0x536E6144;
    pub const NAME: &'static str = "IMAGE_RICH_HEADER";

    /// Creates the Rich header found from the given reader. The reader should be positioned
    /// directly after the DOS header.
    ///
    /// Port of `RichHeader(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> Self {
        let curr_pos = reader.get_pointer_index();

        let table = RichTable::new_from_reader(&*reader);

        if table.get_size() == 0 {
            reader.set_pointer_index(curr_pos);
        } else {
            reader.set_pointer_index((table.get_offset() + table.get_size() as i64) as u64);
        }

        RichHeader { table }
    }

    /// Gets the offset of the Rich header.
    ///
    /// Returns the offset of the Rich header, or -1 if a Rich header was not found.
    pub fn get_offset(&self) -> i32 {
        self.table.get_offset() as i32
    }

    /// Gets the size of the Rich header. Will be 0 if a Rich header was not found.
    pub fn get_size(&self) -> i32 {
        self.table.get_size()
    }

    /// Gets the Rich header mask, or -1 if a Rich header was not found.
    pub fn get_mask(&self) -> i32 {
        self.table.get_mask()
    }

    /// Gets the Rich header records. Could be empty if a Rich header was not found.
    pub fn get_records(&self) -> &[RichHeaderRecord] {
        self.table.get_records()
    }
}

impl StructConverter for RichHeader {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        if self.table.get_size() == 0 {
            // Java returns `null` here; there is no Rich header to describe.
            return Err(ToDataTypeError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no Rich header present",
            )));
        }
        Ok(Box::new(self.table.to_data_type()))
    }
}

impl Writeable for RichHeader {
    fn write(&self, raf: &mut dyn Write, dc: &dyn DataConverter) -> std::io::Result<()> {
        let mask = self.table.get_mask();

        raf.write_all(&dc.int_to_bytes(Self::IMAGE_DANS_SIGNATURE ^ mask))?;

        raf.write_all(&dc.int_to_bytes(mask))?; // 0 ^ mask
        raf.write_all(&dc.int_to_bytes(mask))?; // 0 ^ mask
        raf.write_all(&dc.int_to_bytes(mask))?; // 0 ^ mask

        for rec in self.table.get_records() {
            raf.write_all(&dc.int_to_bytes(rec.get_comp_id().value() ^ mask))?;
            raf.write_all(&dc.int_to_bytes(rec.get_object_count() ^ mask))?;
        }

        raf.write_all(&dc.int_to_bytes(Self::IMAGE_RICH_SIGNATURE))?;
        raf.write_all(&dc.int_to_bytes(mask))?;

        Ok(())
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
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0.get(index as usize).copied().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")
            })
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct FixtureReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        big_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        fn new(data: Vec<u8>) -> Self {
            FixtureReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                big_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for FixtureReader {
        fn length(&self) -> std::io::Result<u64> {
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
            !self.big_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.big_endian = !is_little_endian;
        }
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(FixtureReader {
                provider: Rc::clone(&self.provider),
                big_endian: self.big_endian,
                current_index: new_index,
            })
        }
    }

    /// Builds the bytes of a minimal, valid Rich header: `DanS` XORed with `mask`, three mask
    /// padding dwords, one record (compid/count XORed with mask), then the mask and the `Rich`
    /// signature. Big-endian to match `FixtureReader`'s default endianness.
    fn build_rich_header_bytes(mask: i32, compid: i32, count: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(RichHeader::IMAGE_DANS_SIGNATURE ^ mask).to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&(compid ^ mask).to_be_bytes());
        bytes.extend_from_slice(&(count ^ mask).to_be_bytes());
        bytes.extend_from_slice(&RichHeader::IMAGE_RICH_SIGNATURE.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_valid_rich_header_and_advances_pointer_past_it() {
        let mask = 0x1234_5678;
        let bytes = build_rich_header_bytes(mask, 0x0009_0042, 3);
        let len = bytes.len() as u64;
        let mut reader = FixtureReader::new(bytes);

        let header = RichHeader::new(&mut reader);

        assert_eq!(header.get_mask(), mask);
        assert_eq!(header.get_offset(), 0);
        assert_eq!(header.get_size(), 32);
        assert_eq!(header.get_records().len(), 1);
        assert_eq!(header.get_records()[0].get_comp_id().value(), 0x0009_0042);
        assert_eq!(header.get_records()[0].get_object_count(), 3);
        assert_eq!(reader.get_pointer_index(), len);
    }

    #[test]
    fn missing_rich_header_resets_pointer_and_reports_defaults() {
        let mut reader = FixtureReader::new(vec![0u8; 512]);
        reader.set_pointer_index(4);

        let header = RichHeader::new(&mut reader);

        assert_eq!(header.get_mask(), -1);
        assert_eq!(header.get_offset(), -1);
        assert_eq!(header.get_size(), 0);
        assert!(header.get_records().is_empty());
        // parse() should have restored the pointer to where it started.
        assert_eq!(reader.get_pointer_index(), 4);
    }

    #[test]
    fn write_round_trips_dans_mask_records_and_rich_signature() {
        let mask = 0x1234_5678;
        let compid = 0x0009_0042;
        let count = 3;
        let bytes = build_rich_header_bytes(mask, compid, count);
        let mut reader = FixtureReader::new(bytes.clone());
        let header = RichHeader::new(&mut reader);

        struct BigEndianConverter;
        impl DataConverter for BigEndianConverter {
            fn is_big_endian(&self) -> bool {
                true
            }
            fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
                i16::from_be_bytes([b[offset], b[offset + 1]])
            }
            fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
                i32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
            }
            fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&b[offset..offset + 8]);
                i64::from_be_bytes(buf)
            }
            fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
                let mut val: u64 = 0;
                for i in 0..size {
                    val = (val << 8) | b[offset + i] as u64;
                }
                val
            }
            fn get_big_integer_at(
                &self,
                b: &[u8],
                offset: usize,
                size: usize,
                signed: bool,
            ) -> i128 {
                let unsigned = self.get_value_at(b, offset, size) as i128;
                if signed && size < 16 && size > 0 {
                    let shift_bits = (16 - size) * 8;
                    (unsigned << shift_bits) >> shift_bits
                } else {
                    unsigned
                }
            }
            fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
                b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            }
            fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
                b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
            fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
                for i in 0..size {
                    b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
                }
            }
            fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
                for i in 0..size {
                    b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
                }
            }
        }

        let mut out = Vec::new();
        header.write(&mut out, &BigEndianConverter).unwrap();

        assert_eq!(out, bytes);
    }

    #[test]
    fn to_data_type_errs_when_no_rich_header_found() {
        let mut reader = FixtureReader::new(vec![0u8; 512]);
        let header = RichHeader::new(&mut reader);

        assert!(header.to_data_type().is_err());
    }
}
