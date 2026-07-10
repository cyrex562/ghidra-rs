use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use super::x_coff_archive_constants::MAGIC_LEN;

const FIELD_LEN: usize = 20;

/// Stores the archive header for XCOFF archives ("ar" format).
///
/// Mirrors the `XCoffArchiveHeader` Java class in `ghidra.app.util.bin.format.xcoff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XCoffArchiveHeader {
    fl_magic: Vec<u8>,
    fl_memoff: Vec<u8>,
    fl_gstoff: Vec<u8>,
    fl_gst64off: Vec<u8>,
    fl_fstmoff: Vec<u8>,
    fl_lstmoff: Vec<u8>,
    fl_freeoff: Vec<u8>,
}

impl XCoffArchiveHeader {
    /// Reads an `XCoffArchiveHeader` from the given binary reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(XCoffArchiveHeader {
            fl_magic: reader.read_next_byte_array(MAGIC_LEN)?,
            fl_memoff: reader.read_next_byte_array(FIELD_LEN)?,
            fl_gstoff: reader.read_next_byte_array(FIELD_LEN)?,
            fl_gst64off: reader.read_next_byte_array(FIELD_LEN)?,
            fl_fstmoff: reader.read_next_byte_array(FIELD_LEN)?,
            fl_lstmoff: reader.read_next_byte_array(FIELD_LEN)?,
            fl_freeoff: reader.read_next_byte_array(FIELD_LEN)?,
        })
    }

    /// Returns the archive magic string.
    pub fn fl_magic(&self) -> String {
        trimmed_string(&self.fl_magic)
    }

    /// Returns the offset to the member table.
    pub fn fl_memoff(&self) -> i64 {
        parse_decimal_i64(&self.fl_memoff)
    }

    /// Returns the offset to the global symbol table.
    pub fn fl_gstoff(&self) -> i64 {
        parse_decimal_i64(&self.fl_gstoff)
    }

    /// Returns the offset to the global symbol table for 64-bit objects.
    pub fn fl_gst64off(&self) -> i64 {
        parse_decimal_i64(&self.fl_gst64off)
    }

    /// Returns the offset to the first archive member.
    pub fn fstmoff(&self) -> i64 {
        parse_decimal_i64(&self.fl_fstmoff)
    }

    /// Returns the offset to the last archive member.
    pub fn lstmoff(&self) -> i64 {
        parse_decimal_i64(&self.fl_lstmoff)
    }

    /// Returns the offset to the first member on the free list.
    pub fn fl_freeoff(&self) -> i64 {
        parse_decimal_i64(&self.fl_freeoff)
    }
}

fn trimmed_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

fn parse_decimal_i64(bytes: &[u8]) -> i64 {
    trimmed_string(bytes)
        .parse()
        .expect("archive header field is not a valid decimal number")
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

    fn build_header() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"<bigaf>\n"); // fl_magic (8 bytes)
        data.extend_from_slice(format!("{:<20}", 100).as_bytes()); // fl_memoff
        data.extend_from_slice(format!("{:<20}", 200).as_bytes()); // fl_gstoff
        data.extend_from_slice(format!("{:<20}", 300).as_bytes()); // fl_gst64off
        data.extend_from_slice(format!("{:<20}", 400).as_bytes()); // fl_fstmoff
        data.extend_from_slice(format!("{:<20}", 500).as_bytes()); // fl_lstmoff
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_freeoff
        data
    }

    #[test]
    fn reads_magic() {
        let data = build_header();
        let mut r = MockReader::new(data);
        let header = XCoffArchiveHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.fl_magic(), "<bigaf>");
    }

    #[test]
    fn reads_all_offset_fields() {
        let data = build_header();
        let mut r = MockReader::new(data);
        let header = XCoffArchiveHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.fl_memoff(), 100);
        assert_eq!(header.fl_gstoff(), 200);
        assert_eq!(header.fl_gst64off(), 300);
        assert_eq!(header.fstmoff(), 400);
        assert_eq!(header.lstmoff(), 500);
        assert_eq!(header.fl_freeoff(), 0);
    }

    #[test]
    fn parses_offset_with_leading_whitespace() {
        let mut data = Vec::new();
        data.extend_from_slice(b"<bigaf>\n");
        data.extend_from_slice(b"       12345        "); // fl_memoff with whitespace (20 bytes)
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_gstoff
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_gst64off
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_fstmoff
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_lstmoff
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // fl_freeoff

        let mut r = MockReader::new(data);
        let header = XCoffArchiveHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.fl_memoff(), 12345);
    }

    #[test]
    fn clone_and_equality() {
        let data = build_header();
        let mut r1 = MockReader::new(data.clone());
        let header1 = XCoffArchiveHeader::new(&mut r1).expect("failed to read header");

        let mut r2 = MockReader::new(data);
        let header2 = XCoffArchiveHeader::new(&mut r2).expect("failed to read header");

        assert_eq!(header1, header2.clone());
    }
}
