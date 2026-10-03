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
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
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
        let mut r = BinaryReader::from_bytes(data, true);
        let header = XCoffArchiveHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.fl_magic(), "<bigaf>");
    }

    #[test]
    fn reads_all_offset_fields() {
        let data = build_header();
        let mut r = BinaryReader::from_bytes(data, true);
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

        let mut r = BinaryReader::from_bytes(data, true);
        let header = XCoffArchiveHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.fl_memoff(), 12345);
    }

    #[test]
    fn clone_and_equality() {
        let data = build_header();
        let mut r1 = BinaryReader::from_bytes(data.clone(), true);
        let header1 = XCoffArchiveHeader::new(&mut r1).expect("failed to read header");

        let mut r2 = BinaryReader::from_bytes(data, true);
        let header2 = XCoffArchiveHeader::new(&mut r2).expect("failed to read header");

        assert_eq!(header1, header2.clone());
    }
}
