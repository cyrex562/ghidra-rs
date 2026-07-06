use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

const AR_SIZE_LEN: usize = 20;
const AR_NXTMEM_LEN: usize = 20;
const AR_PRVMEM_LEN: usize = 20;
const AR_DATE_LEN: usize = 12;
const AR_UID_LEN: usize = 12;
const AR_GID_LEN: usize = 12;
const AR_MODE_LEN: usize = 12;
const AR_NAMLEN_LEN: usize = 4;
const AR_FMAG_LEN: usize = 2;

/// Stores the per-object file archive header used by XCOFF archives ("ar" format).
///
/// Mirrors the `XCoffArchiveMemberHeader` Java class in
/// `ghidra.app.util.bin.format.xcoff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XCoffArchiveMemberHeader {
    ar_size: Vec<u8>,
    ar_nxtmem: Vec<u8>,
    ar_prvmem: Vec<u8>,
    ar_date: Vec<u8>,
    ar_uid: Vec<u8>,
    ar_gid: Vec<u8>,
    ar_mode: Vec<u8>,
    ar_namlen: Vec<u8>,
    ar_name: Vec<u8>,
    ar_fmag: Vec<u8>,
    file_offset: u64,
}

impl XCoffArchiveMemberHeader {
    /// Reads an `XCoffArchiveMemberHeader` from the given binary reader, mirroring the
    /// Java constructor.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let ar_size = reader.read_next_byte_array(AR_SIZE_LEN)?;
        let ar_nxtmem = reader.read_next_byte_array(AR_NXTMEM_LEN)?;
        let ar_prvmem = reader.read_next_byte_array(AR_PRVMEM_LEN)?;
        let ar_date = reader.read_next_byte_array(AR_DATE_LEN)?;
        let ar_uid = reader.read_next_byte_array(AR_UID_LEN)?;
        let ar_gid = reader.read_next_byte_array(AR_GID_LEN)?;
        let ar_mode = reader.read_next_byte_array(AR_MODE_LEN)?;
        let ar_namlen = reader.read_next_byte_array(AR_NAMLEN_LEN)?;
        let name_length = parse_decimal_i64(&ar_namlen) as usize;
        let ar_name = reader.read_next_byte_array(name_length)?;
        let ar_fmag = reader.read_next_byte_array(AR_FMAG_LEN)?;

        // Save this location so we can create the XCOFF object later.
        let mut file_offset = reader.get_pointer_index();
        if (file_offset % 2) == 1 {
            file_offset += 1;
        }

        Ok(XCoffArchiveMemberHeader {
            ar_size,
            ar_nxtmem,
            ar_prvmem,
            ar_date,
            ar_uid,
            ar_gid,
            ar_mode,
            ar_namlen,
            ar_name,
            ar_fmag,
            file_offset,
        })
    }

    /// Returns the file member size.
    pub fn size(&self) -> i64 {
        parse_decimal_i64(&self.ar_size)
    }

    /// Returns the next member offset.
    pub fn next_member_offset(&self) -> i64 {
        parse_decimal_i64(&self.ar_nxtmem)
    }

    /// Returns the previous member offset.
    pub fn previous_member_offset(&self) -> i64 {
        parse_decimal_i64(&self.ar_prvmem)
    }

    /// Returns the file member date.
    pub fn date(&self) -> i64 {
        parse_decimal_i64(&self.ar_date)
    }

    /// Returns the file member user id.
    pub fn user_id(&self) -> i64 {
        parse_decimal_i64(&self.ar_uid)
    }

    /// Returns the file member group id.
    pub fn group_id(&self) -> i64 {
        parse_decimal_i64(&self.ar_gid)
    }

    /// Returns the file member mode.
    pub fn mode(&self) -> i64 {
        parse_decimal_i64(&self.ar_mode)
    }

    /// Returns the file member name length.
    pub fn name_length(&self) -> i32 {
        parse_decimal_i64(&self.ar_namlen) as i32
    }

    /// Returns the file member name.
    pub fn name(&self) -> String {
        trimmed_string(&self.ar_name)
    }

    /// Returns the AIAFMAG terminator string.
    pub fn terminator(&self) -> String {
        trimmed_string(&self.ar_fmag)
    }

    /// Returns the offset of the member's XCOFF object data.
    pub fn object_data_offset(&self) -> u64 {
        self.file_offset
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

    fn build_header(name: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:<20}", 1234).as_bytes()); // ar_size
        data.extend_from_slice(format!("{:<20}", 100).as_bytes()); // ar_nxtmem
        data.extend_from_slice(format!("{:<20}", 0).as_bytes()); // ar_prvmem
        data.extend_from_slice(format!("{:<12}", 1700000000_i64).as_bytes()); // ar_date
        data.extend_from_slice(format!("{:<12}", 501).as_bytes()); // ar_uid
        data.extend_from_slice(format!("{:<12}", 20).as_bytes()); // ar_gid
        data.extend_from_slice(format!("{:<12}", 644).as_bytes()); // ar_mode
        data.extend_from_slice(format!("{:<4}", name.len()).as_bytes()); // ar_namlen
        data.extend_from_slice(name.as_bytes()); // ar_name
        data.extend_from_slice(b"`\n"); // ar_fmag
        data
    }

    #[test]
    fn reads_header_fields() {
        let data = build_header("foo.o");
        let mut r = MockReader::new(data);
        let header = XCoffArchiveMemberHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.size(), 1234);
        assert_eq!(header.next_member_offset(), 100);
        assert_eq!(header.previous_member_offset(), 0);
        assert_eq!(header.date(), 1700000000);
        assert_eq!(header.user_id(), 501);
        assert_eq!(header.group_id(), 20);
        assert_eq!(header.mode(), 644);
        assert_eq!(header.name_length(), 5);
        assert_eq!(header.name(), "foo.o");
        assert_eq!(header.terminator(), "`");
    }

    #[test]
    fn object_data_offset_rounds_odd_up_to_even() {
        // "foo.o" (5 bytes) makes the header end on an odd byte, so the offset must
        // be rounded up to the next even value.
        let data = build_header("foo.o");
        let mut r = MockReader::new(data);
        let header = XCoffArchiveMemberHeader::new(&mut r).expect("failed to read header");

        assert_eq!(r.get_pointer_index() % 2, 1);
        assert_eq!(header.object_data_offset(), r.get_pointer_index() + 1);
    }

    #[test]
    fn object_data_offset_stays_even_when_already_even() {
        // "ab" (2 bytes) keeps the header length even, so no rounding occurs.
        let data = build_header("ab");
        let mut r = MockReader::new(data);
        let header = XCoffArchiveMemberHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.object_data_offset(), r.get_pointer_index());
    }

    #[test]
    fn zero_length_name_reads_empty_string() {
        let data = build_header("");
        let mut r = MockReader::new(data);
        let header = XCoffArchiveMemberHeader::new(&mut r).expect("failed to read header");

        assert_eq!(header.name_length(), 0);
        assert_eq!(header.name(), "");
    }

    #[test]
    fn clone_and_equality() {
        let data = build_header("bar.o");
        let mut r1 = MockReader::new(data.clone());
        let header1 = XCoffArchiveMemberHeader::new(&mut r1).expect("failed to read header");

        let mut r2 = MockReader::new(data);
        let header2 = XCoffArchiveMemberHeader::new(&mut r2).expect("failed to read header");

        assert_eq!(header1, header2.clone());
    }
}
