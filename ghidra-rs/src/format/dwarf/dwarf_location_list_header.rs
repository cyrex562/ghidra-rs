use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_length_value::DWARFLengthValue;

/// Header found at the start of a set of [`DWARFLocationList`](super::dwarf_location_list::DWARFLocationList)
/// entries, which are stored sequentially in the `.debug_loclists` section.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.DWARFLocationListHeader`. The Java class extends the
/// abstract `DWARFIndirectTableHeader`, whose three offset fields are inlined here since Rust has
/// no class inheritance and no other ported type currently needs to share that base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFLocationListHeader {
    start_offset: u64,
    end_offset: u64,
    first_element_offset: u64,
    offset_int_size: i32,
    offset_entry_count: u32,
    address_size: i32,
    segment_selector_size: i32,
}

impl DWARFLocationListHeader {
    pub fn new(
        start_offset: u64,
        end_offset: u64,
        first_element_offset: u64,
        offset_int_size: i32,
        offset_entry_count: u32,
        address_size: i32,
        segment_selector_size: i32,
    ) -> Self {
        DWARFLocationListHeader {
            start_offset,
            end_offset,
            first_element_offset,
            offset_int_size,
            offset_entry_count,
            address_size,
            segment_selector_size,
        }
    }

    /// Mirrors `DWARFLocationListHeader.read(BinaryReader, int)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        default_int_size: i32,
    ) -> io::Result<Option<DWARFLocationListHeader>> {
        // length : dwarf_length
        // version : 2 bytes
        // address_size : 1 byte
        // segment_selector_size : 1 byte
        // offset entry count: 4 bytes
        // offsets : array of elements that are dwarf_format_int sized

        let start_offset = reader.get_pointer_index();
        let length_info = match DWARFLengthValue::read(reader, default_int_size)? {
            Some(length_info) => length_info,
            None => return Ok(None),
        };

        let end_offset = reader.get_pointer_index() + length_info.length() as u64;
        let version = reader.read_next_short()?;
        if version < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                DWARFException::with_message(format!(
                    "DWARFLocationListHeader (0x{start_offset:x}): unsupported DWARF version [{version}]"
                )),
            ));
        }
        let address_size = reader.read_next_unsigned_byte()? as i32;
        let segment_selector_size = reader.read_next_unsigned_byte()? as i32;
        let offset_entry_count = reader.read_next_unsigned_int_exact()?;
        let offset_list_position = reader.get_pointer_index();

        reader.set_pointer_index(end_offset);
        if segment_selector_size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported segmentSelectorSize: {segment_selector_size}"),
            ));
        }

        Ok(Some(DWARFLocationListHeader::new(
            start_offset,
            end_offset,
            offset_list_position,
            length_info.int_size(),
            offset_entry_count,
            address_size,
            segment_selector_size,
        )))
    }

    /// Mirrors `DWARFIndirectTableHeader.getStartOffset()`.
    pub fn get_start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getFirstElementOffset()`.
    pub fn get_first_element_offset(&self) -> u64 {
        self.first_element_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getEndOffset()`.
    pub fn get_end_offset(&self) -> u64 {
        self.end_offset
    }

    pub fn get_address_size(&self) -> i32 {
        self.address_size
    }

    pub fn get_segment_selector_size(&self) -> i32 {
        self.segment_selector_size
    }

    /// Mirrors `DWARFLocationListHeader.getOffset(int, BinaryReader)`.
    pub fn get_offset(&self, index: i32, reader: &dyn BinaryReader) -> io::Result<u64> {
        if index < 0 || index as u32 >= self.offset_entry_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid location list index: {index}"),
            ));
        }
        let value = reader.read_unsigned_value(
            self.first_element_offset + (index as u64 * self.offset_int_size as u64),
            self.offset_int_size as usize,
        )?;
        Ok(self.first_element_offset + value)
    }
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
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// Minimal `BinaryReader` implementation backed by an in-memory byte vector, for testing.
    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0, little_endian: true }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
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
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index, little_endian: self.little_endian })
        }
    }

    /// A minimal v5 `.debug_loclists` header: 4-byte length, version=5, address_size=8,
    /// segment_selector_size=0, offset_entry_count=2, followed by two 4-byte offsets, then two
    /// bytes of trailing "offset list body" that the reader should skip over (per Java: after
    /// parsing the fixed header fields, the pointer is reset to `endOffset`).
    fn build_header_bytes() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // version
        body.push(8); // address_size
        body.push(0); // segment_selector_size
        body.extend_from_slice(&2u32.to_le_bytes()); // offset_entry_count
        body.extend_from_slice(&0x10u32.to_le_bytes()); // offsets[0]
        body.extend_from_slice(&0x20u32.to_le_bytes()); // offsets[1]
        body.extend_from_slice(&[0xAA, 0xBB]); // trailing location-list body bytes

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwarf length
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn read_parses_v5_header_and_skips_to_end_offset() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFLocationListHeader::read(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.get_start_offset(), 0);
        assert_eq!(header.get_address_size(), 8);
        assert_eq!(header.get_segment_selector_size(), 0);
        // firstElementOffset points right after the fixed 8-byte sub-header (version, addr size,
        // seg size, entry count), which itself follows the 4-byte length field.
        assert_eq!(header.get_first_element_offset(), 4 + 8);
        // endOffset == start of body (4) + length field value; reader must be left there.
        assert_eq!(header.get_end_offset(), reader.get_pointer_index());
    }

    #[test]
    fn get_offset_reads_the_offset_table_entry() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFLocationListHeader::read(&mut reader, 4).unwrap().unwrap();

        // offset[0] = firstElementOffset + rawValue(offsets[0]) = 12 + 0x10
        assert_eq!(header.get_offset(0, &reader).unwrap(), 12 + 0x10);
        // offset[1] = firstElementOffset + rawValue(offsets[1]) = 12 + 0x20
        assert_eq!(header.get_offset(1, &reader).unwrap(), 12 + 0x20);
    }

    #[test]
    fn get_offset_rejects_out_of_range_index() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFLocationListHeader::read(&mut reader, 4).unwrap().unwrap();

        let err = header.get_offset(2, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Invalid location list index"));

        let err = header.get_offset(-1, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_rejects_pre_v5_dwarf_version() {
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // version 4: unsupported
        body.push(8);
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);

        let mut reader = TestReader::new(bytes);
        let err = DWARFLocationListHeader::read(&mut reader, 4).unwrap_err();
        assert!(err.to_string().contains("unsupported DWARF version"));
    }

    #[test]
    fn read_rejects_nonzero_segment_selector_size() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes());
        body.push(8);
        body.push(1); // segment_selector_size != 0: unsupported
        body.extend_from_slice(&0u32.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);

        let mut reader = TestReader::new(bytes);
        let err = DWARFLocationListHeader::read(&mut reader, 4).unwrap_err();
        assert!(err.to_string().contains("Unsupported segmentSelectorSize"));
    }
}
