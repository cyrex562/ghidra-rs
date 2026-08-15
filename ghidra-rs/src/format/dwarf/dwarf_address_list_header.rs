use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_length_value::DWARFLengthValue;

/// Header at the beginning of an address list table.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.DWARFAddressListHeader`. The Java class extends the
/// abstract `DWARFIndirectTableHeader`, whose three offset fields are inlined here since Rust has
/// no class inheritance (same convention used by
/// [`DWARFLocationListHeader`](super::dwarf_location_list_header::DWARFLocationListHeader)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFAddressListHeader {
    start_offset: u64,
    end_offset: u64,
    first_element_offset: u64,
    address_size: i32,
    segment_selector_size: i32,
    addr_count: i32,
}

impl DWARFAddressListHeader {
    pub fn new(
        start_offset: u64,
        end_offset: u64,
        first_element_offset: u64,
        address_size: i32,
        segment_selector_size: i32,
        addr_count: i32,
    ) -> Self {
        DWARFAddressListHeader {
            start_offset,
            end_offset,
            first_element_offset,
            address_size,
            segment_selector_size,
            addr_count,
        }
    }

    /// Mirrors `DWARFAddressListHeader.read(BinaryReader, int)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        default_int_size: i32,
    ) -> io::Result<Option<DWARFAddressListHeader>> {
        // length : dwarf_length
        // version : 2 bytes
        // addr_size : 1 byte
        // seg_sel_size : 1 byte

        let start_offset = reader.get_pointer_index();
        let length_info = match DWARFLengthValue::read(reader, default_int_size)? {
            Some(length_info) => length_info,
            None => return Ok(None),
        };

        let end_offset = reader.get_pointer_index() + length_info.length() as u64;
        let version = reader.read_next_short()?;
        if version != 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                DWARFException::with_message(format!(
                    "Unsupported DWARF version [{version}]"
                )),
            ));
        }
        let address_size = reader.read_next_unsigned_byte()? as i32;
        let segment_selector_size = reader.read_next_unsigned_byte()? as i32;
        let first_addr = reader.get_pointer_index();
        reader.set_pointer_index(end_offset);

        let count = if address_size + segment_selector_size != 0 {
            (end_offset - first_addr) / (address_size + segment_selector_size) as u64
        } else {
            0
        };

        Ok(Some(DWARFAddressListHeader::new(
            start_offset,
            end_offset,
            first_addr,
            address_size,
            segment_selector_size,
            count as i32,
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

    /// Mirrors `DWARFAddressListHeader.getOffset(int, BinaryReader)`.
    pub fn get_offset(&self, index: i32, reader: &dyn BinaryReader) -> io::Result<i64> {
        if index < 0 || self.addr_count <= index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid address index: {index}"),
            ));
        }
        let offset =
            self.first_element_offset + ((self.address_size + self.segment_selector_size) * index) as u64;

        if self.segment_selector_size > 0 {
            reader.read_unsigned_value(offset, self.segment_selector_size as usize)?;
        }

        let addr = reader.read_unsigned_value(
            offset + self.segment_selector_size as u64,
            self.address_size as usize,
        )?;
        Ok(addr as i64)
    }

    pub fn get_address_size(&self) -> i32 {
        self.address_size
    }

    pub fn get_segment_selector_size(&self) -> i32 {
        self.segment_selector_size
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

    /// A minimal v5 `.debug_addr` header: 4-byte length, version=5, address_size=8,
    /// segment_selector_size=0, followed by two 8-byte addresses.
    fn build_header_bytes() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // version
        body.push(8); // address_size
        body.push(0); // segment_selector_size
        body.extend_from_slice(&0x1111_1111_2222_2222u64.to_le_bytes()); // addrs[0]
        body.extend_from_slice(&0x3333_3333_4444_4444u64.to_le_bytes()); // addrs[1]

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwarf length
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn read_parses_v5_header_and_skips_to_end_offset() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFAddressListHeader::read(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.get_start_offset(), 0);
        assert_eq!(header.get_address_size(), 8);
        assert_eq!(header.get_segment_selector_size(), 0);
        // firstElementOffset points right after the fixed 4-byte sub-header (version, addr size,
        // seg size), which itself follows the 4-byte length field.
        assert_eq!(header.get_first_element_offset(), 4 + 4);
        assert_eq!(header.get_end_offset(), reader.get_pointer_index());
        assert_eq!(header.addr_count, 2);
    }

    #[test]
    fn get_offset_reads_address_table_entries() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFAddressListHeader::read(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.get_offset(0, &reader).unwrap(), 0x1111_1111_2222_2222u64 as i64);
        assert_eq!(header.get_offset(1, &reader).unwrap(), 0x3333_3333_4444_4444u64 as i64);
    }

    #[test]
    fn get_offset_rejects_out_of_range_index() {
        let bytes = build_header_bytes();
        let mut reader = TestReader::new(bytes);
        let header = DWARFAddressListHeader::read(&mut reader, 4).unwrap().unwrap();

        let err = header.get_offset(2, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Invalid address index"));

        let err = header.get_offset(-1, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_rejects_non_v5_dwarf_version() {
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // version 4: unsupported
        body.push(8);
        body.push(0);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);

        let mut reader = TestReader::new(bytes);
        let err = DWARFAddressListHeader::read(&mut reader, 4).unwrap_err();
        assert!(err.to_string().contains("Unsupported DWARF version"));
    }
}
