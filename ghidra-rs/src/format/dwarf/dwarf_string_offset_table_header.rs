use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_length_value::DWARFLengthValue;

/// Table of offsets that point into the string table. These tables are stored sequentially in
/// the `.debug_str_offsets` section.
///
/// Elements in the table are referred to by index via `DW_FORM_strx` and friends. The table's
/// [`Self::get_first_element_offset`] is referred to by a compUnit's `DW_AT_str_offsets_base`
/// value.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.DWARFStringOffsetTableHeader`. The Java class
/// extends the abstract `DWARFIndirectTableHeader`, whose three offset fields are inlined here
/// since Rust has no class inheritance (same convention used by
/// [`DWARFAddressListHeader`](super::dwarf_address_list_header::DWARFAddressListHeader) and
/// [`DWARFLocationListHeader`](super::dwarf_location_list_header::DWARFLocationListHeader)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFStringOffsetTableHeader {
    start_offset: u64,
    end_offset: u64,
    first_element_offset: u64,
    int_size: i32,
    count: i32,
}

impl DWARFStringOffsetTableHeader {
    pub fn new(
        start_offset: u64,
        end_offset: u64,
        first_element_offset: u64,
        int_size: i32,
        count: i32,
    ) -> Self {
        DWARFStringOffsetTableHeader {
            start_offset,
            end_offset,
            first_element_offset,
            int_size,
            count,
        }
    }

    /// Reads a string offset table header (found in the `.debug_str_offsets` section).
    ///
    /// Mirrors `DWARFStringOffsetTableHeader.readV5(BinaryReader, int)`.
    pub fn read_v5(
        reader: &mut BinaryReader,
        default_int_size: i32,
    ) -> io::Result<Option<DWARFStringOffsetTableHeader>> {
        // length : dwarf_length
        // version : 2 bytes
        // padding : 2 bytes
        // offsets : array of elements that are dwarf_format_int sized

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
                DWARFException::with_message(format!("Unsupported DWARF version [{version}]")),
            ));
        }

        let _padding = reader.read_next_short()?;

        let offset_array_start = reader.get_pointer_index();
        reader.set_pointer_index(end_offset);

        let count = ((end_offset - offset_array_start) / length_info.int_size() as u64) as i32;

        Ok(Some(DWARFStringOffsetTableHeader::new(
            start_offset,
            end_offset,
            offset_array_start,
            length_info.int_size(),
            count,
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

    /// Mirrors `DWARFStringOffsetTableHeader.getOffset(int, BinaryReader)`.
    pub fn get_offset(&self, index: i32, reader: &BinaryReader) -> io::Result<i64> {
        if index < 0 || self.count <= index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid indirect string index: {index} [{index:#x}]"),
            ));
        }
        let offset = self.first_element_offset + (index * self.int_size) as u64;
        let value = reader.read_unsigned_value(offset, self.int_size as usize)?;
        Ok(value as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal v5 `.debug_str_offsets` header: 4-byte length, version=5, 2-byte padding,
    /// followed by three 4-byte offsets.
    fn build_header_bytes() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // version
        body.extend_from_slice(&0u16.to_le_bytes()); // padding
        body.extend_from_slice(&0x1000u32.to_le_bytes()); // offsets[0]
        body.extend_from_slice(&0x2000u32.to_le_bytes()); // offsets[1]
        body.extend_from_slice(&0x3000u32.to_le_bytes()); // offsets[2]

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwarf length
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn read_v5_parses_header_and_skips_to_end_offset() {
        let bytes = build_header_bytes();
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.get_start_offset(), 0);
        // firstElementOffset is right after: 4-byte length + 2-byte version + 2-byte padding.
        assert_eq!(header.get_first_element_offset(), 8);
        assert_eq!(header.get_end_offset(), reader.get_pointer_index());
        assert_eq!(header.count, 3);
        assert_eq!(header.int_size, 4);
    }

    #[test]
    fn get_offset_reads_string_offset_table_entries() {
        let bytes = build_header_bytes();
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.get_offset(0, &reader).unwrap(), 0x1000);
        assert_eq!(header.get_offset(1, &reader).unwrap(), 0x2000);
        assert_eq!(header.get_offset(2, &reader).unwrap(), 0x3000);
    }

    #[test]
    fn get_offset_rejects_out_of_range_index() {
        let bytes = build_header_bytes();
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap().unwrap();

        let err = header.get_offset(3, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Invalid indirect string index"));

        let err = header.get_offset(-1, &reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_v5_rejects_non_v5_dwarf_version() {
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // version 4: unsupported
        body.extend_from_slice(&0u16.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let err = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap_err();
        assert!(err.to_string().contains("Unsupported DWARF version"));
    }

    #[test]
    fn read_v5_returns_none_for_trailing_padding() {
        // A zero-length header followed by all-zero padding to EOF is treated as trailing
        // section padding, mirroring `DWARFLengthValue::read`'s special case.
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let result = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn header_with_8_byte_int_size_from_64bit_dwarf_format() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // version
        body.extend_from_slice(&0u16.to_le_bytes()); // padding
        body.extend_from_slice(&0x1111_1111_2222_2222u64.to_le_bytes()); // offsets[0]

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // 64-bit DWARF format marker
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes()); // 8-byte length
        bytes.extend_from_slice(&body);

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DWARFStringOffsetTableHeader::read_v5(&mut reader, 4).unwrap().unwrap();

        assert_eq!(header.int_size, 8);
        assert_eq!(header.count, 1);
        assert_eq!(header.get_offset(0, &reader).unwrap(), 0x1111_1111_2222_2222u64 as i64);
    }
}
