//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInSegment`.
//!
//! Represents a `dyld_chained_starts_in_segment` structure. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{array_with_element_length, dword, word, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::ibo64_data_type::IBO64DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A `dyld_chained_starts_in_segment`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInSegment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldChainedStartsInSegment {
    size: i32,
    page_size: i16,
    pointer_format: i16,
    segment_offset: i64,
    max_valid_pointer: i32,
    page_count: i16,
    page_starts: Vec<i16>,
}

impl DyldChainedStartsInSegment {
    /// Java `DyldChainedStartsInSegment(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let size = reader.read_next_int()?;
        let page_size = reader.read_next_short()?;
        let pointer_format = reader.read_next_short()?;
        let segment_offset = reader.read_next_long()?;
        let max_valid_pointer = reader.read_next_int()?;
        let page_count = reader.read_next_short()?;
        // Java `readNextShortArray(pageCount)` throws on a negative count.
        if page_count < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("negative dyld_chained_starts_in_segment page_count {page_count}"),
            ));
        }
        let page_starts = reader.read_next_short_array(page_count as usize)?;
        Ok(DyldChainedStartsInSegment {
            size,
            page_size,
            pointer_format,
            segment_offset,
            max_valid_pointer,
            page_count,
            page_starts,
        })
    }

    /// Java `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`. The Java body is an
    /// empty `// TODO?` try block, so this does nothing.
    pub fn markup(
        &self,
        _program: &dyn Program,
        _address: &Address,
        _header: &MachHeader,
        _monitor: &dyn TaskMonitor,
        _log: &MessageLog,
    ) -> Result<(), CancelledException> {
        Ok(())
    }

    /// Java `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_chained_starts_in_segment");
        s.add(dword(), "size", Some("size of this (amount kernel needs to copy)"))?;
        s.add(word(), "page_size", Some("0x1000 or 0x4000"))?;
        s.add(word(), "pointer_format", Some("DYLD_CHAINED_PTR_*"))?;
        s.add(Box::new(IBO64DataType::new()), "segment_offset", Some("offset in memory to start of segment"))?;
        s.add(dword(), "max_valid_pointer", Some("for 32-bit OS, any value beyond this is not a pointer"))?;
        s.add(word(), "page_count", Some("how many pages are in array"))?;
        s.add(
            array_with_element_length(word(), self.page_count as i32, 1)?,
            "page_starts",
            Some("each entry is offset in each page of first element in chain or DYLD_CHAINED_PTR_START_NONE if no fixups on page"),
        )?;
        s.finish_structure()
    }

    /// Java `getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Java `getPageSize()`.
    pub fn get_page_size(&self) -> i16 {
        self.page_size
    }

    /// Java `getPointerFormat()`.
    pub fn get_pointer_format(&self) -> i16 {
        self.pointer_format
    }

    /// Java `getSegmentOffset()`.
    pub fn get_segment_offset(&self) -> i64 {
        self.segment_offset
    }

    /// Java `getMaxValidPointer()`.
    pub fn get_max_valid_pointer(&self) -> i32 {
        self.max_valid_pointer
    }

    /// Java `getPageCount()`.
    pub fn get_page_count(&self) -> i16 {
        self.page_count
    }

    /// Java `getPageStarts()`.
    pub fn get_page_starts(&self) -> &[i16] {
        &self.page_starts
    }
}

impl StructConverter for DyldChainedStartsInSegment {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Little-endian `dyld_chained_starts_in_segment` bytes.
    pub(crate) fn segment_bytes(pointer_format: u16, segment_offset: u64, page_starts: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(22 + 2 * page_starts.len() as u32).to_le_bytes());
        v.extend_from_slice(&0x4000u16.to_le_bytes());
        v.extend_from_slice(&pointer_format.to_le_bytes());
        v.extend_from_slice(&segment_offset.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(page_starts.len() as u16).to_le_bytes());
        for p in page_starts {
            v.extend_from_slice(&p.to_le_bytes());
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::segment_bytes;
    use super::*;
    use crate::format::macho::struct_builder::test_support::fields;

    #[test]
    fn parses_fields_and_page_starts() {
        let mut r = BinaryReader::from_bytes(segment_bytes(6, 0x8000, &[0, 0xFFFF, 0x10]), true);
        let s = DyldChainedStartsInSegment::new(&mut r).unwrap();
        assert_eq!(s.get_size(), 28);
        assert_eq!(s.get_page_size(), 0x4000);
        assert_eq!(s.get_pointer_format(), 6);
        assert_eq!(s.get_segment_offset(), 0x8000);
        assert_eq!(s.get_max_valid_pointer(), 0);
        assert_eq!(s.get_page_count(), 3);
        assert_eq!(s.get_page_starts(), &[0, -1, 0x10]);
        assert_eq!(r.get_pointer_index(), 28);
    }

    #[test]
    fn to_data_type_matches_java_layout() {
        let mut r = BinaryReader::from_bytes(segment_bytes(2, 0, &[0, 4]), true);
        let s = DyldChainedStartsInSegment::new(&mut r).unwrap().to_structure().unwrap();
        assert_eq!(s.get_name(), "dyld_chained_starts_in_segment");
        assert_eq!(s.get_category_path().to_string(), "/MachO");
        assert_eq!(
            fields(&s),
            vec![
                ("size".to_string(), 0, 4),
                ("page_size".to_string(), 4, 2),
                ("pointer_format".to_string(), 6, 2),
                ("segment_offset".to_string(), 8, 8),
                ("max_valid_pointer".to_string(), 16, 4),
                ("page_count".to_string(), 20, 2),
                ("page_starts".to_string(), 22, 4),
            ]
        );
    }
}
