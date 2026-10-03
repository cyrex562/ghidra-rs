//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInImage`.
//!
//! Represents a `dyld_chained_starts_in_image` structure. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::chained::dyld_chained_starts_in_segment::DyldChainedStartsInSegment;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{array_with_element_length, dword, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// A `dyld_chained_starts_in_image`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInImage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldChainedStartsInImage {
    seg_count: i32,
    seg_info_offset: Vec<i32>,
    chained_starts: Vec<DyldChainedStartsInSegment>,
}

impl DyldChainedStartsInImage {
    /// Java `DyldChainedStartsInImage(BinaryReader)`: `reader` positioned at the start of the
    /// structure. Each non-zero `seg_info_offset` is relative to that start.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let ptr_index = reader.get_pointer_index();
        let seg_count = reader.read_next_int()?;
        if seg_count < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("negative dyld_chained_starts_in_image seg_count {seg_count}"),
            ));
        }
        let seg_info_offset = reader.read_next_int_array(seg_count as usize)?;

        let mut chained_starts = Vec::new();
        for &offset in &seg_info_offset {
            if offset != 0 {
                reader.set_pointer_index((ptr_index as i64).wrapping_add(offset as i64) as u64);
                chained_starts.push(DyldChainedStartsInSegment::new(reader)?);
            }
        }
        Ok(DyldChainedStartsInImage { seg_count, seg_info_offset, chained_starts })
    }

    /// Java `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`: lays down a
    /// `dyld_chained_starts_in_segment` structure at each non-zero segment-info offset. Failures
    /// are logged, not propagated.
    pub fn markup(
        &self,
        program: &dyn Program,
        address: &Address,
        _header: &MachHeader,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        let result: Result<(), String> = (|| {
            let mut skip_count = 0usize;
            for (i, &offset) in self.seg_info_offset.iter().enumerate() {
                if offset == 0 {
                    // The chained-starts list has no entries for 0 offsets, so track the index
                    // difference between the two.
                    skip_count += 1;
                    continue;
                }
                let starts_in_seg = self
                    .chained_starts
                    .get(i - skip_count)
                    .ok_or("chained starts index out of range")?;
                let dt = starts_in_seg.to_data_type().map_err(|e| e.to_string())?;
                let addr = address.add(offset as i64).map_err(|e| e.to_string())?;
                Du.create_data(program, &addr, dt, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(
                Some("DyldChainedStartsInImage"),
                "Failed to markup dyld_chained_starts_in_image",
            );
        }
        Ok(())
    }

    /// Java `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_chained_starts_in_image");
        s.add(dword(), "seg_count", None)?;
        s.add(
            array_with_element_length(dword(), self.seg_count, 1)?,
            "seg_info_offset",
            Some("each entry is offset into this struct for that segment followed by pool of dyld_chain_starts_in_segment data"),
        )?;
        s.finish_structure()
    }

    /// Java `getSegCount()`.
    pub fn get_seg_count(&self) -> i32 {
        self.seg_count
    }

    /// Java `getSegInfoOffset()`.
    pub fn get_seg_info_offset(&self) -> &[i32] {
        &self.seg_info_offset
    }

    /// Java `getChainedStarts()`.
    pub fn get_chained_starts(&self) -> &[DyldChainedStartsInSegment] {
        &self.chained_starts
    }
}

impl StructConverter for DyldChainedStartsInImage {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::chained::dyld_chained_starts_in_segment::test_support::segment_bytes;

    /// `seg_count` 3 with offsets `[0, 16, 0]`: only the middle segment has fixups.
    fn image_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&3i32.to_le_bytes());
        for o in [0i32, 16, 0] {
            v.extend_from_slice(&o.to_le_bytes());
        }
        assert_eq!(v.len(), 16);
        v.extend(segment_bytes(6, 0x4000, &[0x20]));
        v
    }

    #[test]
    fn parses_only_non_zero_segment_offsets() {
        let mut bytes = vec![0xEE; 8];
        bytes.extend(image_bytes());
        let mut r = BinaryReader::from_bytes(bytes, true);
        r.set_pointer_index(8);
        let img = DyldChainedStartsInImage::new(&mut r).unwrap();
        assert_eq!(img.get_seg_count(), 3);
        assert_eq!(img.get_seg_info_offset(), &[0, 16, 0]);
        assert_eq!(img.get_chained_starts().len(), 1);
        assert_eq!(img.get_chained_starts()[0].get_segment_offset(), 0x4000);
        assert_eq!(img.get_chained_starts()[0].get_page_starts(), &[0x20]);
    }

    #[test]
    fn to_data_type_is_count_plus_offset_array() {
        let mut r = BinaryReader::from_bytes(image_bytes(), true);
        let s = DyldChainedStartsInImage::new(&mut r).unwrap().to_structure().unwrap();
        assert_eq!(s.get_name(), "dyld_chained_starts_in_image");
        assert_eq!(s.get_length(), 16);
        assert_eq!(s.get_category_path().to_string(), "/MachO");
    }

    #[test]
    fn negative_seg_count_is_an_error() {
        let mut r = BinaryReader::from_bytes((-1i32).to_le_bytes().to_vec(), true);
        assert!(DyldChainedStartsInImage::new(&mut r).is_err());
    }
}
