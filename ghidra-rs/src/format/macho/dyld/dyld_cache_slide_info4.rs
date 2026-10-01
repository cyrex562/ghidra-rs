//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo4`.
//!
//! Represents a `dyld_cache_slide_info4` (32-bit caches): like version 2, with 4-byte chain
//! entries and small-value sign handling. See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::dyld::dyld_cache_mapping_info::DyldCacheMappingInfo;
use crate::format::macho::dyld::dyld_cache_slide_info_common::{
    DyldCacheSlideInfoCommon, DyldCacheSlideInfoCommonBase, DyldSlideFixupError, BYTES_PER_CHAIN_OFFSET,
    CHAIN_OFFSET_MASK,
};
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::macho::struct_builder::{array_with_element_length, dword, qword, word, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::task::TaskMonitor;

const DYLD_CACHE_SLIDE4_PAGE_NO_REBASE: i32 = 0xFFFF;
const DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA: i32 = 0x8000;
const HEADERSIZE4: i32 = 40;

/// A version 4 `dyld_cache_slide_info4`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo4`.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo4 {
    base: DyldCacheSlideInfoCommonBase,
    page_size: i32,
    page_starts_offset: i32,
    page_starts_count: i32,
    page_extras_offset: i32,
    page_extras_count: i32,
    delta_mask: i64,
    value_add: i64,
    page_starts: Vec<i16>,
    page_extras: Vec<i16>,
}

impl DyldCacheSlideInfo4 {
    /// Java: `DyldCacheSlideInfo4(BinaryReader, DyldCacheMappingInfo)`. The starts and extras are
    /// read from their (absolute) offsets.
    pub fn new(reader: &mut BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        let base = DyldCacheSlideInfoCommonBase::new(reader, mapping_info)?;
        let page_size = reader.read_next_int()?;
        let page_starts_offset = reader.read_next_int()?;
        let page_starts_count = reader.read_next_int()?;
        let page_extras_offset = reader.read_next_int()?;
        let page_extras_count = reader.read_next_int()?;
        let delta_mask = reader.read_next_long()?;
        let value_add = reader.read_next_long()?;
        reader.set_pointer_index(page_starts_offset as i64 as u64);
        let page_starts = reader.read_next_short_array(page_starts_count.max(0) as usize)?;
        reader.set_pointer_index(page_extras_offset as i64 as u64);
        let page_extras = reader.read_next_short_array(page_extras_count.max(0) as usize)?;
        Ok(DyldCacheSlideInfo4 {
            base,
            page_size,
            page_starts_offset,
            page_starts_count,
            page_extras_offset,
            page_extras_count,
            delta_mask,
            value_add,
            page_starts,
            page_extras,
        })
    }

    /// Java: `getPageSize()`.
    pub fn get_page_size(&self) -> i32 {
        self.page_size
    }

    /// Java: `getPageStartsOffset()`.
    pub fn get_page_starts_offset(&self) -> i32 {
        self.page_starts_offset
    }

    /// Java: `getPageStartsCount()`.
    pub fn get_page_starts_count(&self) -> i32 {
        self.page_starts_count
    }

    /// Java: `getPageExtrasOffset()`.
    pub fn get_page_extras_offset(&self) -> i32 {
        self.page_extras_offset
    }

    /// Java: `getPageExtrasCount()`.
    pub fn get_page_extras_count(&self) -> i32 {
        self.page_extras_count
    }

    /// Java: `getDeltaMask()`.
    pub fn get_delta_mask(&self) -> i64 {
        self.delta_mask
    }

    /// Java: `getValueAdd()`.
    pub fn get_value_add(&self) -> i64 {
        self.value_add
    }

    /// Java: `getPageStarts()`.
    pub fn get_page_starts(&self) -> &[i16] {
        &self.page_starts
    }

    /// Java: `getPageExtras()`.
    pub fn get_page_extras(&self) -> &[i16] {
        &self.page_extras
    }

    /// Java: the private `processPointerChain`. The chain value is a Java `int`, so the masking
    /// and `valueAdd` arithmetic narrow back to 32 bits, and the fixup value is sign-extended.
    fn process_pointer_chain(
        &self,
        segment_offset: i64,
        mut page_offset: i64,
        reader: &BinaryReader,
        monitor: &dyn TaskMonitor,
        fixups: &mut Vec<DyldFixup>,
    ) -> Result<(), DyldSlideFixupError> {
        let value_mask = !self.delta_mask;
        let delta_shift = self.delta_mask.trailing_zeros();
        let mut delta: i64 = -1;
        while delta != 0 {
            monitor.check_cancelled()?;
            let data_offset = segment_offset + page_offset;
            let mut chain_value = reader.read_int(data_offset as u64)?;
            delta = ((chain_value as i64) & self.delta_mask).checked_shr(delta_shift).unwrap_or(0);
            chain_value = ((chain_value as i64) & value_mask) as i32;
            if (chain_value as u32 & 0xFFFF_8000) == 0 {
                // small positive non-pointer, use as-is
            } else if (chain_value as u32 & 0x3FFF_8000) == 0x3FFF_8000 {
                // small negative non-pointer
                chain_value = (chain_value as u32 | 0xC000_0000) as i32;
            } else {
                chain_value = (chain_value as i64).wrapping_add(self.value_add) as i32;
            }
            fixups.push(DyldFixup::new(data_offset, Some(chain_value as i64), 4, None, None));
            page_offset += delta * 4;
        }
        Ok(())
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_slide_info4");
        s.add(dword(), "version", Some("currently 4"))?;
        s.add(dword(), "page_size", Some("currently 4096 (may also be 16384)"))?;
        for name in ["page_starts_offset", "page_starts_count", "page_extras_offset", "page_extras_count"] {
            s.add(dword(), name, Some(""))?;
        }
        s.add(
            qword(),
            "delta_mask",
            Some("which (contiguous) set of bits contains the delta to the next rebase location (0xC0000000)"),
        )?;
        s.add(qword(), "value_add", Some("base address of cache"))?;
        if self.page_starts_offset == HEADERSIZE4 {
            s.add(array_with_element_length(word(), self.page_starts_count, 1)?, "page_starts", Some(""))?;
        }
        if self.page_extras_offset == HEADERSIZE4 + self.page_starts_count * 2 {
            s.add(array_with_element_length(word(), self.page_extras_count, 1)?, "page_extras", Some(""))?;
        }
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheSlideInfo4 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl DyldCacheSlideInfoCommon for DyldCacheSlideInfo4 {
    fn base(&self) -> &DyldCacheSlideInfoCommonBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut DyldCacheSlideInfoCommonBase {
        &mut self.base
    }

    /// Java: `getSlideFixups(BinaryReader, int, MessageLog, TaskMonitor)`.
    fn get_slide_fixups(
        &self,
        reader: &mut BinaryReader,
        _pointer_size: i32,
        _log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<DyldFixup>, DyldSlideFixupError> {
        let mut fixups = Vec::new();
        monitor.initialize(self.page_starts_count as i64);
        monitor.set_message("Getting DYLD Cache V4 slide fixups...");
        for index in 0..self.page_starts_count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let segment_offset = self.page_size.wrapping_mul(index) as i64;
            let mut page_entry = self.page_starts[index as usize] as u16 as i32;
            if page_entry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE {
                continue;
            }
            if page_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA != 0 {
                let mut extra_index = (page_entry & CHAIN_OFFSET_MASK) as usize;
                loop {
                    page_entry = *self.page_extras.get(extra_index).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "page extras index out of range")
                    })? as u16 as i32;
                    let page_offset = ((page_entry & CHAIN_OFFSET_MASK) * BYTES_PER_CHAIN_OFFSET) as i64;
                    self.process_pointer_chain(segment_offset, page_offset, reader, monitor, &mut fixups)?;
                    extra_index += 1;
                    if page_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA != 0 {
                        break;
                    }
                }
            } else {
                let page_offset = (page_entry * BYTES_PER_CHAIN_OFFSET) as i64;
                self.process_pointer_chain(segment_offset, page_offset, reader, monitor, &mut fixups)?;
            }
        }
        Ok(fixups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::util::task::DummyMonitor;

    #[test]
    fn handles_small_values_and_value_add() {
        let mut b = Bytes::new(true);
        b.u32(4).u32(0x1000).u32(40).u32(1).u32(42).u32(0);
        b.u64(0xC000_0000).u64(0x1000_0000).u16(0);
        let info = DyldCacheSlideInfo4::new(&mut BinaryReader::from_bytes(b.buf, true), DyldCacheMappingInfo::new(0, 0, 0, 0, 0))
            .unwrap();
        let mut page = vec![0u8; 0x1000];
        // delta field is bits 30..32 in 4-byte units
        page[0..4].copy_from_slice(&((1u32 << 30) | 0x0000_0010).to_le_bytes()); // small positive -> as is
        page[4..8].copy_from_slice(&((1u32 << 30) | 0x3FFF_8001).to_le_bytes()); // small negative
        page[8..12].copy_from_slice(&0x0002_0000u32.to_le_bytes()); // pointer -> + value_add
        let mut r = BinaryReader::from_bytes(page, true);
        let fixups = info.get_slide_fixups(&mut r, 4, &MessageLog::new(), &DummyMonitor).unwrap();
        let values: Vec<i64> = fixups.iter().map(|f| f.value.unwrap()).collect();
        assert_eq!(values, [0x10, 0xFFFF_8001u32 as i32 as i64, 0x1002_0000]);
        assert!(fixups.iter().all(|f| f.size == 4));
        let names = crate::format::macho::struct_builder::test_support::names(&info.to_structure().unwrap());
        assert_eq!(names.last().unwrap(), "page_extras");
    }
}
