//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo2`.
//!
//! Represents a `dyld_cache_slide_info2`: per-page starts of pointer chains whose links are
//! encoded in `delta_mask`. See `dyld3/shared-cache/dyld_cache_format.h`.

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
use crate::format::macho::struct_builder::{array_with_element_length, byte, dword, qword, word, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::task::TaskMonitor;

const DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE: i32 = 0x4000;
const DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA: i32 = 0x8000;

/// A version 2 `dyld_cache_slide_info2`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo2`.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo2 {
    base: DyldCacheSlideInfoCommonBase,
    page_size: i32,
    page_starts_offset: i32,
    page_starts_count: i32,
    page_extras_offset: i32,
    page_extras_count: i32,
    delta_mask: i64,
    value_add: i64,
    page_starts_entries: Vec<i16>,
    page_extras_entries: Vec<i16>,
}

impl DyldCacheSlideInfo2 {
    /// Java: `DyldCacheSlideInfo2(BinaryReader, DyldCacheMappingInfo)`. The starts and extras
    /// arrays are read sequentially after the header.
    pub fn new(reader: &mut BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        let base = DyldCacheSlideInfoCommonBase::new(reader, mapping_info)?;
        let page_size = reader.read_next_int()?;
        let page_starts_offset = reader.read_next_int()?;
        let page_starts_count = reader.read_next_int()?;
        let page_extras_offset = reader.read_next_int()?;
        let page_extras_count = reader.read_next_int()?;
        let delta_mask = reader.read_next_long()?;
        let value_add = reader.read_next_long()?;
        let page_starts_entries = reader.read_next_short_array(page_starts_count.max(0) as usize)?;
        let page_extras_entries = reader.read_next_short_array(page_extras_count.max(0) as usize)?;
        Ok(DyldCacheSlideInfo2 {
            base,
            page_size,
            page_starts_offset,
            page_starts_count,
            page_extras_offset,
            page_extras_count,
            delta_mask,
            value_add,
            page_starts_entries,
            page_extras_entries,
        })
    }

    /// Java: `getPageSize()`.
    pub fn get_page_size(&self) -> i64 {
        self.page_size as u32 as i64
    }

    /// Java: `getPageStartsOffset()`.
    pub fn get_page_starts_offset(&self) -> i64 {
        self.page_starts_offset as u32 as i64
    }

    /// Java: `getPageStartsCount()`.
    pub fn get_page_starts_count(&self) -> i64 {
        self.page_starts_count as u32 as i64
    }

    /// Java: `getPageExtrasOffset()`.
    pub fn get_page_extras_offset(&self) -> i64 {
        self.page_extras_offset as u32 as i64
    }

    /// Java: `getPageExtrasCount()`.
    pub fn get_page_extras_count(&self) -> i64 {
        self.page_extras_count as u32 as i64
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
        &self.page_starts_entries
    }

    /// Java: `getPageExtras()`.
    pub fn get_page_extras(&self) -> &[i16] {
        &self.page_extras_entries
    }

    /// Java: the private `processPointerChain`.
    fn process_pointer_chain(
        &self,
        segment_offset: i64,
        mut page_offset: i64,
        reader: &BinaryReader,
        pointer_size: i32,
        monitor: &dyn TaskMonitor,
        fixups: &mut Vec<DyldFixup>,
    ) -> Result<(), DyldSlideFixupError> {
        let value_mask = !self.delta_mask;
        let delta_shift = self.delta_mask.trailing_zeros();
        let mut delta: i64 = -1;
        while delta != 0 {
            monitor.check_cancelled()?;
            let data_offset = segment_offset + page_offset;
            let mut chain_value = if pointer_size == 8 {
                reader.read_long(data_offset as u64)?
            } else {
                reader.read_unsigned_int(data_offset as u64)? as i64
            };
            delta = (chain_value & self.delta_mask).checked_shr(delta_shift).unwrap_or(0);
            chain_value &= value_mask;
            if chain_value != 0 {
                chain_value = chain_value.wrapping_add(self.value_add);
                fixups.push(DyldFixup::new(data_offset, Some(chain_value), pointer_size, None, None));
            }
            page_offset += delta * 4;
        }
        Ok(())
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_slide_info2");
        s.add(dword(), "version", Some("currently 2"))?;
        s.add(dword(), "page_size", Some("currently 4096 (may also be 16384)"))?;
        for name in ["page_starts_offset", "page_starts_count", "page_extras_offset", "page_extras_count"] {
            s.add(dword(), name, Some(""))?;
        }
        s.add(qword(), "delta_mask", Some("which (contiguous) set of bits contains the delta to the next rebase location"))?;
        s.add(qword(), "value_add", Some(""))?;
        if self.page_starts_count > 0 {
            if self.page_starts_offset > 0x28 {
                s.add(array_with_element_length(byte(), self.page_starts_offset - 0x28, -1)?, "align", Some(""))?;
            }
            s.add(array_with_element_length(word(), self.page_starts_count, -1)?, "page_starts", Some(""))?;
        }
        if self.page_extras_count > 0 {
            let starts_end = self.page_starts_offset + self.page_starts_count * 2;
            if self.page_extras_offset > starts_end {
                s.add(array_with_element_length(byte(), self.page_extras_offset - starts_end, -1)?, "align", Some(""))?;
            }
            s.add(array_with_element_length(word(), self.page_extras_count, -1)?, "page_extras", Some(""))?;
        }
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheSlideInfo2 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl DyldCacheSlideInfoCommon for DyldCacheSlideInfo2 {
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
        pointer_size: i32,
        _log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<DyldFixup>, DyldSlideFixupError> {
        let mut fixups = Vec::new();
        monitor.initialize(self.page_starts_count as i64);
        monitor.set_message("Getting DYLD Cache V2 slide fixups...");
        for index in 0..self.page_starts_count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            // Java: `long segmentOffset = pageSize * index;` -- an int multiply, then widened.
            let segment_offset = self.page_size.wrapping_mul(index) as i64;
            let mut page_entry = self.page_starts_entries[index as usize] as u16 as i32;
            if page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE {
                continue;
            }
            if page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA != 0 {
                let mut extra_index = (page_entry & CHAIN_OFFSET_MASK) as usize;
                loop {
                    page_entry = *self.page_extras_entries.get(extra_index).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "page extras index out of range")
                    })? as u16 as i32;
                    let page_offset = ((page_entry & CHAIN_OFFSET_MASK) * BYTES_PER_CHAIN_OFFSET) as i64;
                    self.process_pointer_chain(segment_offset, page_offset, reader, pointer_size, monitor, &mut fixups)?;
                    extra_index += 1;
                    if page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA != 0 {
                        break;
                    }
                }
            } else {
                let page_offset = (page_entry * BYTES_PER_CHAIN_OFFSET) as i64;
                self.process_pointer_chain(segment_offset, page_offset, reader, pointer_size, monitor, &mut fixups)?;
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

    fn info(starts: &[u16], extras: &[u16]) -> DyldCacheSlideInfo2 {
        let mut b = Bytes::new(true);
        b.u32(2).u32(0x1000).u32(0x28).u32(starts.len() as u32);
        b.u32(0x28 + 2 * starts.len() as u32).u32(extras.len() as u32);
        b.u64(0x00ff_ff00_0000_0000).u64(0x1_8000_0000);
        for s in starts {
            b.u16(*s);
        }
        for e in extras {
            b.u16(*e);
        }
        DyldCacheSlideInfo2::new(&mut BinaryReader::from_bytes(b.buf, true), DyldCacheMappingInfo::new(0, 0, 0, 0, 0))
            .unwrap()
    }

    /// A 64-bit chain value: `delta` (in 4-byte units) in bits 40..56, `target` below.
    fn link(delta: u64, target: u64) -> u64 {
        (delta << 40) | target
    }

    #[test]
    fn walks_pointer_chains() {
        let info = info(&[0x0002, DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE as u16], &[]);
        assert_eq!(info.get_page_starts_count(), 2);
        let mut page = vec![0u8; 0x2000];
        page[8..16].copy_from_slice(&link(4, 0x10).to_le_bytes()); // -> offset 24
        page[24..32].copy_from_slice(&link(0, 0x20).to_le_bytes());
        let mut r = BinaryReader::from_bytes(page, true);
        let fixups = info.get_slide_fixups(&mut r, 8, &MessageLog::new(), &DummyMonitor).unwrap();
        assert_eq!(fixups, [
            DyldFixup::new(8, Some(0x1_8000_0010), 8, None, None),
            DyldFixup::new(24, Some(0x1_8000_0020), 8, None, None),
        ]);
    }

    #[test]
    fn follows_page_extras_until_end_marker() {
        let info = info(&[DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA as u16], &[0x0000, 0x8000 | 0x0004]);
        let mut page = vec![0u8; 0x1000];
        page[0..8].copy_from_slice(&link(0, 0x1).to_le_bytes());
        page[16..24].copy_from_slice(&link(0, 0x2).to_le_bytes());
        let mut r = BinaryReader::from_bytes(page, true);
        let fixups = info.get_slide_fixups(&mut r, 8, &MessageLog::new(), &DummyMonitor).unwrap();
        let offsets: Vec<i64> = fixups.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, [0, 16]);
        assert_eq!(info.to_structure().unwrap().get_length(), 0x28 + 2 + 4);
    }
}
