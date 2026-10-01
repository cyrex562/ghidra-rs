//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo5`.
//!
//! Represents a `dyld_cache_slide_info5` (arm64e shared-cache chained pointers). See
//! `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::dyld::dyld_cache_mapping_info::DyldCacheMappingInfo;
use crate::format::macho::dyld::dyld_cache_slide_info_common::{
    DyldCacheSlideInfoCommon, DyldCacheSlideInfoCommonBase, DyldSlideFixupError
};
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::macho::struct_builder::{array_with_element_length, dword, qword, word, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::task::TaskMonitor;
use crate::format::macho::dyld::dyld_chained_ptr::DyldChainType;

const DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE: i32 = 0xFFFF;
const TYPE: DyldChainType = DyldChainType::Arm64eSharedCache;

/// A version 5 `dyld_cache_slide_info5`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo5`.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo5 {
    base: DyldCacheSlideInfoCommonBase,
    page_size: i32,
    page_starts_count: i32,
    value_add: i64,
    page_starts: Vec<i16>,
}

impl DyldCacheSlideInfo5 {
    /// Java: `DyldCacheSlideInfo5(BinaryReader, DyldCacheMappingInfo)`.
    pub fn new(reader: &mut BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        let base = DyldCacheSlideInfoCommonBase::new(reader, mapping_info)?;
        let page_size = reader.read_next_int()?;
        let page_starts_count = reader.read_next_int()?;
        reader.read_next_int()?; // padding
        let value_add = reader.read_next_long()?;
        let page_starts = reader.read_next_short_array(page_starts_count.max(0) as usize)?;
        Ok(DyldCacheSlideInfo5 { base, page_size, page_starts_count, value_add, page_starts })
    }

    /// Java: `getPageSize()`.
    pub fn get_page_size(&self) -> i32 {
        self.page_size
    }

    /// Java: `getPageStartsCount()`.
    pub fn get_page_starts_count(&self) -> i32 {
        self.page_starts_count
    }

    /// Java: `getValueAdd()`.
    pub fn get_value_add(&self) -> i64 {
        self.value_add
    }

    /// Java: `getPageStarts()`.
    pub fn get_page_starts(&self) -> &[i16] {
        &self.page_starts
    }

    /// Java: the private `processPointerChain`.
    fn process_pointer_chain(
        &self,
        segment_offset: i64,
        mut page_offset: i64,
        reader: &BinaryReader,
        monitor: &dyn TaskMonitor,
        fixups: &mut Vec<DyldFixup>,
    ) -> Result<(), DyldSlideFixupError> {
        let size = TYPE.size();
        let stride = TYPE.stride();
        let mut delta: i64 = -1;
        while delta != 0 {
            monitor.check_cancelled()?;
            let data_offset = segment_offset + page_offset;
            let chain_value = TYPE.chain_value(reader, data_offset as u64)?;
            let mut new_ptr_value = TYPE.target(chain_value).wrapping_add(self.value_add);
            delta = TYPE.next(chain_value);
            if !TYPE.is_authenticated(chain_value) {
                let high8 = ((chain_value as u64) >> 34) & 0xff;
                new_ptr_value |= (high8 << 56) as i64;
            }
            fixups.push(DyldFixup::new(data_offset, Some(new_ptr_value), size, None, None));
            page_offset += delta * stride;
        }
        Ok(())
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_slide_info5");
        s.add(dword(), "version", Some("currently 5"))?;
        s.add(dword(), "page_size", Some("currently 4096 (may also be 16384)"))?;
        s.add(dword(), "page_starts_count", Some(""))?;
        s.add(dword(), "pad", Some(""))?;
        s.add(qword(), "value_add", Some(""))?;
        s.add(array_with_element_length(word(), self.page_starts_count, 1)?, "page_starts", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheSlideInfo5 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl DyldCacheSlideInfoCommon for DyldCacheSlideInfo5 {
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
        monitor.set_message("Getting DYLD Cache V5 slide fixups...");
        for index in 0..self.page_starts_count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let segment_offset = self.page_size.wrapping_mul(index) as i64;
            let page_entry = self.page_starts[index as usize] as u16 as i32;
            if page_entry == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
                continue;
            }
            let page_offset = ((page_entry / 8) * 8) as i64; // first entry byte based
            self.process_pointer_chain(segment_offset, page_offset, reader, monitor, &mut fixups)?;
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
    fn decodes_shared_cache_chain() {
        let mut b = Bytes::new(true);
        b.u32(5).u32(0x4000).u32(1).u32(0).u64(0x1_8000_0000).u16(0);
        let info = DyldCacheSlideInfo5::new(&mut BinaryReader::from_bytes(b.buf, true), DyldCacheMappingInfo::new(0, 0, 0, 0, 0))
            .unwrap();
        assert_eq!(info.get_page_starts(), [0]);
        let mut page = vec![0u8; 0x4000];
        // runtimeOffset 0x1234 (bits 0..34), high8 0x5 (bits 34..42), next 0 (bits 52..63)
        let v: u64 = (0x5 << 34) | 0x1234;
        page[0..8].copy_from_slice(&v.to_le_bytes());
        let mut r = BinaryReader::from_bytes(page, true);
        let fixups = info.get_slide_fixups(&mut r, 8, &MessageLog::new(), &DummyMonitor).unwrap();
        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].offset, 0);
        assert_eq!(fixups[0].size, TYPE.size());
        let expected = (TYPE.target(v as i64) + 0x1_8000_0000) | (5i64 << 56);
        assert_eq!(fixups[0].value, Some(expected));
        assert_eq!(info.to_structure().unwrap().get_length(), 24 + 2);
    }
}
