//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo3`.
//!
//! Represents a `dyld_cache_slide_info3` (arm64e): per-page starts of 8-byte pointer chains that
//! carry authenticated or plain targets. See `dyld3/shared-cache/dyld_cache_format.h`.

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

const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE: i32 = 0xFFFF;

/// A version 3 `dyld_cache_slide_info3`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo3`.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo3 {
    base: DyldCacheSlideInfoCommonBase,
    page_size: i32,
    page_starts_count: i32,
    auth_value_add: i64,
    page_starts: Vec<i16>,
}

impl DyldCacheSlideInfo3 {
    /// Java: `DyldCacheSlideInfo3(BinaryReader, DyldCacheMappingInfo)`.
    pub fn new(reader: &mut BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        let base = DyldCacheSlideInfoCommonBase::new(reader, mapping_info)?;
        let page_size = reader.read_next_int()?;
        let page_starts_count = reader.read_next_int()?;
        reader.read_next_int()?; // padding
        let auth_value_add = reader.read_next_long()?;
        let page_starts = reader.read_next_short_array(page_starts_count.max(0) as usize)?;
        Ok(DyldCacheSlideInfo3 { base, page_size, page_starts_count, auth_value_add, page_starts })
    }

    /// Java: `getPageSize()`.
    pub fn get_page_size(&self) -> i32 {
        self.page_size
    }

    /// Java: `getPageStartsCount()`.
    pub fn get_page_starts_count(&self) -> i32 {
        self.page_starts_count
    }

    /// Java: `getAuthValueAdd()`.
    pub fn get_auth_value_add(&self) -> i64 {
        self.auth_value_add
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
        let mut delta: i64 = -1;
        while delta != 0 {
            monitor.check_cancelled()?;
            let data_offset = segment_offset + page_offset;
            let mut chain_value = reader.read_long(data_offset as u64)?;
            let is_authenticated = (chain_value as u64 >> 63) != 0;
            delta = (chain_value & (0x7FF << 51)) >> 51;
            if is_authenticated {
                let offset_from_shared_cache_base = chain_value & 0xFFFF_FFFF;
                chain_value = offset_from_shared_cache_base.wrapping_add(self.auth_value_add);
            } else {
                let top8_bits = chain_value & 0x0007_F800_0000_0000;
                let bottom43_bits = chain_value & 0x0000_07FF_FFFF_FFFF;
                chain_value = (top8_bits << 13) | bottom43_bits;
            }
            fixups.push(DyldFixup::new(data_offset, Some(chain_value), 8, None, None));
            page_offset += delta * 8;
        }
        Ok(())
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_slide_info3");
        s.add(dword(), "version", Some("currently 3"))?;
        s.add(dword(), "page_size", Some("currently 4096 (may also be 16384)"))?;
        s.add(dword(), "page_starts_count", Some(""))?;
        s.add(dword(), "pad", Some(""))?;
        s.add(qword(), "auth_value_add", Some(""))?;
        s.add(array_with_element_length(word(), self.page_starts_count, 1)?, "page_starts", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheSlideInfo3 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl DyldCacheSlideInfoCommon for DyldCacheSlideInfo3 {
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
        monitor.set_message("Getting DYLD Cache V3 slide fixups...");
        for index in 0..self.page_starts_count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let segment_offset = self.page_size.wrapping_mul(index) as i64;
            let page_entry = self.page_starts[index as usize] as u16 as i32;
            if page_entry == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
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
    fn decodes_authenticated_and_plain_pointers() {
        let mut b = Bytes::new(true);
        b.u32(3).u32(0x4000).u32(2).u32(0).u64(0x1_8000_0000).u16(0x10).u16(0xFFFF);
        let info = DyldCacheSlideInfo3::new(&mut BinaryReader::from_bytes(b.buf, true), DyldCacheMappingInfo::new(0, 0, 0, 0, 0))
            .unwrap();
        let mut page = vec![0u8; 0x8000];
        // plain: delta 2 (x8 bytes), high8 0x12 in bits 43..51, low 0x4000
        let plain: u64 = (2 << 51) | (0x12 << 43) | 0x4000;
        // authenticated: bit 63, delta 0, offset 0x5000
        let auth: u64 = (1 << 63) | 0x5000;
        page[0x10..0x18].copy_from_slice(&plain.to_le_bytes());
        page[0x20..0x28].copy_from_slice(&auth.to_le_bytes());
        let mut r = BinaryReader::from_bytes(page, true);
        let fixups = info.get_slide_fixups(&mut r, 8, &MessageLog::new(), &DummyMonitor).unwrap();
        assert_eq!(fixups, [
            DyldFixup::new(0x10, Some((0x12i64 << 56) | 0x4000), 8, None, None),
            DyldFixup::new(0x20, Some(0x1_8000_5000), 8, None, None),
        ]);
        assert_eq!(info.to_structure().unwrap().get_length(), 24 + 4);
    }
}
