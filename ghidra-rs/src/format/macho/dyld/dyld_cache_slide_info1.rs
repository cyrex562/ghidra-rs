//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo1`.
//!
//! Represents a `dyld_cache_slide_info` (version 1): a table of contents mapping each 4K page to
//! a 128-byte bitmap of which 4-byte words hold pointers. See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::dyld::dyld_cache_mapping_info::DyldCacheMappingInfo;
use crate::format::macho::dyld::dyld_cache_slide_info_common::{
    DyldCacheSlideInfoCommon, DyldCacheSlideInfoCommonBase, DyldSlideFixupError,
};
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::macho::struct_builder::{array_with_element_length, byte, dword, word, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::task::TaskMonitor;

/// A version 1 `dyld_cache_slide_info`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfo1`.
#[derive(Debug, Clone)]
pub struct DyldCacheSlideInfo1 {
    base: DyldCacheSlideInfoCommonBase,
    toc_offset: i32,
    toc_count: i32,
    entries_offset: i32,
    entries_count: i32,
    entries_size: i32,
    toc: Vec<i16>,
    bits: Vec<Vec<u8>>,
}

impl DyldCacheSlideInfo1 {
    /// Java: `DyldCacheSlideInfo1(BinaryReader, DyldCacheMappingInfo)`. The table and entries are
    /// located relative to the start of the slide info.
    pub fn new(reader: &mut BinaryReader, mapping_info: DyldCacheMappingInfo) -> io::Result<Self> {
        let base = DyldCacheSlideInfoCommonBase::new(reader, mapping_info)?;
        let start_index = reader.get_pointer_index() - 4; // version # already read
        let toc_offset = reader.read_next_int()?;
        let toc_count = reader.read_next_int()?;
        let entries_offset = reader.read_next_int()?;
        let entries_count = reader.read_next_int()?;
        let entries_size = reader.read_next_int()?;
        reader.set_pointer_index(start_index.wrapping_add(toc_offset as i64 as u64));
        let toc = reader.read_next_short_array(toc_count.max(0) as usize)?;
        reader.set_pointer_index(start_index.wrapping_add(entries_offset as i64 as u64));
        let mut bits = Vec::with_capacity(entries_count.max(0) as usize);
        for _ in 0..entries_count {
            bits.push(reader.read_next_byte_array(entries_size.max(0) as usize)?);
        }
        Ok(DyldCacheSlideInfo1 { base, toc_offset, toc_count, entries_offset, entries_count, entries_size, toc, bits })
    }

    /// Java: `getTocOffset()`.
    pub fn get_toc_offset(&self) -> i32 {
        self.toc_offset
    }

    /// Java: `getTocCount()`.
    pub fn get_toc_count(&self) -> i32 {
        self.toc_count
    }

    /// Java: `getEntriesOffset()`.
    pub fn get_entries_offset(&self) -> i32 {
        self.entries_offset
    }

    /// Java: `getEntriesCount()`.
    pub fn get_entries_count(&self) -> i32 {
        self.entries_count
    }

    /// Java: `getEntriesSize()`.
    pub fn get_entries_size(&self) -> i32 {
        self.entries_size
    }

    /// Java: `getToc()`.
    pub fn get_toc(&self) -> &[i16] {
        &self.toc
    }

    /// Java: `getEntries()`.
    pub fn get_entries(&self) -> &[Vec<u8>] {
        &self.bits
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_slide_info");
        for name in ["version", "toc_offset", "toc_count", "entries_offset", "entries_count", "entries_size"] {
            s.add(dword(), name, Some(""))?;
        }
        if self.toc_offset > 0x18 {
            s.add(array_with_element_length(byte(), self.toc_offset - 0x18, -1)?, "align", Some(""))?;
        }
        s.add(array_with_element_length(word(), self.toc_count, -1)?, "toc", Some(""))?;
        let toc_end = self.toc_offset + self.toc_count * 2;
        if self.entries_offset > toc_end {
            s.add(array_with_element_length(byte(), self.entries_offset - toc_end, -1)?, "align", Some(""))?;
        }
        let entry = array_with_element_length(byte(), self.entries_size, -1)?;
        s.add(array_with_element_length(entry, self.entries_count, -1)?, "entries", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheSlideInfo1 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl DyldCacheSlideInfoCommon for DyldCacheSlideInfo1 {
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
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<DyldFixup>, DyldSlideFixupError> {
        let mut fixups = Vec::with_capacity(1024);
        monitor.initialize(self.toc_count as i64);
        monitor.set_message("Getting DYLD Cache V1 slide fixups...");
        for toc_index in 0..self.toc_count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let entry_index = self.toc[toc_index as usize] as u16 as i32;
            if entry_index >= self.entries_count {
                log.append_msg(&format!(
                    "Entry too big! [{toc_index}] {entry_index} {} {}",
                    self.entries_count,
                    self.bits.len()
                ));
                continue;
            }
            let entry = &self.bits[entry_index as usize];
            let segment_offset = 4096i64 * toc_index as i64;
            for page_entries_index in 0..128usize {
                monitor.check_cancelled()?;
                let bitmap = *entry.get(page_entries_index).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "slide info entry shorter than 128 bytes")
                })? as u64;
                if bitmap == 0 {
                    continue;
                }
                for bit_map_index in 0..8i64 {
                    if bitmap & (1 << bit_map_index) != 0 {
                        let page_offset = page_entries_index as i64 * 8 * 4 + bit_map_index * 4;
                        let value = reader.read_long((segment_offset + page_offset) as u64)?;
                        fixups.push(DyldFixup::new(segment_offset + page_offset, Some(value), 8, None, None));
                    }
                }
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
    fn decodes_bitmap_fixups() {
        let mut b = Bytes::new(true);
        // version, toc_offset 0x18, toc_count 2, entries_offset 0x1c, entries_count 1, size 128
        b.u32(1).u32(0x18).u32(2).u32(0x1c).u32(1).u32(128);
        b.u16(0).u16(5); // second toc entry is out of range
        let mut entry = vec![0u8; 128];
        entry[1] = 0b0000_0101; // words 8 and 10 of the page
        b.raw(&entry);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let info = DyldCacheSlideInfo1::new(&mut r, DyldCacheMappingInfo::new(0, 0, 0, 0, 0)).unwrap();
        assert_eq!(info.get_version(), 1);
        assert_eq!(info.get_toc(), [0, 5]);
        assert_eq!(info.get_entries()[0][1], 5);

        let mut page = vec![0u8; 4096];
        page[32..40].copy_from_slice(&0x1111u64.to_le_bytes());
        page[40..48].copy_from_slice(&0x2222u64.to_le_bytes());
        let mut data = BinaryReader::from_bytes(page, true);
        let log = MessageLog::new();
        let fixups = info.get_slide_fixups(&mut data, 8, &log, &DummyMonitor).unwrap();
        assert_eq!(fixups, [
            DyldFixup::new(32, Some(0x1111), 8, None, None),
            DyldFixup::new(40, Some(0x2222), 8, None, None),
        ]);
        assert_eq!(log.messages()[0], "Entry too big! [1] 5 1 1");
        let s = info.to_structure().unwrap();
        assert_eq!(s.get_length(), 0x1c + 128);
    }
}
