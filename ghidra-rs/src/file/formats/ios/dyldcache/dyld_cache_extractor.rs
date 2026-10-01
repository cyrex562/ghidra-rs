//! Port of `ghidra.file.formats.ios.dyldcache.DyldCacheExtractor`.
//!
//! Extracts DYLIBs and raw mappings from a (possibly split) DYLD cache. The Java class holds
//! only a static constant, three static methods and a private `ExtractedMacho` subclass, so per
//! the shape rules it is a plain module; the subclass (`DyldPackedSegments`) becomes
//! [`ExtractedMacho`] configured with a slid-segment provider and the image's local symbols.

use std::collections::HashMap;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::byte_provider_wrapper::ByteProviderWrapper;
use crate::app::util::importer::message_log::MessageLog;
use crate::app::util::opinion::dyld_cache_utils::SplitDyldCache;
use crate::file::formats::ios::extracted_macho::{ExtractError, ExtractedMacho};
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::dyld::dyld_cache_slide_info_common::DyldSlideFixupError;
use crate::format::macho::mach_constants::MH_MAGIC_64;
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::program::model::lang::endian::Endian;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::dyld_cache_entry::DyldCacheEntry;
use super::dyld_cache_slid_provider::{DyldCacheSlidProvider, SlideFixupMap};

/// A footer that gets appended to the end of every extracted component so Ghidra can identify
/// them and treat them special when imported. Java: `FOOTER_V1`.
pub const FOOTER_V1: &[u8] = b"Ghidra DYLD extraction v1";

/// Why an extraction failed (Java: `IOException`, `MachException`, `CancelledException`).
#[derive(Debug, thiserror::Error)]
pub enum DyldExtractError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Mach(#[from] MachException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

impl From<ExtractError> for DyldExtractError {
    fn from(e: ExtractError) -> Self {
        match e {
            ExtractError::Io(e) => DyldExtractError::Io(e),
            ExtractError::Cancelled(c) => DyldExtractError::Cancelled(c),
        }
    }
}

impl From<DyldSlideFixupError> for DyldExtractError {
    fn from(e: DyldSlideFixupError) -> Self {
        match e {
            DyldSlideFixupError::Io(e) => DyldExtractError::Io(e),
            DyldSlideFixupError::Cancelled(c) => DyldExtractError::Cancelled(c),
        }
    }
}

/// Java `extractDylib(DyldCacheEntry, SplitDyldCache, Map, FSRL, TaskMonitor)`: the DYLIB as a
/// standalone, packed Mach-O whose segments are read slid.
pub fn extract_dylib(
    entry: &DyldCacheEntry,
    split_dyld_cache: &SplitDyldCache,
    slide_fixup_map: &Rc<SlideFixupMap>,
    fsrl: Option<Fsrl>,
    monitor: &dyn TaskMonitor,
) -> Result<ByteArrayProvider, DyldExtractError> {
    let index = entry.split_cache_index() as usize;
    let (lower, _) = *entry
        .range_set()
        .first()
        .ok_or_else(|| std::io::Error::other(format!("DYLD cache entry {} has no ranges", entry.path())))?;
    let dylib_offset = lower - split_dyld_cache.get_dyld_cache_header(index).get_base_address();

    // DyldPackedSegments
    let provider = Rc::clone(split_dyld_cache.get_provider(index));
    let mut header = MachHeader::with_start_index_relative(Rc::clone(&provider), dylib_offset as u64, false)?;
    header.parse_split(Some(split_dyld_cache))?;
    let extra_symbols = match (split_dyld_cache.get_local_symbol_info(), header.get_segment("__TEXT")) {
        (Some(info), Some(text)) => {
            info.get_nlist_for(text.get_vm_address() - split_dyld_cache.get_base_address()).to_vec()
        }
        _ => Vec::new(),
    };
    let slide_map = Rc::clone(slide_fixup_map);
    let mut extracted = ExtractedMacho::new(provider, dylib_offset, header, FOOTER_V1, monitor)
        .with_extra_symbols(extra_symbols)
        .with_segment_provider(Box::new(move |segment: &SegmentCommand| {
            for i in 0..split_dyld_cache.size() {
                let dyld_cache_header = split_dyld_cache.get_dyld_cache_header(i);
                for mapping_info in dyld_cache_header.get_mapping_infos() {
                    if mapping_info.contains(segment.get_vm_address(), true) {
                        let p = DyldCacheSlidProvider::new(*mapping_info, split_dyld_cache, i, Rc::clone(&slide_map));
                        return Ok(Rc::new(p) as Rc<dyn ByteProvider>);
                    }
                }
            }
            Err(std::io::Error::other(format!(
                "Failed to find provider for segment: {}",
                segment.get_segment_name()
            )))
        }));
    extracted.pack()?;
    Ok(extracted.get_byte_provider(fsrl))
}

/// Java `extractMapping(DyldCacheEntry, String, SplitDyldCache, Map, FSRL, TaskMonitor)`: the
/// entry's ranges of one mapping, each wrapped as a segment (`<name>.<cache>.<i>`) of a minimal
/// 64-bit Mach-O, read slid.
pub fn extract_mapping(
    entry: &DyldCacheEntry,
    segment_name: &str,
    split_dyld_cache: &SplitDyldCache,
    slide_fixup_map: &Rc<SlideFixupMap>,
    fsrl: Option<Fsrl>,
    _monitor: &dyn TaskMonitor,
) -> Result<ByteArrayProvider, DyldExtractError> {
    let magic = MH_MAGIC_64;
    let ranges = entry.range_set();
    let mapping_info = *entry
        .mapping_info()
        .ok_or_else(|| std::io::Error::other(format!("DYLD cache entry {} is not a mapping", entry.path())))?;
    let all_segments_size = SegmentCommand::size(magic)? * ranges.len() as i32;

    // Mach-O Header
    let header = MachHeader::create(
        magic,
        0x100000c,
        0x80000002u32 as i32,
        6,
        ranges.len() as i32,
        all_segments_size,
        0x42100085,
        0,
    )?;

    // Segment commands and data
    let mut segments = Vec::new();
    let mut data = Vec::new();
    let mut current = header.len() as i64 + all_segments_size as i64;
    let slid_provider = DyldCacheSlidProvider::new(
        mapping_info,
        split_dyld_cache,
        entry.split_cache_index() as usize,
        Rc::clone(slide_fixup_map),
    );
    for (i, &(lower, upper)) in ranges.iter().enumerate() {
        let data_size = upper - lower;
        segments.push(SegmentCommand::create(
            magic,
            &format!("{segment_name}.{}.{i}", entry.split_cache_index()),
            lower,
            data_size,
            current,
            data_size,
            mapping_info.get_max_protection(),
            mapping_info.get_max_protection(),
            0,
        )?);
        data.push(slid_provider.read_bytes(
            (lower - mapping_info.get_address() + mapping_info.get_file_offset()) as u64,
            data_size as u64,
        )?);
        current += data_size;
    }

    // Combine pieces, then add the footer.
    let mut result = header;
    for segment in &segments {
        result.extend_from_slice(segment);
    }
    for d in &data {
        result.extend_from_slice(d);
    }
    result.extend_from_slice(FOOTER_V1);
    Ok(ByteArrayProvider::with_fsrl(result, fsrl))
}

/// Java `getSlideFixups(SplitDyldCache, TaskMonitor)`: every mapping's slide fixups, keyed by
/// container file offset.
pub fn get_slide_fixups(
    split_dyld_cache: &SplitDyldCache,
    monitor: &dyn TaskMonitor,
) -> Result<SlideFixupMap, DyldExtractError> {
    let mut slide_fixup_map = SlideFixupMap::new();
    let log = MessageLog::new();
    for i in 0..split_dyld_cache.size() {
        let header = split_dyld_cache.get_dyld_cache_header(i);
        let bp = split_dyld_cache.get_provider(i);
        let arch = header
            .get_architecture()
            .ok_or_else(|| std::io::Error::other("DYLD cache has an unknown architecture"))?;
        for slide_info in header.get_slide_infos() {
            let mapping_info = *slide_info.get_mapping_info();
            let wrapper = ByteProviderWrapper::with_range(
                Rc::clone(bp),
                mapping_info.get_file_offset() as u64,
                mapping_info.get_size() as u64,
            );
            let wrapper: Rc<dyn ByteProvider> = Rc::new(wrapper);
            let mut wrapper_reader = BinaryReader::new(wrapper, arch.endianness() != Endian::Big);
            let fixups = slide_info.get_slide_fixups(
                &mut wrapper_reader,
                if arch.is_64bit() { 8 } else { 4 },
                &log,
                monitor,
            )?;
            let sub_map: HashMap<i64, _> = fixups
                .into_iter()
                .map(|fixup| (mapping_info.get_file_offset() + fixup.offset, fixup))
                .collect();
            slide_fixup_map.insert(mapping_info, sub_map);
        }
    }
    Ok(slide_fixup_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::file::formats::ios::dyldcache::dyld_cache_file_system::test_support::{dyld_cache, BASE};
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
    use crate::util::task::DummyMonitor;

    fn split() -> (tempfile::TempDir, SplitDyldCache) {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        let p: Rc<dyn ByteProvider> = Rc::new(ByteArrayProvider::with_name("dyld_shared_cache_x86_64", dyld_cache()));
        let split = SplitDyldCache::new(p, false, &MessageLog::new(), &DummyMonitor, &svc).unwrap();
        (dir, split)
    }

    #[test]
    fn slide_fixups_are_keyed_by_container_offset_and_read_slid() {
        let (_dir, split) = split();
        let map = get_slide_fixups(&split, &DummyMonitor).unwrap();
        assert_eq!(map.len(), 1);
        let (mapping, fixups) = map.iter().next().unwrap();
        assert_eq!(mapping.get_file_offset(), 0x2000);
        let fixup = &fixups[&0x2900];
        assert_eq!(fixup.value, Some(BASE as i64 + 0x1234));
        assert_eq!(fixup.size, 8);

        let slid = DyldCacheSlidProvider::new(*mapping, &split, 0, Rc::new(map.clone()));
        assert_eq!(slid.read_bytes(0x2900, 8).unwrap(), (BASE + 0x1234).to_le_bytes());
        assert_eq!(split.get_provider(0).read_bytes(0x2900, 8).unwrap(), 0x1234u64.to_le_bytes());
    }

    #[test]
    fn extract_mapping_and_dylib_directly() {
        let (_dir, split) = split();
        let map = Rc::new(get_slide_fixups(&split, &DummyMonitor).unwrap());
        let mapping = *split.get_dyld_cache_header(0).get_mapping_infos().get(1).unwrap();
        let lower = BASE as i64 + 0x3800;
        let entry = DyldCacheEntry::new("m", 0, vec![(lower, lower + 0x200)], Some(mapping), None, 1);
        let p = extract_mapping(&entry, "DATA", &split, &map, None, &DummyMonitor).unwrap();
        let bytes = p.read_bytes(0, p.length()).unwrap();
        // The extracted range starts at file 0x2800, so the slid pointer is at +0x100.
        let data = 32 + 72;
        assert_eq!(&bytes[data + 0x100..data + 0x108], &(BASE + 0x1234).to_le_bytes());
        assert!(bytes.ends_with(FOOTER_V1));
        let mut h = MachHeader::new(Rc::new(ByteArrayProvider::new(bytes))).unwrap();
        h.parse().unwrap();
        assert_eq!(h.get_segment("DATA.0.0").unwrap().get_max_protection(), 3);

        let dylib = DyldCacheEntry::new("/usr/lib/libA.dylib", 0, vec![(BASE as i64 + 0x1000, BASE as i64 + 0x2000)], None, None, -1);
        let p = extract_dylib(&dylib, &split, &map, None, &DummyMonitor).unwrap();
        assert!(p.read_bytes(0, p.length()).unwrap().ends_with(FOOTER_V1));
    }
}
