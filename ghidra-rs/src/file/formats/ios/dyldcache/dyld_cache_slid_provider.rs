//! Port of `ghidra.file.formats.ios.dyldcache.DyldCacheSlidProvider`.
//!
//! A [`ByteProvider`] over one DYLD cache file that returns "slid" bytes for a mapping: any
//! pointer the mapping's slide info rebases reads back as its fixed-up value.
//!
//! Divergence: Java's `readBytes` reports per-byte progress on the `TaskMonitor` it was built
//! with. A provider here is handed out as an owned `Rc<dyn ByteProvider>` that cannot borrow a
//! monitor, so no progress is reported (the bytes returned are identical).

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::opinion::dyld_cache_utils::SplitDyldCache;
use crate::format::macho::dyld::dyld_cache_mapping_info::DyldCacheMappingInfo;
use crate::format::macho::dyld::dyld_fixup::DyldFixup;

/// Each mapping's slide fixups, keyed by container file offset (Java:
/// `Map<DyldCacheMappingInfo, Map<Long, DyldFixup>>`).
pub type SlideFixupMap = HashMap<DyldCacheMappingInfo, HashMap<i64, DyldFixup>>;

/// Port of `ghidra.file.formats.ios.dyldcache.DyldCacheSlidProvider`.
pub struct DyldCacheSlidProvider {
    name: String,
    orig_provider: Rc<dyn ByteProvider>,
    mapping_info: DyldCacheMappingInfo,
    slide_fixup_map: Rc<SlideFixupMap>,
}

impl DyldCacheSlidProvider {
    /// Java `DyldCacheSlidProvider(DyldCacheMappingInfo, SplitDyldCache, int, Map, TaskMonitor)`
    /// (see the module docs for the monitor).
    pub fn new(
        mapping_info: DyldCacheMappingInfo,
        split_dyld_cache: &SplitDyldCache,
        split_cache_index: usize,
        slide_fixup_map: Rc<SlideFixupMap>,
    ) -> Self {
        DyldCacheSlidProvider {
            name: split_dyld_cache.get_name(split_cache_index).to_string(),
            orig_provider: Rc::clone(split_dyld_cache.get_provider(split_cache_index)),
            mapping_info,
            slide_fixup_map,
        }
    }

    /// The fixup covering container offset `index`, and the aligned offset it starts at:
    /// a 4-byte fixup at `index & !3`, else an 8-byte fixup at `index & !7`.
    fn fixup_at(&self, index: i64) -> Option<(i64, i64)> {
        if !self.mapping_info.contains(index, false) {
            return None;
        }
        let fixups = self.slide_fixup_map.get(&self.mapping_info)?;
        let aligned = index & !3;
        if let Some(value) = fixups.get(&aligned).and_then(|f| f.value) {
            return Some((aligned, value));
        }
        let aligned = index & !7;
        match fixups.get(&aligned) {
            Some(f) if f.size == 8 => f.value.map(|v| (aligned, v)),
            _ => None,
        }
    }
}

impl ByteProvider for DyldCacheSlidProvider {
    fn get_file(&self) -> Option<PathBuf> {
        self.orig_provider.get_file()
    }

    fn get_name(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn get_absolute_path(&self) -> Option<String> {
        self.orig_provider.get_absolute_path()
    }

    fn length(&self) -> u64 {
        self.orig_provider.length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.orig_provider.is_valid_index(index)
    }

    /// This is a wrapper, so it does not close the underlying provider.
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Java `readByte(long)`.
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        match self.fixup_at(index as i64) {
            Some((aligned, value)) => Ok((value >> ((index as i64 - aligned) * 8)) as u8),
            None => self.orig_provider.read_byte(index),
        }
    }

    /// Java `readBytes(long, long)`: the original bytes with every slid byte replaced.
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        if length > i32::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported length"));
        }
        if index > i64::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid index"));
        }
        let mut ret = self.orig_provider.read_bytes(index, length)?;
        for (i, b) in ret.iter_mut().enumerate() {
            let idx = index as i64 + i as i64;
            if let Some((aligned, value)) = self.fixup_at(idx) {
                *b = (value >> ((idx - aligned) * 8)) as u8;
            }
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    fn provider(map: SlideFixupMap, mapping: DyldCacheMappingInfo) -> DyldCacheSlidProvider {
        let orig: Rc<dyn ByteProvider> = Rc::new(ByteArrayProvider::with_name("dyld_shared_cache_arm64e", vec![0xAAu8; 0x40]));
        DyldCacheSlidProvider {
            name: "dyld_shared_cache_arm64e".to_string(),
            orig_provider: orig,
            mapping_info: mapping,
            slide_fixup_map: Rc::new(map),
        }
    }

    #[test]
    fn slid_bytes_replace_fixed_up_pointers() {
        // Mapping covers file offsets [0x10, 0x30).
        let mapping = DyldCacheMappingInfo::new(0x1_8000_0000, 0x20, 0x10, 3, 3);
        let mut fixups = HashMap::new();
        fixups.insert(0x10, DyldFixup::new(0x10, Some(0x1122_3344_5566_7788), 8, None, None));
        fixups.insert(0x20, DyldFixup::new(0x20, Some(0x0102_0304), 4, None, None));
        let mut map = SlideFixupMap::new();
        map.insert(mapping, fixups);
        let p = provider(map, mapping);

        assert_eq!(p.read_byte(0x10).unwrap(), 0x88);
        assert_eq!(p.read_byte(0x17).unwrap(), 0x11);
        assert_eq!(p.read_byte(0x18).unwrap(), 0xAA);
        assert_eq!(p.read_bytes(0x20, 4).unwrap(), [0x04, 0x03, 0x02, 0x01]);
        // Outside the mapping, and the 4-byte fixup does not cover 0x24.
        assert_eq!(p.read_byte(0x24).unwrap(), 0xAA);
        assert_eq!(p.read_byte(0x0).unwrap(), 0xAA);
        assert_eq!(p.read_bytes(0x0e, 4).unwrap(), [0xAA, 0xAA, 0x88, 0x77]);
        assert_eq!(p.get_name().as_deref(), Some("dyld_shared_cache_arm64e"));
        assert_eq!(p.length(), 0x40);
    }

    #[test]
    fn mapping_without_fixups_reads_original() {
        let mapping = DyldCacheMappingInfo::new(0, 0x40, 0, 1, 1);
        let p = provider(SlideFixupMap::new(), mapping);
        assert_eq!(p.read_bytes(0, 0x40).unwrap(), vec![0xAA; 0x40]);
        assert!(p.read_bytes(0, 1 << 32).is_err());
    }
}
