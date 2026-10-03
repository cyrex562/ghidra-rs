//! Port of `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem`.
//!
//! A [`GFileSystem`] over the components of a (possibly split) DYLD cache: one file per cached
//! DYLIB, plus one file per stretch of each mapping that no DYLIB claims.
//!
//! Follows [`CpioFileSystem`](crate::file::formats::cpio::cpio_file_system::CpioFileSystem):
//! the inherited `AbstractFileSystem` state is an embedded [`AbstractFileSystemBase`], and the
//! state that is filled lazily or released on close sits behind `RefCell`s because the
//! filesystem is shared through [`FsHandle`](crate::filesystem::gfilesystem::g_file_system::FsHandle)s.
//!
//! Guava's `Range`/`RangeSet`/`RangeMap` (used with open-closed `Range<Long>`s) are replaced by
//! the small private [`AddrRange`]/[`AddrRangeSet`]/[`AddrRangeMap`] below.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::io;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use super::dyld_cache_entry::DyldCacheEntry;
use super::dyld_cache_extractor::{self, DyldExtractError};
use super::dyld_cache_slid_provider::SlideFixupMap;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::importer::message_log::MessageLog;
use crate::app::util::opinion::dyld_cache_utils::{SplitDyldCache, SplitDyldCacheError};
use crate::filesystem::gfilesystem::abstract_file_system::{AbstractFileSystemBase, AbstractFsHandle};
use crate::filesystem::gfilesystem::annotations::file_system_info::{FileSystemInfo, PRIORITY_DEFAULT};
use crate::filesystem::gfilesystem::file_system_index_helper::copy_file;
use crate::filesystem::gfilesystem::file_system_ref_manager::FileSystemRefManager;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_system::{GFileSystem, GFileSystemError};
use crate::format::macho::dyld::dyld_cache_mapping_and_slide_info::DyldCacheMappingAndSlideInfo;
use crate::util::task::TaskMonitor;

/// Java: `DYLD_CACHE_FSTYPE`.
pub const DYLD_CACHE_FSTYPE: &str = "dyldcachev1";

// ─── Guava `Range`/`RangeSet`/`RangeMap` stand-ins ─────────────────────────────

/// An open-closed `Range<Long>` `(lower, upper]`, stored as the equivalent half-open
/// `[start, end)` so connected ranges coalesce exactly as Guava's do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AddrRange {
    start: i64,
    end: i64,
}

impl AddrRange {
    /// Java `Range.openClosed(lower, upper)`.
    fn open_closed(lower: i64, upper: i64) -> Self {
        AddrRange { start: lower.wrapping_add(1), end: upper.wrapping_add(1) }
    }

    /// Java `Range.lowerEndpoint()`.
    fn lower_endpoint(&self) -> i64 {
        self.start.wrapping_sub(1)
    }

    /// Java `Range.upperEndpoint()`.
    fn upper_endpoint(&self) -> i64 {
        self.end.wrapping_sub(1)
    }
}

/// Java's `TreeRangeSet<Long>`: sorted, disjoint, coalesced ranges.
#[derive(Debug, Clone, Default)]
struct AddrRangeSet {
    ranges: Vec<AddrRange>,
}

impl AddrRangeSet {
    /// Java `RangeSet.add(Range)`, coalescing connected ranges.
    fn add(&mut self, range: AddrRange) {
        if range.start >= range.end {
            return;
        }
        let mut merged = range;
        let mut result = Vec::with_capacity(self.ranges.len() + 1);
        let mut inserted = false;
        for r in &self.ranges {
            if r.end < merged.start {
                result.push(*r);
            } else if r.start > merged.end {
                if !inserted {
                    result.push(merged);
                    inserted = true;
                }
                result.push(*r);
            } else {
                merged = AddrRange { start: merged.start.min(r.start), end: merged.end.max(r.end) };
            }
        }
        if !inserted {
            result.push(merged);
        }
        self.ranges = result;
    }

    /// Java `RangeSet.addAll(RangeSet)`.
    fn add_all(&mut self, other: &AddrRangeSet) {
        for r in &other.ranges {
            self.add(*r);
        }
    }

    /// Java `RangeSet.removeAll(RangeSet)`.
    fn remove_all(&mut self, other: &AddrRangeSet) {
        let mut result = Vec::new();
        for r in &self.ranges {
            let mut pieces = vec![*r];
            for o in &other.ranges {
                let mut next = Vec::new();
                for p in pieces {
                    if o.end <= p.start || o.start >= p.end {
                        next.push(p);
                    } else {
                        if p.start < o.start {
                            next.push(AddrRange { start: p.start, end: o.start });
                        }
                        if o.end < p.end {
                            next.push(AddrRange { start: o.end, end: p.end });
                        }
                    }
                }
                pieces = next;
            }
            result.extend(pieces);
        }
        result.sort();
        self.ranges = result;
    }

    /// The ranges as `(lowerEndpoint, upperEndpoint)` pairs (what [`DyldCacheEntry`] stores).
    fn endpoints(&self) -> Vec<(i64, i64)> {
        self.ranges.iter().map(|r| (r.lower_endpoint(), r.upper_endpoint())).collect()
    }
}

/// Java's `TreeRangeMap<Long, DyldCacheEntry>`. Every range put by this class is disjoint from
/// the others, so no splitting of existing entries is needed.
#[derive(Debug, Default)]
struct AddrRangeMap {
    entries: Vec<(AddrRange, Rc<DyldCacheEntry>)>,
}

impl AddrRangeMap {
    fn put(&mut self, range: AddrRange, value: Rc<DyldCacheEntry>) {
        let pos = self.entries.partition_point(|(r, _)| r < &range);
        self.entries.insert(pos, (range, value));
    }

    /// Java `RangeMap.get(Long)`.
    fn get(&self, addr: i64) -> Option<&Rc<DyldCacheEntry>> {
        self.entries.iter().find(|(r, _)| addr >= r.start && addr < r.end).map(|(_, v)| v)
    }

    /// Java `RangeMap.asMapOfRanges().values()` (in range order).
    fn values(&self) -> impl Iterator<Item = &Rc<DyldCacheEntry>> {
        self.entries.iter().map(|(_, v)| v)
    }
}

/// Guava's `RangeSet.toString()` for open-closed ranges, e.g. `[(4096..8192]]`.
fn range_set_string(ranges: &[(i64, i64)]) -> String {
    let parts: Vec<String> = ranges.iter().map(|(lo, hi)| format!("({lo}..{hi}]")).collect();
    format!("[{}]", parts.join(", "))
}

// ─── DyldCacheFileSystem ───────────────────────────────────────────────────────

/// Port of `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem`.
pub struct DyldCacheFileSystem {
    base: AbstractFileSystemBase<Rc<DyldCacheEntry>>,
    provider: RefCell<Option<Rc<dyn ByteProvider>>>,
    split_dyld_cache: RefCell<Option<SplitDyldCache>>,
    parsed_local_symbols: RefCell<bool>,
    slide_fixup_map: RefCell<Option<Rc<SlideFixupMap>>>,
    range_map: RefCell<AddrRangeMap>,
}

impl DyldCacheFileSystem {
    /// `@FileSystemInfo(type = "dyldcachev1")`.
    pub const FS_TYPE: &'static str = DYLD_CACHE_FSTYPE;
    /// `@FileSystemInfo(description = "iOS DYLD Cache Version 1")`.
    pub const DESCRIPTION: &'static str = "iOS DYLD Cache Version 1";
    /// The `@FileSystemInfo` annotation (default priority).
    pub const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, PRIORITY_DEFAULT);

    /// Java `DyldCacheFileSystem(FSRLRoot, ByteProvider)` (Java takes the service from
    /// `FileSystemService.getInstance()`).
    pub fn new(fs_fsrl: FsrlRoot, provider: Rc<dyn ByteProvider>, fs_service: &FileSystemService) -> Self {
        DyldCacheFileSystem {
            base: AbstractFileSystemBase::new(fs_fsrl, fs_service),
            provider: RefCell::new(Some(provider)),
            split_dyld_cache: RefCell::new(None),
            parsed_local_symbols: RefCell::new(false),
            slide_fixup_map: RefCell::new(None),
            range_map: RefCell::new(AddrRangeMap::default()),
        }
    }

    /// Java `mount(TaskMonitor)`: opens the (split) cache, adds every DYLIB as a file, then every
    /// stretch of each mapping not covered by a DYLIB.
    ///
    /// # Errors
    /// I/O errors (including a `MachException`, which Java's factory wraps the same way),
    /// missing sub-caches, or cancellation.
    pub fn mount(&mut self, monitor: &dyn TaskMonitor) -> Result<(), GFileSystemError> {
        let provider = self.provider.borrow().clone().ok_or_else(|| io::Error::other("filesystem is closed"))?;
        let fs_service = self.base.fs_service().get()?;
        let split = SplitDyldCache::new(provider, false, &MessageLog::new(), monitor, &fs_service)
            .map_err(|e| match e {
                SplitDyldCacheError::Io(e) => GFileSystemError::Io(e),
                SplitDyldCacheError::Cancelled(c) => GFileSystemError::Cancelled(c),
            })?;

        let mut range_map = AddrRangeMap::default();
        let mut all_dylib_ranges = AddrRangeSet::default();

        // Find the DYLIB's and add them as files
        let image_records = split.get_image_records();
        monitor.initialize(image_records.len() as i64);
        monitor.set_message("Find DYLD DYLIBs...");
        for image_record in &image_records {
            monitor.increment_progress(1);
            let mut mach_header = split
                .get_macho(image_record)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut range_set = AddrRangeSet::default();
            for segment in mach_header
                .parse_segments()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            {
                range_set.add(AddrRange::open_closed(
                    segment.get_vm_address(),
                    segment.get_vm_address() + segment.get_vm_size(),
                ));
            }
            let path = image_record.image.get_path().to_string();
            let entry = Rc::new(DyldCacheEntry::new(
                path.clone(),
                image_record.split_cache_index as i32,
                range_set.endpoints(),
                None,
                None,
                -1,
            ));
            for r in &range_set.ranges {
                range_map.put(*r, Rc::clone(&entry));
            }
            all_dylib_ranges.add_all(&range_set);
            let index = self.base.fs_index_mut();
            let file_count = index.get_file_count() as i64;
            index.store_file(&path, file_count, false, -1, entry);
        }

        // Find and store all the mappings for all of the subcaches, minus the DYLIB's just found
        // so no bytes are accounted for more than once. This breaks the mappings up into a lot
        // of small chunks, each its own file.
        monitor.initialize(split.size() as i64);
        monitor.set_message("Find DYLD mapping ranges...");
        for i in 0..split.size() {
            monitor.increment_progress(1);
            let header = split.get_dyld_cache_header(i);
            let name = split.get_name(i);
            let mapping_infos = header.get_mapping_infos();
            let mapping_and_slide_infos = header.get_cache_mapping_and_slide_infos();
            for (j, mapping_info) in mapping_infos.iter().enumerate() {
                let mapping_and_slide_info =
                    if mapping_and_slide_infos.is_empty() { None } else { mapping_and_slide_infos.get(j).copied() };
                let mut reduced_range_set = AddrRangeSet::default();
                reduced_range_set.add(AddrRange::open_closed(
                    mapping_info.get_address(),
                    mapping_info.get_address() + mapping_info.get_size(),
                ));
                reduced_range_set.remove_all(&all_dylib_ranges);
                for range in reduced_range_set.ranges.clone() {
                    let path = get_component_path(name, mapping_and_slide_info.as_ref(), j, range);
                    let entry = Rc::new(DyldCacheEntry::new(
                        path.clone(),
                        i as i32,
                        vec![(range.lower_endpoint(), range.upper_endpoint())],
                        Some(*mapping_info),
                        mapping_and_slide_info,
                        j as i32,
                    ));
                    range_map.put(range, Rc::clone(&entry));
                    let index = self.base.fs_index_mut();
                    let file_count = index.get_file_count() as i64;
                    index.store_file(&path, file_count, false, -1, entry);
                }
            }
        }

        *self.split_dyld_cache.borrow_mut() = Some(split);
        *self.range_map.borrow_mut() = range_map;
        Ok(())
    }

    /// Java `findAddress(long)`: the path of the file containing `addr`, if any.
    pub fn find_address(&self, addr: i64) -> Option<String> {
        self.range_map.borrow().get(addr).map(|e| e.path().to_string())
    }

    /// Java `getFiles(long)`: the mapping files whose `dyld_cache_mapping_and_slide_info` flags
    /// intersect `flags`, in address order.
    pub fn get_files(&self, flags: i64) -> Vec<Box<dyn GFile<AbstractFsHandle>>> {
        let range_map = self.range_map.borrow();
        let mut files = Vec::new();
        for entry in range_map.values() {
            if let Some(info) = entry.mapping_and_slide_info() {
                if (flags & info.get_flags()) != 0 {
                    if let Some(f) = self.base.lookup(Some(entry.path())) {
                        files.push(Self::owned(f));
                    }
                }
            }
        }
        files
    }

    fn owned(f: &dyn GFile<AbstractFsHandle>) -> Box<dyn GFile<AbstractFsHandle>> {
        Box::new(copy_file(f))
    }
}

/// Java's private `getComponentName(DyldCacheMappingAndSlideInfo)`.
fn get_component_name(mapping_and_slide_info: Option<&DyldCacheMappingAndSlideInfo>) -> &'static str {
    let Some(m) = mapping_and_slide_info else {
        return "DYLD";
    };
    if m.is_dirty_data() {
        "DATA_DIRTY"
    } else if m.is_const_data() {
        if m.is_auth_data() {
            "AUTH_CONST"
        } else {
            "DATA_CONST"
        }
    } else if m.is_text_stubs() {
        "TEXT_STUBS"
    } else if m.is_config_data() {
        "DATA_CONFIG"
    } else if m.is_auth_data() {
        "AUTH"
    } else if m.is_read_only_data() {
        "DATA_RO"
    } else if m.is_const_tpro_data() {
        "DATA_CONST_TPRO"
    } else {
        "DYLD"
    }
}

/// Java's private `getComponentPath(String, DyldCacheMappingInfo, DyldCacheMappingAndSlideInfo,
/// int, Range)` (the mapping info argument is unused in Java).
fn get_component_path(
    dyld_cache_name: &str,
    mapping_and_slide_info: Option<&DyldCacheMappingAndSlideInfo>,
    mapping_index: usize,
    range: AddrRange,
) -> String {
    format!(
        "/DYLD/{}/{}.{}.0x{:x}-0x{:x}",
        dyld_cache_name,
        get_component_name(mapping_and_slide_info),
        mapping_index,
        range.lower_endpoint(),
        range.upper_endpoint()
    )
}

impl GFileSystem for DyldCacheFileSystem {
    type Fs = AbstractFsHandle;

    fn get_name(&self) -> String {
        self.base.get_name()
    }

    fn get_type(&self) -> String {
        Self::FS_TYPE.to_string()
    }

    fn get_description(&self) -> String {
        Self::DESCRIPTION.to_string()
    }

    fn get_fsrl(&self) -> &FsrlRoot {
        self.base.get_fsrl()
    }

    /// Java `isClosed()`.
    fn is_closed(&self) -> bool {
        self.provider.borrow().is_none()
    }

    fn get_ref_manager(&self) -> &FileSystemRefManager {
        self.base.get_ref_manager()
    }

    fn get_file_count(&self) -> i32 {
        self.base.get_file_count()
    }

    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.lookup(path).map(|f| Self::owned(f)))
    }

    fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> io::Result<Option<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.lookup_with_comparator(path, name_comp).map(|f| Self::owned(f)))
    }

    /// Java `getByteProvider(GFile, TaskMonitor)`: a mapping chunk wrapped as a Mach-O, or a
    /// DYLIB extracted as a packed Mach-O, both read slid; `None` if `file` has no entry. The
    /// slide fixups and local symbols are computed on first use.
    fn get_byte_provider(
        &self,
        file: &dyn GFile<AbstractFsHandle>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        let Some(entry) = self.base.fs_index().get_metadata(file).cloned() else {
            return Ok(None);
        };
        let convert = |e: DyldExtractError| -> GFileSystemError {
            match e {
                DyldExtractError::Io(e) => GFileSystemError::Io(e),
                DyldExtractError::Cancelled(c) => GFileSystemError::Cancelled(c),
                DyldExtractError::Mach(_) => GFileSystemError::Io(io::Error::other(format!(
                    "Invalid Mach-O header detected at: {}",
                    entry.path()
                ))),
            }
        };

        let slide_fixup_map = {
            let existing = self.slide_fixup_map.borrow().clone();
            match existing {
                Some(map) => map,
                None => {
                    let split = self.split_dyld_cache.borrow();
                    let split = split.as_ref().ok_or_else(|| io::Error::other("DYLD cache filesystem is not mounted"))?;
                    let map = Rc::new(dyld_cache_extractor::get_slide_fixups(split, monitor).map_err(convert)?);
                    *self.slide_fixup_map.borrow_mut() = Some(Rc::clone(&map));
                    map
                }
            }
        };
        if !*self.parsed_local_symbols.borrow() {
            let mut split = self.split_dyld_cache.borrow_mut();
            let split = split.as_mut().ok_or_else(|| io::Error::other("DYLD cache filesystem is not mounted"))?;
            for i in 0..split.size() {
                split.get_dyld_cache_header_mut(i).parse_local_symbols_info(true, &MessageLog::new(), monitor)?;
            }
            *self.parsed_local_symbols.borrow_mut() = true;
        }

        let split = self.split_dyld_cache.borrow();
        let split = split.as_ref().ok_or_else(|| io::Error::other("DYLD cache filesystem is not mounted"))?;
        let fsrl = Some(file.get_fsrl().clone());
        let provider = if entry.mapping_info().is_some() {
            dyld_cache_extractor::extract_mapping(
                &entry,
                get_component_name(entry.mapping_and_slide_info()),
                split,
                &slide_fixup_map,
                fsrl,
                monitor,
            )
        } else {
            dyld_cache_extractor::extract_dylib(&entry, split, &slide_fixup_map, fsrl, monitor)
        }
        .map_err(convert)?;
        Ok(Some(Box::new(provider)))
    }

    fn get_listing(
        &self,
        directory: Option<&dyn GFile<AbstractFsHandle>>,
    ) -> io::Result<Vec<Box<dyn GFile<AbstractFsHandle>>>> {
        Ok(self.base.get_listing(directory).into_iter().map(|f| Self::owned(f)).collect())
    }

    /// Java `getFileAttributes(GFile, TaskMonitor)`.
    fn get_file_attributes(&self, file: &dyn GFile<AbstractFsHandle>, _monitor: &dyn TaskMonitor) -> FileAttributes {
        let mut result = FileAttributes::new();
        if let Some(entry) = self.base.fs_index().get_metadata(file) {
            result.add(FileAttributeType::NameAttr, Some(entry.path().into()));
            result.add(FileAttributeType::PathAttr, Some(entry.path().into()));
            result.add_named("Cache Index", Some((entry.split_cache_index() as i64).into()));
            result.add_named("Address Range", Some(range_set_string(entry.range_set()).into()));
        }
        result
    }

    /// Java `close()`.
    fn close(&self) -> io::Result<()> {
        let _ = self.base.get_ref_manager().on_close(self);
        self.base.fs_index().clear();
        self.split_dyld_cache.borrow_mut().take();
        if let Some(mut provider) = self.provider.borrow_mut().take() {
            if let Some(p) = Rc::get_mut(&mut provider) {
                p.close()?;
            }
        }
        self.slide_fixup_map.borrow_mut().take();
        *self.parsed_local_symbols.borrow_mut() = false;
        *self.range_map.borrow_mut() = AddrRangeMap::default();
        Ok(())
    }
}

impl Deref for DyldCacheFileSystem {
    type Target = AbstractFileSystemBase<Rc<DyldCacheEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for DyldCacheFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::file::formats::ios::extracted_macho::test_support::write_macho;
    use crate::format::macho::mach_header::test_support::Bytes;

    /// The base address of [`dyld_cache`]'s first mapping.
    pub(crate) const BASE: u64 = 0x7fff_2000_0000;

    /// A single-file, version-1-era x86_64 DYLD cache: mapping 0 `[BASE, BASE+0x2000)` (file 0,
    /// r-x) holds the cache header and `/usr/lib/libA.dylib` at `BASE+0x1000`; mapping 1
    /// `[BASE+0x3000, BASE+0x4000)` (file 0x2000, rw-) holds that dylib's `__LINKEDIT`, plus a
    /// v2 slide info rebasing the pointer at file 0x2900 to `BASE + 0x1234`.
    pub(crate) fn dyld_cache() -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name("dyld_v1  x86_64", 16).u32(0x78).u32(2).u32(0xb8).u32(1).u64(BASE);
        b.u64(0).u64(0); // code signature
        b.u64(0x2a00).u64(0x30); // slide info (v2, for mapping 1)
        b.u64(0).u64(0); // local symbols
        b.raw(&[0x22; 16]); // uuid
        b.u64(0); // cache type
        b.u32(0).u32(0); // branch pools
        assert_eq!(b.len(), 0x78);
        b.u64(BASE).u64(0x2000).u64(0).u32(5).u32(5);
        b.u64(BASE + 0x3000).u64(0x1000).u64(0x2000).u32(3).u32(3);
        assert_eq!(b.len(), 0xb8);
        b.u64(BASE + 0x1000).u64(0).u64(0).u32(0xd8).u32(0);
        assert_eq!(b.len(), 0xd8);
        b.name("/usr/lib/libA.dylib", 32);
        // write_macho puts __LINKEDIT at text_vm + 0x2000 = BASE + 0x3000.
        write_macho(&mut b, 0x1000, BASE + 0x1000, 0x2000, "_libA_func");
        // A rebased pointer in mapping 1 (target 0x1234, slid by value_add BASE).
        b.pad_to(0x2900).u64(0x1234);
        // dyld_cache_slide_info2: one page whose chain starts at 0x900 (0x240 * 4).
        b.pad_to(0x2a00).u32(2).u32(0x1000).u32(0x28).u32(1).u32(0x2a).u32(0);
        b.u64(0x00ff_ff00_0000_0000).u64(BASE).u16(0x240);
        b.pad_to(0x3000);
        b.buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{dyld_cache, BASE};
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::file::formats::ios::dyldcache::dyld_cache_extractor::FOOTER_V1;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
    use crate::format::macho::mach_header::MachHeader;
    use crate::util::task::DummyMonitor;

    struct Fixture {
        _dir: tempfile::TempDir,
        svc: FileSystemService,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        Fixture { _dir: dir, svc }
    }

    fn mount(fx: &Fixture) -> DyldCacheFileSystem {
        let container = Fsrl::from_string("file:///dyld_shared_cache_x86_64").unwrap();
        let provider: Rc<dyn ByteProvider> =
            Rc::new(ByteArrayProvider::with_fsrl(dyld_cache(), Some(container.clone())));
        let mut fs = DyldCacheFileSystem::new(container.make_nested(DYLD_CACHE_FSTYPE), provider, &fx.svc);
        fs.mount(&DummyMonitor).unwrap();
        fs
    }

    #[test]
    fn range_set_coalesces_and_subtracts_like_guava() {
        let mut s = AddrRangeSet::default();
        s.add(AddrRange::open_closed(0, 10));
        s.add(AddrRange::open_closed(10, 20)); // connected: (0..20]
        s.add(AddrRange::open_closed(30, 40));
        assert_eq!(s.endpoints(), [(0, 20), (30, 40)]);
        let mut m = AddrRangeSet::default();
        m.add(AddrRange::open_closed(0, 50));
        m.remove_all(&s);
        assert_eq!(m.endpoints(), [(20, 30), (40, 50)]);
        assert_eq!(range_set_string(&s.endpoints()), "[(0..20], (30..40]]");
    }

    #[test]
    fn component_names() {
        assert_eq!(get_component_name(None), "DYLD");
        let dirty = DyldCacheMappingAndSlideInfo::new(0, 0, 0, 0, 0, 0x2, 0, 0);
        let auth_const = DyldCacheMappingAndSlideInfo::new(0, 0, 0, 0, 0, 0x1 | 0x4, 0, 0);
        assert_eq!(get_component_name(Some(&dirty)), "DATA_DIRTY");
        assert_eq!(get_component_name(Some(&auth_const)), "AUTH_CONST");
        assert_eq!(
            get_component_path("c", None, 2, AddrRange::open_closed(0x1000, 0x2000)),
            "/DYLD/c/DYLD.2.0x1000-0x2000"
        );
    }

    #[test]
    fn mounts_dylibs_and_unclaimed_mapping_ranges() {
        let fx = fixture();
        let fs = mount(&fx);
        assert_eq!(fs.get_type(), "dyldcachev1");
        let mut paths = Vec::new();
        let mut stack = vec![GFileSystem::get_listing(&fs, None).unwrap()];
        while let Some(list) = stack.pop() {
            for f in list {
                if f.is_directory() {
                    stack.push(GFileSystem::get_listing(&fs, Some(&*f)).unwrap());
                } else {
                    paths.push(f.get_path().to_string());
                }
            }
        }
        paths.sort();
        let mapping_path = format!("/DYLD/dyld_shared_cache_x86_64/DYLD.0.0x{:x}-0x{:x}", BASE, BASE + 0x1000);
        assert_eq!(paths, [mapping_path.clone(), "/usr/lib/libA.dylib".to_string()]);

        assert_eq!(fs.find_address((BASE + 0x1800) as i64).as_deref(), Some("/usr/lib/libA.dylib"));
        assert_eq!(fs.find_address((BASE + 0x3800) as i64).as_deref(), Some("/usr/lib/libA.dylib"));
        assert_eq!(fs.find_address((BASE + 0x10) as i64).as_deref(), Some(mapping_path.as_str()));
        assert_eq!(fs.find_address((BASE + 0x2800) as i64), None);
        assert!(fs.get_files(-1).is_empty(), "old caches have no mapping-and-slide infos");

        let lib = GFileSystem::lookup(&fs, Some("/usr/lib/libA.dylib")).unwrap().unwrap();
        let attrs = fs.get_file_attributes(&*lib, &DummyMonitor);
        assert!(attrs.get(FileAttributeType::NameAttr).is_some());
    }

    #[test]
    fn extracts_dylib_and_mapping() {
        let fx = fixture();
        let fs = mount(&fx);

        let lib = GFileSystem::lookup(&fs, Some("/usr/lib/libA.dylib")).unwrap().unwrap();
        let p = fs.get_byte_provider(&*lib, &DummyMonitor).unwrap().unwrap();
        let bytes = p.read_bytes(0, p.length()).unwrap();
        assert!(bytes.ends_with(FOOTER_V1));
        let mut h = MachHeader::new(Rc::new(ByteArrayProvider::new(bytes))).unwrap();
        h.parse().unwrap();
        assert_eq!(h.get_segment("__TEXT").unwrap().get_file_offset(), 0);
        let symtab = h.get_first_load_command::<SymbolTableCommand>().unwrap();
        assert_eq!(symtab.get_symbols()[0].get_string(), "_libA_func");

        let mapping = format!("/DYLD/dyld_shared_cache_x86_64/DYLD.0.0x{:x}-0x{:x}", BASE, BASE + 0x1000);
        let m = GFileSystem::lookup(&fs, Some(&mapping)).unwrap().unwrap();
        let p = fs.get_byte_provider(&*m, &DummyMonitor).unwrap().unwrap();
        let bytes = p.read_bytes(0, p.length()).unwrap();
        assert_eq!(bytes.len(), 32 + 72 + 0x1000 + FOOTER_V1.len());
        assert_eq!(&bytes[32 + 72..32 + 72 + 15], b"dyld_v1  x86_64");
        let mut h = MachHeader::new(Rc::new(ByteArrayProvider::new(bytes))).unwrap();
        h.parse().unwrap();
        let seg = h.get_segment("DYLD.0.0").unwrap();
        assert_eq!(seg.get_vm_address() as u64, BASE);
        assert_eq!(seg.get_vm_size(), 0x1000);
        assert_eq!(seg.get_max_protection(), 5);

        GFileSystem::close(&fs).unwrap();
        assert!(fs.is_closed());
    }
}
