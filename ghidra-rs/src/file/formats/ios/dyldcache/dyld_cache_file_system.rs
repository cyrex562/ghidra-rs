//! Rust port of `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem`.
//!
//! A `GFileSystem` implementation for the components of a DYLD Cache: each Mach-O DYLIB and
//! each unclaimed chunk of a subcache's memory mappings surfaces as its own file.
//!
//! # Shape
//!
//! The Java class is a concrete leaf (`AbstractFileSystem<DyldCacheEntry>`, nothing extends
//! it), so this ports directly to a `struct` + `impl`, mirroring
//! [`SplitDyldCache`](crate::file::seam_stubs::SplitDyldCache)'s sibling stub rather than the
//! trait-plus-base-struct split used for [`SevenZipFileSystem`](super::super::super::sevenzip)'s
//! hierarchy.
//!
//! # Guava seam
//!
//! `mount` builds its index with `com.google.common.collect`'s `Range`/`RangeSet`/`RangeMap`,
//! none of which are in-repo Ghidra types (so none get a `seam_stubs.rs` placeholder). They are
//! modeled locally, in the same spirit as
//! [`SevenZipFileSystem`](super::super::super::sevenzip::seven_zip_file_system)'s in-file
//! modeling of the third-party `net.sf.sevenzipjbinding` API:
//!
//! * [`AddrRange`] stands in for `Range<Long>`, restricted to the one factory this class ever
//!   calls -- `Range.openClosed(lower, upper)` -- and stored internally as the equivalent
//!   half-open `[lower+1, upper+1)` interval so the set operations below reduce to ordinary
//!   half-open interval arithmetic.
//! * [`AddrRangeSet`] stands in for `RangeSet<Long>` (specifically `TreeRangeSet`): a list of
//!   disjoint, non-touching (coalesced) ranges supporting `add`/`add_all`/`remove_all`.
//! * [`AddrRangeMap`] stands in for `RangeMap<Long, DyldCacheEntry>` (specifically
//!   `TreeRangeMap`): `put`/`get`/`values`. Java's `TreeRangeMap` additionally coalesces
//!   adjacent map entries that carry `.equals()`-equal values; this port never relies on that
//!   coalescing (every read here either looks up a single address or is filtered by
//!   `mappingAndSlideInfo` -- which the DYLIB entries this could affect are always `None` --
//!   so the extra coalescing pass would only be cosmetic).
//!
//! # Unported dependencies
//!
//! `mount`'s image/mapping discovery ultimately bottoms out in Mach-O load-command parsing
//! ([`MachHeader::parse_segments`](crate::file::seam_stubs::MachHeader::parse_segments)) and
//! `DyldCacheHeader`'s mapping/image tables
//! ([`DyldCacheHeader::mapping_infos`](crate::file::seam_stubs::DyldCacheHeader::mapping_infos)
//! etc.), neither of which is ported yet; see `crate::file::seam_stubs` (STUBS.tsv) for the
//! placeholders, which always report empty. The algorithms here (range coalescing, path
//! derivation, extraction dispatch) are implemented in full against those placeholders, so a
//! real `DyldCacheFileSystem` mount today successfully indexes zero files -- and will start
//! indexing real ones the moment the placeholders are replaced, with no change needed here.
//! [`SplitDyldCache::new`](crate::file::seam_stubs::SplitDyldCache::new) is similarly narrowed
//! to the single (non-split) cache file case; see its docs.

use std::cell::RefCell;
use std::fmt;
use std::io;
use std::rc::Rc;

use crate::file::seam_stubs::{
    DyldCacheEntry, DyldCacheExtractor, DyldCacheMappingAndSlideInfo, FileAttributeValue,
    FileAttributes, FileSystemIndexHelper, SlideFixupMap, SplitDyldCache, SplitDyldCacheError,
};
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{
    FsGetListing, FsrlLike as GFileFsrlLike, GFileImpl, HasFsrlRoot,
};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::macho::mach_exception::MachException;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Mirrors `DyldCacheFileSystem.DYLD_CACHE_FSTYPE`.
pub const DYLD_CACHE_FSTYPE: &str = "dyldcachev1";

// ─── FSRL stand-ins ───────────────────────────────────────────────────────────
//
// Mirrors the same narrow substitution `SevenZipFileSystem` makes for `FSRL`/`FSRLRoot`: the
// ported `Fsrl`/`FsrlRootLike` seams have no implementer yet, so this filesystem parameterizes
// `GFileImpl`/`FileSystemIndexHelper` with small concrete stand-ins instead.

/// Stand-in for `ghidra.formats.gfilesystem.FSRL`, used to parameterize [`GFileImpl`] and the
/// index. See [`crate::file::formats::sevenzip::seven_zip_file_system::SzFsrl`] for the sibling
/// substitution this mirrors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DyldFsrl {
    path: String,
}

impl DyldFsrl {
    /// Creates an FSRL for `path`.
    pub fn new(path: impl Into<String>) -> Self {
        DyldFsrl { path: path.into() }
    }
}

impl GFileFsrlLike for DyldFsrl {
    fn fsrl_name(&self) -> String {
        base_name_of(&self.path).to_string()
    }

    fn fsrl_path(&self) -> String {
        self.path.clone()
    }

    fn append_path(&self, segment: &str) -> Self {
        let path = if self.path.ends_with('/') {
            format!("{}{}", self.path, segment)
        } else {
            format!("{}/{}", self.path, segment)
        };
        DyldFsrl { path }
    }
}

impl crate::filesystem::seam_stubs::FsrlLike for DyldFsrl {}

/// Stand-in for `ghidra.formats.gfilesystem.FSRLRoot`, this filesystem's own `fsFSRL`.
///
/// Only `getContainer().getName()` is exercised by this class (`getName()`, the container
/// file's name).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DyldFsrlRoot {
    container_name: String,
}

impl DyldFsrlRoot {
    /// Creates a root whose container file is named `container_name`.
    pub fn new(container_name: impl Into<String>) -> Self {
        DyldFsrlRoot { container_name: container_name.into() }
    }

    /// Mirrors `FSRLRoot.getContainer().getName()`.
    pub fn name(&self) -> &str {
        &self.container_name
    }
}

/// Filesystem handle stored inside each [`GFileImpl`] this filesystem hands out.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DyldFsHandle {
    root: DyldFsrl,
}

impl DyldFsHandle {
    /// Creates a handle rooted at `root`.
    pub fn new(root: DyldFsrl) -> Self {
        DyldFsHandle { root }
    }
}

impl HasFsrlRoot<DyldFsrl> for DyldFsHandle {
    fn root_fsrl(&self) -> &DyldFsrl {
        &self.root
    }
}

impl FsGetListing<DyldFsHandle, DyldFsrl> for DyldFsHandle {
    fn fs_get_listing(
        &self,
        _file: &dyn GFile<DyldFsHandle, DyldFsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<DyldFsHandle, DyldFsrl>>>> {
        Ok(vec![])
    }
}

/// The concrete [`GFile`] type this filesystem indexes.
pub type DyldGFile = GFileImpl<DyldFsHandle, DyldFsrl>;

// ─── Guava `Range`/`RangeSet`/`RangeMap` stand-ins ─────────────────────────────

/// See the [module docs](self) for what this stands in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AddrRange {
    /// Inclusive lower bound of the equivalent half-open interval.
    start: i64,
    /// Exclusive upper bound of the equivalent half-open interval.
    end: i64,
}

impl AddrRange {
    /// Mirrors `Range.openClosed(lower, upper)`.
    fn open_closed(lower: i64, upper: i64) -> Self {
        AddrRange { start: lower + 1, end: upper + 1 }
    }

    /// Mirrors `Range.lowerEndpoint()`.
    fn lower_endpoint(&self) -> i64 {
        self.start - 1
    }

    /// Mirrors `Range.upperEndpoint()`.
    fn upper_endpoint(&self) -> i64 {
        self.end - 1
    }
}

/// See the [module docs](self) for what this stands in for.
#[derive(Debug, Clone, Default)]
struct AddrRangeSet {
    /// Sorted, disjoint, non-touching (coalesced) ranges.
    ranges: Vec<AddrRange>,
}

impl AddrRangeSet {
    fn new() -> Self {
        AddrRangeSet::default()
    }

    /// Mirrors `RangeSet.add(Range)`, including `TreeRangeSet`'s coalescing of connected
    /// ranges.
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

    /// Mirrors `RangeSet.addAll(RangeSet)`.
    fn add_all(&mut self, other: &AddrRangeSet) {
        for r in &other.ranges {
            self.add(*r);
        }
    }

    /// Mirrors `RangeSet.removeAll(RangeSet)`.
    fn remove_all(&mut self, other: &AddrRangeSet) {
        if other.ranges.is_empty() {
            return;
        }
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

    /// Mirrors `RangeSet.asRanges()`.
    fn as_ranges(&self) -> &[AddrRange] {
        &self.ranges
    }
}

/// See the [module docs](self) for what this stands in for.
#[derive(Debug, Default)]
struct AddrRangeMap {
    entries: Vec<(AddrRange, Rc<DyldCacheEntry>)>,
}

impl AddrRangeMap {
    fn new() -> Self {
        AddrRangeMap::default()
    }

    /// Mirrors `RangeMap.put(Range, V)`. Every caller in this class inserts already-disjoint
    /// ranges, so (unlike `TreeRangeMap`) this never needs to split an existing entry's span.
    fn put(&mut self, range: AddrRange, value: Rc<DyldCacheEntry>) {
        self.entries.push((range, value));
    }

    /// Mirrors `RangeMap.get(Long)`.
    fn get(&self, addr: i64) -> Option<&Rc<DyldCacheEntry>> {
        self.entries.iter().find(|(r, _)| addr >= r.start && addr < r.end).map(|(_, v)| v)
    }

    /// Mirrors `RangeMap.asMapOfRanges().values()`.
    fn values(&self) -> impl Iterator<Item = &Rc<DyldCacheEntry>> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// Mirrors `RangeMap.clear()`.
    fn clear(&mut self) {
        self.entries.clear();
    }
}

// ─── DyldCacheFileSystem ───────────────────────────────────────────────────────

/// A `GFileSystem` implementation for the components of a DYLD Cache.
///
/// Mirrors `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem`.
pub struct DyldCacheFileSystem {
    /// Mirrors the inherited `AbstractFileSystem.fsFSRL`.
    fs_fsrl: DyldFsrlRoot,
    /// Mirrors `provider`. `None` once [`close`](Self::close) has run, matching Java's
    /// `provider == null` after close.
    provider: Option<Rc<RefCell<dyn ByteProvider>>>,
    /// Mirrors `splitDyldCache`.
    split_dyld_cache: Option<SplitDyldCache>,
    /// Mirrors `parsedLocalSymbols`.
    parsed_local_symbols: bool,
    /// Mirrors `slideFixupMap`.
    slide_fixup_map: Option<SlideFixupMap>,
    /// Mirrors `rangeMap`.
    range_map: AddrRangeMap,
    /// Mirrors the inherited `AbstractFileSystem.fsIndex`. `AbstractFileSystem.refManager` is
    /// not modeled: this port has no arena-backed `FileSystemRefManager` yet (see
    /// `crate::filesystem::gfilesystem::file_system_ref_manager`'s docs), and nothing in this
    /// class other than `close()`'s `refManager.onClose()` -- itself a no-op absent listeners --
    /// touches it.
    fs_index: FileSystemIndexHelper<DyldFsHandle, DyldFsrl, Rc<DyldCacheEntry>>,
}

impl DyldCacheFileSystem {
    /// Creates a new [`DyldCacheFileSystem`].
    ///
    /// Mirrors `DyldCacheFileSystem(FSRLRoot, ByteProvider)`.
    pub fn new(fs_fsrl: DyldFsrlRoot, provider: Rc<RefCell<dyn ByteProvider>>) -> Self {
        let root = DyldFsrl::new("/");
        let fs_index = FileSystemIndexHelper::new(DyldFsHandle::new(root.clone()), root);
        DyldCacheFileSystem {
            fs_fsrl,
            provider: Some(provider),
            split_dyld_cache: None,
            parsed_local_symbols: false,
            slide_fixup_map: None,
            range_map: AddrRangeMap::new(),
            fs_index,
        }
    }

    /// Mirrors the inherited `AbstractFileSystem.getFSRL()`.
    pub fn get_fsrl(&self) -> &DyldFsrlRoot {
        &self.fs_fsrl
    }

    /// Mirrors the inherited `AbstractFileSystem.getName()`.
    pub fn get_name(&self) -> &str {
        self.fs_fsrl.name()
    }

    /// Mirrors the inherited `AbstractFileSystem.getRootDir()`.
    pub fn get_root_dir(&self) -> &DyldGFile {
        self.fs_index.get_root_dir()
    }

    /// Mirrors the inherited `AbstractFileSystem.getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        self.fs_index.get_file_count()
    }

    /// Mounts this file system.
    ///
    /// Mirrors `mount(TaskMonitor)`.
    pub fn mount(&mut self, monitor: &dyn TaskMonitor) -> Result<(), MountError> {
        let provider = self.provider.clone().ok_or_else(|| MountError::Io(closed_error()))?;
        let split = SplitDyldCache::new(provider, false, monitor).map_err(MountError::from_split)?;

        let mut all_dylib_ranges = AddrRangeSet::new();

        // Find the DYLIB's and add them as files
        let image_records = split.image_records();
        monitor.set_message("Find DYLD DYLIBs...");
        monitor.initialize(image_records.len() as i64);
        for image_record in &image_records {
            if monitor.is_cancelled() {
                return Err(MountError::Cancelled(CancelledException::default()));
            }
            monitor.increment_progress(1);

            let image = image_record.image();
            let mach_header = split.macho(image_record).map_err(MountError::Mach)?;

            let mut range_set = AddrRangeSet::new();
            for segment in mach_header.parse_segments().map_err(MountError::Io)? {
                let range = AddrRange::open_closed(
                    segment.vm_address(),
                    segment.vm_address() + segment.vm_size(),
                );
                range_set.add(range);
            }

            let entry = Rc::new(DyldCacheEntry::new(
                image.path().to_string(),
                image_record.split_cache_index(),
                range_set.as_ranges().iter().map(|r| (r.start, r.end)).collect(),
                None,
                None,
                -1,
            ));
            for r in range_set.as_ranges() {
                self.range_map.put(*r, Rc::clone(&entry));
            }
            all_dylib_ranges.add_all(&range_set);

            let file_index = self.fs_index.get_file_count() as i64;
            self.fs_index.store_file(image.path(), file_index, false, -1, entry);
        }

        // Find and store all the mappings for all of the subcaches. We need to remove the
        // DYLIB's that we just found so we don't account for any bytes more than once. This
        // will result in the mappings being broken up into a lot of small chunks, each being
        // its own file.
        monitor.set_message("Find DYLD mapping ranges...");
        monitor.initialize(split.size() as i64);
        for i in 0..split.size() {
            if monitor.is_cancelled() {
                return Err(MountError::Cancelled(CancelledException::default()));
            }
            monitor.increment_progress(1);

            let header = split.dyld_cache_header(i);
            let name = split.name(i).to_string();
            let mapping_infos = header.mapping_infos().to_vec();
            let mapping_and_slide_infos = header.cache_mapping_and_slide_infos().to_vec();
            for (j, mapping_info) in mapping_infos.iter().enumerate() {
                let mapping_and_slide_info = mapping_and_slide_infos.get(j).copied();
                let mapping_range = AddrRange::open_closed(
                    mapping_info.address(),
                    mapping_info.address() + mapping_info.size(),
                );
                let mut reduced_range_set = AddrRangeSet::new();
                reduced_range_set.add(mapping_range);
                reduced_range_set.remove_all(&all_dylib_ranges);

                for range in reduced_range_set.as_ranges() {
                    let path = component_path(&name, mapping_and_slide_info.as_ref(), j, range);
                    let entry = Rc::new(DyldCacheEntry::new(
                        path.clone(),
                        i as i32,
                        vec![(range.start, range.end)],
                        Some(*mapping_info),
                        mapping_and_slide_info,
                        j as i32,
                    ));
                    self.range_map.put(*range, Rc::clone(&entry));

                    let file_index = self.fs_index.get_file_count() as i64;
                    self.fs_index.store_file(&path, file_index, false, -1, entry);
                }
            }
        }

        self.split_dyld_cache = Some(split);
        Ok(())
    }

    /// Mirrors `getByteProvider(GFile, TaskMonitor)`.
    pub fn get_byte_provider(
        &mut self,
        file: &DyldGFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GetByteProviderError> {
        let Some(entry) = self.fs_index.get_metadata(file).map(Rc::clone) else {
            return Ok(None);
        };

        if self.slide_fixup_map.is_none() {
            let split = self
                .split_dyld_cache
                .as_ref()
                .ok_or_else(|| GetByteProviderError::Io(not_mounted_error()))?;
            let fixups = DyldCacheExtractor::get_slide_fixups(split, monitor)
                .map_err(GetByteProviderError::Io)?;
            self.slide_fixup_map = Some(fixups);
        }

        if !self.parsed_local_symbols {
            let split = self
                .split_dyld_cache
                .as_mut()
                .ok_or_else(|| GetByteProviderError::Io(not_mounted_error()))?;
            for i in 0..split.size() {
                split
                    .dyld_cache_header_mut(i)
                    .parse_local_symbols_info()
                    .map_err(GetByteProviderError::Io)?;
            }
            self.parsed_local_symbols = true;
        }

        let split = self
            .split_dyld_cache
            .as_ref()
            .ok_or_else(|| GetByteProviderError::Io(not_mounted_error()))?;
        let slide_fixup_map = self.slide_fixup_map.as_ref().expect("populated above");

        let result = if entry.mapping_info.is_some() {
            DyldCacheExtractor::extract_mapping(
                &entry,
                component_name(entry.mapping_and_slide_info.as_ref()),
                split,
                slide_fixup_map,
                monitor,
            )
        } else {
            DyldCacheExtractor::extract_dylib(&entry, split, slide_fixup_map, monitor)
        };

        result.map(Some).map_err(GetByteProviderError::Io)
    }

    /// Attempts to find the given address in the DYLD Cache.
    ///
    /// Returns the path of the file within this file system that contains the given address, or
    /// `None` if the address was not found.
    ///
    /// Mirrors `findAddress(long)`.
    pub fn find_address(&self, addr: i64) -> Option<String> {
        self.range_map.get(addr).map(|e| e.path.clone())
    }

    /// Gets the files that have the given mapping flags.
    ///
    /// Mirrors `getFiles(long)`.
    pub fn get_files(&self, flags: i64) -> Vec<DyldGFile> {
        let mut files = Vec::new();
        for entry in self.range_map.values() {
            if let Some(info) = entry.mapping_and_slide_info.as_ref() {
                if flags & info.flags() != 0 {
                    if let Some(file) = self.lookup(&entry.path) {
                        files.push(file);
                    }
                }
            }
        }
        files
    }

    /// Mirrors `getFileAttributes(GFile, TaskMonitor)`.
    pub fn get_file_attributes(&self, file: &DyldGFile, _monitor: &dyn TaskMonitor) -> FileAttributes {
        let mut result = FileAttributes::new();
        if let Some(entry) = self.fs_index.get_metadata(file) {
            result.add(FileAttributeType::NameAttr, Some(FileAttributeValue::Str(entry.path.clone())));
            result.add(FileAttributeType::PathAttr, Some(FileAttributeValue::Str(entry.path.clone())));
            result.add_named(
                "Cache Index",
                Some(FileAttributeValue::Long(entry.split_cache_index as i64)),
            );
            // TODO: display as hex (carried from the Java source, which has the same TODO)
            result.add_named("Address Range", Some(FileAttributeValue::Str(format_range_set(&entry.range_set))));
        }
        result
    }

    /// Mirrors the inherited `AbstractFileSystem.isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.provider.is_none()
    }

    /// Mirrors `close()`.
    pub fn close(&mut self) {
        // `refManager.onClose()` -- see the `fs_index` field docs for why it is not modeled.
        self.fs_index.clear();
        if let Some(mut split) = self.split_dyld_cache.take() {
            split.close();
        }
        // `ByteProvider` has no explicit close in this port (see
        // `crate::file::formats::zip::zip_file_system_factory`'s module docs for the same
        // substitution elsewhere in this crate); releasing it is just dropping it.
        self.provider = None;
        self.slide_fixup_map = None;
        self.parsed_local_symbols = false;
        self.range_map.clear();
    }

    /// Rebuilds a detached [`DyldGFile`] for `path`, mirroring the inherited
    /// `AbstractFileSystem.lookup(String)` this class's `getFiles` calls.
    fn lookup(&self, path: &str) -> Option<DyldGFile> {
        let file = self.fs_index.lookup(path)?;
        let root = self.fs_index.get_root_dir();
        let handle = DyldFsHandle::new(DyldFsrl::new(root.get_path()));
        Some(GFileImpl::from_fsrl(
            handle,
            None,
            DyldFsrl::new(file.get_path()),
            file.is_directory(),
            file.get_length(),
        ))
    }
}

/// Mirrors `getComponentName(DyldCacheMappingAndSlideInfo)`.
fn component_name(mapping_and_slide_info: Option<&DyldCacheMappingAndSlideInfo>) -> &'static str {
    let Some(info) = mapping_and_slide_info else {
        return "DYLD";
    };
    if info.is_dirty_data() {
        "DATA_DIRTY"
    } else if info.is_const_data() {
        if info.is_auth_data() { "AUTH_CONST" } else { "DATA_CONST" }
    } else if info.is_text_stubs() {
        "TEXT_STUBS"
    } else if info.is_config_data() {
        "DATA_CONFIG"
    } else if info.is_auth_data() {
        "AUTH"
    } else if info.is_read_only_data() {
        "DATA_RO"
    } else if info.is_const_tpro_data() {
        "DATA_CONST_TPRO"
    } else {
        "DYLD"
    }
}

/// Mirrors `getComponentPath(String, DyldCacheMappingInfo, DyldCacheMappingAndSlideInfo, int,
/// Range<Long>)`. The `mappingInfo` parameter is dropped: the Java method never reads it either.
fn component_path(
    dyld_cache_name: &str,
    mapping_and_slide_info: Option<&DyldCacheMappingAndSlideInfo>,
    mapping_index: usize,
    range: &AddrRange,
) -> String {
    format!(
        "/DYLD/{}/{}.{}.0x{:x}-0x{:x}",
        dyld_cache_name,
        component_name(mapping_and_slide_info),
        mapping_index,
        range.lower_endpoint(),
        range.upper_endpoint()
    )
}

/// Renders a `DyldCacheEntry.rangeSet()`-equivalent list for the "Address Range" file
/// attribute, in the same open-closed-interval notation Guava's `RangeSet.toString()` uses.
fn format_range_set(range_set: &[(i64, i64)]) -> String {
    let parts: Vec<String> = range_set
        .iter()
        .map(|(start, end)| format!("(0x{:x}, 0x{:x}]", start - 1, end - 1))
        .collect();
    format!("[{}]", parts.join(", "))
}

fn base_name_of(path: &str) -> &str {
    let start = path.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    &path[start..]
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "DyldCacheFileSystem is closed")
}

fn not_mounted_error() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "DyldCacheFileSystem has not been mounted")
}

/// The failure modes of [`DyldCacheFileSystem::mount`], mirroring Java's `throws IOException,
/// MachException, CancelledException`.
#[derive(Debug)]
pub enum MountError {
    Io(io::Error),
    Mach(MachException),
    Cancelled(CancelledException),
}

impl MountError {
    fn from_split(e: SplitDyldCacheError) -> Self {
        match e {
            SplitDyldCacheError::Io(e) => MountError::Io(e),
            SplitDyldCacheError::Cancelled(e) => MountError::Cancelled(e),
        }
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::Io(e) => write!(f, "{e}"),
            MountError::Mach(e) => write!(f, "{e}"),
            MountError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MountError {}

/// The failure modes of [`DyldCacheFileSystem::get_byte_provider`], mirroring Java's `throws
/// CancelledException, IOException` (collapsed to a single `io::Error`, since none of the
/// unported extraction seams distinguish cancellation from any other failure yet).
#[derive(Debug)]
pub enum GetByteProviderError {
    Io(io::Error),
}

impl fmt::Display for GetByteProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetByteProviderError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GetByteProviderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MemoryByteProvider {
        bytes: Vec<u8>,
    }

    impl ByteProvider for MemoryByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    fn dyld_v1_provider() -> Rc<RefCell<dyn ByteProvider>> {
        // "dyld_v1  x86_64" is one of `DyldArchitecture::ARCHITECTURES`'s real signatures
        // (from the Java source), padded to the fixed magic length the header reads.
        let mut bytes = b"dyld_v1  x86_64".to_vec();
        bytes.resize(4096, 0);
        Rc::new(RefCell::new(MemoryByteProvider { bytes }))
    }

    #[test]
    fn fstype_matches_java_constant() {
        assert_eq!(DYLD_CACHE_FSTYPE, "dyldcachev1");
    }

    #[test]
    fn new_filesystem_is_open_with_empty_root() {
        let fs = DyldCacheFileSystem::new(DyldFsrlRoot::new("dyld_shared_cache"), dyld_v1_provider());
        assert!(!fs.is_closed());
        assert_eq!(fs.get_name(), "dyld_shared_cache");
        assert_eq!(fs.get_file_count(), 1); // just the synthetic root dir
    }

    #[test]
    fn mount_of_stubbed_dependencies_succeeds_with_zero_files() {
        // With `MachHeader::parse_segments`/`DyldCacheHeader::mapping_infos` always empty (see
        // the module docs), a real cache mounts successfully but indexes nothing yet.
        let mut fs = DyldCacheFileSystem::new(DyldFsrlRoot::new("dyld_shared_cache"), dyld_v1_provider());
        let monitor = crate::util::task::DummyMonitor;
        fs.mount(&monitor).expect("mount should succeed against the stubbed dependencies");
        assert_eq!(fs.get_file_count(), 1);
        assert_eq!(fs.find_address(0x1000), None);
        assert!(fs.get_files(0x1).is_empty());
    }

    #[test]
    fn close_resets_to_closed_state() {
        let mut fs = DyldCacheFileSystem::new(DyldFsrlRoot::new("dyld_shared_cache"), dyld_v1_provider());
        let monitor = crate::util::task::DummyMonitor;
        fs.mount(&monitor).expect("mount should succeed");
        fs.close();
        assert!(fs.is_closed());
        assert_eq!(fs.get_file_count(), 1);
    }

    #[test]
    fn get_component_name_defaults_to_dyld_for_dylibs() {
        // Mirrors `getComponentName(null)` returning `"DYLD"` for the plain-DYLIB case.
        assert_eq!(component_name(None), "DYLD");
    }

    #[test]
    fn get_component_name_matches_java_flag_precedence() {
        use crate::file::seam_stubs::DyldCacheMappingAndSlideInfo as Info;
        assert_eq!(
            component_name(Some(&Info::new(0, 0, Info::DYLD_CACHE_MAPPING_DIRTY_DATA))),
            "DATA_DIRTY"
        );
        assert_eq!(
            component_name(Some(&Info::new(0, 0, Info::DYLD_CACHE_MAPPING_CONST_DATA))),
            "DATA_CONST"
        );
        assert_eq!(
            component_name(Some(&Info::new(
                0,
                0,
                Info::DYLD_CACHE_MAPPING_CONST_DATA | Info::DYLD_CACHE_MAPPING_AUTH_DATA
            ))),
            "AUTH_CONST"
        );
        assert_eq!(
            component_name(Some(&Info::new(0, 0, Info::DYLD_CACHE_MAPPING_AUTH_DATA))),
            "AUTH"
        );
        assert_eq!(component_name(Some(&Info::new(0, 0, 0))), "DYLD");
    }

    #[test]
    fn addr_range_set_coalesces_adjacent_open_closed_ranges() {
        // (0x1000, 0x2000] followed by (0x2000, 0x3000] is contiguous under Guava's
        // open-closed semantics and should coalesce into a single range.
        let mut set = AddrRangeSet::new();
        set.add(AddrRange::open_closed(0x1000, 0x2000));
        set.add(AddrRange::open_closed(0x2000, 0x3000));
        let ranges = set.as_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].lower_endpoint(), 0x1000);
        assert_eq!(ranges[0].upper_endpoint(), 0x3000);
    }

    #[test]
    fn addr_range_set_remove_all_splits_around_a_hole() {
        let mut set = AddrRangeSet::new();
        set.add(AddrRange::open_closed(0x1000, 0x4000));
        let mut hole = AddrRangeSet::new();
        hole.add(AddrRange::open_closed(0x2000, 0x3000));
        set.remove_all(&hole);
        let ranges = set.as_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!((ranges[0].lower_endpoint(), ranges[0].upper_endpoint()), (0x1000, 0x2000));
        assert_eq!((ranges[1].lower_endpoint(), ranges[1].upper_endpoint()), (0x3000, 0x4000));
    }

    #[test]
    fn component_path_matches_java_format() {
        let range = AddrRange::open_closed(0x1000, 0x2000);
        let path = component_path("dyld_shared_cache_arm64", None, 0, &range);
        assert_eq!(path, "/DYLD/dyld_shared_cache_arm64/DYLD.0.0x1000-0x2000");
    }
}
