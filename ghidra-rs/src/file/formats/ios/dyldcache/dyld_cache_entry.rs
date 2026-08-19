//! Rust port of `ghidra.file.formats.ios.dyldcache.DyldCacheEntry`.
//!
//! A value object representing an entry in the DYLD Cache file system: a DYLIB or a memory
//! mapping's unclaimed region. Carries the entry's indexed path, cache split information,
//! address range coverage, and associated cache mapping metadata.

use crate::file::seam_stubs::DyldCacheMappingAndSlideInfo;
use crate::file::seam_stubs::DyldCacheMappingInfo;

/// Mirrors `ghidra.file.formats.ios.dyldcache.DyldCacheEntry` (a Java record).
///
/// An immutable value object indexing one entry in a `DyldCacheFileSystem`. In Java, this is a
/// compact record with six components; here, it is a `struct` with accessor methods matching
/// the record's generated accessors (all `pub` fields with no setter, since Java records are
/// immutable).
#[derive(Debug, Clone, PartialEq)]
pub struct DyldCacheEntry {
    /// The path of the entry within the filesystem.
    pub path: String,
    /// The entry's [`SplitDyldCache`](crate::file::seam_stubs::SplitDyldCache) index.
    pub split_cache_index: i32,
    /// The entry's address ranges. Mirrors `RangeSet<Long>` as a list of half-open `[start, end)`
    /// intervals, in sorted, non-overlapping order (coalesced), matching the Java Guava
    /// `TreeRangeSet` behavior.
    pub range_set: Vec<(i64, i64)>,
    /// The entry's [`DyldCacheMappingInfo`], or `None` if this entry represents a DYLIB.
    pub mapping_info: Option<DyldCacheMappingInfo>,
    /// The entry's [`DyldCacheMappingAndSlideInfo`], or `None` if this entry represents a DYLIB
    /// or if the cache is old and does not support this structure.
    pub mapping_and_slide_info: Option<DyldCacheMappingAndSlideInfo>,
    /// The entry's [`DyldCacheMappingInfo`] index; ignored if `mapping_info` is `None`.
    pub mapping_index: i32,
}

impl DyldCacheEntry {
    /// Creates a new `DyldCacheEntry`.
    ///
    /// Mirrors the Java record constructor.
    pub fn new(
        path: impl Into<String>,
        split_cache_index: i32,
        range_set: Vec<(i64, i64)>,
        mapping_info: Option<DyldCacheMappingInfo>,
        mapping_and_slide_info: Option<DyldCacheMappingAndSlideInfo>,
        mapping_index: i32,
    ) -> Self {
        DyldCacheEntry {
            path: path.into(),
            split_cache_index,
            range_set,
            mapping_info,
            mapping_and_slide_info,
            mapping_index,
        }
    }

    /// Mirrors the record accessor `path()`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Mirrors the record accessor `splitCacheIndex()`.
    pub fn split_cache_index(&self) -> i32 {
        self.split_cache_index
    }

    /// Mirrors the record accessor `rangeSet()`. Returns the address ranges as a list of
    /// half-open `[start, end)` intervals.
    pub fn range_set(&self) -> &[(i64, i64)] {
        &self.range_set
    }

    /// Mirrors the record accessor `mappingInfo()`.
    pub fn mapping_info(&self) -> Option<&DyldCacheMappingInfo> {
        self.mapping_info.as_ref()
    }

    /// Mirrors the record accessor `mappingAndSlideInfo()`.
    pub fn mapping_and_slide_info(&self) -> Option<&DyldCacheMappingAndSlideInfo> {
        self.mapping_and_slide_info.as_ref()
    }

    /// Mirrors the record accessor `mappingIndex()`.
    pub fn mapping_index(&self) -> i32 {
        self.mapping_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dyld_cache_entry_creation() {
        let entry = DyldCacheEntry::new(
            "/System/Library/libSystem.B.dylib",
            0,
            vec![(0x1000, 0x5000), (0x8000, 0xa000)],
            Some(DyldCacheMappingInfo::new(0x1000, 0x9000)),
            None,
            0,
        );

        assert_eq!(entry.path(), "/System/Library/libSystem.B.dylib");
        assert_eq!(entry.split_cache_index(), 0);
        assert_eq!(entry.range_set(), &[(0x1000, 0x5000), (0x8000, 0xa000)]);
        assert!(entry.mapping_info().is_some());
        assert!(entry.mapping_and_slide_info().is_none());
        assert_eq!(entry.mapping_index(), 0);
    }

    #[test]
    fn test_dyld_cache_entry_with_all_fields() {
        let mapping_info = DyldCacheMappingInfo::new(0x100000000, 0x200000);
        let mapping_and_slide_info = DyldCacheMappingAndSlideInfo::new(0x100000000, 0x200000, 0x5);

        let entry = DyldCacheEntry::new(
            "test_dylib",
            1,
            vec![(0x100000000, 0x100100000)],
            Some(mapping_info),
            Some(mapping_and_slide_info),
            2,
        );

        assert_eq!(entry.path(), "test_dylib");
        assert_eq!(entry.split_cache_index(), 1);
        assert_eq!(entry.mapping_index(), 2);
        assert_eq!(entry.range_set().len(), 1);
        assert_eq!(entry.range_set()[0], (0x100000000, 0x100100000));
    }

    #[test]
    fn test_dyld_cache_entry_clone() {
        let entry = DyldCacheEntry::new(
            "/test/path",
            0,
            vec![(0x1000, 0x2000)],
            None,
            None,
            0,
        );
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }
}
