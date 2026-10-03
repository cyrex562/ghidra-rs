//! Port of `ghidra.file.formats.ios.fileset.MachoFileSetEntry`.
//!
//! Promotes the placeholder previously modeled directly in
//! [`crate::file::seam_stubs`] (referenced by
//! [`MachoFileSetFileSystem`](super::macho_file_set_file_system::MachoFileSetFileSystem)) to its
//! own file, now that this record has had its own port turn. The shape is unchanged: a Java
//! `record` with three components, ported the same way as every other already-ported Ghidra
//! `record` in this crate -- a plain struct with accessor methods mirroring the record's own
//! auto-generated accessors.

/// An entry in the `MachoFileSetFileSystem`.
///
/// Port of `ghidra.file.formats.ios.fileset.MachoFileSetEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachoFileSetEntry {
    id: String,
    offset: i64,
    is_branch_segment: bool,
}

impl MachoFileSetEntry {
    /// Constructs a new entry.
    ///
    /// Mirrors the record constructor `MachoFileSetEntry(String id, long offset, boolean
    /// isBranchSegment)`.
    ///
    /// * `id` - The id of the entry
    /// * `offset` - The offset of the entry in the provider
    /// * `is_branch_segment` - True if this entry represents a branch segment; false if it
    ///   represents an `LC_FILESET_ENTRY` Mach-O
    pub fn new(id: impl Into<String>, offset: i64, is_branch_segment: bool) -> Self {
        MachoFileSetEntry { id: id.into(), offset, is_branch_segment }
    }

    /// Mirrors the record accessor `id()`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Mirrors the record accessor `offset()`.
    pub fn offset(&self) -> i64 {
        self.offset
    }

    /// Mirrors the record accessor `isBranchSegment()`.
    pub fn is_branch_segment(&self) -> bool {
        self.is_branch_segment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_return_constructed_values() {
        let entry = MachoFileSetEntry::new("com.example.dylib", 0x1000, false);
        assert_eq!(entry.id(), "com.example.dylib");
        assert_eq!(entry.offset(), 0x1000);
        assert!(!entry.is_branch_segment());
    }

    #[test]
    fn branch_segment_entry() {
        let entry = MachoFileSetEntry::new("__BRANCH_STUBS", 0, true);
        assert_eq!(entry.id(), "__BRANCH_STUBS");
        assert_eq!(entry.offset(), 0);
        assert!(entry.is_branch_segment());
    }

    #[test]
    fn equality_and_hash_are_by_value() {
        use std::collections::HashSet;

        let a = MachoFileSetEntry::new("id", 5, false);
        let b = MachoFileSetEntry::new("id", 5, false);
        let c = MachoFileSetEntry::new("id", 6, false);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn clone_produces_an_independent_equal_copy() {
        let a = MachoFileSetEntry::new("id", 5, true);
        let cloned = a.clone();
        assert_eq!(a, cloned);
    }
}
