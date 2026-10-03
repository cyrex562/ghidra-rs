//! Port of `ghidra.program.model.sourcemap.DummySourceFileManager`.

use std::sync::Arc;

use crate::framework::store::LockException;
use crate::program::database::sourcemap::{AddSourceMapEntryError, SourceFile};
use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::sourcemap::source_map_entry_iterator;
use crate::program::model::sourcemap::{SourceFileManager, SourceMapEntry, SourceMapEntryIterator};

/// A "dummy" implementation of [`SourceFileManager`].
///
/// Port of `ghidra.program.model.sourcemap.DummySourceFileManager`. The Java class throws
/// `UnsupportedOperationException` -- an unchecked exception -- from every mutator, even though
/// several of the trait's mutator methods are typed to return a checked, catchable error (e.g.
/// [`LockException`]/[`AddSourceMapEntryError`]). Rather than misrepresent those as ordinary,
/// handleable errors, this port panics from the same methods, faithfully preserving that calling
/// them is a hard failure rather than a recoverable one.
#[derive(Debug, Default, Clone, Copy)]
pub struct DummySourceFileManager;

impl DummySourceFileManager {
    /// Java: `DummySourceFileManager()`.
    pub fn new() -> Self {
        DummySourceFileManager
    }
}

impl SourceFileManager for DummySourceFileManager {
    fn get_source_map_entries_at(&self, _addr: &Address) -> Vec<Arc<dyn SourceMapEntry>> {
        Vec::new()
    }

    fn add_source_map_entry(
        &mut self,
        _source_file: &SourceFile,
        _line_number: i32,
        _base_addr: &Address,
        _length: i64,
    ) -> Result<Arc<dyn SourceMapEntry>, AddSourceMapEntryError> {
        panic!("Cannot add source map entries with this manager")
    }

    fn intersects_source_map_entry(&self, _addrs: &dyn AddressSetView) -> bool {
        false
    }

    fn add_source_file(&mut self, _source_file: &SourceFile) -> Result<bool, LockException> {
        panic!("cannot add source files to this manager")
    }

    fn remove_source_file(&mut self, _source_file: &SourceFile) -> Result<bool, LockException> {
        panic!("cannot remove source files from this manager")
    }

    fn contains_source_file(&self, _source_file: &SourceFile) -> bool {
        false
    }

    fn get_all_source_files(&self) -> Vec<SourceFile> {
        Vec::new()
    }

    fn get_mapped_source_files(&self) -> Vec<SourceFile> {
        Vec::new()
    }

    fn transfer_source_map_entries(
        &mut self,
        _source: &SourceFile,
        _target: &SourceFile,
    ) -> Result<(), LockException> {
        panic!("Dummy source file manager cannot transfer map info")
    }

    fn get_source_map_entry_iterator(
        &self,
        _address: &Address,
        _forward: bool,
    ) -> Box<dyn SourceMapEntryIterator> {
        source_map_entry_iterator::empty()
    }

    fn get_source_map_entries_for_range(
        &self,
        _source_file: &SourceFile,
        _min_line: i32,
        _max_line: i32,
    ) -> Vec<Arc<dyn SourceMapEntry>> {
        Vec::new()
    }

    fn remove_source_map_entry(&mut self, _entry: &dyn SourceMapEntry) -> Result<bool, LockException> {
        panic!("cannot remove source map entries from this manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn queries_return_empty_or_false() {
        let manager = DummySourceFileManager::new();
        let source_file = SourceFile::new("/src/main.c").unwrap();

        assert!(manager.get_source_map_entries_at(&addr(0x1000)).is_empty());
        assert!(!manager.intersects_source_map_entry(&crate::program::model::address::AddressSet::new()));
        assert!(!manager.contains_source_file(&source_file));
        assert!(manager.get_all_source_files().is_empty());
        assert!(manager.get_mapped_source_files().is_empty());
        assert!(manager
            .get_source_map_entries_for_range(&source_file, 0, i32::MAX)
            .is_empty());
    }

    #[test]
    fn get_source_map_entry_iterator_is_empty() {
        let manager = DummySourceFileManager::new();
        let mut iter = manager.get_source_map_entry_iterator(&addr(0x1000), true);
        assert!(iter.next().is_none());
    }

    #[test]
    #[should_panic(expected = "Cannot add source map entries with this manager")]
    fn add_source_map_entry_panics() {
        let mut manager = DummySourceFileManager::new();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        let _ = manager.add_source_map_entry(&source_file, 1, &addr(0x1000), 4);
    }

    #[test]
    #[should_panic(expected = "cannot add source files to this manager")]
    fn add_source_file_panics() {
        let mut manager = DummySourceFileManager::new();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        let _ = manager.add_source_file(&source_file);
    }

    #[test]
    #[should_panic(expected = "cannot remove source files from this manager")]
    fn remove_source_file_panics() {
        let mut manager = DummySourceFileManager::new();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        let _ = manager.remove_source_file(&source_file);
    }

    #[test]
    #[should_panic(expected = "Dummy source file manager cannot transfer map info")]
    fn transfer_source_map_entries_panics() {
        let mut manager = DummySourceFileManager::new();
        let a = SourceFile::new("/src/a.c").unwrap();
        let b = SourceFile::new("/src/b.c").unwrap();
        let _ = manager.transfer_source_map_entries(&a, &b);
    }

    #[test]
    #[should_panic(expected = "cannot remove source map entries from this manager")]
    fn remove_source_map_entry_panics() {
        struct MockEntry;
        impl SourceMapEntry for MockEntry {
            fn get_line_number(&self) -> i32 {
                0
            }
            fn get_source_file(&self) -> SourceFile {
                SourceFile::new("/src/a.c").unwrap()
            }
            fn get_base_address(&self) -> Address {
                addr(0)
            }
            fn get_length(&self) -> i64 {
                0
            }
            fn get_range(&self) -> Option<AddressRange> {
                None
            }
            fn compare_to(&self, _other: &dyn SourceMapEntry) -> std::cmp::Ordering {
                std::cmp::Ordering::Equal
            }
        }

        let mut manager = DummySourceFileManager::new();
        let _ = manager.remove_source_map_entry(&MockEntry);
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let manager: Box<dyn SourceFileManager> = Box::new(DummySourceFileManager::new());
        assert!(manager.get_all_source_files().is_empty());
    }
}
