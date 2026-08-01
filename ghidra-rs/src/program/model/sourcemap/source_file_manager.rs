//! Port of `ghidra.program.model.sourcemap.SourceFileManager` as a trait (cycle cut-point).
//!
//! The Java interface is implemented by `ghidra.program.database.sourcemap.SourceFileManagerDB`
//! (see [`SourceFileManagerDB`](crate::program::database::sourcemap::SourceFileManagerDB), which
//! folds this interface's entire surface directly into its own trait) and is returned from
//! `ghidra.program.model.listing.Program.getSourceFileManager()`. Porting it here as a standalone,
//! `ManagerDB`/`ErrorHandler`-free trait lets `Program` (and other consumers such as
//! `ProgramDiff`, `ProgramMerge`, and the DWARF/PDB importers) depend on the query/mutation API
//! without pulling in the database-manager machinery, breaking the cycle through the concrete
//! `SourceFileManagerDB` implementation.
//!
//! Left out: the `DUMMY` static field (`new DummySourceFileManager()`), since
//! `ghidra.program.model.sourcemap.DummySourceFileManager` is a separate, not-yet-ported class
//! (see `PORT_MANIFEST.tsv`); a future port can provide an equivalent constant or default impl
//! once that type exists.
//!
//! Java's overloaded `getSourceMapEntries`/`addSourceMapEntry` methods (which differ only by
//! parameter type, not name) are given distinct names here since Rust traits do not support
//! overloading, mirroring the naming already used by
//! [`SourceFileManagerDB`](crate::program::database::sourcemap::SourceFileManagerDB):
//! - `getSourceMapEntries(Address)` -> [`get_source_map_entries_at`]
//! - `getSourceMapEntries(SourceFile, int, int)` -> [`get_source_map_entries_for_range`]
//! - `getSourceMapEntries(SourceFile, int)` (default) -> [`get_source_map_entries_for_line`]
//! - `getSourceMapEntries(SourceFile)` (default) -> [`get_source_map_entries_for_file`]
//! - `addSourceMapEntry(SourceFile, int, Address, long)` -> [`add_source_map_entry`]
//! - `addSourceMapEntry(SourceFile, int, AddressRange)` (default) -> [`add_source_map_entry_for_range`]
//!
//! [`get_source_map_entries_at`]: SourceFileManager::get_source_map_entries_at
//! [`get_source_map_entries_for_range`]: SourceFileManager::get_source_map_entries_for_range
//! [`get_source_map_entries_for_line`]: SourceFileManager::get_source_map_entries_for_line
//! [`get_source_map_entries_for_file`]: SourceFileManager::get_source_map_entries_for_file
//! [`add_source_map_entry`]: SourceFileManager::add_source_map_entry
//! [`add_source_map_entry_for_range`]: SourceFileManager::add_source_map_entry_for_range

use std::sync::Arc;

use crate::framework::store::LockException;
use crate::program::database::sourcemap::{AddSourceMapEntryError, SourceFile};
use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::sourcemap::SourceMapEntryIterator;
use crate::program::seam_stubs::SourceMapEntry;

/// Manages [`SourceFile`]s and [`SourceMapEntry`]s for a program.
///
/// Port of `ghidra.program.model.sourcemap.SourceFileManager`. See the module docs for what was
/// intentionally left out (the `DUMMY` static instance).
pub trait SourceFileManager {
    /// Returns a sorted list of [`SourceMapEntry`]s associated with address `addr`. Stands in for
    /// `SourceFileManager.getSourceMapEntries(Address)`.
    fn get_source_map_entries_at(&self, addr: &Address) -> Vec<Arc<dyn SourceMapEntry>>;

    /// Creates a [`SourceMapEntry`] with source file `source_file`, line number `line_number`, and
    /// non-negative `length` starting at `base_addr`, and adds it to the program database.
    /// Entries with non-zero lengths must either cover the same address range or be disjoint.
    /// Stands in for `SourceFileManager.addSourceMapEntry(SourceFile, int, Address, long)`.
    fn add_source_map_entry(
        &mut self,
        source_file: &SourceFile,
        line_number: i32,
        base_addr: &Address,
        length: i64,
    ) -> Result<Arc<dyn SourceMapEntry>, AddSourceMapEntryError>;

    /// Returns `true` precisely when at least one address in `addrs` has source map information.
    /// Stands in for `SourceFileManager.intersectsSourceMapEntry(AddressSetView)`.
    fn intersects_source_map_entry(&self, addrs: &dyn AddressSetView) -> bool;

    /// Adds a [`SourceFile`] to this manager. A `SourceFile` must be added before it can be
    /// associated with any source map information. Returns `true` if this manager did not already
    /// contain `source_file`. Stands in for `SourceFileManager.addSourceFile(SourceFile)`.
    fn add_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException>;

    /// Removes a [`SourceFile`] from this manager. Any associated [`SourceMapEntry`]s are also
    /// removed. Returns `true` if `source_file` was in the manager. Stands in for
    /// `SourceFileManager.removeSourceFile(SourceFile)`.
    fn remove_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException>;

    /// Returns `true` precisely when this manager contains `source_file`. Stands in for
    /// `SourceFileManager.containsSourceFile(SourceFile)`.
    fn contains_source_file(&self, source_file: &SourceFile) -> bool;

    /// Returns a list containing all [`SourceFile`]s of the program. Stands in for
    /// `SourceFileManager.getAllSourceFiles()`.
    fn get_all_source_files(&self) -> Vec<SourceFile>;

    /// Returns a list containing [`SourceFile`]s which are mapped to at least one address in the
    /// program. Stands in for `SourceFileManager.getMappedSourceFiles()`.
    fn get_mapped_source_files(&self) -> Vec<SourceFile>;

    /// Changes the source map so that any [`SourceMapEntry`] associated with `source` is
    /// associated with `target` instead. Entries already associated with `target` are unaffected.
    /// `source` will not be associated with any entries afterward (unless `source` and `target`
    /// are the same). Line number information is not changed. Stands in for
    /// `SourceFileManager.transferSourceMapEntries(SourceFile, SourceFile)`.
    fn transfer_source_map_entries(
        &mut self,
        source: &SourceFile,
        target: &SourceFile,
    ) -> Result<(), LockException>;

    /// Returns a [`SourceMapEntryIterator`] starting at `address`. Stands in for
    /// `SourceFileManager.getSourceMapEntryIterator(Address, boolean)`.
    fn get_source_map_entry_iterator(
        &self,
        address: &Address,
        forward: bool,
    ) -> Box<dyn SourceMapEntryIterator>;

    /// Returns the sorted list of [`SourceMapEntry`]s for `source_file` with line number between
    /// `min_line` and `max_line`, inclusive. Stands in for
    /// `SourceFileManager.getSourceMapEntries(SourceFile, int, int)`.
    fn get_source_map_entries_for_range(
        &self,
        source_file: &SourceFile,
        min_line: i32,
        max_line: i32,
    ) -> Vec<Arc<dyn SourceMapEntry>>;

    /// Removes a [`SourceMapEntry`] from this manager. Returns `true` if `entry` was in the
    /// manager. Stands in for `SourceFileManager.removeSourceMapEntry(SourceMapEntry)`.
    fn remove_source_map_entry(&mut self, entry: &dyn SourceMapEntry) -> Result<bool, LockException>;

    /// Returns the sorted list of [`SourceMapEntry`]s for `source_file` with line number equal to
    /// `line_number`. Stands in for the Java default method
    /// `SourceFileManager.getSourceMapEntries(SourceFile, int)`.
    fn get_source_map_entries_for_line(
        &self,
        source_file: &SourceFile,
        line_number: i32,
    ) -> Vec<Arc<dyn SourceMapEntry>> {
        self.get_source_map_entries_for_range(source_file, line_number, line_number)
    }

    /// Returns a sorted list of all [`SourceMapEntry`]s in the program corresponding to
    /// `source_file`. Stands in for the Java default method
    /// `SourceFileManager.getSourceMapEntries(SourceFile)`.
    fn get_source_map_entries_for_file(&self, source_file: &SourceFile) -> Vec<Arc<dyn SourceMapEntry>> {
        self.get_source_map_entries_for_range(source_file, 0, i32::MAX)
    }

    /// Creates a [`SourceMapEntry`] with source file `source_file`, line number `line_number`, and
    /// address range `range`, and adds it to the program database. Stands in for the Java default
    /// method `SourceFileManager.addSourceMapEntry(SourceFile, int, AddressRange)`, which can never
    /// hit the `AddressOverflowException` case since `range` is already a valid range.
    fn add_source_map_entry_for_range(
        &mut self,
        source_file: &SourceFile,
        line_number: i32,
        range: &AddressRange,
    ) -> Result<Arc<dyn SourceMapEntry>, LockException> {
        match self.add_source_map_entry(source_file, line_number, range.min_address(), range.length() as i64) {
            Ok(entry) => Ok(entry),
            Err(AddSourceMapEntryError::Lock(e)) => Err(e),
            Err(AddSourceMapEntryError::Overflow(_)) => {
                unreachable!("AddressRange is already a valid, non-overflowing range")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Mutex;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        test_space().address(offset)
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockEntry {
        source_file: SourceFile,
        line_number: i32,
        base_address: Address,
        length: i64,
    }

    impl SourceMapEntry for MockEntry {
        fn get_line_number(&self) -> i32 {
            self.line_number
        }

        fn get_source_file(&self) -> SourceFile {
            self.source_file.clone()
        }

        fn get_base_address(&self) -> Address {
            self.base_address.clone()
        }

        fn get_length(&self) -> i64 {
            self.length
        }

        fn get_range(&self) -> Option<AddressRange> {
            if self.length == 0 {
                return None;
            }
            AddressRange::from_start_len(self.base_address.clone(), self.length as u64).ok()
        }
    }

    /// Minimal in-memory mock proving object-safety and exercising real add/query/remove/transfer
    /// behavior, rather than trivially-true assertions.
    #[derive(Default)]
    struct MockSourceFileManager {
        source_files: Mutex<Vec<SourceFile>>,
        entries: Mutex<Vec<MockEntry>>,
    }

    impl SourceFileManager for MockSourceFileManager {
        fn get_source_map_entries_at(&self, addr: &Address) -> Vec<Arc<dyn SourceMapEntry>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|e| &e.base_address == addr)
                .map(|e| Arc::new(e.clone()) as Arc<dyn SourceMapEntry>)
                .collect()
        }

        fn add_source_map_entry(
            &mut self,
            source_file: &SourceFile,
            line_number: i32,
            base_addr: &Address,
            length: i64,
        ) -> Result<Arc<dyn SourceMapEntry>, AddSourceMapEntryError> {
            if !self.source_files.lock().unwrap().contains(source_file) {
                return Err(AddSourceMapEntryError::Lock(LockException::new(
                    "source file not associated with program",
                )));
            }
            let entry = MockEntry {
                source_file: source_file.clone(),
                line_number,
                base_address: base_addr.clone(),
                length,
            };
            self.entries.lock().unwrap().push(entry.clone());
            Ok(Arc::new(entry))
        }

        fn intersects_source_map_entry(&self, addrs: &dyn AddressSetView) -> bool {
            self.entries.lock().unwrap().iter().any(|e| addrs.contains(&e.base_address))
        }

        fn add_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException> {
            let mut files = self.source_files.lock().unwrap();
            if files.contains(source_file) {
                return Ok(false);
            }
            files.push(source_file.clone());
            Ok(true)
        }

        fn remove_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException> {
            let mut files = self.source_files.lock().unwrap();
            let before = files.len();
            files.retain(|f| f != source_file);
            self.entries.lock().unwrap().retain(|e| &e.source_file != source_file);
            Ok(files.len() != before)
        }

        fn contains_source_file(&self, source_file: &SourceFile) -> bool {
            self.source_files.lock().unwrap().contains(source_file)
        }

        fn get_all_source_files(&self) -> Vec<SourceFile> {
            self.source_files.lock().unwrap().clone()
        }

        fn get_mapped_source_files(&self) -> Vec<SourceFile> {
            let mut files: Vec<SourceFile> =
                self.entries.lock().unwrap().iter().map(|e| e.source_file.clone()).collect();
            files.sort_by(|a, b| a.path().cmp(b.path()));
            files.dedup();
            files
        }

        fn transfer_source_map_entries(
            &mut self,
            source: &SourceFile,
            target: &SourceFile,
        ) -> Result<(), LockException> {
            let files = self.source_files.lock().unwrap();
            if !files.contains(source) {
                return Err(LockException::new("source not associated with program"));
            }
            if !files.contains(target) {
                return Err(LockException::new("target not associated with program"));
            }
            drop(files);
            if source == target {
                return Ok(());
            }
            for entry in self.entries.lock().unwrap().iter_mut() {
                if &entry.source_file == source {
                    entry.source_file = target.clone();
                }
            }
            Ok(())
        }

        fn get_source_map_entry_iterator(
            &self,
            address: &Address,
            forward: bool,
        ) -> Box<dyn SourceMapEntryIterator> {
            let mut entries: Vec<Arc<dyn SourceMapEntry>> = self
                .entries
                .lock()
                .unwrap()
                .iter()
                .filter(|e| if forward { e.base_address >= *address } else { e.base_address <= *address })
                .map(|e| Arc::new(e.clone()) as Arc<dyn SourceMapEntry>)
                .collect();
            entries.sort_by_key(|e| e.get_base_address());
            crate::program::model::sourcemap::source_map_entry_iterator::of(entries)
        }

        fn get_source_map_entries_for_range(
            &self,
            source_file: &SourceFile,
            min_line: i32,
            max_line: i32,
        ) -> Vec<Arc<dyn SourceMapEntry>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|e| &e.source_file == source_file && e.line_number >= min_line && e.line_number <= max_line)
                .map(|e| Arc::new(e.clone()) as Arc<dyn SourceMapEntry>)
                .collect()
        }

        fn remove_source_map_entry(&mut self, entry: &dyn SourceMapEntry) -> Result<bool, LockException> {
            let mut entries = self.entries.lock().unwrap();
            let before = entries.len();
            entries.retain(|e| {
                !(e.source_file == entry.get_source_file()
                    && e.line_number == entry.get_line_number()
                    && e.base_address == entry.get_base_address()
                    && e.length == entry.get_length())
            });
            Ok(entries.len() != before)
        }
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let manager: Box<dyn SourceFileManager> = Box::new(MockSourceFileManager::default());
        assert!(manager.get_all_source_files().is_empty());
    }

    #[test]
    fn add_and_query_source_map_entries_with_line_and_file_defaults() {
        let mut manager = MockSourceFileManager::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        assert!(manager.add_source_file(&source_file).unwrap());
        assert!(!manager.add_source_file(&source_file).unwrap());
        assert!(manager.contains_source_file(&source_file));

        let entry = manager.add_source_map_entry(&source_file, 10, &addr(0x1000), 4).unwrap();
        assert_eq!(entry.get_line_number(), 10);

        assert_eq!(manager.get_source_map_entries_for_line(&source_file, 10).len(), 1);
        assert!(manager.get_source_map_entries_for_line(&source_file, 11).is_empty());
        assert_eq!(manager.get_source_map_entries_for_file(&source_file).len(), 1);
        assert_eq!(manager.get_source_map_entries_at(&addr(0x1000)).len(), 1);
        let range = AddressRange::from_start_len(addr(0x1000), 4).unwrap();
        assert!(manager
            .intersects_source_map_entry(&crate::program::model::address::AddressSet::from_range(range)));
        assert_eq!(manager.get_mapped_source_files(), vec![source_file.clone()]);

        let other = SourceFile::new("/src/other.c").unwrap();
        assert!(manager.add_source_file(&other).unwrap());
        manager.transfer_source_map_entries(&source_file, &other).unwrap();
        assert!(manager.get_source_map_entries_for_file(&source_file).is_empty());
        assert_eq!(manager.get_source_map_entries_for_file(&other).len(), 1);

        let moved_entry = manager.get_source_map_entries_for_file(&other).remove(0);
        assert!(manager.remove_source_map_entry(moved_entry.as_ref()).unwrap());
        assert!(manager.get_source_map_entries_for_file(&other).is_empty());

        assert!(manager.remove_source_file(&other).unwrap());
        assert!(!manager.remove_source_file(&other).unwrap());
    }

    #[test]
    fn add_source_map_entry_for_range_default_delegates_to_base_address_and_length() {
        let mut manager = MockSourceFileManager::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        manager.add_source_file(&source_file).unwrap();

        let range = AddressRange::from_start_len(addr(0x2000), 8).unwrap();
        let entry = manager.add_source_map_entry_for_range(&source_file, 5, &range).unwrap();
        assert_eq!(entry.get_base_address(), addr(0x2000));
        assert_eq!(entry.get_length(), 8);
    }
}
