//! Port of `ghidra.program.database.sourcemap.SourceFileManagerDB` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `SourceFileManager`/`ManagerDB`/`ErrorHandler` implementation that
//! owns a `SourceFileAdapter`/`SourceMapAdapter` pair and calls back into `ProgramDB`
//! (`program.getMemory()`, `program.setChanged(...)`, `program.checkExclusiveAccess()`,
//! `program.dbError(...)`) on every mutating/lookup method. That dependency on the unported
//! `ProgramDB` -- itself depending on the manager classes it owns -- is what makes
//! `SourceFileManagerDB` a cycle cut-point.
//!
//! Following the precedent set by
//! [`RelocationManager`](crate::program::database::reloc::RelocationManager) (and, for dropping
//! `ManagerDB`'s `setProgram`/`programReady`/`TaskMonitor` parameters,
//! [`EquateManager`](crate::program::database::symbol::EquateManager) and
//! [`CodeManager`](crate::program::database::code::CodeManager)), this trait combines the
//! already-ported [`ManagerDB`] and [`ErrorHandler`] traits as supertraits, and adds the query/
//! mutation surface of the not-yet-ported `ghidra.program.model.sourcemap.SourceFileManager`
//! interface directly as trait methods (that interface is `SourceFileManagerDB`'s entire
//! `@Override`-able public API, so there is nothing left to place in a separate stub).
//!
//! Left out: the constructor (`DBHandle`/`AddressMapDB`/`OpenMode`/`Lock`/`TaskMonitor` wiring and
//! adapter selection), `program.checkExclusiveAccess()` enforcement (a `ProgramDB` concern), and
//! the private helpers (`getSourceFileFromKey`, `getKeyForSourceFile`,
//! `updateLastSourceFileAndLastKey`, `addZeroLengthEntry`, `isLessInSameSpace`,
//! `isLessOrEqualInSameSpace`, `getStartAddress`/`getEndAddress`/`getLength`/`getFileAndLine`) used
//! internally to implement the methods below against the two DB adapters -- these are
//! implementation details of whichever concrete adapter-backed type is added later, not part of
//! the callable API other code depends on.
//!
//! Java's overloaded `getSourceMapEntries`/`addSourceMapEntry` methods (which differ only by
//! parameter type, not name) are given distinct names here since Rust traits do not support
//! overloading:
//! - `getSourceMapEntries(Address)` -> [`get_source_map_entries_at`]
//! - `getSourceMapEntries(SourceFile, int, int)` -> [`get_source_map_entries_for_range`]
//! - `getSourceMapEntries(SourceFile, int)` (default) -> [`get_source_map_entries_for_line`]
//! - `getSourceMapEntries(SourceFile)` (default) -> [`get_source_map_entries_for_file`]
//! - `addSourceMapEntry(SourceFile, int, Address, long)` -> [`add_source_map_entry`]
//! - `addSourceMapEntry(SourceFile, int, AddressRange)` (default) -> [`add_source_map_entry_for_range`]
//!
//! [`get_source_map_entries_at`]: SourceFileManagerDB::get_source_map_entries_at
//! [`get_source_map_entries_for_range`]: SourceFileManagerDB::get_source_map_entries_for_range
//! [`get_source_map_entries_for_line`]: SourceFileManagerDB::get_source_map_entries_for_line
//! [`get_source_map_entries_for_file`]: SourceFileManagerDB::get_source_map_entries_for_file
//! [`add_source_map_entry`]: SourceFileManagerDB::add_source_map_entry
//! [`add_source_map_entry_for_range`]: SourceFileManagerDB::add_source_map_entry_for_range

use std::sync::Arc;

use thiserror::Error;

use crate::framework::db::util::ErrorHandler;
use crate::framework::store::LockException;
use crate::program::database::sourcemap::SourceFile;
use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressOverflowException, AddressRange, AddressSetView};
use crate::program::model::sourcemap::SourceMapEntryIterator;
use crate::program::seam_stubs::SourceMapEntry;

/// Error produced by [`SourceFileManagerDB::add_source_map_entry`], mirroring the Java method's
/// `throws LockException, AddressOverflowException`.
#[derive(Debug, Error)]
pub enum AddSourceMapEntryError {
    #[error(transparent)]
    Lock(#[from] LockException),
    #[error(transparent)]
    Overflow(#[from] AddressOverflowException),
}

/// Database manager for managing source files and source map information.
///
/// Port of `ghidra.program.database.sourcemap.SourceFileManagerDB`, folding in the query/mutation
/// surface of `ghidra.program.model.sourcemap.SourceFileManager`. See the module docs for what was
/// intentionally left out (construction, exclusive-access enforcement, and internal helpers).
pub trait SourceFileManagerDB: ManagerDB + ErrorHandler {
    /// Adds a [`SourceFile`] to this manager. A `SourceFile` must be added before it can be
    /// associated with any source map information. Returns `true` if this manager did not already
    /// contain `source_file`. Stands in for `SourceFileManagerDB.addSourceFile(SourceFile)`.
    fn add_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException>;

    /// Removes a [`SourceFile`] from this manager. Any associated [`SourceMapEntry`]s are also
    /// removed. Returns `true` if `source_file` was in the manager. Stands in for
    /// `SourceFileManagerDB.removeSourceFile(SourceFile)`.
    fn remove_source_file(&mut self, source_file: &SourceFile) -> Result<bool, LockException>;

    /// Returns a sorted list of [`SourceMapEntry`]s associated with address `addr`. Stands in for
    /// `SourceFileManagerDB.getSourceMapEntries(Address)`.
    fn get_source_map_entries_at(&self, addr: &Address) -> Vec<Arc<dyn SourceMapEntry>>;

    /// Creates a [`SourceMapEntry`] with source file `source_file`, line number `line_number`, and
    /// non-negative `length` starting at `base_addr`, and adds it to the program database.
    /// Entries with non-zero lengths must either cover the same address range or be disjoint.
    /// Stands in for `SourceFileManagerDB.addSourceMapEntry(SourceFile, int, Address, long)`.
    fn add_source_map_entry(
        &mut self,
        source_file: &SourceFile,
        line_number: i32,
        base_addr: &Address,
        length: i64,
    ) -> Result<Arc<dyn SourceMapEntry>, AddSourceMapEntryError>;

    /// Returns `true` precisely when at least one address in `addrs` has source map information.
    /// Stands in for `SourceFileManagerDB.intersectsSourceMapEntry(AddressSetView)`.
    fn intersects_source_map_entry(&self, addrs: &dyn AddressSetView) -> bool;

    /// Returns a list containing [`SourceFile`]s which are mapped to at least one address in the
    /// program. Stands in for `SourceFileManagerDB.getMappedSourceFiles()`.
    fn get_mapped_source_files(&self) -> Vec<SourceFile>;

    /// Returns a list containing all [`SourceFile`]s of the program. Stands in for
    /// `SourceFileManagerDB.getAllSourceFiles()`.
    fn get_all_source_files(&self) -> Vec<SourceFile>;

    /// Changes the source map so that any [`SourceMapEntry`] associated with `source` is
    /// associated with `target` instead. Entries already associated with `target` are unaffected.
    /// `source` will not be associated with any entries afterward (unless `source` and `target`
    /// are the same). Stands in for
    /// `SourceFileManagerDB.transferSourceMapEntries(SourceFile, SourceFile)`.
    fn transfer_source_map_entries(
        &mut self,
        source: &SourceFile,
        target: &SourceFile,
    ) -> Result<(), LockException>;

    /// Returns a [`SourceMapEntryIterator`] starting at `address`. Stands in for
    /// `SourceFileManagerDB.getSourceMapEntryIterator(Address, boolean)`.
    fn get_source_map_entry_iterator(
        &self,
        address: &Address,
        forward: bool,
    ) -> Box<dyn SourceMapEntryIterator>;

    /// Returns `true` precisely when this manager contains `source_file`. Stands in for
    /// `SourceFileManagerDB.containsSourceFile(SourceFile)`.
    fn contains_source_file(&self, source_file: &SourceFile) -> bool;

    /// Returns the sorted list of [`SourceMapEntry`]s for `source_file` with line number between
    /// `min_line` and `max_line`, inclusive. Stands in for
    /// `SourceFileManagerDB.getSourceMapEntries(SourceFile, int, int)`.
    fn get_source_map_entries_for_range(
        &self,
        source_file: &SourceFile,
        min_line: i32,
        max_line: i32,
    ) -> Vec<Arc<dyn SourceMapEntry>>;

    /// Removes a [`SourceMapEntry`] from this manager. Returns `true` if `entry` was in the
    /// manager. Stands in for `SourceFileManagerDB.removeSourceMapEntry(SourceMapEntry)`.
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
    use std::io;
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

    /// Simple in-memory mock proving object-safety and exercising real add/query/remove/transfer
    /// behavior, rather than trivially-true assertions.
    #[derive(Default)]
    struct MockSourceFileManagerDB {
        source_files: Mutex<Vec<SourceFile>>,
        entries: Mutex<Vec<MockEntry>>,
    }

    impl ManagerDB for MockSourceFileManagerDB {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }

        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl ErrorHandler for MockSourceFileManagerDB {
        fn db_error(&self, e: io::Error) {
            panic!("db error: {e}");
        }
    }

    impl SourceFileManagerDB for MockSourceFileManagerDB {
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

        fn get_mapped_source_files(&self) -> Vec<SourceFile> {
            let mut files: Vec<SourceFile> =
                self.entries.lock().unwrap().iter().map(|e| e.source_file.clone()).collect();
            files.sort_by(|a, b| a.path().cmp(b.path()));
            files.dedup();
            files
        }

        fn get_all_source_files(&self) -> Vec<SourceFile> {
            self.source_files.lock().unwrap().clone()
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

        fn contains_source_file(&self, source_file: &SourceFile) -> bool {
            self.source_files.lock().unwrap().contains(source_file)
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
        let manager: Box<dyn SourceFileManagerDB> = Box::new(MockSourceFileManagerDB::default());
        assert!(manager.get_all_source_files().is_empty());
    }

    #[test]
    fn add_and_query_source_map_entries() {
        let mut manager = MockSourceFileManagerDB::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        assert!(manager.add_source_file(&source_file).unwrap());
        assert!(!manager.add_source_file(&source_file).unwrap());

        let entry = manager
            .add_source_map_entry(&source_file, 10, &addr(0x1000), 0x10)
            .unwrap();
        assert_eq!(entry.get_line_number(), 10);

        let at_addr = manager.get_source_map_entries_at(&addr(0x1000));
        assert_eq!(at_addr.len(), 1);
        assert_eq!(at_addr[0].get_line_number(), 10);

        let for_line = manager.get_source_map_entries_for_line(&source_file, 10);
        assert_eq!(for_line.len(), 1);

        let for_file = manager.get_source_map_entries_for_file(&source_file);
        assert_eq!(for_file.len(), 1);

        assert!(manager.contains_source_file(&source_file));
        assert_eq!(manager.get_mapped_source_files(), vec![source_file.clone()]);
    }

    #[test]
    fn add_source_map_entry_for_range_default_delegates() {
        let mut manager = MockSourceFileManagerDB::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        manager.add_source_file(&source_file).unwrap();

        let range = AddressRange::from_start_len(addr(0x2000), 0x10).unwrap();
        let entry = manager.add_source_map_entry_for_range(&source_file, 5, &range).unwrap();
        assert_eq!(entry.get_base_address(), addr(0x2000));
        assert_eq!(entry.get_length(), 0x10);
    }

    #[test]
    fn add_source_map_entry_rejects_unassociated_source_file() {
        let mut manager = MockSourceFileManagerDB::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        let result = manager.add_source_map_entry(&source_file, 1, &addr(0x1000), 4);
        assert!(matches!(result, Err(AddSourceMapEntryError::Lock(_))));
    }

    #[test]
    fn transfer_and_remove_source_map_entries() {
        let mut manager = MockSourceFileManagerDB::default();
        let source = SourceFile::new("/src/a.c").unwrap();
        let target = SourceFile::new("/src/b.c").unwrap();
        manager.add_source_file(&source).unwrap();
        manager.add_source_file(&target).unwrap();

        manager.add_source_map_entry(&source, 1, &addr(0x100), 4).unwrap();
        manager.transfer_source_map_entries(&source, &target).unwrap();

        assert!(manager.get_source_map_entries_for_file(&source).is_empty());
        let transferred = manager.get_source_map_entries_for_file(&target);
        assert_eq!(transferred.len(), 1);

        assert!(manager.remove_source_map_entry(transferred[0].as_ref()).unwrap());
        assert!(manager.get_source_map_entries_for_file(&target).is_empty());
    }

    #[test]
    fn remove_source_file_clears_its_entries() {
        let mut manager = MockSourceFileManagerDB::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        manager.add_source_file(&source_file).unwrap();
        manager.add_source_map_entry(&source_file, 1, &addr(0x100), 4).unwrap();

        assert!(manager.remove_source_file(&source_file).unwrap());
        assert!(!manager.contains_source_file(&source_file));
        assert!(manager.get_source_map_entries_for_file(&source_file).is_empty());
    }

    #[test]
    fn intersects_source_map_entry_checks_address_set() {
        use crate::program::model::address::AddressSet;

        let mut manager = MockSourceFileManagerDB::default();
        let source_file = SourceFile::new("/src/main.c").unwrap();
        manager.add_source_file(&source_file).unwrap();
        manager.add_source_map_entry(&source_file, 1, &addr(0x100), 4).unwrap();

        let hit = AddressSet::from_address(addr(0x100));
        let miss = AddressSet::from_address(addr(0x999));
        assert!(manager.intersects_source_map_entry(&hit));
        assert!(!manager.intersects_source_map_entry(&miss));
    }
}
