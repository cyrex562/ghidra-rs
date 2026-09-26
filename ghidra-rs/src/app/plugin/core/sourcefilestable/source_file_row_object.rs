//! Port of `ghidra.app.plugin.core.sourcefilestable.SourceFileRowObject`.

use crate::program::database::sourcemap::{SourceFile, SourceFileIdType};
use crate::program::model::sourcemap::SourceFileManager;

/// A row object for the source files table (`SourceFilesTableModel`).
///
/// The number of source map entries for the file is computed once, at construction, because it
/// is expensive to compute (mirrors the Java class caching `numEntries`).
#[derive(Debug, Clone)]
pub struct SourceFileRowObject {
    source_file: SourceFile,
    num_entries: usize,
}

impl SourceFileRowObject {
    /// Creates a row for `source_file`, caching the number of source map entries that
    /// `source_manager` reports for it.
    pub fn new(source_file: SourceFile, source_manager: &dyn SourceFileManager) -> Self {
        let num_entries = source_manager.get_source_map_entries_for_file(&source_file).len();
        Self { source_file, num_entries }
    }

    /// Returns the file name of the source file.
    pub fn get_file_name(&self) -> &str {
        self.source_file.filename()
    }

    /// Returns the path of the source file.
    pub fn get_path(&self) -> &str {
        self.source_file.path()
    }

    /// Returns the (cached) number of source map entries for the source file.
    pub fn get_num_source_map_entries(&self) -> usize {
        self.num_entries
    }

    /// Returns the source file.
    pub fn get_source_file(&self) -> &SourceFile {
        &self.source_file
    }

    /// Returns the id type of the source file.
    pub fn get_source_file_id_type(&self) -> SourceFileIdType {
        self.source_file.id_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::framework::store::LockException;
    use crate::program::database::sourcemap::AddSourceMapEntryError;
    use crate::program::model::address::{
        Address, AddressRange, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::sourcemap::{
        source_map_entry_iterator, DummySourceFileManager, SourceMapEntry, SourceMapEntryIterator,
    };

    #[derive(Debug)]
    struct Entry {
        file: SourceFile,
        line: i32,
        base: Address,
    }

    impl SourceMapEntry for Entry {
        fn get_line_number(&self) -> i32 {
            self.line
        }
        fn get_source_file(&self) -> SourceFile {
            self.file.clone()
        }
        fn get_base_address(&self) -> Address {
            self.base.clone()
        }
        fn get_length(&self) -> i64 {
            0
        }
        fn get_range(&self) -> Option<AddressRange> {
            None
        }
        fn compare_to(&self, other: &dyn SourceMapEntry) -> std::cmp::Ordering {
            self.base.cmp(&other.get_base_address())
        }
    }

    /// Read-only manager holding a fixed entry list; counts calls to the per-file query so the
    /// test can prove the count is cached rather than recomputed.
    struct FixedManager {
        entries: Vec<(SourceFile, i32)>,
        queries: std::cell::Cell<u32>,
    }

    impl SourceFileManager for FixedManager {
        fn get_source_map_entries_at(&self, _addr: &Address) -> Vec<Arc<dyn SourceMapEntry>> {
            Vec::new()
        }
        fn add_source_map_entry(
            &mut self,
            _f: &SourceFile,
            _l: i32,
            _a: &Address,
            _len: i64,
        ) -> Result<Arc<dyn SourceMapEntry>, AddSourceMapEntryError> {
            Err(AddSourceMapEntryError::Lock(LockException::new("read-only")))
        }
        fn intersects_source_map_entry(&self, _addrs: &dyn AddressSetView) -> bool {
            false
        }
        fn add_source_file(&mut self, _f: &SourceFile) -> Result<bool, LockException> {
            Err(LockException::new("read-only"))
        }
        fn remove_source_file(&mut self, _f: &SourceFile) -> Result<bool, LockException> {
            Err(LockException::new("read-only"))
        }
        fn contains_source_file(&self, f: &SourceFile) -> bool {
            self.entries.iter().any(|(e, _)| e == f)
        }
        fn get_all_source_files(&self) -> Vec<SourceFile> {
            self.entries.iter().map(|(f, _)| f.clone()).collect()
        }
        fn get_mapped_source_files(&self) -> Vec<SourceFile> {
            self.get_all_source_files()
        }
        fn transfer_source_map_entries(
            &mut self,
            _s: &SourceFile,
            _t: &SourceFile,
        ) -> Result<(), LockException> {
            Err(LockException::new("read-only"))
        }
        fn get_source_map_entry_iterator(
            &self,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn SourceMapEntryIterator> {
            source_map_entry_iterator::of(Vec::new())
        }
        fn get_source_map_entries_for_range(
            &self,
            source_file: &SourceFile,
            min_line: i32,
            max_line: i32,
        ) -> Vec<Arc<dyn SourceMapEntry>> {
            self.queries.set(self.queries.get() + 1);
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            self.entries
                .iter()
                .filter(|(f, l)| f == source_file && *l >= min_line && *l <= max_line)
                .enumerate()
                .map(|(i, (f, l))| {
                    Arc::new(Entry { file: f.clone(), line: *l, base: space.address(i as i64) })
                        as Arc<dyn SourceMapEntry>
                })
                .collect()
        }
        fn remove_source_map_entry(&mut self, _e: &dyn SourceMapEntry) -> Result<bool, LockException> {
            Err(LockException::new("read-only"))
        }
    }

    #[test]
    fn accessors_delegate_to_source_file() {
        let file = SourceFile::with_identifier(
            "/src/dir/../main.c",
            SourceFileIdType::Md5,
            Some(&[0u8; 16]),
        )
        .unwrap();
        let row = SourceFileRowObject::new(file.clone(), &DummySourceFileManager::new());
        assert_eq!(row.get_file_name(), "main.c");
        assert_eq!(row.get_path(), "/src/main.c");
        assert_eq!(row.get_source_file(), &file);
        assert_eq!(row.get_source_file_id_type(), SourceFileIdType::Md5);
        assert_eq!(row.get_num_source_map_entries(), 0);
    }

    #[test]
    fn entry_count_is_per_file_and_cached_at_construction() {
        let a = SourceFile::new("/a.c").unwrap();
        let b = SourceFile::new("/b.c").unwrap();
        let mgr = FixedManager {
            entries: vec![(a.clone(), 1), (b.clone(), 2), (a.clone(), 0), (a.clone(), i32::MAX)],
            queries: std::cell::Cell::new(0),
        };
        let row_a = SourceFileRowObject::new(a, &mgr);
        let row_b = SourceFileRowObject::new(b, &mgr);
        assert_eq!(mgr.queries.get(), 2);
        // All lines 0..=i32::MAX are counted, matching Java's getSourceMapEntries(SourceFile).
        assert_eq!(row_a.get_num_source_map_entries(), 3);
        assert_eq!(row_b.get_num_source_map_entries(), 1);
        assert_eq!(row_a.get_num_source_map_entries(), 3);
        assert_eq!(mgr.queries.get(), 2);
        assert_eq!(row_a.get_source_file_id_type(), SourceFileIdType::None);
    }
}
