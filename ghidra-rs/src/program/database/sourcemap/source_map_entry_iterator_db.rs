//! Port of `ghidra.program.database.sourcemap.SourceMapEntryIteratorDB`.
//!
//! Database-backed implementation of `SourceMapEntryIterator`. The Java class is a hand-rolled
//! `hasNext()`/`next()` pull iterator with a one-record lookahead cache; this port instead
//! implements the standard [`Iterator`] trait directly (matching
//! [`SourceMapEntryIterator`](crate::program::model::sourcemap::SourceMapEntryIterator)'s own
//! `Iterator<Item = Arc<dyn SourceMapEntry>>` supertrait bound), since Rust's `Iterator::next`
//! already provides the same "pull one item, `None` when exhausted" contract without needing a
//! separate cached-lookahead field. `remove()` (`throw new UnsupportedOperationException()` in
//! Java) has no Rust `Iterator` counterpart to port.
//!
//! Like [`SourceMapEntryDB`], this is built against [`SourceFileLookup`] rather than a concrete
//! `SourceFileManagerDB` (see that module's docs for why). Java's `hasNext()` also catches
//! `IOException` from the wrapped `RecordIterator`, reports it via `manager.dbError(e)`, and treats
//! it as end-of-iteration; this port takes an [`ErrorHandler`] to do the same instead of requiring
//! a full manager.

use std::sync::Arc;

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::RecordIterator;
use crate::program::database::map::AddressMap;
use crate::program::database::sourcemap::source_map_entry_db::{SourceFileLookup, SourceMapEntryDB};
use crate::program::model::sourcemap::{SourceMapEntry, SourceMapEntryIterator};

/// Database implementation of `SourceMapEntryIterator`.
///
/// Port of `ghidra.program.database.sourcemap.SourceMapEntryIteratorDB`. See the module docs for
/// how the Java `hasNext()`/`next()`/lookahead-cache split collapses into a plain [`Iterator`] impl,
/// and for the [`SourceFileLookup`]/[`ErrorHandler`] seams used in place of a concrete
/// `SourceFileManagerDB`.
pub struct SourceMapEntryIteratorDB<'a> {
    lookup: &'a dyn SourceFileLookup,
    addr_map: &'a dyn AddressMap,
    error_handler: &'a dyn ErrorHandler,
    rec_iter: Box<dyn RecordIterator + 'a>,
    forward: bool,
}

impl<'a> SourceMapEntryIteratorDB<'a> {
    /// Constructs a new `SourceMapEntryIteratorDB`.
    ///
    /// # Parameters
    /// - `lookup`: resolves the source-file id encoded in each record.
    /// - `addr_map`: decodes each record's base address.
    /// - `error_handler`: receives any I/O error from `rec_iter`; iteration ends (as if exhausted)
    ///   immediately afterward, mirroring Java's `hasNext()` catching `IOException` and returning
    ///   `false`.
    /// - `rec_iter`: the underlying record iterator to wrap.
    /// - `forward`: direction to iterate (`true` pulls via [`RecordIterator::next`], `false` via
    ///   [`RecordIterator::previous`]), mirroring Java's `forward ? recIter.hasNext() :
    ///   recIter.hasPrevious()` / `.next()` / `.previous()` split.
    pub fn new(
        lookup: &'a dyn SourceFileLookup,
        addr_map: &'a dyn AddressMap,
        error_handler: &'a dyn ErrorHandler,
        rec_iter: Box<dyn RecordIterator + 'a>,
        forward: bool,
    ) -> Self {
        SourceMapEntryIteratorDB {
            lookup,
            addr_map,
            error_handler,
            rec_iter,
            forward,
        }
    }
}

impl<'a> Iterator for SourceMapEntryIteratorDB<'a> {
    type Item = Arc<dyn SourceMapEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = if self.forward {
            self.rec_iter.next()
        } else {
            self.rec_iter.previous()
        };
        match result {
            Ok(Some(rec)) => Some(Arc::new(SourceMapEntryDB::new(self.lookup, &rec, self.addr_map))
                as Arc<dyn SourceMapEntry>),
            Ok(None) => None,
            Err(e) => {
                self.error_handler.db_error(e);
                None
            }
        }
    }
}

impl<'a> SourceMapEntryIterator for SourceMapEntryIteratorDB<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field, FieldType, Schema};
    use crate::program::database::sourcemap::source_map_adapter::{BASE_ADDR_COL, FILE_LINE_COL, LENGTH_COL};
    use crate::program::database::sourcemap::SourceFile;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::sync::Arc;

    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap {
                space: self.space.clone(),
            })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    struct MapLookup(HashMap<i64, SourceFile>);

    impl SourceFileLookup for MapLookup {
        fn get_source_file(&self, id: i64) -> Option<SourceFile> {
            self.0.get(&id).cloned()
        }
    }

    #[derive(Default)]
    struct RecordingErrorHandler {
        errors: RefCell<Vec<String>>,
    }

    impl ErrorHandler for RecordingErrorHandler {
        fn db_error(&self, e: io::Error) {
            self.errors.borrow_mut().push(e.to_string());
        }
    }

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        pos: usize,
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            if self.pos >= self.records.len() {
                return Ok(None);
            }
            let rec = self.records[self.pos].clone();
            self.pos += 1;
            Ok(Some(rec))
        }

        fn has_next(&self) -> bool {
            self.pos < self.records.len()
        }

        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }

        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.pos == 0 {
                return Ok(None);
            }
            self.pos -= 1;
            Ok(Some(self.records[self.pos].clone()))
        }
    }

    struct ErroringRecordIterator;

    impl RecordIterator for ErroringRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }

        fn has_next(&self) -> bool {
            true
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Long],
            vec!["FileLine".to_string(), "BaseAddr".to_string(), "Length".to_string()],
            vec![],
        ))
    }

    fn make_record(key: i64, file_id: i64, line: i32, base: i64, length: i64) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        let file_line = (file_id << 32) | (line as i64 & 0xFFFF_FFFF);
        rec.set_long(FILE_LINE_COL, file_line);
        rec.set_long(BASE_ADDR_COL, base);
        rec.set_long(LENGTH_COL, length);
        rec
    }

    fn lookup_with(id: i64, source_file: SourceFile) -> MapLookup {
        let mut map = HashMap::new();
        map.insert(id, source_file);
        MapLookup(map)
    }

    #[test]
    fn iterates_forward_in_record_order() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let addr_map = IdentityAddressMap { space: ram_space() };
        let errors = RecordingErrorHandler::default();
        let records = vec![
            make_record(1, 1, 10, 0x100, 4),
            make_record(2, 1, 20, 0x200, 4),
        ];
        let rec_iter = Box::new(VecRecordIterator { records, pos: 0 });

        let mut iter =
            SourceMapEntryIteratorDB::new(&lookup, &addr_map, &errors, rec_iter, true);
        let first = iter.next().expect("first entry");
        assert_eq!(first.get_line_number(), 10);
        let second = iter.next().expect("second entry");
        assert_eq!(second.get_line_number(), 20);
        assert!(iter.next().is_none());
        assert!(errors.errors.borrow().is_empty());
    }

    #[test]
    fn iterates_backward_using_previous() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let addr_map = IdentityAddressMap { space: ram_space() };
        let errors = RecordingErrorHandler::default();
        let records = vec![
            make_record(1, 1, 10, 0x100, 4),
            make_record(2, 1, 20, 0x200, 4),
        ];
        let mut rec_iter = VecRecordIterator { records, pos: 0 };
        // Position at the end, as a caller would after seeking, so `previous()` yields entries in
        // reverse.
        rec_iter.pos = 2;
        let rec_iter: Box<dyn RecordIterator> = Box::new(rec_iter);

        let mut iter =
            SourceMapEntryIteratorDB::new(&lookup, &addr_map, &errors, rec_iter, false);
        let first = iter.next().expect("first entry");
        assert_eq!(first.get_line_number(), 20);
        let second = iter.next().expect("second entry");
        assert_eq!(second.get_line_number(), 10);
        assert!(iter.next().is_none());
    }

    #[test]
    fn io_error_is_reported_and_ends_iteration() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let addr_map = IdentityAddressMap { space: ram_space() };
        let errors = RecordingErrorHandler::default();
        let rec_iter: Box<dyn RecordIterator> = Box::new(ErroringRecordIterator);

        let mut iter =
            SourceMapEntryIteratorDB::new(&lookup, &addr_map, &errors, rec_iter, true);
        assert!(iter.next().is_none());
        assert_eq!(errors.errors.borrow().len(), 1);
    }

    #[test]
    fn usable_as_source_map_entry_iterator_trait_object() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let addr_map = IdentityAddressMap { space: ram_space() };
        let errors = RecordingErrorHandler::default();
        let records = vec![make_record(1, 1, 10, 0x100, 4)];
        let rec_iter: Box<dyn RecordIterator> = Box::new(VecRecordIterator { records, pos: 0 });

        let mut iter: Box<dyn SourceMapEntryIterator> = Box::new(SourceMapEntryIteratorDB::new(
            &lookup, &addr_map, &errors, rec_iter, true,
        ));
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }
}
