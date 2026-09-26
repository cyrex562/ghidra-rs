//! Port of `ghidra.program.database.oldfunction.OldFunctionMapDB`.
//!
//! `OldFunctionMapDB` is a thin wrapper over the `@Deprecated` `ghidra.program.database.util.
//! SharedRangeMapDB` (itself documented "should not be used except by the OldFunctionMapDB
//! class"), which provides a long-value range map backed by two database tables: a "ranges" table
//! (contiguous `[start, end]` index ranges) and a "map" table (associating each range with zero or
//! more `long` values, so ranges may be shared by multiple values -- hence "Shared"). Grepping the
//! whole Ghidra source tree for `SharedRangeMapDB` turns up exactly three references: its own
//! declaration, its own (now-superseded) test, and this class -- and this class itself only ever
//! calls the *read* half of that API (its constructor opens existing tables with `create=false`,
//! never `true`, and its only query method is `getBody`, backed by `getValueRangeIterator`).
//! Nothing in the whole codebase ever calls `SharedRangeMapDB.add`/`remove` (the range data these
//! tables hold was populated by pre-2.2 Ghidra code that predates this whole package and no longer
//! exists). This port therefore covers exactly the read/construct/dispose surface this class
//! actually exercises: [`OldFunctionMapDB::new`] opens the two existing tables by name (reporting,
//! not failing, if either is missing -- matching `SharedRangeMapDB`'s `create=false` constructor
//! path, which reports via `errHandler.dbError` rather than throwing), and
//! [`get_body`](OldFunctionMapDB::get_body) reads them back via a linear scan (see below).
//!
//! `SharedRangeMapDB.getValueRangeIterator(long)` uses `Table.indexIterator` (an indexed lookup on
//! the map table's `MAP_VALUE_COL`); this port's [`Table`] has no index support, so
//! [`get_body`](OldFunctionMapDB::get_body) instead does a full linear scan of the map table
//! filtering on that column, which is observationally equivalent (same result set) -- the same
//! tradeoff already made throughout this port wherever `db.Table`'s indexed queries have no ported
//! equivalent (see e.g.
//! [`OldStackVariableDBAdapterV1::get_stack_variable_keys`](crate::program::database::oldfunction::OldStackVariableDBAdapterV1)).
//!
//! Implements the [`OldFunctionMapDB`](crate::program::seam_stubs::OldFunctionMapDB) placeholder
//! trait `OldFunctionManager`'s module docs introduced as this class's stand-in, so a concrete
//! `OldFunctionManager` implementor can now hold a real instance of this type behind that trait
//! object.
//!
//! **`dispose()`'s divergence from Java:** Java's `dispose()` calls `dbHandle.deleteTable(name)`
//! on both tables, permanently removing them from the handle's registry. This port instead clears
//! each table's own records in place (`Table::clear_all`), for exactly the reason
//! [`AddressRangeMapDB::dispose`](crate::program::database::util::AddressRangeMapDB::dispose)
//! already documents for the identical situation: `self.range_table`/`self.map_table` are cloned
//! `Arc<RwLock<Table>>` handles that stay fully live in memory regardless of whether the owning
//! [`DBHandle`] still knows their names, so removing just the name from the registry would not
//! actually empty them -- a real correctness bug, not a faithful reproduction of anything Java
//! does. Clearing the live tables' records in place actually empties the map, matching every
//! caller's *observable* expectation.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::{DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::model::address::{AddressSet, AddressSetView};

const RANGES_TABLE_NAME_PREFIX: &str = "Shared Ranges - ";
const MAP_TABLE_NAME_PREFIX: &str = "Shared Map - ";

/// Name passed to the underlying shared range map. Mirrors `OldFunctionMapDB`'s hard-coded
/// `new SharedRangeMapDB(dbHandle, "Functions", fnMgr, false)` call.
const SHARED_RANGE_MAP_NAME: &str = "Functions";

// Ranges table columns (key is the "From" index value). Mirrors `SharedRangeMapDB.RANGE_TO_COL`.
const RANGE_TO_COL: usize = 0;

// Map table columns (key is a one-up ID value). Mirrors `SharedRangeMapDB.MAP_VALUE_COL`/
// `MAP_RANGE_KEY_COL`.
const MAP_VALUE_COL: usize = 0;
const MAP_RANGE_KEY_COL: usize = 1;

/// Build the ranges table schema, as defined by `SharedRangeMapDB.RANGES_SCHEMA`.
fn ranges_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "From".to_string(),
        vec![FieldType::Long],
        vec!["To".to_string()],
        vec![],
    ))
}

/// Build the map table schema, as defined by `SharedRangeMapDB.MAP_SCHEMA`.
fn map_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Long],
        vec!["Value".to_string(), "Range Key".to_string()],
        vec![],
    ))
}

/// Tracks each old function's address-set body as a range map keyed by function ID.
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionMapDB`. See the module docs for what
/// was intentionally left out (the `add`/`remove` mutation half of the underlying
/// `SharedRangeMapDB`, never called by this class) and for `dispose`'s divergence from Java.
pub struct OldFunctionMapDB {
    err_handler: Arc<dyn ErrorHandler>,
    addr_map: Arc<dyn AddressMap>,
    range_table: Option<Arc<RwLock<Table>>>,
    map_table: Option<Arc<RwLock<Table>>>,
}

impl OldFunctionMapDB {
    /// Opens the shared range map's two backing tables (named `"Shared Ranges - Functions"`/
    /// `"Shared Map - Functions"`) for read access, reporting -- not failing -- via `err_handler`
    /// if either is missing.
    ///
    /// Port of `OldFunctionMapDB(DBHandle, OldFunctionManager, AddressMap)`, inlining
    /// `SharedRangeMapDB`'s `create=false` constructor path (see the module docs for why the
    /// `create=true` path is not ported: nothing ever calls it).
    pub fn new(handle: &DBHandle, err_handler: Arc<dyn ErrorHandler>, addr_map: Arc<dyn AddressMap>) -> Self {
        let range_table_name = format!("{RANGES_TABLE_NAME_PREFIX}{SHARED_RANGE_MAP_NAME}");
        let map_table_name = format!("{MAP_TABLE_NAME_PREFIX}{SHARED_RANGE_MAP_NAME}");

        let range_table = handle.get_table(&range_table_name);
        if range_table.is_none() {
            err_handler.db_error(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Table not found: {range_table_name}"),
            ));
        }
        let map_table = handle.get_table(&map_table_name);
        if map_table.is_none() {
            err_handler.db_error(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Table not found: {map_table_name}"),
            ));
        }

        OldFunctionMapDB { err_handler, addr_map, range_table, map_table }
    }

    /// Permanently discards this map's resource data.
    ///
    /// Stands in for `OldFunctionMapDB.dispose()`/`SharedRangeMapDB.dispose()`. See the module
    /// docs for how this diverges from Java (clears the tables' records in place rather than
    /// deleting them from the owning [`DBHandle`]'s registry).
    pub fn dispose(&mut self) {
        if let Some(table) = self.range_table.take() {
            if let Err(e) = table.write().unwrap().clear_all() {
                self.err_handler.db_error(e);
            }
        }
        if let Some(table) = self.map_table.take() {
            if let Err(e) = table.write().unwrap().clear_all() {
                self.err_handler.db_error(e);
            }
        }
    }

    /// Get the address set which makes up a function.
    ///
    /// Stands in for `OldFunctionMapDB.getBody(long)`. See the module docs for why this scans the
    /// map table linearly rather than using an indexed lookup.
    pub fn get_body(&self, function_key: i64) -> Box<dyn AddressSetView> {
        let mut body = AddressSet::new();
        let (Some(range_table), Some(map_table)) = (&self.range_table, &self.map_table) else {
            return Box::new(body);
        };

        let map_table = map_table.read().unwrap();
        let mut iter = match map_table.get_record_iterator() {
            Ok(iter) => iter,
            Err(e) => {
                self.err_handler.db_error(e);
                return Box::new(body);
            }
        };

        loop {
            let rec = match iter.next() {
                Ok(Some(rec)) => rec,
                Ok(None) => break,
                Err(e) => {
                    self.err_handler.db_error(e);
                    break;
                }
            };
            if rec.get_long(MAP_VALUE_COL) != Some(function_key) {
                continue;
            }
            let Some(range_key) = rec.get_long(MAP_RANGE_KEY_COL) else {
                continue;
            };
            let range_rec = {
                let range_table = range_table.read().unwrap();
                range_table.get_record(&Field::Long(Some(range_key)))
            };
            match range_rec {
                Ok(Some(range_rec)) => {
                    let start = self.addr_map.decode_address(range_rec.get_key().get_long_value());
                    let end_key = range_rec.get_long(RANGE_TO_COL).unwrap_or(range_key);
                    let end = self.addr_map.decode_address(end_key);
                    body.add_range(&start, &end);
                }
                Ok(None) => {}
                Err(e) => {
                    self.err_handler.db_error(e);
                    break;
                }
            }
        }

        Box::new(body)
    }
}

impl crate::program::seam_stubs::OldFunctionMapDB for OldFunctionMapDB {
    fn dispose(&mut self) {
        OldFunctionMapDB::dispose(self)
    }

    fn get_body(&self, function_key: i64) -> Box<dyn AddressSetView> {
        OldFunctionMapDB::get_body(self, function_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBRecord;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType, KeyRange};
    use std::cell::RefCell;

    struct TestAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for TestAddressMap {
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
            Box::new(TestAddressMap { space: self.space.clone() })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Arc::new(TestAddressMap { space })
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

    /// Seeds a shared range map's two tables directly (bypassing the never-ported `add`), giving
    /// function `100` a two-range body: `[10, 20]` and `[30, 40]`.
    fn seed_shared_range_map(handle: &mut DBHandle) {
        let range_table_name = format!("{RANGES_TABLE_NAME_PREFIX}{SHARED_RANGE_MAP_NAME}");
        let map_table_name = format!("{MAP_TABLE_NAME_PREFIX}{SHARED_RANGE_MAP_NAME}");

        let range_table = handle.create_table(range_table_name, ranges_schema()).unwrap();
        {
            let mut t = range_table.write().unwrap();
            let mut r1 = DBRecord::new(ranges_schema(), Field::Long(Some(10)));
            r1.set_long(RANGE_TO_COL, 20);
            t.put_record(r1).unwrap();
            let mut r2 = DBRecord::new(ranges_schema(), Field::Long(Some(30)));
            r2.set_long(RANGE_TO_COL, 40);
            t.put_record(r2).unwrap();
        }

        let map_table = handle.create_table(map_table_name, map_schema()).unwrap();
        {
            let mut t = map_table.write().unwrap();
            let mut m1 = DBRecord::new(map_schema(), Field::Long(Some(1)));
            m1.set_long(MAP_VALUE_COL, 100);
            m1.set_long(MAP_RANGE_KEY_COL, 10);
            t.put_record(m1).unwrap();
            let mut m2 = DBRecord::new(map_schema(), Field::Long(Some(2)));
            m2.set_long(MAP_VALUE_COL, 100);
            m2.set_long(MAP_RANGE_KEY_COL, 30);
            t.put_record(m2).unwrap();
        }
    }

    #[test]
    fn get_body_unions_every_range_mapped_to_the_function_key() {
        let mut handle = DBHandle::new().unwrap();
        seed_shared_range_map(&mut handle);
        let err_handler: Arc<dyn ErrorHandler> = Arc::new(RecordingErrorHandler::default());
        let map = OldFunctionMapDB::new(&handle, err_handler, addr_map());

        let body = map.get_body(100);
        assert!(!body.is_empty());
        assert!(body.contains(&addr_map().decode_address(15)));
        assert!(body.contains(&addr_map().decode_address(35)));
        assert!(!body.contains(&addr_map().decode_address(25)));
    }

    #[test]
    fn get_body_for_unknown_function_is_empty() {
        let mut handle = DBHandle::new().unwrap();
        seed_shared_range_map(&mut handle);
        let err_handler: Arc<dyn ErrorHandler> = Arc::new(RecordingErrorHandler::default());
        let map = OldFunctionMapDB::new(&handle, err_handler, addr_map());

        assert!(map.get_body(999).is_empty());
    }

    #[test]
    fn missing_tables_are_reported_but_construction_does_not_fail() {
        let handle = DBHandle::new().unwrap();
        let err_handler = Arc::new(RecordingErrorHandler::default());
        let map = OldFunctionMapDB::new(&handle, err_handler.clone(), addr_map());

        assert_eq!(err_handler.errors.borrow().len(), 2);
        assert!(map.get_body(1).is_empty());
    }

    #[test]
    fn dispose_clears_records_and_further_lookups_return_empty() {
        let mut handle = DBHandle::new().unwrap();
        seed_shared_range_map(&mut handle);
        let err_handler: Arc<dyn ErrorHandler> = Arc::new(RecordingErrorHandler::default());
        let mut map = OldFunctionMapDB::new(&handle, err_handler, addr_map());

        assert!(!map.get_body(100).is_empty());
        map.dispose();
        assert!(map.get_body(100).is_empty());
    }

    #[test]
    fn implements_seam_stub_trait_object_safely() {
        let mut handle = DBHandle::new().unwrap();
        seed_shared_range_map(&mut handle);
        let err_handler: Arc<dyn ErrorHandler> = Arc::new(RecordingErrorHandler::default());
        let map = OldFunctionMapDB::new(&handle, err_handler, addr_map());
        let mut boxed: Box<dyn crate::program::seam_stubs::OldFunctionMapDB> = Box::new(map);

        assert!(!boxed.get_body(100).is_empty());
        boxed.dispose();
    }
}
