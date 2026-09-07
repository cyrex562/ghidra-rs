//! Port of `ghidra.program.database.symbol.AddressSetFilteredSymbolIterator`.
//!
//! Iterator (in address order) over all symbols that match a given query, restricted to an
//! address set.
//!
//! The Java class also inlines a private one-shot use of
//! `ghidra.program.database.util.QueryRecordIterator` (filtering `adapter.getSymbols(set,
//! forward)` by `Query`) and falls back to
//! `ghidra.program.database.util.EmptyRecordIterator` if the initial `getSymbols` call fails.
//! Neither of those is ported yet, so this port inlines the same forward-only filtering logic
//! directly (this crate's [`RecordIterator`] has no backward/`previous()` counterpart to port
//! anyway, unlike Java's `db.RecordIterator`) and uses a local empty iterator, mirroring the
//! convention already used by e.g.
//! [`VariableStorageDBAdapterNoTable`](crate::program::database::symbol::VariableStorageDBAdapterNoTable).
//!
//! `SymbolManager.getSymbol(DBRecord)` (used to resolve each matching record into a `Symbol`) and
//! `SymbolManager.dbError(IOException)` (used to report iteration failures) are likewise not
//! reachable through a single already-ported trait, so both are taken as a `resolve` callback and
//! swallowed-on-error respectively -- composing over the minimal capability needed rather than
//! depdepending on the concrete `SymbolManager`.

use std::cell::RefCell;
use std::sync::Arc;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::symbol::SymbolDatabaseAdapter;
use crate::program::database::util::RecordFilter;
use crate::program::model::address::AddressSetView;
use crate::program::model::symbol::{Symbol, SymbolIterator};

/// A `RecordIterator` that never yields any records, used in place of the unported
/// `ghidra.program.database.util.EmptyRecordIterator`.
struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> std::io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

/// Iterator (in address order) over all symbols that match the given query in an address set.
///
/// Port of `ghidra.program.database.symbol.AddressSetFilteredSymbolIterator`. See the module docs
/// for what was intentionally left out (`QueryRecordIterator`/`EmptyRecordIterator`, and the
/// `SymbolManager` callbacks, taken as a `resolve` closure instead).
pub struct AddressSetFilteredSymbolIterator<'a> {
    record_iter: RefCell<Box<dyn RecordIterator + 'a>>,
    filter: Box<dyn RecordFilter>,
    resolve: Box<dyn Fn(&DBRecord) -> Option<Arc<dyn Symbol>>>,
    next_symbol: RefCell<Option<Arc<dyn Symbol>>>,
    errored: RefCell<bool>,
}

impl<'a> AddressSetFilteredSymbolIterator<'a> {
    /// Construct a new `AddressSetFilteredSymbolIterator`. `adapter` is the symbol database
    /// adapter to query, `set` is the address set to iterate over (required), `filter` is the
    /// query to use to filter records, `forward` is the direction of the iterator, and `resolve`
    /// resolves a matching record into a [`Symbol`] (standing in for `SymbolManager.getSymbol`).
    ///
    /// Mirrors the Java constructor's fallback: if `adapter.get_symbols_in_set` fails, iteration
    /// proceeds as empty rather than propagating the error (matching `symbolMgr.dbError(e)`
    /// followed by continuing with an `EmptyRecordIterator`).
    pub fn new(
        adapter: &'a dyn SymbolDatabaseAdapter,
        set: &dyn AddressSetView,
        filter: Box<dyn RecordFilter>,
        forward: bool,
        resolve: Box<dyn Fn(&DBRecord) -> Option<Arc<dyn Symbol>>>,
    ) -> Self {
        let record_iter: Box<dyn RecordIterator + 'a> = adapter
            .get_symbols_in_set(set, forward)
            .unwrap_or_else(|_| Box::new(EmptyRecordIterator));
        AddressSetFilteredSymbolIterator {
            record_iter: RefCell::new(record_iter),
            filter,
            resolve,
            next_symbol: RefCell::new(None),
            errored: RefCell::new(false),
        }
    }

    fn find_next(&self) -> bool {
        if *self.errored.borrow() {
            return false;
        }
        let mut iter = self.record_iter.borrow_mut();
        loop {
            match iter.next() {
                Ok(Some(rec)) => {
                    if self.filter.matches(&rec) {
                        if let Some(sym) = (self.resolve)(&rec) {
                            *self.next_symbol.borrow_mut() = Some(sym);
                            return true;
                        }
                    }
                }
                Ok(None) => return false,
                Err(_) => {
                    // Mirrors `symbolMgr.dbError(e)`: report (here, simply stop) rather than
                    // propagate, matching this trait's infallible `has_next`/`next_symbol`.
                    *self.errored.borrow_mut() = true;
                    return false;
                }
            }
        }
    }
}

impl<'a> SymbolIterator for AddressSetFilteredSymbolIterator<'a> {
    fn has_next(&self) -> bool {
        if self.next_symbol.borrow().is_some() {
            return true;
        }
        self.find_next()
    }

    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        if self.has_next() {
            self.next_symbol.borrow_mut().take()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::symbol::symbol_database_adapter::*;
    use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};
    use std::io;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::String],
            vec!["Address".to_string(), "Name".to_string()],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }
    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }
        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    /// A minimal `SymbolDatabaseAdapter` stub that only implements `get_symbols_in_set`
    /// (the only method this iterator calls); all other methods are unreachable in these tests.
    struct StubAdapter {
        records: Vec<DBRecord>,
        fail: bool,
    }

    impl SymbolDatabaseAdapter for StubAdapter {
        fn get_symbols_in_set(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::Other, "boom"));
            }
            Ok(Box::new(VecRecordIterator {
                records: self.records.clone().into_iter(),
            }))
        }

        fn create_symbol_record(
            &self,
            _name: &str,
            _namespace_id: i64,
            _address: &Address,
            _symbol_type: SymbolType,
            _is_primary: bool,
            _source: SourceType,
        ) -> DBRecord {
            unreachable!()
        }
        fn get_symbol_record(&self, _symbol_id: i64) -> io::Result<Option<DBRecord>> {
            unreachable!()
        }
        fn remove_symbol(&mut self, _symbol_id: i64) -> io::Result<()> {
            unreachable!()
        }
        fn has_symbol(&self, _addr: &Address) -> io::Result<bool> {
            unreachable!()
        }
        fn get_symbol_ids(&self, _addr: &Address) -> io::Result<Vec<Field>> {
            unreachable!()
        }
        fn get_symbol_count(&self) -> i32 {
            unreachable!()
        }
        fn get_symbols_by_address(
            &self,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_symbols_by_address_from(
            &self,
            _start_addr: &Address,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn update_symbol_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            unreachable!()
        }
        fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_symbols_in_range(
            &self,
            _start: &Address,
            _end: &Address,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_primary_symbols(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_primary_symbol(&self, _address: &Address) -> io::Result<Option<DBRecord>> {
            unreachable!()
        }
        fn move_address(&mut self, _old_addr: &Address, _new_addr: &Address) -> io::Result<()> {
            unreachable!()
        }
        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<std::collections::BTreeSet<Address>, SymbolDeleteAddressRangeError> {
            unreachable!()
        }
        fn get_symbols_by_namespace(&self, _id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_symbols_by_name(&self, _name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn scan_symbols_by_name(&self, _start_name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_external_symbols_by_original_import_name(
            &self,
            _ext_label: &str,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_external_symbols_by_memory_address(
            &self,
            _ext_prog_addr: &Address,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_symbols_by_name_and_namespace(
            &self,
            _name: &str,
            _id: i64,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            unreachable!()
        }
        fn get_symbol_record_by_address_name_namespace(
            &self,
            _address: &Address,
            _name: &str,
            _namespace_id: i64,
        ) -> io::Result<Option<DBRecord>> {
            unreachable!()
        }
        fn get_max_symbol_address(
            &self,
            _space: &crate::program::model::address::AddressSpace,
        ) -> io::Result<Option<Address>> {
            unreachable!()
        }
        fn get_table(&self) -> std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>> {
            unreachable!()
        }
    }

    struct NameStartsWithFilter(&'static str);
    impl RecordFilter for NameStartsWithFilter {
        fn matches(&self, record: &DBRecord) -> bool {
            record.get_string(1).map(|n| n.starts_with(self.0)).unwrap_or(false)
        }
    }

    fn record(key: i64, addr: i64, name: &str) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_long(0, addr);
        rec.set_string(1, Some(name.to_string()));
        rec
    }

    fn resolver() -> Box<dyn Fn(&DBRecord) -> Option<Arc<dyn Symbol>>> {
        Box::new(|rec: &DBRecord| {
            let name = rec.get_string(1)?.to_string();
            let address = rec.get_long(0)?;
            Some(Arc::new(TestSymbol { name, address: addr(address) }) as Arc<dyn Symbol>)
        })
    }

    struct TestSymbol {
        name: String,
        address: Address,
    }
    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    #[test]
    fn filters_and_resolves_matching_records() {
        let adapter = StubAdapter {
            records: vec![
                record(1, 0x1000, "foo_a"),
                record(2, 0x2000, "bar_b"),
                record(3, 0x3000, "foo_c"),
            ],
            fail: false,
        };
        let set = AddressSet::new();

        let mut iter = AddressSetFilteredSymbolIterator::new(
            &adapter,
            &set,
            Box::new(NameStartsWithFilter("foo_")),
            true,
            resolver(),
        );

        let mut names = Vec::new();
        while iter.has_next() {
            names.push(iter.next_symbol().unwrap().get_name().to_string());
        }
        assert_eq!(names, vec!["foo_a", "foo_c"]);
    }

    #[test]
    fn adapter_failure_yields_empty_iteration() {
        let adapter = StubAdapter {
            records: Vec::new(),
            fail: true,
        };
        let set = AddressSet::new();

        let mut iter = AddressSetFilteredSymbolIterator::new(
            &adapter,
            &set,
            Box::new(NameStartsWithFilter("foo_")),
            true,
            resolver(),
        );

        assert!(!iter.has_next());
        assert!(iter.next_symbol().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter = StubAdapter {
            records: vec![record(1, 0x1000, "only")],
            fail: false,
        };
        let set = AddressSet::new();

        let mut iter: Box<dyn SymbolIterator + '_> = Box::new(AddressSetFilteredSymbolIterator::new(
            &adapter,
            &set,
            Box::new(NameStartsWithFilter("")),
            true,
            resolver(),
        ));
        assert_eq!(iter.next_symbol().unwrap().get_name(), "only");
        assert!(!iter.has_next());
    }
}
