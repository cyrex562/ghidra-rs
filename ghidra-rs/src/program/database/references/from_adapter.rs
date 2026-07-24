//! Port of `ghidra.program.database.references.FromAdapter`.
//!
//! `FromAdapter` is the abstract "from address" reference-storage adapter: for each source
//! address that has at least one outgoing reference, it stores a [`RefList`] (encoded reference
//! data) keyed by that address's database key. Concrete Java subclasses (`FromAdapterV0`,
//! `FromAdapterSharedTable`) implement the actual table format and are not ported here.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait
//! rather than a concrete struct. Its abstract instance API — `getRecordCount`/`createRefList`/
//! `getRefList`/`hasRefFrom`/the three `getFromIterator` overloads — maps directly to trait
//! methods, following the same convention already used for
//! [`ToAdapter`](crate::program::database::references::ToAdapter).
//!
//! Not ported here: the static factory (`getAdapter`/`findReadOnlyAdapter`/`upgrade`), since it
//! only ever constructs and migrates between the concrete, not-yet-ported subclasses above — the
//! same convention already used for `ToAdapter`. The `FROM_REFS_TABLE_NAME`/`FROM_REFS_SCHEMA`/
//! column-index constants are likewise left for whichever concrete subclass is ported first,
//! since they describe that subclass's own table layout rather than the trait's dynamic-dispatch
//! surface.

use std::io;

use crate::program::database::references::{RecordAdapter, RefList};
use crate::program::database::ProgramDB;
use crate::program::model::address::{Address, AddressIterator, AddressSetView};

/// Adapter storing, per source address, the list of references that originate from it.
///
/// Port of `ghidra.program.database.references.FromAdapter`. See the module docs for what was
/// intentionally left out (the static factory and table-layout constants).
pub trait FromAdapter: RecordAdapter {
    /// Stands in for `FromAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Creates a new, empty reference list for `from_addr` and stores it.
    ///
    /// Stands in for `FromAdapter.createRefList(ProgramDB, Address)`. `program` mirrors the Java
    /// parameter's nullability (some call sites pass `null`).
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_ref_list(
        &mut self,
        program: Option<&ProgramDB>,
        from_addr: &Address,
    ) -> io::Result<Box<dyn RefList>>;

    /// Gets the existing reference list for `from`, or `None` if `from` has no outgoing
    /// references.
    ///
    /// Stands in for `FromAdapter.getRefList(ProgramDB, Address, long)`. `program` mirrors the
    /// Java parameter's nullability (some call sites pass `null`).
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_ref_list(
        &self,
        program: Option<&ProgramDB>,
        from: &Address,
        from_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>>;

    /// Stands in for `FromAdapter.hasRefFrom(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn has_ref_from(&self, from_addr: i64) -> io::Result<bool>;

    /// Stands in for `FromAdapter.getFromIterator(boolean)`: iterates over every "from" address
    /// that has a stored reference list, in address order (ascending if `forward`).
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_from_iterator(&self, forward: bool) -> io::Result<Box<dyn AddressIterator>>;

    /// Stands in for `FromAdapter.getFromIterator(Address, boolean)`: like
    /// [`Self::get_from_iterator`], starting at (and including) `start_addr`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_from_iterator_from(
        &self,
        start_addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn AddressIterator>>;

    /// Stands in for `FromAdapter.getFromIterator(AddressSetView, boolean)`: like
    /// [`Self::get_from_iterator`], restricted to addresses contained in `set`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_from_iterator_in_set(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn AddressIterator>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field, FieldType, Schema};
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::references::EmptyMemReferenceIterator;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::symbol::{RefType, Reference, ReferenceIterator, SourceType};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// An opaque stand-in: `FromAdapter` only ever constructs and returns a `RefList`, it never
    /// inspects one, so this mock tracks just enough (`from`-address offsets) to prove round-trip
    /// storage without needing a real reference-list implementation.
    struct MockRefList {
        refs: Vec<i64>,
        state: DbObjectState,
    }

    impl MockRefList {
        fn new() -> Self {
            MockRefList {
                refs: Vec::new(),
                state: DbObjectState::new(0),
            }
        }
    }

    impl DbObject for MockRefList {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockRefList {
        fn add_ref(
            &mut self,
            from_addr: &Address,
            _to_addr: &Address,
            _ref_type: RefType,
            _op_index: i32,
            _symbol_id: i64,
            _is_primary: bool,
            _source: SourceType,
            _is_offset: bool,
            _is_shift: bool,
            _offset_or_shift: i64,
        ) -> io::Result<()> {
            self.refs.push(from_addr.offset());
            Ok(())
        }

        fn update_ref_type(
            &mut self,
            _addr: &Address,
            _op_index: i32,
            _ref_type: RefType,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_ref(&self, _address: &Address, _op_index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn remove_ref(&mut self, addr: &Address, _op_index: i32) -> io::Result<bool> {
            let before = self.refs.len();
            self.refs.retain(|offset| *offset != addr.offset());
            Ok(self.refs.len() != before)
        }

        fn is_empty(&self) -> bool {
            self.refs.is_empty()
        }

        fn set_primary(&mut self, _reference: &dyn Reference, _is_primary: bool) -> io::Result<bool> {
            Ok(false)
        }

        fn get_refs(&self) -> Box<dyn ReferenceIterator> {
            Box::new(EmptyMemReferenceIterator)
        }

        fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_num_refs(&self) -> i32 {
            self.refs.len() as i32
        }

        fn get_primary_ref(&self, _op_index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn remove_all(&mut self) -> io::Result<()> {
            self.refs.clear();
            Ok(())
        }

        fn set_symbol_id(&mut self, _reference: &dyn Reference, _symbol_id: i64) -> io::Result<bool> {
            Ok(false)
        }

        fn has_reference(&self, _op_index: i32) -> bool {
            !self.refs.is_empty()
        }

        fn get_reference_level(&self) -> i8 {
            -1
        }
    }

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["NumRefs".to_string()],
            vec![],
        ))
    }

    fn space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockFromAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        ref_lists: HashMap<i64, MockRefList>,
    }

    impl MockFromAdapter {
        fn new() -> Self {
            MockFromAdapter {
                schema: test_schema(),
                records: HashMap::new(),
                ref_lists: HashMap::new(),
            }
        }
    }

    impl RecordAdapter for MockFromAdapter {
        fn create_record(
            &mut self,
            key: i64,
            num_refs: i32,
            _ref_level: u8,
            _ref_data: &[u8],
        ) -> io::Result<DBRecord> {
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_int(0, num_refs);
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "record not found"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            Ok(())
        }
    }

    impl FromAdapter for MockFromAdapter {
        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn create_ref_list(
            &mut self,
            _program: Option<&ProgramDB>,
            from_addr: &Address,
        ) -> io::Result<Box<dyn RefList>> {
            let key = from_addr.offset();
            self.ref_lists.insert(key, MockRefList::new());
            Ok(Box::new(MockRefList::new()))
        }

        fn get_ref_list(
            &self,
            _program: Option<&ProgramDB>,
            from: &Address,
            _from_addr: i64,
        ) -> io::Result<Option<Box<dyn RefList>>> {
            let key = from.offset();
            Ok(self.ref_lists.get(&key).map(|list| {
                let mut cloned = MockRefList::new();
                cloned.refs = list.refs.clone();
                Box::new(cloned) as Box<dyn RefList>
            }))
        }

        fn has_ref_from(&self, from_addr: i64) -> io::Result<bool> {
            Ok(self.ref_lists.contains_key(&from_addr))
        }

        fn get_from_iterator(&self, forward: bool) -> io::Result<Box<dyn AddressIterator>> {
            let mut keys: Vec<i64> = self.ref_lists.keys().copied().collect();
            keys.sort_unstable();
            if !forward {
                keys.reverse();
            }
            let addrs: Vec<Address> = keys.into_iter().map(addr).collect();
            Ok(Box::new(
                crate::program::model::address::AddressIteratorAdapter::from_vec(addrs),
            ))
        }

        fn get_from_iterator_from(
            &self,
            start_addr: &Address,
            forward: bool,
        ) -> io::Result<Box<dyn AddressIterator>> {
            let start = start_addr.offset();
            let mut keys: Vec<i64> = self
                .ref_lists
                .keys()
                .copied()
                .filter(|k| if forward { *k >= start } else { *k <= start })
                .collect();
            keys.sort_unstable();
            if !forward {
                keys.reverse();
            }
            let addrs: Vec<Address> = keys.into_iter().map(addr).collect();
            Ok(Box::new(
                crate::program::model::address::AddressIteratorAdapter::from_vec(addrs),
            ))
        }

        fn get_from_iterator_in_set(
            &self,
            set: &dyn AddressSetView,
            forward: bool,
        ) -> io::Result<Box<dyn AddressIterator>> {
            let mut keys: Vec<i64> = self
                .ref_lists
                .keys()
                .copied()
                .filter(|k| set.contains(&addr(*k)))
                .collect();
            keys.sort_unstable();
            if !forward {
                keys.reverse();
            }
            let addrs: Vec<Address> = keys.into_iter().map(addr).collect();
            Ok(Box::new(
                crate::program::model::address::AddressIteratorAdapter::from_vec(addrs),
            ))
        }
    }

    #[test]
    fn create_and_lookup_ref_list_round_trip() {
        let mut adapter = MockFromAdapter::new();
        let from = addr(0x1000);

        adapter.create_ref_list(None, &from).unwrap();
        assert!(adapter.has_ref_from(0x1000).unwrap());
        assert!(adapter
            .get_ref_list(None, &from, 0x1000)
            .unwrap()
            .is_some());

        let missing = addr(0x2000);
        assert!(!adapter.has_ref_from(0x2000).unwrap());
        assert!(adapter
            .get_ref_list(None, &missing, 0x2000)
            .unwrap()
            .is_none());
    }

    #[test]
    fn from_iterator_visits_addresses_in_order() {
        let mut adapter = MockFromAdapter::new();
        adapter.create_ref_list(None, &addr(0x300)).unwrap();
        adapter.create_ref_list(None, &addr(0x100)).unwrap();
        adapter.create_ref_list(None, &addr(0x200)).unwrap();

        let mut iter = adapter.get_from_iterator(true).unwrap();
        let mut seen = Vec::new();
        while iter.has_next() {
            seen.push(iter.next_address().unwrap().offset());
        }
        assert_eq!(seen, vec![0x100, 0x200, 0x300]);

        let mut rev = adapter.get_from_iterator(false).unwrap();
        let mut seen_rev = Vec::new();
        while rev.has_next() {
            seen_rev.push(rev.next_address().unwrap().offset());
        }
        assert_eq!(seen_rev, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn object_safety_via_trait_object() {
        let adapter: Box<dyn FromAdapter> = Box::new(MockFromAdapter::new());
        let mut adapter = adapter;
        assert_eq!(adapter.get_record_count(), 0);
        adapter.create_ref_list(None, &addr(0x42)).unwrap();
        assert!(adapter.has_ref_from(0x42).unwrap());
    }
}
