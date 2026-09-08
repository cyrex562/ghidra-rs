//! Port of `ghidra.program.database.code.DataKeyIterator`.
//!
//! Java's constructor is `DataKeyIterator(CodeManager codeMgr, AddressMap addrMap, DBLongIterator
//! it)`, and each key is resolved via the package-private `CodeManager.getDataAt(Address, long)`,
//! which is itself just `cache.getCachedInstance(addr)` filtered to `DataDB` results (i.e. the
//! *raw-key* cache overload -- see the "What could not be ported" section of
//! [`CodeUnitCache`](super::code_unit_cache::CodeUnitCache)'s module docs for why that overload
//! is not implementable here without the not-yet-ported concrete `CodeManagerDB`).
//!
//! This class, however, has no callers anywhere in the Ghidra source tree this port is checked
//! against (confirmed by search; the similarly-named `DataKeyIterator` inner class in
//! `DataTableModel.java` is unrelated). Its only sensible source of raw keys, given it lives
//! beside [`DataDBAdapter`](super::data_db_adapter::DataDBAdapter) in this same package, is that
//! adapter's own [`DataDBAdapter::get_keys`]/`get_keys_in_range` -- i.e. keys already known to
//! belong to the data table. Under that (only plausible) reading, `codeMgr.getDataAt(address,
//! addr)`'s raw-key factory would always resolve via `dataAdapter.getRecord(addr)` succeeding
//! (never falling through to the instruction table or `instantiateUndefinedOrExternalData`, both
//! of which only fire for a key with *no* data-table record). This port therefore takes a
//! [`DataDBAdapter`] plus a [`CodeUnitCache`] directly and looks the record up by key -- the exact
//! same `get_data(record)` cache path [`DataRecordIterator`](super::data_record_iterator::DataRecordIterator)
//! uses -- rather than routing through the unported raw-key overload. For every key that source
//! can actually produce, the two are observably identical; for a key with no data-table record
//! this returns `None` for it (skips it) exactly as Java's `getDataAt` would too (its result would
//! fail the `instanceof DataDB` check either way, whether the raw key resolved to an
//! `InstructionDB` or to nothing at all).

use crate::program::database::code::code_unit_cache::CodeUnitCache;
use crate::program::database::code::data_db::DataDb;
use crate::program::database::code::data_db_adapter::DataDBAdapter;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::data_iterator::DataIterator;
use crate::program::seam_stubs::AddressKeyIteratorLike;
use std::sync::Arc;

/// Converts a [`AddressKeyIteratorLike`] (Java's `DBLongIterator`) into a `DataIterator`.
///
/// Port of `ghidra.program.database.code.DataKeyIterator`. See the module docs for the
/// construction-parameter deviation forced by the unported raw-key `CodeUnitCache` overload.
pub struct DataKeyIterator<'a> {
    cache: Arc<CodeUnitCache>,
    adapter: &'a dyn DataDBAdapter,
    it: Box<dyn AddressKeyIteratorLike>,
}

impl<'a> DataKeyIterator<'a> {
    /// Constructs a new `DataKeyIterator`.
    ///
    /// # Arguments
    /// * `cache` - the code unit cache used to resolve (and share) `DataDB` instances
    /// * `adapter` - the data table adapter `it`'s keys are drawn from
    /// * `it` - the raw key iterator
    pub fn new(
        cache: Arc<CodeUnitCache>,
        adapter: &'a dyn DataDBAdapter,
        it: Box<dyn AddressKeyIteratorLike>,
    ) -> Self {
        DataKeyIterator { cache, adapter, it }
    }
}

impl<'a> Iterator for DataKeyIterator<'a> {
    type Item = Box<dyn Data>;

    /// Port of the private `DataKeyIterator.findNext()`.
    fn next(&mut self) -> Option<Self::Item> {
        while self.it.has_next() {
            let key = self.it.next()?;
            let Ok(Some(record)) = self.adapter.get_record_by_key(key) else {
                continue;
            };
            if let Some(data) = self.cache.get_data(&record) {
                return Some(data.to_boxed_data());
            }
        }
        None
    }
}

impl<'a> DataIterator for DataKeyIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::code::code_unit_owner::CodeUnitOwner;
    use crate::program::database::code::data_db_adapter::DATA_TYPE_ID_COL;
    use crate::program::database::code::test_support::{TestCodeUnitOwner, TestDataType};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use std::collections::BTreeMap;
    use std::io;

    struct VecKeyIterator {
        keys: Vec<i64>,
        pos: usize,
    }

    impl VecKeyIterator {
        fn new(keys: Vec<i64>) -> Self {
            VecKeyIterator { keys, pos: 0 }
        }
    }

    impl AddressKeyIteratorLike for VecKeyIterator {
        fn has_next(&mut self) -> bool {
            self.pos < self.keys.len()
        }
        fn has_previous(&mut self) -> bool {
            false
        }
        fn next(&mut self) -> Option<i64> {
            if self.pos < self.keys.len() {
                let v = self.keys[self.pos];
                self.pos += 1;
                Some(v)
            } else {
                None
            }
        }
        fn previous(&mut self) -> Option<i64> {
            None
        }
    }

    /// A `DataDBAdapter` that answers `get_record_by_key` from a fixed map; every other method is
    /// unreachable from this test.
    struct MapBackedDataDBAdapter {
        records: BTreeMap<i64, crate::framework::db::DBRecord>,
    }

    impl DataDBAdapter for MapBackedDataDBAdapter {
        fn get_record_at_or_after(&self, _start: &Address) -> io::Result<Option<crate::framework::db::DBRecord>> {
            unimplemented!("not exercised by this test")
        }
        fn get_record_after(&self, _start: &Address) -> io::Result<Option<crate::framework::db::DBRecord>> {
            unimplemented!("not exercised by this test")
        }
        fn get_record(&self, _start: &Address) -> io::Result<Option<crate::framework::db::DBRecord>> {
            unimplemented!("not exercised by this test")
        }
        fn get_record_by_key(&self, key: i64) -> io::Result<Option<crate::framework::db::DBRecord>> {
            Ok(self.records.get(&key).cloned())
        }
        fn get_record_before(&self, _addr: &Address) -> io::Result<Option<crate::framework::db::DBRecord>> {
            unimplemented!("not exercised by this test")
        }
        fn get_records_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by this test")
        }
        fn get_records_in_range(
            &self,
            _start: &Address,
            _end: &Address,
            _at_start: bool,
        ) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by this test")
        }
        fn delete_record(&mut self, _key: i64) -> io::Result<()> {
            unimplemented!("not exercised by this test")
        }
        fn create_data(&mut self, _addr: &Address, _data_type_id: i64) -> io::Result<crate::framework::db::DBRecord> {
            unimplemented!("not exercised by this test")
        }
        fn get_record_count(&self) -> io::Result<i32> {
            Ok(self.records.len() as i32)
        }
        fn get_record_at_or_before(&self, _addr: &Address) -> io::Result<Option<crate::framework::db::DBRecord>> {
            unimplemented!("not exercised by this test")
        }
        fn get_keys_in_range(
            &self,
            _start: &Address,
            _end: &Address,
            _at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            unimplemented!("not exercised by this test")
        }
        fn get_records(&self) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by this test")
        }
        fn delete_records(&mut self, _start: &Address, _end: &Address) -> io::Result<bool> {
            unimplemented!("not exercised by this test")
        }
        fn put_record(&mut self, _record: &crate::framework::db::DBRecord) -> io::Result<()> {
            unimplemented!("not exercised by this test")
        }
        fn get_keys(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            unimplemented!("not exercised by this test")
        }
        fn get_records_in_set(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by this test")
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: i64,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::program::database::code::data_db_adapter::MoveAddressRangeError> {
            unimplemented!("not exercised by this test")
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn owner() -> (Arc<TestCodeUnitOwner>, Arc<dyn CodeUnitOwner>) {
        let owner = Arc::new(TestCodeUnitOwner::new(space(), 0x1000, vec![0u8; 0x100]));
        let dynamic: Arc<dyn CodeUnitOwner> = owner.clone();
        (owner, dynamic)
    }

    fn data_record(addr: i64) -> crate::framework::db::DBRecord {
        use crate::framework::db::Field;
        let mut record = crate::framework::db::DBRecord::new(
            crate::program::database::code::data_db_adapter::schema(),
            Field::Long(Some(addr)),
        );
        record.set_field(DATA_TYPE_ID_COL, Field::Long(Some(0)));
        record
    }

    #[test]
    fn resolves_each_key_to_its_data_and_skips_keys_with_no_record() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x1000, Arc::new(TestDataType::fixed("dword", 4)));
        test_owner.set_data_type_at(0x1010, Arc::new(TestDataType::fixed("byte", 1)));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));

        let mut records = BTreeMap::new();
        records.insert(0x1000, data_record(0x1000));
        records.insert(0x1010, data_record(0x1010));
        let adapter = MapBackedDataDBAdapter { records };

        // 0x1008 has no data-table record and must be skipped, just like Java's getDataAt would
        // fail its `instanceof DataDB` check for a non-data key.
        let keys = VecKeyIterator::new(vec![0x1000, 0x1008, 0x1010]);

        let mut iter = DataKeyIterator::new(cache, &adapter, Box::new(keys));
        let first = iter.next().expect("0x1000 should resolve");
        assert_eq!(first.get_min_address(), space().address(0x1000));
        let second = iter.next().expect("0x1010 should resolve");
        assert_eq!(second.get_min_address(), space().address(0x1010));
        assert!(iter.next().is_none());
    }

    #[test]
    fn does_not_materialize_full_data_for_keys_that_are_never_consumed() {
        // Prove the iterator is lazy: only pulling the first item must not have touched the
        // second key's record at all, i.e. nothing was ever cached for it.
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x2000, Arc::new(TestDataType::fixed("dword", 4)));
        test_owner.set_data_type_at(0x2010, Arc::new(TestDataType::fixed("byte", 1)));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));

        let mut records = BTreeMap::new();
        records.insert(0x2000, data_record(0x2000));
        records.insert(0x2010, data_record(0x2010));
        let adapter = MapBackedDataDBAdapter { records };
        let keys = VecKeyIterator::new(vec![0x2000, 0x2010]);

        let mut iter = DataKeyIterator::new(cache.clone(), &adapter, Box::new(keys));
        let _first = iter.next().expect("first key");
        assert_eq!(cache.size(), 1, "only the consumed key should have been instantiated");
    }

    #[test]
    fn empty_when_no_keys_resolve() {
        let (_test_owner, dyn_owner) = owner();
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let adapter = MapBackedDataDBAdapter {
            records: BTreeMap::new(),
        };
        let keys = VecKeyIterator::new(vec![0x1000]);

        let mut iter = DataKeyIterator::new(cache, &adapter, Box::new(keys));
        assert!(iter.next().is_none());
    }
}
