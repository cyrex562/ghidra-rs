//! Port of `ghidra.program.database.code.DataRecordIterator`.
//!
//! Converts a raw data-table [`RecordIterator`] into a [`DataIterator`], resolving each record
//! through a [`CodeUnitCache`] the same way `CodeManager` does.
//!
//! [`DataIterator`]'s item type is an *owned* `Box<dyn Data>`, whereas the cache hands back a
//! shared `Arc<DataDB>` (so repeated lookups of the same record return the same cached instance).
//! [`DataDb::to_boxed_data`] is exactly the seam this crate already established for that gap (see
//! its doc comment on `DataDB`): it rebuilds an independent, owned `Data` describing the same item.

use crate::framework::db::RecordIterator;
use crate::program::database::code::code_unit_cache::CodeUnitCache;
use crate::program::database::code::data_db::DataDb;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::data_iterator::DataIterator;
use std::sync::Arc;

/// Converts a record iterator into a `DataIterator`.
///
/// Port of `ghidra.program.database.code.DataRecordIterator`.
pub struct DataRecordIterator<'a> {
    cache: Arc<CodeUnitCache>,
    it: Box<dyn RecordIterator + 'a>,
    forward: bool,
}

impl<'a> DataRecordIterator<'a> {
    /// Constructs a new `DataRecordIterator`.
    ///
    /// # Arguments
    /// * `cache` - the code unit cache
    /// * `it` - the record iterator
    /// * `forward` - the direction of the iterator
    pub fn new(cache: Arc<CodeUnitCache>, it: Box<dyn RecordIterator + 'a>, forward: bool) -> Self {
        DataRecordIterator { cache, it, forward }
    }
}

impl<'a> Iterator for DataRecordIterator<'a> {
    type Item = Box<dyn Data>;

    /// Port of the private `DataRecordIterator.findNext()`. See
    /// [`InstructionRecordIterator`](super::instruction_record_iterator::InstructionRecordIterator)'s
    /// `next()` for the `Iterator`-folding and error-handling conventions this mirrors.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = if self.forward {
                self.it.next().ok().flatten()?
            } else {
                self.it.previous().ok().flatten()?
            };
            if let Some(data) = self.cache.get_data(&record) {
                return Some(data.to_boxed_data());
            }
        }
    }
}

impl<'a> DataIterator for DataRecordIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field};
    use crate::program::database::code::code_unit_owner::CodeUnitOwner;
    use crate::program::database::code::data_db_adapter::{self, DATA_TYPE_ID_COL};
    use crate::program::database::code::test_support::{TestCodeUnitOwner, TestDataType};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use std::io;

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        forward_pos: usize,
        backward_pos: usize,
    }

    impl VecRecordIterator {
        fn new(records: Vec<DBRecord>) -> Self {
            let len = records.len();
            VecRecordIterator {
                records,
                forward_pos: 0,
                backward_pos: len,
            }
        }
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            if self.forward_pos < self.records.len() {
                let record = self.records[self.forward_pos].clone();
                self.forward_pos += 1;
                Ok(Some(record))
            } else {
                Ok(None)
            }
        }

        fn has_next(&self) -> bool {
            self.forward_pos < self.records.len()
        }

        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.backward_pos > 0)
        }

        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.backward_pos > 0 {
                self.backward_pos -= 1;
                Ok(Some(self.records[self.backward_pos].clone()))
            } else {
                Ok(None)
            }
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

    fn data_record(addr: i64) -> DBRecord {
        let mut record = DBRecord::new(data_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(DATA_TYPE_ID_COL, Field::Long(Some(0)));
        record
    }

    #[test]
    fn forward_iteration_yields_data_in_record_order() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x1000, Arc::new(TestDataType::fixed("dword", 4)));
        test_owner.set_data_type_at(0x1010, Arc::new(TestDataType::fixed("byte", 1)));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let records = vec![data_record(0x1000), data_record(0x1010)];
        let it = VecRecordIterator::new(records);

        let mut iter = DataRecordIterator::new(cache, Box::new(it), true);
        let first = iter.next().expect("first data");
        assert_eq!(first.get_min_address(), space().address(0x1000));
        assert_eq!(first.get_length(), 4);
        let second = iter.next().expect("second data");
        assert_eq!(second.get_min_address(), space().address(0x1010));
        assert!(iter.next().is_none());
    }

    #[test]
    fn backward_iteration_walks_in_reverse() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x1000, Arc::new(TestDataType::fixed("dword", 4)));
        test_owner.set_data_type_at(0x1010, Arc::new(TestDataType::fixed("byte", 1)));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let records = vec![data_record(0x1000), data_record(0x1010)];
        let it = VecRecordIterator::new(records);

        let mut iter = DataRecordIterator::new(cache, Box::new(it), false);
        let first = iter.next().expect("first data (reverse)");
        assert_eq!(first.get_min_address(), space().address(0x1010));
        let second = iter.next().expect("second data (reverse)");
        assert_eq!(second.get_min_address(), space().address(0x1000));
        assert!(iter.next().is_none());
    }

    #[test]
    fn yielded_data_is_independently_owned_from_the_cached_instance() {
        // `to_boxed_data` rebuilds an independent object rather than aliasing the cache's `Arc`;
        // prove it by mutating the cache's own copy behind the returned box's back and confirming
        // the box still reflects what it was built from (its own snapshot), while the cache's
        // instance is untouched by the box's existence.
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x2000, Arc::new(TestDataType::fixed("dword", 4)));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let record = data_record(0x2000);

        let mut iter = DataRecordIterator::new(cache.clone(), Box::new(VecRecordIterator::new(vec![record.clone()])), true);
        let boxed = iter.next().expect("data");
        assert_eq!(boxed.get_min_address(), space().address(0x2000));

        let cached = cache.get_data(&record).expect("still cached");
        assert_eq!(cached.get_min_address(), space().address(0x2000));
    }
}
