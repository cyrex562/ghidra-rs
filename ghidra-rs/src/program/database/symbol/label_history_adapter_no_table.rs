//! Port of `ghidra.program.database.symbol.LabelHistoryAdapterNoTable`.
//!
//! Adapter needed when a program is being opened read-only and the label history table does not
//! exist in the program.

use std::collections::BTreeSet;
use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::map::AddressMap;
use crate::program::database::symbol::label_history_adapter::LabelHistoryRangeError;
use crate::program::database::symbol::LabelHistoryAdapter;
use crate::program::model::address::Address;
use crate::util::task::TaskMonitor;

/// A `RecordIterator` that never yields any records, used in place of the unported
/// `ghidra.program.database.util.EmptyRecordIterator`, mirroring the convention already used by
/// e.g. [`VariableStorageDBAdapterNoTable`](crate::program::database::symbol::VariableStorageDBAdapterNoTable).
struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

/// Adapter needed when a program is being opened read-only and the label history table does not
/// exist in the program.
///
/// Port of `ghidra.program.database.symbol.LabelHistoryAdapterNoTable`.
#[derive(Debug, Default)]
pub struct LabelHistoryAdapterNoTable;

impl LabelHistoryAdapterNoTable {
    /// Constructs a new adapter. The Java constructor takes a `DBHandle` argument but never uses
    /// it, so this port takes none.
    pub fn new() -> Self {
        LabelHistoryAdapterNoTable
    }
}

impl LabelHistoryAdapter for LabelHistoryAdapterNoTable {
    fn create_record(&mut self, _addr: i64, _action_id: i8, _label_str: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no label history table exists",
        ))
    }

    fn get_records_by_address(&self, _addr: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_record_count(&self) -> i32 {
        0
    }

    fn move_address(&mut self, _old_addr: i64, _new_addr: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no label history table exists",
        ))
    }

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: i64,
        _addr_map: &dyn AddressMap,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError> {
        Err(LabelHistoryRangeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "no label history table exists",
        )))
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _addr_map: &dyn AddressMap,
        _do_not_delete: Option<&BTreeSet<Address>>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError> {
        Err(LabelHistoryRangeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "no label history table exists",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn lookups_are_empty_or_zero() {
        let adapter = LabelHistoryAdapterNoTable::new();
        assert_eq!(adapter.get_record_count(), 0);

        let mut iter = adapter.get_all_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());

        let mut iter = adapter.get_records_by_address(0x1000).unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn mutations_are_unsupported() {
        let mut adapter = LabelHistoryAdapterNoTable::new();
        assert_eq!(
            adapter.create_record(0x1000, 0, "foo").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.move_address(0x1000, 0x2000).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut adapter: Box<dyn LabelHistoryAdapter> = Box::new(LabelHistoryAdapterNoTable::new());
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.create_record(0, 0, "x").is_err());

        struct NoopAddressMap {
            base: Address,
        }
        impl AddressMap for NoopAddressMap {
            fn get_key(&self, _addr: &Address, _create: bool) -> i64 {
                0
            }
            fn get_absolute_encoding(&self, _addr: &Address, _create: bool) -> i64 {
                0
            }
            fn find_key_range(
                &self,
                _key_range_list: &[crate::program::model::address::KeyRange],
                _addr: Option<&Address>,
            ) -> i32 {
                -1
            }
            fn decode_address(&self, _value: i64) -> Address {
                self.base.clone()
            }
            fn get_address_factory(
                &self,
            ) -> Option<std::sync::Arc<dyn crate::program::model::address::AddressFactory>> {
                None
            }
            fn get_key_ranges_absolute(
                &self,
                _start: &Address,
                _end: &Address,
                _absolute: bool,
                _create: bool,
            ) -> Vec<crate::program::model::address::KeyRange> {
                Vec::new()
            }
            fn get_key_ranges_for_set_absolute(
                &self,
                _set: Option<&dyn crate::program::model::address::AddressSetView>,
                _absolute: bool,
                _create: bool,
            ) -> Vec<crate::program::model::address::KeyRange> {
                Vec::new()
            }
            fn get_old_address_map(&self) -> Box<dyn AddressMap> {
                Box::new(NoopAddressMap {
                    base: self.base.clone(),
                })
            }
            fn is_upgraded(&self) -> bool {
                false
            }
            fn get_image_base(&self) -> Address {
                self.base.clone()
            }
        }

        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        );
        let addr_map = NoopAddressMap {
            base: space.address(0),
        };
        let result = adapter.move_address_range(
            &space.address(0),
            &space.address(0x100),
            0x10,
            &addr_map,
            &DummyMonitor,
        );
        assert!(result.is_err());
    }
}
