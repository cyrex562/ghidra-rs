//! Port of `ghidra.program.database.reloc.RelocationDBAdapterNoTable`.
//!
//! A stub for programs created before any relocations table existed at all. Its constructor is
//! only satisfied when *no* `"Relocations"` table is present -- that is the whole point of this
//! version: it is the unconditional final fallback `find_read_only_adapter` reaches after every
//! real historical schema (`V1`..`V5`) fails to open (see `relocation_db_adapter.rs`'s module
//! docs), so if a table *does* exist but doesn't match any recognized schema, this constructor's
//! own failure is what ultimately surfaces to the caller.
//!
//! [`RelocationDBAdapter::add`] returns an `io::ErrorKind::Unsupported` error, and
//! [`RelocationDBAdapter::adapt_record`] unconditionally panics -- both mirror Java's
//! `UnsupportedOperationException`s (the latter is an infallible `DBRecord -> DBRecord` signature
//! with no `Result` to carry an error through, so a `panic!` is this port's closest honest
//! equivalent to Java's unconditional throw; see `RelocationDbAdapterV6`'s module docs for the
//! same reasoning applied to its own unconditionally-throwing `adaptRecord`). Since
//! [`RelocationDBAdapter::get_record_count`] is always `0` and every iterator is always empty,
//! `adapt_record` should never actually be reachable in practice.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, RecordIterator};
use crate::program::database::reloc::relocation_db_adapter::{RelocationDBAdapter, TABLE_NAME};
use crate::program::database::util::empty_record_iterator::EmptyRecordIterator;
use crate::program::model::address::{Address, AddressSetView};
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterNoTable.VERSION`.
pub const VERSION: i32 = 0;

/// A stub for a time when we did not produce relocations tables.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterNoTable`.
pub struct RelocationDbAdapterNoTable;

impl RelocationDbAdapterNoTable {
    /// Constructs the no-table adapter.
    ///
    /// Port of `RelocationDBAdapterNoTable(DBHandle)`.
    ///
    /// # Errors
    /// Returns a non-upgradeable [`VersionException`] if a `"Relocations"` table actually exists
    /// (this version's whole point is that one does not).
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        if handle.get_table(TABLE_NAME).is_some() {
            return Err(VersionException::new());
        }
        Ok(RelocationDbAdapterNoTable)
    }
}

impl RelocationDBAdapter for RelocationDbAdapterNoTable {
    fn add(
        &mut self,
        _addr: &Address,
        _flags: u8,
        _type_: i32,
        _values: &[i64],
        _bytes: Option<&[u8]>,
        _symbol_name: Option<&str>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RelocationDBAdapterNoTable has no relocations table",
        ))
    }

    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator::new()))
    }

    fn iterator_in_set(&self, _set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator::new()))
    }

    fn iterator_from(&self, _start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator::new()))
    }

    fn get_record_count(&self) -> i32 {
        0
    }

    fn adapt_record(&self, _rec: DBRecord) -> DBRecord {
        panic!("RelocationDBAdapterNoTable.adaptRecord: no schema to adapt from");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[test]
    fn construction_succeeds_when_no_relocations_table_exists() {
        let handle = DBHandle::new().unwrap();
        assert!(RelocationDbAdapterNoTable::new(&handle).is_ok());
    }

    #[test]
    fn construction_fails_as_non_upgradeable_when_a_table_exists() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                TABLE_NAME.to_string(),
                Arc::new(Schema::new(1, FieldType::Long, "Address".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        match RelocationDbAdapterNoTable::new(&handle) {
            Err(e) => assert!(!e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn add_is_unsupported() {
        let handle = DBHandle::new().unwrap();
        let mut adapter = RelocationDbAdapterNoTable::new(&handle).unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let err = adapter.add(&space.address(0), 0, 0, &[], None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn every_iterator_is_empty_and_count_is_zero() {
        let handle = DBHandle::new().unwrap();
        let adapter = RelocationDbAdapterNoTable::new(&handle).unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);

        assert_eq!(adapter.get_record_count(), 0);
        assert!(!adapter.iterator().unwrap().has_next());
        let set = AddressSet::from_start_end(space.address(0), space.address(0x1000));
        assert!(!adapter.iterator_in_set(&set).unwrap().has_next());
        assert!(!adapter.iterator_from(&space.address(0)).unwrap().has_next());
    }

    #[test]
    #[should_panic(expected = "no schema to adapt from")]
    fn adapt_record_panics() {
        let handle = DBHandle::new().unwrap();
        let adapter = RelocationDbAdapterNoTable::new(&handle).unwrap();
        let schema = Arc::new(Schema::new(1, FieldType::Long, "Address".to_string(), vec![], vec![], vec![]));
        let rec = DBRecord::new(schema, Field::Long(Some(0)));
        adapter.adapt_record(rec);
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = DBHandle::new().unwrap();
        let adapter: Box<dyn RelocationDBAdapter> = Box::new(RelocationDbAdapterNoTable::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}
