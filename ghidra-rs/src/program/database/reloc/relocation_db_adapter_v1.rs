//! Port of `ghidra.program.database.reloc.RelocationDBAdapterV1`.
//!
//! Read-only legacy adapter for the earliest schema with an actual table: a single `Type` column,
//! with the primary key being the address-encoded value itself (see `RelocationDbAdapterV4`'s
//! module docs for why -- that convention starts here at `V1`). No `Values`/`Bytes`/`Symbol Name`
//! columns exist yet. [`RelocationDBAdapter::add`] returns an `io::ErrorKind::Unsupported` error,
//! mirroring Java's `throw new UnsupportedOperationException()`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::map::{AddressKeyRecordIterator, AddressMap};
use crate::program::database::reloc::relocation_db_adapter::{
    get_flags, RelocationDBAdapter, VecRelocationRecordIterator, ADDR_COL, FLAGS_COL, TABLE_NAME,
    TYPE_COL,
};
use crate::program::database::reloc::relocation_db_adapter_v6::schema;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterV1.VERSION`.
pub const VERSION: i32 = 1;

/// Column index of a V1 relocation's type (the only column in this schema). Port of
/// `RelocationDBAdapterV1.V1_TYPE_COL`.
pub const V1_TYPE_COL: usize = 0;

/// The read-only, `V1`-schema implementation of the relocations database adapter.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterV1`.
pub struct RelocationDbAdapterV1 {
    reloc_table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl RelocationDbAdapterV1 {
    /// Opens an existing `V1` relocations table.
    ///
    /// Port of `RelocationDBAdapterV1(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns a non-upgradeable [`VersionException`] if no relocations table exists, or it
    /// exists at a schema version other than [`VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(TABLE_NAME).ok_or_else(VersionException::new)?;
        if table.read().unwrap().get_schema().get_version() != VERSION {
            return Err(VersionException::new());
        }
        Ok(RelocationDbAdapterV1 { reloc_table: table, addr_map })
    }

    fn collect_records(
        &self,
        set: Option<&dyn AddressSetView>,
        start: Option<&Address>,
    ) -> io::Result<Vec<DBRecord>> {
        let mut it = match start {
            Some(start) => {
                AddressKeyRecordIterator::new_at(&self.reloc_table, self.addr_map.as_ref(), start, true)?
            }
            None => AddressKeyRecordIterator::new_over_set(
                &self.reloc_table,
                self.addr_map.as_ref(),
                set,
                None,
                true,
            )?,
        };
        let mut records = Vec::new();
        while it.has_next() {
            if let Some(rec) = it.next()? {
                records.push(self.adapt_record(rec));
            }
        }
        Ok(records)
    }
}

impl RelocationDBAdapter for RelocationDbAdapterV1 {
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
            "RelocationDBAdapterV1 is read-only",
        ))
    }

    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(self.collect_records(None, None)?)))
    }

    fn iterator_in_set(&self, set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(
            self.collect_records(Some(set), None)?,
        )))
    }

    fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(
            self.collect_records(None, Some(start))?,
        )))
    }

    fn get_record_count(&self) -> i32 {
        self.reloc_table.read().unwrap().get_record_count() as i32
    }

    fn adapt_record(&self, rec: DBRecord) -> DBRecord {
        let mut new_rec = DBRecord::new(schema(), rec.get_key().clone());
        // Key was encoded address (V1..V4 have no separate address column).
        new_rec.set_field(ADDR_COL, Field::Long(Some(rec.get_key().get_long_value())));
        new_rec.set_field(FLAGS_COL, Field::Byte(Some(get_flags(RelocationStatus::Unknown, 0) as i8)));
        new_rec.set_field(TYPE_COL, Field::Int(Some(rec.get_field(V1_TYPE_COL).get_int_value())));
        // No Values/Bytes/Symbol Name columns at V1 -- left unset, matching Java's untouched
        // defaults.
        new_rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::database::reloc::relocation_db_adapter::{get_status, BYTES_COL, SYMBOL_NAME_COL, VALUE_COL};
    use crate::program::database::reloc::test_support::IdentityAddressMap;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn v1_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "Address".to_string(),
            vec![FieldType::Int],
            vec!["Type".to_string()],
            vec![],
        ))
    }

    fn make_v1_table(handle: &mut DBHandle) -> Arc<RwLock<Table>> {
        handle.create_table(TABLE_NAME.to_string(), v1_schema()).unwrap()
    }

    #[test]
    fn open_rejects_missing_table() {
        let handle = DBHandle::new().unwrap();
        assert!(RelocationDbAdapterV1::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn open_rejects_wrong_version_as_non_upgradeable() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                TABLE_NAME.to_string(),
                Arc::new(Schema::new(2, FieldType::Long, "Address".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        match RelocationDbAdapterV1::new(&handle, addr_map()) {
            Err(e) => assert!(!e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn add_is_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        make_v1_table(&mut handle);
        let mut adapter = RelocationDbAdapterV1::new(&handle, addr_map()).unwrap();
        let err = adapter.add(&space().address(0), 0, 0, &[], None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn adapt_record_recovers_address_from_key_and_leaves_other_columns_unset() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v1_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(0x8000)));
            rec.set_field(V1_TYPE_COL, Field::Int(Some(4)));
            t.put_record(rec).unwrap();
        }
        let adapter = RelocationDbAdapterV1::new(&handle, addr_map()).unwrap();

        let mut it = adapter.iterator().unwrap();
        let translated = it.next().unwrap().unwrap();
        assert_eq!(translated.get_field(ADDR_COL), &Field::Long(Some(0x8000)));
        assert_eq!(translated.get_field(TYPE_COL), &Field::Int(Some(4)));
        assert_eq!(translated.get_field(VALUE_COL), &Field::Binary(None));
        assert_eq!(translated.get_field(BYTES_COL), &Field::Binary(None));
        assert_eq!(translated.get_string(SYMBOL_NAME_COL), None);
        let flags = match translated.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(flags), RelocationStatus::Unknown);
    }

    #[test]
    fn iterator_in_set_and_iterator_from_filter_correctly() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v1_table(&mut handle);
        let s = space();
        {
            let mut t = table.write().unwrap();
            for addr_val in [0x100i64, 0x200, 0x300] {
                let rec = DBRecord::new(v1_schema(), Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }
        let adapter = RelocationDbAdapterV1::new(&handle, addr_map()).unwrap();

        let set = AddressSet::from_start_end(s.address(0x150), s.address(0x250));
        let mut it = adapter.iterator_in_set(&set).unwrap();
        let rec = it.next().unwrap().unwrap();
        assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x200)));
        assert!(it.next().unwrap().is_none());

        let mut from_it = adapter.iterator_from(&s.address(0x200)).unwrap();
        let mut addrs = Vec::new();
        while let Some(rec) = from_it.next().unwrap() {
            addrs.push(rec.get_field(ADDR_COL).get_long_value());
        }
        assert_eq!(addrs, vec![0x200, 0x300]);
    }
}
