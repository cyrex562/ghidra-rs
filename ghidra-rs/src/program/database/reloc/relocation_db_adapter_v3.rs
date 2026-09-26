//! Port of `ghidra.program.database.reloc.RelocationDBAdapterV3`.
//!
//! Read-only legacy adapter. Like `V1`/`V2`/`V4`, `V3`'s primary key *is* the address-encoded
//! value (see `RelocationDbAdapterV4`'s module docs for why). `V3` added a `Bytes` column and
//! already stores `Values` as a binary-coded `long[]` (copied through untouched by
//! [`RelocationDbAdapterV3::adapt_record`] via `getBinaryData`/`setBinaryData` in Java) -- there is
//! no `Symbol Name` column yet (added in `V4`). Every record this adapter hands back is translated
//! on the fly to the current schema, matching Java's `RecordIteratorAdapter` wrapper.
//! [`RelocationDBAdapter::add`] returns an `io::ErrorKind::Unsupported` error, mirroring Java's
//! `throw new UnsupportedOperationException()`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::map::{AddressKeyRecordIterator, AddressMap};
use crate::program::database::reloc::relocation_db_adapter::{
    get_flags, RelocationDBAdapter, VecRelocationRecordIterator, ADDR_COL, BYTES_COL, FLAGS_COL,
    TABLE_NAME, TYPE_COL, VALUE_COL,
};
use crate::program::database::reloc::relocation_db_adapter_v6::schema;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterV3.VERSION`.
pub const VERSION: i32 = 3;

/// Column index of a V3 relocation's type. Port of `RelocationDBAdapterV3.V3_TYPE_COL`.
pub const V3_TYPE_COL: usize = 0;
/// Column index of a V3 relocation's binary-coded `long[]` value. Port of
/// `RelocationDBAdapterV3.V3_VALUE_COL`.
pub const V3_VALUE_COL: usize = 1;
/// Column index of a V3 relocation's original bytes. Port of `RelocationDBAdapterV3.V3_BYTES_COL`.
pub const V3_BYTES_COL: usize = 2;

/// The read-only, `V3`-schema implementation of the relocations database adapter.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterV3`.
pub struct RelocationDbAdapterV3 {
    reloc_table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl RelocationDbAdapterV3 {
    /// Opens an existing `V3` relocations table.
    ///
    /// Port of `RelocationDBAdapterV3(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns a non-upgradeable [`VersionException`] if no relocations table exists, or it
    /// exists at a schema version other than [`VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(TABLE_NAME).ok_or_else(VersionException::new)?;
        if table.read().unwrap().get_schema().get_version() != VERSION {
            return Err(VersionException::new());
        }
        Ok(RelocationDbAdapterV3 { reloc_table: table, addr_map })
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

impl RelocationDBAdapter for RelocationDbAdapterV3 {
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
            "RelocationDBAdapterV3 is read-only",
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
        new_rec.set_field(TYPE_COL, Field::Int(Some(rec.get_field(V3_TYPE_COL).get_int_value())));
        new_rec.set_field(
            VALUE_COL,
            Field::Binary(rec.get_field(V3_VALUE_COL).get_binary_data().map(|b| b.to_vec())),
        );
        new_rec.set_field(
            BYTES_COL,
            Field::Binary(rec.get_field(V3_BYTES_COL).get_binary_data().map(|b| b.to_vec())),
        );
        // No Symbol Name column at V3 -- left unset (None), matching Java's untouched default.
        new_rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::database::reloc::relocation_db_adapter::{get_status, SYMBOL_NAME_COL};
    use crate::program::database::reloc::test_support::IdentityAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn v3_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "Address".to_string(),
            vec![FieldType::Int, FieldType::Binary, FieldType::Binary],
            vec!["Type".to_string(), "Values".to_string(), "Bytes".to_string()],
            vec![],
        ))
    }

    fn make_v3_table(handle: &mut DBHandle) -> Arc<RwLock<Table>> {
        handle.create_table(TABLE_NAME.to_string(), v3_schema()).unwrap()
    }

    #[test]
    fn open_rejects_missing_table() {
        let handle = DBHandle::new().unwrap();
        assert!(RelocationDbAdapterV3::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn add_is_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        make_v3_table(&mut handle);
        let mut adapter = RelocationDbAdapterV3::new(&handle, addr_map()).unwrap();
        let err = adapter.add(&space().address(0), 0, 0, &[], None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn adapt_record_copies_binary_values_and_leaves_symbol_name_unset() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v3_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            let mut rec = DBRecord::new(v3_schema(), Field::Long(Some(0x6000)));
            rec.set_field(V3_TYPE_COL, Field::Int(Some(2)));
            rec.set_field(V3_VALUE_COL, Field::Binary(Some(vec![1, 2, 3, 4, 5, 6, 7, 8])));
            rec.set_field(V3_BYTES_COL, Field::Binary(Some(vec![0xFF])));
            t.put_record(rec).unwrap();
        }
        let adapter = RelocationDbAdapterV3::new(&handle, addr_map()).unwrap();

        let mut it = adapter.iterator().unwrap();
        let translated = it.next().unwrap().unwrap();
        assert_eq!(translated.get_field(ADDR_COL), &Field::Long(Some(0x6000)));
        assert_eq!(translated.get_field(TYPE_COL), &Field::Int(Some(2)));
        assert_eq!(
            translated.get_field(VALUE_COL),
            &Field::Binary(Some(vec![1, 2, 3, 4, 5, 6, 7, 8]))
        );
        assert_eq!(translated.get_field(BYTES_COL), &Field::Binary(Some(vec![0xFF])));
        assert_eq!(translated.get_string(SYMBOL_NAME_COL), None);
        let flags = match translated.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(flags), RelocationStatus::Unknown);
    }

    #[test]
    fn record_count_matches_table() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v3_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            for addr_val in [0x100i64, 0x200] {
                let rec = DBRecord::new(v3_schema(), Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }
        let adapter = RelocationDbAdapterV3::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_record_count(), 2);
    }
}
