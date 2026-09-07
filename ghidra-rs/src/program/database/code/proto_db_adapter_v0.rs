//! Port of `ghidra.program.database.code.ProtoDBAdapterV0`.
//!
//! Version 0's on-disk schema only has the `Bytes`/`Address` columns (no `InDelaySlot`); this
//! adapter reads through that legacy table and converts each record into the current (version 1)
//! record shape on the fly, with `InDelaySlot` always `false` (Java's `convertRecord` does the
//! same). Records are read-only: `create_record`/`delete_all` are rejected exactly as Java's
//! `UnsupportedOperationException`s are, and negative legacy keys (used by Java to distinguish
//! delay-slot prototypes under the old schema) are un-negated on the way out, matching
//! `convertRecord`'s `if (key < 0) key = -key`.
//!
//! Java's `getRecords()` returns a live wrapping `RecordUpdateIterator` over `table.iterator()`;
//! this port instead eagerly collects and converts every record up front, matching the convention
//! already established by `ProtoDBAdapterV1`/`CompositeDBAdapterV5V6` in this DB-adapter family.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::proto_db_adapter::{
    self, ProtoDBAdapter, ADDR_COL, BYTES_COL, DELAY_COL, PROTO_TABLE_NAME,
};
use crate::program::database::util::database_version_exception::DatabaseVersionException;

/// Converts a legacy (version 0) record -- `[Bytes, Address]`, keyed by a possibly-negative
/// prototype ID -- into the current (version 1) record shape, `InDelaySlot` always `false`.
/// Stands in for `ProtoDBAdapterV0.convertRecord(DBRecord)`.
fn convert_record(old_rec: &DBRecord) -> DBRecord {
    let key = match old_rec.get_key() {
        Field::Int(Some(v)) => *v,
        _ => 0,
    };
    let key = if key < 0 { -key } else { key };
    let mut new_rec = DBRecord::new(proto_db_adapter::schema(), Field::Int(Some(key)));
    new_rec.set_field(BYTES_COL, old_rec.get_field(0).clone());
    new_rec.set_field(ADDR_COL, old_rec.get_field(1).clone());
    new_rec.set_field(DELAY_COL, Field::Boolean(Some(false)));
    new_rec
}

/// A `RecordIterator` over an eagerly-collected, already-converted set of records.
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

/// Version 0 of the [`ProtoDBAdapter`] interface.
///
/// Port of `ghidra.program.database.code.ProtoDBAdapterV0`. See the module docs for the
/// record-conversion and read-only deviations.
pub struct ProtoDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl ProtoDBAdapterV0 {
    /// Constructs a new Version 0 prototype adapter, opening the existing prototype table from
    /// `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseVersionException`] if the table does not exist or is not schema version
    /// 0.
    pub fn new(handle: &crate::framework::db::DBHandle) -> Result<Self, DatabaseVersionException> {
        let table = handle
            .get_table(PROTO_TABLE_NAME)
            .ok_or_else(|| DatabaseVersionException::with_message("Instruction table not found"))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(DatabaseVersionException::with_message(format!(
                "Prototype table: Expected Version 0, got {version}"
            )));
        }
        Ok(ProtoDBAdapterV0 { table })
    }
}

impl ProtoDBAdapter for ProtoDBAdapterV0 {
    fn get_record(&self, proto_id: i32) -> io::Result<Option<DBRecord>> {
        Ok(self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Int(Some(proto_id)))?
            .map(|rec| convert_record(&rec)))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(convert_record(&rec));
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_version(&self) -> i32 {
        0
    }

    fn get_key(&self) -> io::Result<i64> {
        Ok(self.table.read().unwrap().peek_next_key())
    }

    fn create_record(
        &mut self,
        _proto_id: i32,
        _addr: i64,
        _bytes: &[u8],
        _in_delay_slot: bool,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records with old schema",
        ))
    }

    fn get_num_records(&self) -> io::Result<i32> {
        Ok(self.table.read().unwrap().get_record_count() as i32)
    }

    fn delete_all(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot delete records with old schema",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, FieldType, Schema};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Int,
            "Keys".to_string(),
            vec![FieldType::Binary, FieldType::Long],
            vec!["Bytes".to_string(), "Address".to_string()],
            vec![],
        ))
    }

    fn create_table_with_record(handle: &mut DBHandle, key: i32, bytes: &[u8], addr: i64) {
        let table = handle
            .create_table(PROTO_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut record = DBRecord::new(v0_schema(), Field::Int(Some(key)));
        record.set_field(0, Field::Binary(Some(bytes.to_vec())));
        record.set_field(1, Field::Long(Some(addr)));
        table.write().unwrap().put_record(record).unwrap();
    }

    #[test]
    fn get_record_converts_to_current_shape() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, 5, &[0xab, 0xcd], 0x2000);
        let adapter = ProtoDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_version(), 0);
        let rec = adapter.get_record(5).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(BYTES_COL), &Field::Binary(Some(vec![0xab, 0xcd])));
        assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x2000)));
        assert_eq!(rec.get_field(DELAY_COL), &Field::Boolean(Some(false)));
    }

    #[test]
    fn negative_legacy_keys_are_un_negated() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, -7, &[1], 0x100);
        let adapter = ProtoDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(-7).unwrap().expect("record should exist");
        assert_eq!(rec.get_key(), &Field::Int(Some(7)));
    }

    #[test]
    fn create_record_and_delete_all_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, 1, &[1], 0x100);
        let mut adapter = ProtoDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record(2, 0x200, &[2], false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(adapter.delete_all().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_records_converts_every_record() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, 1, &[1], 0x100);
        {
            let table = handle.get_table(PROTO_TABLE_NAME).unwrap();
            let mut record = DBRecord::new(v0_schema(), Field::Int(Some(2)));
            record.set_field(0, Field::Binary(Some(vec![2])));
            record.set_field(1, Field::Long(Some(0x200)));
            table.write().unwrap().put_record(record).unwrap();
        }
        let adapter = ProtoDBAdapterV0::new(&handle).unwrap();

        let mut total = 0;
        let mut iter = adapter.get_records().unwrap();
        while let Some(rec) = iter.next().unwrap() {
            assert_eq!(rec.get_field(DELAY_COL), &Field::Boolean(Some(false)));
            total += 1;
        }
        assert_eq!(total, 2);
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, 1, &[1], 0x100);
        // v0_schema's table is version 0; requesting a V1 open against it should fail.
        assert!(
            crate::program::database::code::proto_db_adapter_v1::ProtoDBAdapterV1::new(&handle)
                .is_err()
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        create_table_with_record(&mut handle, 1, &[1], 0x100);
        let adapter: Box<dyn ProtoDBAdapter> = Box::new(ProtoDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_num_records().unwrap(), 1);
    }
}
