//! Port of `ghidra.program.database.code.ProtoDBAdapterV1`.
//!
//! Java's `getRecords()` returns a live `Table.iterator()` that keeps reading through the open
//! `Table` as the caller advances it. This port's [`Table`] cannot hand out such a borrow without
//! tying the returned iterator's lifetime to a lock guard that is dropped at the end of the
//! call, so -- matching the convention already established by `CompositeDBAdapterV5V6` and
//! `CommentHistoryAdapterV0` in this DB-adapter family -- `get_records` eagerly collects into a
//! `Vec` up front instead. Same observable result.
//!
//! Java's `deleteAll()` calls `Table.deleteAll()` directly; this port's `Table` has no such bulk
//! operation, so it collects every key and deletes them one at a time.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::proto_db_adapter::{
    self, ProtoDBAdapter, ADDR_COL, BYTES_COL, DELAY_COL, PROTO_TABLE_NAME,
};
use crate::program::database::util::database_version_exception::DatabaseVersionException;

/// A `RecordIterator` over an eagerly-collected set of records.
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

/// Implements version 1 of the [`ProtoDBAdapter`] interface.
///
/// Port of `ghidra.program.database.code.ProtoDBAdapterV1`. See the module docs for the
/// `get_records`/`delete_all` deviations.
pub struct ProtoDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl ProtoDBAdapterV1 {
    /// Constructs a new Version 1 prototype adapter, opening the existing prototype table from
    /// `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseVersionException`] if the table does not exist or is not schema version
    /// 1.
    pub fn new(handle: &crate::framework::db::DBHandle) -> Result<Self, DatabaseVersionException> {
        let table = handle
            .get_table(PROTO_TABLE_NAME)
            .ok_or_else(|| DatabaseVersionException::with_message("Instruction table not found"))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 1 {
            return Err(DatabaseVersionException::with_message(format!(
                "Prototype table: Expected Version 1, got {version}"
            )));
        }
        Ok(ProtoDBAdapterV1 { table })
    }
}

impl ProtoDBAdapter for ProtoDBAdapterV1 {
    fn get_record(&self, proto_id: i32) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Int(Some(proto_id)))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_version(&self) -> i32 {
        1
    }

    fn get_key(&self) -> io::Result<i64> {
        Ok(self.table.read().unwrap().peek_next_key())
    }

    fn create_record(
        &mut self,
        proto_id: i32,
        addr: i64,
        bytes: &[u8],
        in_delay_slot: bool,
    ) -> io::Result<()> {
        let mut record = DBRecord::new(proto_db_adapter::schema(), Field::Int(Some(proto_id)));
        record.set_field(BYTES_COL, Field::Binary(Some(bytes.to_vec())));
        record.set_field(ADDR_COL, Field::Long(Some(addr)));
        record.set_field(DELAY_COL, Field::Boolean(Some(in_delay_slot)));
        self.table.write().unwrap().put_record(record)
    }

    fn get_num_records(&self) -> io::Result<i32> {
        Ok(self.table.read().unwrap().get_record_count() as i32)
    }

    fn delete_all(&mut self) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            keys.push(rec.get_key().clone());
        }
        drop(iter);
        for key in keys {
            table.delete_record(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;

    fn create_table(handle: &mut DBHandle) {
        handle
            .create_table(PROTO_TABLE_NAME.to_string(), proto_db_adapter::schema())
            .unwrap();
    }

    #[test]
    fn create_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        create_table(&mut handle);
        let mut adapter = ProtoDBAdapterV1::new(&handle).unwrap();

        assert_eq!(adapter.get_version(), 1);
        assert_eq!(adapter.get_num_records().unwrap(), 0);

        adapter.create_record(5, 0x1000, &[0xde, 0xad], true).unwrap();
        assert_eq!(adapter.get_num_records().unwrap(), 1);

        let rec = adapter.get_record(5).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x1000)));
        assert_eq!(
            rec.get_field(BYTES_COL),
            &Field::Binary(Some(vec![0xde, 0xad]))
        );
        assert_eq!(rec.get_field(DELAY_COL), &Field::Boolean(Some(true)));

        assert!(adapter.get_record(99).unwrap().is_none());
    }

    #[test]
    fn get_key_peeks_without_consuming() {
        let mut handle = DBHandle::new().unwrap();
        create_table(&mut handle);
        let mut adapter = ProtoDBAdapterV1::new(&handle).unwrap();

        let first_peek = adapter.get_key().unwrap();
        let second_peek = adapter.get_key().unwrap();
        assert_eq!(first_peek, second_peek);

        adapter.create_record(0, 0, &[], false).unwrap();
        // Peeking is independent of records created with explicit, caller-chosen IDs.
        assert_eq!(adapter.get_key().unwrap(), first_peek);
    }

    #[test]
    fn get_records_and_delete_all() {
        let mut handle = DBHandle::new().unwrap();
        create_table(&mut handle);
        let mut adapter = ProtoDBAdapterV1::new(&handle).unwrap();

        adapter.create_record(1, 0x1000, &[1], false).unwrap();
        adapter.create_record(2, 0x2000, &[2], true).unwrap();

        let mut total = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                total += 1;
            }
        }
        assert_eq!(total, 2);

        adapter.delete_all().unwrap();
        assert_eq!(adapter.get_num_records().unwrap(), 0);
    }

    #[test]
    fn opening_missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(ProtoDBAdapterV1::new(&handle).is_err());
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        use crate::framework::db::{FieldType, Schema};
        let v0_schema = Arc::new(Schema::new(
            0,
            FieldType::Int,
            "Keys".to_string(),
            vec![FieldType::Binary, FieldType::Long],
            vec!["Bytes".to_string(), "Address".to_string()],
            vec![],
        ));
        handle
            .create_table(PROTO_TABLE_NAME.to_string(), v0_schema)
            .unwrap();
        assert!(ProtoDBAdapterV1::new(&handle).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        create_table(&mut handle);
        let adapter: Box<dyn ProtoDBAdapter> = Box::new(ProtoDBAdapterV1::new(&handle).unwrap());
        assert_eq!(adapter.get_num_records().unwrap(), 0);
    }
}
