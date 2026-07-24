//! Port of `ghidra.program.database.code.ProtoDBAdapter`.
//!
//! The Java type is a package-private interface implemented by version-specific instruction
//! prototype table adapters. This follows the same convention already used for
//! [`InstDBAdapter`](crate::program::database::code::InstDBAdapter) and
//! [`CommentHistoryAdapter`](crate::program::database::code::CommentHistoryAdapter): only the
//! abstract instance API is modeled, as an object-safe trait. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// Database adapter interface for instruction prototypes.
///
/// Port of `ghidra.program.database.code.ProtoDBAdapter`.
pub trait ProtoDBAdapter {
    /// Returns the record associated with a specific prototype ID, or `None` if none exists.
    ///
    /// Stands in for `ProtoDBAdapter.getRecord(int)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, proto_id: i32) -> io::Result<Option<DBRecord>>;

    /// Returns a record iterator over all records.
    ///
    /// Stands in for `ProtoDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns the database version for this adapter.
    ///
    /// Stands in for `ProtoDBAdapter.getVersion()`.
    fn get_version(&self) -> i32;

    /// Returns the next key to use.
    ///
    /// Stands in for `ProtoDBAdapter.getKey()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_key(&self) -> io::Result<i64>;

    /// Creates a new prototype record in the database. `proto_id` is the id for the new
    /// prototype, `addr` is the address of the bytes for the prototype, `bytes` holds the bytes
    /// used to form the prototype, and `in_delay_slot` is `true` if the prototype is in a delay
    /// slot.
    ///
    /// Stands in for `ProtoDBAdapter.createRecord(int, long, byte[], boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_record(
        &mut self,
        proto_id: i32,
        addr: i64,
        bytes: &[u8],
        in_delay_slot: bool,
    ) -> io::Result<()>;

    /// Returns the total number of prototypes in the database.
    ///
    /// Stands in for `ProtoDBAdapter.getNumRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_num_records(&self) -> io::Result<i32>;

    /// Deletes all prototype records from the database.
    ///
    /// Stands in for `ProtoDBAdapter.deleteAll()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_all(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct ProtoRow {
        proto_id: i32,
        addr: i64,
        bytes: Vec<u8>,
        in_delay_slot: bool,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Int,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Binary, FieldType::Boolean],
            vec![
                "Address".to_string(),
                "Bytes".to_string(),
                "In Delay Slot".to_string(),
            ],
            vec![],
        ))
    }

    struct MockRecordIterator {
        rows: std::vec::IntoIter<ProtoRow>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.next().map(|row| {
                use crate::framework::db::Field;

                let mut record =
                    DBRecord::new(test_schema(), Field::Int(Some(row.proto_id)));
                record.set_long(0, row.addr);
                record.set_field(1, Field::Binary(Some(row.bytes.clone())));
                record.set_field(2, Field::Boolean(Some(row.in_delay_slot)));
                record
            }))
        }

        fn has_next(&self) -> bool {
            self.rows.len() > 0
        }
    }

    struct MockProtoDBAdapter {
        rows: BTreeMap<i32, ProtoRow>,
        next_key: i64,
    }

    impl MockProtoDBAdapter {
        fn new() -> Self {
            MockProtoDBAdapter {
                rows: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl ProtoDBAdapter for MockProtoDBAdapter {
        fn get_record(&self, proto_id: i32) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.get(&proto_id).cloned().map(|row| {
                use crate::framework::db::Field;

                let mut record = DBRecord::new(test_schema(), Field::Int(Some(row.proto_id)));
                record.set_long(0, row.addr);
                record.set_field(1, Field::Binary(Some(row.bytes.clone())));
                record.set_field(2, Field::Boolean(Some(row.in_delay_slot)));
                record
            }))
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let rows: Vec<ProtoRow> = self.rows.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                rows: rows.into_iter(),
            }))
        }

        fn get_version(&self) -> i32 {
            0
        }

        fn get_key(&self) -> io::Result<i64> {
            Ok(self.next_key)
        }

        fn create_record(
            &mut self,
            proto_id: i32,
            addr: i64,
            bytes: &[u8],
            in_delay_slot: bool,
        ) -> io::Result<()> {
            self.rows.insert(
                proto_id,
                ProtoRow {
                    proto_id,
                    addr,
                    bytes: bytes.to_vec(),
                    in_delay_slot,
                },
            );
            self.next_key = self.next_key.max(proto_id as i64 + 1);
            Ok(())
        }

        fn get_num_records(&self) -> io::Result<i32> {
            Ok(self.rows.len() as i32)
        }

        fn delete_all(&mut self) -> io::Result<()> {
            self.rows.clear();
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn ProtoDBAdapter> = Box::new(MockProtoDBAdapter::new());

        assert_eq!(adapter.get_num_records().unwrap(), 0);
        assert_eq!(adapter.get_key().unwrap(), 0);

        adapter
            .create_record(1, 0x1000, &[0xde, 0xad], false)
            .unwrap();
        adapter
            .create_record(2, 0x2000, &[0xbe, 0xef, 0x01], true)
            .unwrap();
        assert_eq!(adapter.get_num_records().unwrap(), 2);
        assert_eq!(adapter.get_key().unwrap(), 3);

        let rec = adapter.get_record(1).unwrap().unwrap();
        assert_eq!(
            rec.get_field(0),
            &crate::framework::db::Field::Long(Some(0x1000))
        );
        assert_eq!(
            rec.get_field(2),
            &crate::framework::db::Field::Boolean(Some(false))
        );

        assert!(adapter.get_record(99).unwrap().is_none());

        let mut total = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                total += 1;
            }
        }
        assert_eq!(total, 2);

        assert_eq!(adapter.get_version(), 0);

        adapter.delete_all().unwrap();
        assert_eq!(adapter.get_num_records().unwrap(), 0);
    }
}
