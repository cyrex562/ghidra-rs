//! Port of `ghidra.program.database.data.SourceArchiveAdapterNoTable`.
//!
//! Adapter needed for a read-only version of a data type manager that is not going to be
//! upgraded, and there is no Data Type Archive ID table in the data type manager.

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema};
use crate::program::database::data::source_archive_adapter::{
    SourceArchiveAdapter, ARCHIVE_ID_DIRTY_FLAG_COL, ARCHIVE_ID_DOMAIN_FILE_ID_COL,
    ARCHIVE_ID_LAST_SYNC_TIME_COL, ARCHIVE_ID_NAME_COL, ARCHIVE_ID_TYPE_COL,
};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::UniversalID;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Archive ID".to_string(),
        vec![
            FieldType::String,
            FieldType::String,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Boolean,
        ],
        vec![
            "Domain File ID".to_string(),
            "Name".to_string(),
            "Type".to_string(),
            "Last Sync Time".to_string(),
            "Dirty".to_string(),
        ],
        vec![],
    ))
}

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn build_local_record() -> DBRecord {
    let mut record = DBRecord::new(schema(), Field::Long(Some(LOCAL_ARCHIVE_KEY)));
    record.set_field(ARCHIVE_ID_DOMAIN_FILE_ID_COL, Field::String(None));
    record.set_field(ARCHIVE_ID_NAME_COL, Field::String(Some(String::new())));
    record.set_field(ARCHIVE_ID_TYPE_COL, Field::Byte(Some(0)));
    record.set_field(
        ARCHIVE_ID_LAST_SYNC_TIME_COL,
        Field::Long(Some(current_time_millis())),
    );
    record.set_field(ARCHIVE_ID_DIRTY_FLAG_COL, Field::Boolean(Some(false)));
    record
}

/// Adapter needed for a read-only version of a data type manager that is not going to be
/// upgraded, and there is no Data Type Archive ID table in the data type manager.
///
/// Port of `ghidra.program.database.data.SourceArchiveAdapterNoTable`.
pub struct SourceArchiveAdapterNoTable {
    local_record: DBRecord,
}

impl SourceArchiveAdapterNoTable {
    /// Gets a pre-table version of the adapter for the data type archive ID database table.
    ///
    /// `_handle` is the handle to the database which doesn't contain the table (unused).
    pub fn new(_handle: &DBHandle) -> Self {
        SourceArchiveAdapterNoTable {
            local_record: build_local_record(),
        }
    }
}

impl Default for SourceArchiveAdapterNoTable {
    fn default() -> Self {
        SourceArchiveAdapterNoTable {
            local_record: build_local_record(),
        }
    }
}

impl SourceArchiveAdapter for SourceArchiveAdapterNoTable {
    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        Ok(())
    }

    fn create_record(&mut self, _source_archive: &dyn SourceArchive) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not allowed to update version prior to existence of the Data Type Archive ID table",
        ))
    }

    fn get_records(&self) -> io::Result<Vec<DBRecord>> {
        Ok(vec![self.local_record.clone()])
    }

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        if key == LOCAL_ARCHIVE_KEY {
            return Ok(Some(self.local_record.clone()));
        }
        Ok(None)
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "updateRecord not supported",
        ))
    }

    fn remove_record(&mut self, _key: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "removeRecord not supported",
        ))
    }

    fn delete_record(&mut self, _source_archive_id: UniversalID) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "updateRecord not supported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> SourceArchiveAdapterNoTable {
        SourceArchiveAdapterNoTable::new(&DBHandle::new().unwrap())
    }

    #[test]
    fn get_record_returns_local_record_for_local_key() {
        let adapter = adapter();
        let rec = adapter
            .get_record(LOCAL_ARCHIVE_KEY)
            .unwrap()
            .expect("local archive record should exist");
        assert_eq!(
            rec.get_field(ARCHIVE_ID_NAME_COL),
            &Field::String(Some(String::new()))
        );
        assert_eq!(
            rec.get_field(ARCHIVE_ID_DIRTY_FLAG_COL),
            &Field::Boolean(Some(false))
        );
    }

    #[test]
    fn get_record_returns_none_for_other_keys() {
        let adapter = adapter();
        assert!(adapter.get_record(42).unwrap().is_none());
    }

    #[test]
    fn get_records_contains_only_local_record() {
        let adapter = adapter();
        let records = adapter.get_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get_key(), &Field::Long(Some(LOCAL_ARCHIVE_KEY)));
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let mut adapter = adapter();
        assert_eq!(
            adapter.remove_record(LOCAL_ARCHIVE_KEY).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter
                .delete_record(UniversalID::new(LOCAL_ARCHIVE_KEY))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let dummy = adapter.get_record(LOCAL_ARCHIVE_KEY).unwrap().unwrap();
        assert_eq!(
            adapter.update_record(&dummy).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn delete_table_is_a_no_op() {
        let mut adapter = adapter();
        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn SourceArchiveAdapter> = Box::new(adapter());
        assert!(adapter.get_record(LOCAL_ARCHIVE_KEY).unwrap().is_some());
    }
}
