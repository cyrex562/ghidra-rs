//! Port of `ghidra.program.database.data.EnumValueDBAdapterV0`.
//!
//! Version 0 implementation for the enumeration data type values table adapter. The V0 on-disk
//! schema has no comment column, but otherwise shares the same column layout (name/value/enum
//! ID) and indices as the current schema, so [`translate_record`](RecordTranslator::translate_record)
//! reads those three columns directly using the current [`ENUMVAL_NAME_COL`]/[`ENUMVAL_VALUE_COL`]/
//! [`ENUMVAL_ID_COL`] indices and synthesizes a `None` comment.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::enum_value_db_adapter::{
    self, EnumValueDBAdapter, ENUMVAL_COMMENT_COL, ENUMVAL_ID_COL, ENUMVAL_NAME_COL,
    ENUMVAL_VALUE_COL, ENUM_VALUE_TABLE_NAME,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
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

/// Version 0 implementation for the enumeration data type values table adapter.
///
/// Port of `ghidra.program.database.data.EnumValueDBAdapterV0`.
pub struct EnumValueDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl EnumValueDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the enumeration data type values database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(ENUM_VALUE_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {ENUM_VALUE_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_message(format!(
                    "Expected version {} for table {} but got {}",
                    Self::VERSION,
                    ENUM_VALUE_TABLE_NAME,
                    version
                )));
            }
        }
        Ok(EnumValueDBAdapterV0 { table })
    }
}

impl DBRecordAdapter for EnumValueDBAdapterV0 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_record(rec)?);
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

impl RecordTranslator for EnumValueDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(enum_value_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(ENUMVAL_ID_COL, old_record.get_field(ENUMVAL_ID_COL).clone());
        rec.set_field(ENUMVAL_NAME_COL, old_record.get_field(ENUMVAL_NAME_COL).clone());
        rec.set_field(ENUMVAL_VALUE_COL, old_record.get_field(ENUMVAL_VALUE_COL).clone());
        rec.set_field(ENUMVAL_COMMENT_COL, Field::String(None));
        Ok(rec)
    }
}

impl EnumValueDBAdapter for EnumValueDBAdapterV0 {
    fn create_record(
        &mut self,
        _enum_id: i64,
        _name: &str,
        _value: i64,
        _comment: Option<&str>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update Version 0",
        ))
    }

    fn get_record(&self, value_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(value_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(ENUM_VALUE_TABLE_NAME);
        Ok(())
    }

    fn remove_record(&mut self, _value_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot remove Version 0",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update Version 0",
        ))
    }

    fn get_value_ids_in_enum(&self, enum_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(ENUMVAL_ID_COL), Field::Long(Some(v)) if *v == enum_id) {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Enum Value ID".to_string(),
            vec![FieldType::String, FieldType::Long, FieldType::Long],
            vec!["Name".to_string(), "Value".to_string(), "Enum ID".to_string()],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(ENUM_VALUE_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (name, value, enum_id) in [("Red", 0i64, 5i64), ("Green", 1, 5), ("On", 1, 7)] {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(ENUMVAL_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(ENUMVAL_VALUE_COL, Field::Long(Some(value)));
            rec.set_field(ENUMVAL_ID_COL, Field::Long(Some(enum_id)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(EnumValueDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema() {
        let handle = make_handle_with_v0_table();
        let adapter = EnumValueDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(ENUMVAL_NAME_COL),
            &Field::String(Some("Red".to_string()))
        );
        assert_eq!(rec.get_field(ENUMVAL_ID_COL), &Field::Long(Some(5)));
        assert_eq!(rec.get_field(ENUMVAL_COMMENT_COL), &Field::String(None));
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_value_ids_in_enum_filters_by_enum_id() {
        let handle = make_handle_with_v0_table();
        let adapter = EnumValueDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_value_ids_in_enum(5).unwrap().len(), 2);
        assert_eq!(adapter.get_value_ids_in_enum(7).unwrap().len(), 1);
        assert!(adapter.get_value_ids_in_enum(99).unwrap().is_empty());
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v0_table();
        let mut adapter = EnumValueDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record(1, "x", 0, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn EnumValueDBAdapter> =
            Box::new(EnumValueDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}
