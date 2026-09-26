//! Port of `ghidra.program.database.data.ArrayDBAdapterV0`.
//!
//! Version 0 (read-only) implementation for accessing the Array database table. This version's
//! on-disk records have no "Cat ID" column; [`translate_record`] synthesizes a category ID of
//! `0` (the root category) for it.
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! The V0 table predates `tablePrefix` support (introduced in V1), so it is always looked up
//! under the bare [`ARRAY_TABLE_NAME`] with no prefix.
//!
//! Java's `createRecord` returns `null` rather than throwing (unlike the sibling `V0` adapters in
//! this family, which throw `UnsupportedOperationException`); since this port's trait returns a
//! `DBRecord` rather than a nullable reference, `create_record` here returns an
//! `io::ErrorKind::Unsupported` error instead -- same "no record can be created" outcome, just
//! surfaced through this port's error-based API rather than a null return. `update_record` is a
//! true no-op in Java (empty method body) and is mirrored as such (`Ok(())`, no error).
//! `get_record_ids_in_category` always returns `Field.EMPTY_ARRAY` in Java regardless of the
//! requested category, which is mirrored by always returning an empty `Vec`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::array_db_adapter::{
    self, ArrayDBAdapter, ARRAY_CAT_COL, ARRAY_DIM_COL, ARRAY_DT_ID_COL, ARRAY_ELEMENT_LENGTH_COL,
    ARRAY_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// Column index of the array's referenced data type ID, as defined by `ArrayDBAdapterV0`.
pub const V0_ARRAY_DT_ID_COL: usize = 0;

/// Column index of the array's dimension (number of elements), as defined by `ArrayDBAdapterV0`.
pub const V0_ARRAY_DIM_COL: usize = 1;

/// Column index of the array's element length, as defined by `ArrayDBAdapterV0`.
pub const V0_ARRAY_ELEMENT_LENGTH_COL: usize = 2;

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

/// Version 0 (read-only) implementation for accessing the Array database table.
///
/// Port of `ghidra.program.database.data.ArrayDBAdapterV0`.
pub struct ArrayDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl ArrayDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 read-only adapter for the Array database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(ARRAY_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {ARRAY_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_message(format!(
                    "Expected version {} for table {} but got {}",
                    Self::VERSION,
                    ARRAY_TABLE_NAME,
                    version
                )));
            }
        }
        Ok(ArrayDBAdapterV0 { table })
    }
}

impl RecordTranslator for ArrayDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(array_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            ARRAY_DT_ID_COL,
            old_record.get_field(V0_ARRAY_DT_ID_COL).clone(),
        );
        rec.set_field(ARRAY_DIM_COL, old_record.get_field(V0_ARRAY_DIM_COL).clone());
        rec.set_field(
            ARRAY_ELEMENT_LENGTH_COL,
            old_record.get_field(V0_ARRAY_ELEMENT_LENGTH_COL).clone(),
        );
        rec.set_field(ARRAY_CAT_COL, Field::Long(Some(0)));
        Ok(rec)
    }
}

impl ArrayDBAdapter for ArrayDBAdapterV0 {
    fn create_record(
        &mut self,
        _data_type_id: i64,
        _number_of_elements: i32,
        _length: i32,
        _cat_id: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 0",
        ))
    }

    fn get_record(&self, array_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(array_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

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

    fn remove_record(&mut self, _data_id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Ok(())
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(ARRAY_TABLE_NAME);
        Ok(())
    }

    fn get_record_ids_in_category(&self, _category_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
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
            "Array ID".to_string(),
            vec![FieldType::Long, FieldType::Int, FieldType::Int],
            vec![
                "Data Type ID".to_string(),
                "Dimension".to_string(),
                "Length".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(ARRAY_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        let key = t.get_next_key();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
        rec.set_field(V0_ARRAY_DT_ID_COL, Field::Long(Some(42)));
        rec.set_field(V0_ARRAY_DIM_COL, Field::Int(Some(4)));
        rec.set_field(V0_ARRAY_ELEMENT_LENGTH_COL, Field::Int(Some(8)));
        t.put_record(rec).unwrap();
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(ArrayDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema() {
        let handle = make_handle_with_v0_table();
        let adapter = ArrayDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(ARRAY_DT_ID_COL), &Field::Long(Some(42)));
        assert_eq!(rec.get_field(ARRAY_DIM_COL), &Field::Int(Some(4)));
        assert_eq!(rec.get_field(ARRAY_CAT_COL), &Field::Long(Some(0)));
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn get_records_yields_translated_records() {
        let handle = make_handle_with_v0_table();
        let adapter = ArrayDBAdapterV0::new(&handle).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let rec = iter.next().unwrap().expect("record present");
        assert_eq!(rec.get_field(ARRAY_DT_ID_COL), &Field::Long(Some(42)));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn mutating_operations_are_unsupported_or_no_op() {
        let handle = make_handle_with_v0_table();
        let mut adapter = ArrayDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter.create_record(1, 2, 4, 5).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_record(0).unwrap().unwrap();
        assert!(adapter.update_record(&existing).is_ok());
        assert_eq!(adapter.remove_record(0).unwrap(), false);
        assert!(adapter.get_record_ids_in_category(0).unwrap().is_empty());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn ArrayDBAdapter> = Box::new(ArrayDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
    }
}
