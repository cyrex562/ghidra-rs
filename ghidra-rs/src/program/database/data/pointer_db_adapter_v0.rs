//! Port of `ghidra.program.database.data.PointerDBAdapterV0`.
//!
//! Version 0 implementation for accessing the pointer database table. This version's on-disk
//! records only carry a data type ID and size; category and current-schema length are
//! synthesized by [`translate_record`](RecordTranslator::translate_record) (length is always
//! reported as unknown/`-1`, category is always the root category).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::pointer_db_adapter::{
    self, PointerDBAdapter, POINTER_TABLE_NAME, PTR_CATEGORY_COL, PTR_DT_ID_COL, PTR_LENGTH_COL,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;

/// Column index of the pointer's referenced data type ID, as defined by `PointerDBAdapterV0`.
pub const V0_PTR_DT_ID_COL: usize = 0;

/// Column index of the pointer's size, as defined by `PointerDBAdapterV0`.
pub const V0_PTR_SIZE_COL: usize = 1;

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

/// Version 0 implementation for accessing the pointer database table.
///
/// Port of `ghidra.program.database.data.PointerDBAdapterV0`.
pub struct PointerDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl PointerDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the pointer database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(POINTER_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {POINTER_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_message(format!(
                    "Expected version {} for table {} but got {}",
                    Self::VERSION,
                    POINTER_TABLE_NAME,
                    version
                )));
            }
        }
        Ok(PointerDBAdapterV0 { table })
    }
}

impl DBRecordAdapter for PointerDBAdapterV0 {
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

impl RecordTranslator for PointerDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(pointer_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(PTR_DT_ID_COL, old_record.get_field(V0_PTR_DT_ID_COL).clone());
        rec.set_field(PTR_CATEGORY_COL, Field::Long(Some(0)));
        rec.set_field(PTR_LENGTH_COL, Field::Byte(Some(-1)));
        Ok(rec)
    }
}

impl PointerDBAdapter for PointerDBAdapterV0 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(POINTER_TABLE_NAME);
        Ok(())
    }

    fn create_record(
        &mut self,
        _data_type_id: i64,
        _category_id: i64,
        _length: i32,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update Version 0",
        ))
    }

    fn get_record(&self, pointer_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(pointer_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn remove_record(&mut self, _pointer_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update Version 0",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update Version 0",
        ))
    }

    fn get_record_ids_in_category(&self, _category_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
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
            "Pointer ID".to_string(),
            vec![FieldType::Long, FieldType::Int],
            vec!["Data Type ID".to_string(), "Size".to_string()],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(POINTER_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        let key = t.get_next_key();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
        rec.set_field(V0_PTR_DT_ID_COL, Field::Long(Some(42)));
        rec.set_field(V0_PTR_SIZE_COL, Field::Int(Some(4)));
        t.put_record(rec).unwrap();
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(PointerDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema() {
        let handle = make_handle_with_v0_table();
        let adapter = PointerDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(PTR_DT_ID_COL), &Field::Long(Some(42)));
        assert_eq!(rec.get_field(PTR_CATEGORY_COL), &Field::Long(Some(0)));
        assert_eq!(rec.get_field(PTR_LENGTH_COL), &Field::Byte(Some(-1)));
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn get_records_yields_translated_records() {
        let handle = make_handle_with_v0_table();
        let adapter = PointerDBAdapterV0::new(&handle).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let rec = iter.next().unwrap().expect("record present");
        assert_eq!(rec.get_field(PTR_DT_ID_COL), &Field::Long(Some(42)));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v0_table();
        let mut adapter = PointerDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter.create_record(1, 2, 4).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(adapter.get_record_ids_in_category(0).unwrap().is_empty());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn PointerDBAdapter> =
            Box::new(PointerDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
    }
}
