//! Port of `ghidra.program.database.data.FunctionParameterAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`FunctionParameterAdapterV0`/`V1`/`NoTable`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.
//!
//! Unlike [`FunctionDefinitionDBAdapter`](super::function_definition_db_adapter::FunctionDefinitionDBAdapter),
//! the Java class does not implement `DBRecordAdapter` (it has no `getRecordCount()`), so
//! `get_records` is declared directly on this trait instead of via that supertrait.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator};

/// Name of the database table used to store function signature definition parameters.
pub const PARAMETER_TABLE_NAME: &str = "Function Parameters";

/// Column index of the parameter's parent function definition ID, as defined by
/// `FunctionParameterAdapterV1`.
pub const PARAMETER_PARENT_ID_COL: usize = 0;

/// Column index of the parameter's data type ID, as defined by `FunctionParameterAdapterV1`.
pub const PARAMETER_DT_ID_COL: usize = 1;

/// Column index of the parameter's name, as defined by `FunctionParameterAdapterV1`.
pub const PARAMETER_NAME_COL: usize = 2;

/// Column index of the parameter's comment, as defined by `FunctionParameterAdapterV1`.
pub const PARAMETER_COMMENT_COL: usize = 3;

/// Column index of the parameter's ordinal, as defined by `FunctionParameterAdapterV1`.
pub const PARAMETER_ORDINAL_COL: usize = 4;

/// Column index of the parameter's data type length (when required, else -1), as defined by
/// `FunctionParameterAdapterV1`.
pub const PARAMETER_DT_LENGTH_COL: usize = 5;

/// Adapter to access the Function Signature Definition Parameters database table.
///
/// Port of `ghidra.program.database.data.FunctionParameterAdapter`.
pub trait FunctionParameterAdapter {
    /// Gets an iterator over all function definition parameter data type records.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Delete underlying database table.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Create new parameter definition record.
    ///
    /// `data_type_id` is the parameter datatype ID, `parent_id` is the parent function
    /// definition ID, `ordinal` is the parameter ordinal, `name` is the parameter name,
    /// `comment` is the parameter comment, and `dt_length` is the datatype length if required,
    /// else -1.
    fn create_record(
        &mut self,
        data_type_id: i64,
        parent_id: i64,
        ordinal: i32,
        name: Option<&str>,
        comment: Option<&str>,
        dt_length: i32,
    ) -> io::Result<DBRecord>;

    /// Get parameter definition record, or `None` if not found.
    fn get_record(&self, parameter_id: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the function definition parameter data type table with the provided record.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Removes the function definition parameter data type record with the specified ID.
    /// Returns `true` if the record is removed.
    fn remove_record(&mut self, parameter_id: i64) -> io::Result<bool>;

    /// Get parameter definition IDs (as `Field::Long` values) for the specified function
    /// definition.
    fn get_parameter_ids_in_function_def(&self, function_def_id: i64) -> io::Result<Vec<Field>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    struct MockFunctionParameterAdapter {
        schema: std::sync::Arc<crate::framework::db::Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockFunctionParameterAdapter {
        fn new() -> Self {
            use crate::framework::db::{FieldType, Schema};
            let schema = std::sync::Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Parameter ID".to_string(),
                vec![
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::String,
                    FieldType::String,
                    FieldType::Int,
                    FieldType::Int,
                ],
                vec![
                    "Parent ID".to_string(),
                    "Data Type ID".to_string(),
                    "Name".to_string(),
                    "Comment".to_string(),
                    "Ordinal".to_string(),
                    "Data Type Length".to_string(),
                ],
                vec![],
            ));
            MockFunctionParameterAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl FunctionParameterAdapter for MockFunctionParameterAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn create_record(
            &mut self,
            data_type_id: i64,
            parent_id: i64,
            ordinal: i32,
            name: Option<&str>,
            comment: Option<&str>,
            dt_length: i32,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(PARAMETER_PARENT_ID_COL, Field::Long(Some(parent_id)));
            rec.set_field(PARAMETER_DT_ID_COL, Field::Long(Some(data_type_id)));
            rec.set_field(
                PARAMETER_NAME_COL,
                Field::String(name.map(str::to_string)),
            );
            rec.set_field(
                PARAMETER_COMMENT_COL,
                Field::String(comment.map(str::to_string)),
            );
            rec.set_field(PARAMETER_ORDINAL_COL, Field::Int(Some(ordinal)));
            rec.set_field(PARAMETER_DT_LENGTH_COL, Field::Int(Some(dt_length)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, parameter_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(parameter_id)))
                .cloned())
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn remove_record(&mut self, parameter_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(parameter_id)));
            Ok(records.len() != len_before)
        }

        fn get_parameter_ids_in_function_def(&self, function_def_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(PARAMETER_PARENT_ID_COL), Field::Long(Some(v)) if *v == function_def_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_parameters() {
        let mut adapter: Box<dyn FunctionParameterAdapter> =
            Box::new(MockFunctionParameterAdapter::new());

        let created = adapter
            .create_record(42, 5, 0, Some("param1"), Some("first param"), -1)
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter
            .create_record(43, 5, 1, Some("param2"), None, 4)
            .unwrap();
        adapter.create_record(44, 9, 0, None, None, -1).unwrap();

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(PARAMETER_NAME_COL),
            &Field::String(Some("param1".to_string()))
        );

        let ids_in_def = adapter.get_parameter_ids_in_function_def(5).unwrap();
        assert_eq!(ids_in_def.len(), 2);
        assert!(ids_in_def.contains(&Field::Long(Some(0))));
        assert!(ids_in_def.contains(&Field::Long(Some(1))));

        let mut updated = fetched.clone();
        updated.set_field(PARAMETER_NAME_COL, Field::String(Some("renamed".to_string())));
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(PARAMETER_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_key(), &Field::Long(Some(1)));
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(adapter.get_records().unwrap().next().unwrap().is_none());
        assert_eq!(
            adapter.get_parameter_ids_in_function_def(5).unwrap().len(),
            0
        );
    }
}
