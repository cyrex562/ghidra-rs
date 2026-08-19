//! Port of `ghidra.program.database.data.EnumValueDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`EnumValueDBAdapterV0`/`V1`/`NoTable`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordTranslator};
use crate::program::util::DBRecordAdapter;

/// Name of the database table used to store enumeration data type values.
pub const ENUM_VALUE_TABLE_NAME: &str = "Enumeration Values";

/// Column index of the enum value's name, as defined by `EnumValueDBAdapterV1`.
pub const ENUMVAL_NAME_COL: usize = 0;

/// Column index of the enum value's numeric value, as defined by `EnumValueDBAdapterV1`.
pub const ENUMVAL_VALUE_COL: usize = 1;

/// Column index of the enum value's owning enum datatype ID, as defined by
/// `EnumValueDBAdapterV1`.
pub const ENUMVAL_ID_COL: usize = 2;

/// Column index of the enum value's comment, as defined by `EnumValueDBAdapterV1`.
pub const ENUMVAL_COMMENT_COL: usize = 3;

/// Adapter to access the Enumeration data type values table.
///
/// Port of `ghidra.program.database.data.EnumValueDBAdapter`.
pub trait EnumValueDBAdapter: DBRecordAdapter + RecordTranslator {
    /// Create new enum value record corresponding to the specified enum datatype ID.
    ///
    /// `enum_id` is the enum datatype ID, `name` is the value name, `value` is the numeric
    /// value, and `comment` is the field comment.
    fn create_record(
        &mut self,
        enum_id: i64,
        name: &str,
        value: i64,
        comment: Option<&str>,
    ) -> io::Result<()>;

    /// Get the enum value record which corresponds to the specified value record ID, or `None`
    /// if not found.
    fn get_record(&self, value_id: i64) -> io::Result<Option<DBRecord>>;

    /// Deletes the table; used when upgrading.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Remove the record for the given enum value ID.
    fn remove_record(&mut self, value_id: i64) -> io::Result<()>;

    /// Updates the enum data type values table with the provided record.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Get enum value record IDs which correspond to the specified enum datatype ID, as
    /// `Field::Long` values.
    fn get_value_ids_in_enum(&self, enum_id: i64) -> io::Result<Vec<Field>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, RecordIterator, Schema};
    use std::cell::RefCell;
    use std::sync::Arc;

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

    struct MockEnumValueDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockEnumValueDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Enum Value ID".to_string(),
                vec![
                    FieldType::String,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::String,
                ],
                vec![
                    "Name".to_string(),
                    "Value".to_string(),
                    "Enum ID".to_string(),
                    "Comment".to_string(),
                ],
                vec![],
            ));
            MockEnumValueDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockEnumValueDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl RecordTranslator for MockEnumValueDBAdapter {
        fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
            Ok(old_record)
        }
    }

    impl EnumValueDBAdapter for MockEnumValueDBAdapter {
        fn create_record(
            &mut self,
            enum_id: i64,
            name: &str,
            value: i64,
            comment: Option<&str>,
        ) -> io::Result<()> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(ENUMVAL_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(ENUMVAL_VALUE_COL, Field::Long(Some(value)));
            rec.set_field(ENUMVAL_ID_COL, Field::Long(Some(enum_id)));
            rec.set_field(
                ENUMVAL_COMMENT_COL,
                Field::String(comment.map(str::to_string)),
            );
            self.records.borrow_mut().push(rec);
            Ok(())
        }

        fn get_record(&self, value_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(value_id)))
                .cloned())
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn remove_record(&mut self, value_id: i64) -> io::Result<()> {
            self.records
                .borrow_mut()
                .retain(|r| r.get_key() != &Field::Long(Some(value_id)));
            Ok(())
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn get_value_ids_in_enum(&self, enum_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(ENUMVAL_ID_COL), Field::Long(Some(v)) if *v == enum_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_enum_values() {
        let mut adapter: Box<dyn EnumValueDBAdapter> = Box::new(MockEnumValueDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        adapter
            .create_record(5, "Red", 0, Some("the color red"))
            .unwrap();
        adapter.create_record(5, "Green", 1, None).unwrap();
        adapter.create_record(7, "On", 1, None).unwrap();

        assert_eq!(adapter.get_record_count(), 3);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(ENUMVAL_NAME_COL),
            &Field::String(Some("Red".to_string()))
        );
        assert_eq!(fetched.get_field(ENUMVAL_VALUE_COL), &Field::Long(Some(0)));

        let ids_in_enum = adapter.get_value_ids_in_enum(5).unwrap();
        assert_eq!(ids_in_enum.len(), 2);
        assert_eq!(adapter.get_value_ids_in_enum(7).unwrap().len(), 1);

        let mut updated = fetched.clone();
        updated.set_field(ENUMVAL_NAME_COL, Field::String(Some("Crimson".to_string())));
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(ENUMVAL_NAME_COL),
            &Field::String(Some("Crimson".to_string()))
        );

        let translated = adapter.translate_record(refetched.clone()).unwrap();
        assert_eq!(translated.get_key(), refetched.get_key());

        adapter.remove_record(0).unwrap();
        assert_eq!(adapter.get_record_count(), 2);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(
                first.get_field(ENUMVAL_NAME_COL),
                &Field::String(Some("Green".to_string()))
            );
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}
