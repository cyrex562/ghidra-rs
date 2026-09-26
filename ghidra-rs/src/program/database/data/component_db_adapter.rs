//! Port of `ghidra.program.database.data.ComponentDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects the
//! concrete version-specific implementation (`ComponentDBAdapterV0`). That concrete adapter has
//! not been ported yet, so this port only models the abstract instance API it implements, as an
//! object-safe trait; the version-selection logic belongs with whichever type ends up owning the
//! concrete adapter. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, Field};

/// Column index of the parent data type id field, as defined by `ComponentDBAdapterV0`.
pub const COMPONENT_PARENT_ID_COL: usize = 0;

/// Column index of the component's offset within its parent, as defined by
/// `ComponentDBAdapterV0`.
pub const COMPONENT_OFFSET_COL: usize = 1;

/// Column index of the component's own data type id, as defined by `ComponentDBAdapterV0`.
pub const COMPONENT_DT_ID_COL: usize = 2;

/// Column index of the component's field name, as defined by `ComponentDBAdapterV0`.
pub const COMPONENT_FIELD_NAME_COL: usize = 3;

/// Column index of the component's comment, as defined by `ComponentDBAdapterV0`.
pub const COMPONENT_COMMENT_COL: usize = 4;

/// Column index of the component's size in bytes, as defined by `ComponentDBAdapterV0`.
pub const COMPONENT_SIZE_COL: usize = 5;

/// Column index of the component's ordinal within its parent, as defined by
/// `ComponentDBAdapterV0`.
pub const COMPONENT_ORDINAL_COL: usize = 6;

/// Adapter to access the Component database table.
///
/// Components are used to specify the individual elements of a composite data type.
///
/// Port of `ghidra.program.database.data.ComponentDBAdapter`.
pub trait ComponentDBAdapter {
    /// Creates a database record for a component data type (an individual member of a composite
    /// data type).
    ///
    /// `data_type_id` is the ID of the data type for this component, `parent_id` is the ID of
    /// the data type that this component is a part of, `length` is the total length of this
    /// component, `ordinal` is the component's ordinal, `offset` is the component's offset,
    /// `field_name` is the component's name (may be `None`), and `comment` is a comment about
    /// this component.
    fn create_record(
        &mut self,
        data_type_id: i64,
        parent_id: i64,
        length: i32,
        ordinal: i32,
        offset: i32,
        field_name: Option<&str>,
        comment: Option<&str>,
    ) -> io::Result<DBRecord>;

    /// Gets the record for the indicated component data type, or `None` if not found.
    fn get_record(&self, component_id: i64) -> io::Result<Option<DBRecord>>;

    /// Removes the component data type record with the specified ID. Returns `true` if the
    /// record was removed.
    fn remove_record(&mut self, component_id: i64) -> io::Result<bool>;

    /// Updates the component data type table with the provided record.
    ///
    /// IMPORTANT: Any modification of the field name should be sanitized (mirroring
    /// `InternalDataTypeComponent.cleanupFieldName`) before this is called.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Gets an array with all of the IDs of the defined components within the composite data
    /// type indicated, as `Field::Long` key values.
    fn get_component_ids_in_composite(&self, composite_id: i64) -> io::Result<Vec<Field>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use std::cell::RefCell;
    use std::sync::Arc;

    struct MockComponentDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
    }

    impl MockComponentDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                0,
                FieldType::Long,
                "Data Type ID".to_string(),
                vec![
                    FieldType::Long,
                    FieldType::Int,
                    FieldType::Long,
                    FieldType::String,
                    FieldType::String,
                    FieldType::Int,
                    FieldType::Int,
                ],
                vec![
                    "Parent".to_string(),
                    "Offset".to_string(),
                    "Data Type ID".to_string(),
                    "Field Name".to_string(),
                    "Comment".to_string(),
                    "Component Size".to_string(),
                    "Ordinal".to_string(),
                ],
                vec![],
            ));
            MockComponentDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
            }
        }
    }

    impl ComponentDBAdapter for MockComponentDBAdapter {
        fn create_record(
            &mut self,
            data_type_id: i64,
            parent_id: i64,
            length: i32,
            ordinal: i32,
            offset: i32,
            field_name: Option<&str>,
            comment: Option<&str>,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(COMPONENT_PARENT_ID_COL, Field::Long(Some(parent_id)));
            rec.set_field(COMPONENT_OFFSET_COL, Field::Int(Some(offset)));
            rec.set_field(COMPONENT_DT_ID_COL, Field::Long(Some(data_type_id)));
            rec.set_field(
                COMPONENT_FIELD_NAME_COL,
                Field::String(field_name.map(str::to_string)),
            );
            rec.set_field(
                COMPONENT_COMMENT_COL,
                Field::String(comment.map(str::to_string)),
            );
            rec.set_field(COMPONENT_SIZE_COL, Field::Int(Some(length)));
            rec.set_field(COMPONENT_ORDINAL_COL, Field::Int(Some(ordinal)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, component_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(component_id)))
                .cloned())
        }

        fn remove_record(&mut self, component_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(component_id)));
            Ok(records.len() != len_before)
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records
                .iter_mut()
                .find(|r| r.get_key() == record.get_key())
            {
                *existing = record.clone();
            }
            Ok(())
        }

        fn get_component_ids_in_composite(&self, composite_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(COMPONENT_PARENT_ID_COL), Field::Long(Some(v)) if *v == composite_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_components() {
        let mut adapter: Box<dyn ComponentDBAdapter> = Box::new(MockComponentDBAdapter::new());

        let created = adapter
            .create_record(42, 7, 4, 0, 0, Some("field0"), Some("first field"))
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));

        let second = adapter
            .create_record(43, 7, 4, 1, 4, Some("field1"), None)
            .unwrap();
        assert_eq!(second.get_key(), &Field::Long(Some(1)));

        let fetched = adapter
            .get_record(0)
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(COMPONENT_FIELD_NAME_COL),
            &Field::String(Some("field0".to_string()))
        );
        assert_eq!(
            fetched.get_field(COMPONENT_COMMENT_COL),
            &Field::String(Some("first field".to_string()))
        );

        let ids = adapter.get_component_ids_in_composite(7).unwrap();
        assert_eq!(ids, vec![Field::Long(Some(0)), Field::Long(Some(1))]);

        let mut updated = fetched.clone();
        updated.set_field(
            COMPONENT_FIELD_NAME_COL,
            Field::String(Some("renamed".to_string())),
        );
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(COMPONENT_FIELD_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert!(adapter.get_record(0).unwrap().is_none());
        assert_eq!(
            adapter.get_component_ids_in_composite(7).unwrap(),
            vec![Field::Long(Some(1))]
        );

        let removed_again = adapter.remove_record(0).unwrap();
        assert!(!removed_again);
    }
}
