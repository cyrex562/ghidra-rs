//! Port of `ghidra.program.database.data.CategoryDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects the
//! concrete version-specific implementation (`CategoryDBAdapterV0`). That concrete adapter has
//! not been ported yet, so this port only models the abstract instance API it implements, as an
//! object-safe trait; the version-selection logic belongs with whichever type ends up owning the
//! concrete adapter. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, Field};

/// Column index of the category name field, as defined by `CategoryDBAdapterV0`.
pub const CATEGORY_NAME_COL: usize = 0;

/// Column index of the parent category id field, as defined by `CategoryDBAdapterV0`.
pub const CATEGORY_PARENT_COL: usize = 1;

/// Database adapter for managing `Category` records.
///
/// Port of `ghidra.program.database.data.CategoryDBAdapter`.
pub trait CategoryDBAdapter {
    /// Gets the category record for the given ID, or `None` if no record with that id exists.
    fn get_record(&self, category_id: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the record in the database.
    ///
    /// `parent_category_id` is `-1` for the root category.
    fn update_record(
        &mut self,
        category_id: i64,
        parent_category_id: i64,
        name: &str,
    ) -> io::Result<()>;

    /// Returns the categoryIDs that have the given parent ID, as `Field::Long` key values.
    fn get_record_ids_with_parent(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Creates a new category with the given name and parent ID, returning its new record.
    fn create_category(&mut self, name: &str, parent_id: i64) -> io::Result<DBRecord>;

    /// Removes the category with the given ID. Returns `true` if a category with that id
    /// existed.
    fn remove_category(&mut self, category_id: i64) -> io::Result<bool>;

    /// Get the record for the root category.
    fn get_root_record(&self) -> io::Result<DBRecord>;

    /// Update the record in the database.
    fn put_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Get the total number of category records.
    fn get_record_count(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use std::cell::RefCell;
    use std::sync::Arc;

    struct MockCategoryDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
    }

    impl MockCategoryDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                0,
                FieldType::Long,
                "Category ID".to_string(),
                vec![FieldType::String, FieldType::Long],
                vec!["Name".to_string(), "Parent ID".to_string()],
                vec![],
            ));
            let adapter = MockCategoryDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(1),
            };
            // Root category always has key 0 and parent -1.
            let mut root = DBRecord::new(adapter.schema.clone(), Field::Long(Some(0)));
            root.set_field(CATEGORY_NAME_COL, Field::String(Some(String::new())));
            root.set_field(CATEGORY_PARENT_COL, Field::Long(Some(-1)));
            adapter.records.borrow_mut().push(root);
            adapter
        }
    }

    impl CategoryDBAdapter for MockCategoryDBAdapter {
        fn get_record(&self, category_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(category_id)))
                .cloned())
        }

        fn update_record(
            &mut self,
            category_id: i64,
            parent_category_id: i64,
            name: &str,
        ) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(rec) = records
                .iter_mut()
                .find(|r| r.get_key() == &Field::Long(Some(category_id)))
            {
                rec.set_field(CATEGORY_NAME_COL, Field::String(Some(name.to_string())));
                rec.set_field(
                    CATEGORY_PARENT_COL,
                    Field::Long(Some(parent_category_id)),
                );
            }
            Ok(())
        }

        fn get_record_ids_with_parent(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(CATEGORY_PARENT_COL), Field::Long(Some(v)) if *v == category_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn create_category(&mut self, name: &str, parent_id: i64) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(CATEGORY_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(CATEGORY_PARENT_COL, Field::Long(Some(parent_id)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn remove_category(&mut self, category_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(category_id)));
            Ok(records.len() != len_before)
        }

        fn get_root_record(&self) -> io::Result<DBRecord> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(0)))
                .cloned()
                .expect("root record always present"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records
                .iter_mut()
                .find(|r| r.get_key() == record.get_key())
            {
                *existing = record.clone();
            }
            Ok(())
        }

        fn get_record_count(&self) -> i32 {
            self.records.borrow().len() as i32
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_categories() {
        let mut adapter: Box<dyn CategoryDBAdapter> = Box::new(MockCategoryDBAdapter::new());

        // Root record exists from construction.
        assert_eq!(adapter.get_record_count(), 1);
        let root = adapter.get_root_record().unwrap();
        assert_eq!(root.get_key(), &Field::Long(Some(0)));

        let child = adapter.create_category("child1", 0).unwrap();
        assert_eq!(adapter.get_record_count(), 2);
        assert_eq!(child.get_key(), &Field::Long(Some(1)));

        let fetched = adapter
            .get_record(1)
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(CATEGORY_NAME_COL),
            &Field::String(Some("child1".to_string()))
        );

        let children = adapter.get_record_ids_with_parent(0).unwrap();
        assert_eq!(children, vec![Field::Long(Some(1))]);

        adapter.update_record(1, 0, "renamed").unwrap();
        let renamed = adapter.get_record(1).unwrap().unwrap();
        assert_eq!(
            renamed.get_field(CATEGORY_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter.remove_category(1).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.get_record(1).unwrap().is_none());

        let removed_again = adapter.remove_category(1).unwrap();
        assert!(!removed_again);
    }
}
