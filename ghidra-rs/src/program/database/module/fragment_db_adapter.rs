//! Port of `ghidra.program.database.module.FragmentDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects and
//! constructs the single concrete implementation (`FragmentDBAdapterV0`). That concrete adapter
//! has not been ported yet, so this port only models the abstract instance API it implements, as
//! an object-safe trait; the version-selection logic belongs with whichever type ends up owning
//! the concrete adapter(s). This follows the same convention already used for
//! [`CommentHistoryAdapter`](crate::program::database::code::CommentHistoryAdapter) and
//! [`InstDBAdapter`](crate::program::database::code::InstDBAdapter). This trait was itself
//! selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::DBRecord;

/// DB table name prefix for the program tree fragment table. Stands in for
/// `FragmentDBAdapter.FRAGMENT_TABLE_NAME`.
pub const FRAGMENT_TABLE_NAME: &str = "Fragment Table";

/// Column index for a fragment record's name. Stands in for
/// `FragmentDBAdapter.FRAGMENT_NAME_COL` (aliasing `FragmentDBAdapterV0.V0_FRAGMENT_NAME_COL`).
pub const FRAGMENT_NAME_COL: usize = 0;
/// Column index for a fragment record's comments. Stands in for
/// `FragmentDBAdapter.FRAGMENT_COMMENTS_COL` (aliasing
/// `FragmentDBAdapterV0.V0_FRAGMENT_COMMENTS_COL`).
pub const FRAGMENT_COMMENTS_COL: usize = 1;

/// Builds the per-tree fragment table name. Stands in for
/// `FragmentDBAdapter.getTableName(long)`.
pub fn get_table_name(tree_id: i64) -> String {
    format!("{FRAGMENT_TABLE_NAME}{tree_id}")
}

/// Adapter for accessing records in a program tree's Fragment table.
///
/// Port of `ghidra.program.database.module.FragmentDBAdapter`. See the module docs for what was
/// intentionally left out (the static factory/version-selection logic).
pub trait FragmentDBAdapter {
    /// Creates a new fragment record with the given name, as a child of the module with key
    /// `parent_module_id`.
    ///
    /// Stands in for `FragmentDBAdapter.createFragmentRecord(long, String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_fragment_record(&mut self, parent_module_id: i64, name: &str)
        -> io::Result<DBRecord>;

    /// Gets the fragment record with the given key, or `None` if there is no such record.
    ///
    /// Stands in for `FragmentDBAdapter.getFragmentRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_fragment_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Gets the fragment record with the given name, or `None` if there is no such record.
    ///
    /// Stands in for `FragmentDBAdapter.getFragmentRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database, or if more than one
    /// fragment is found with the given name (mirrors the Java adapter's `AssertException`).
    fn get_fragment_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>>;

    /// Updates the given fragment record in the table.
    ///
    /// Stands in for `FragmentDBAdapter.updateFragmentRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_fragment_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Removes the fragment record with the given key. Returns `true` if a record was removed.
    ///
    /// Stands in for `FragmentDBAdapter.removeFragmentRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_fragment_record(&mut self, child_id: i64) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct FragmentRow {
        name: String,
        comments: Option<String>,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String, FieldType::String],
            vec!["Name".to_string(), "Comments".to_string()],
            vec![],
        ))
    }

    struct MockFragmentDBAdapter {
        rows: BTreeMap<i64, FragmentRow>,
        next_key: i64,
    }

    impl MockFragmentDBAdapter {
        fn new() -> Self {
            MockFragmentDBAdapter {
                rows: BTreeMap::new(),
                next_key: 1,
            }
        }

        fn build_record(&self, key: i64, row: &FragmentRow) -> DBRecord {
            use crate::framework::db::Field;

            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_string(FRAGMENT_NAME_COL, Some(row.name.clone()));
            record.set_string(FRAGMENT_COMMENTS_COL, row.comments.clone());
            record
        }
    }

    impl FragmentDBAdapter for MockFragmentDBAdapter {
        fn create_fragment_record(
            &mut self,
            _parent_module_id: i64,
            name: &str,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let row = FragmentRow {
                name: name.to_string(),
                comments: None,
            };
            let record = self.build_record(key, &row);
            self.rows.insert(key, row);
            Ok(record)
        }

        fn get_fragment_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
        }

        fn get_fragment_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
            let mut matches = self.rows.iter().filter(|(_, row)| row.name == name);
            let Some((key, row)) = matches.next() else {
                return Ok(None);
            };
            if matches.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Found more than one fragment named {name}"),
                ));
            }
            Ok(Some(self.build_record(*key, row)))
        }

        fn update_fragment_record(&mut self, record: &DBRecord) -> io::Result<()> {
            use crate::framework::db::Field;

            let key = match record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            let name = match record.get_field(FRAGMENT_NAME_COL) {
                Field::String(Some(v)) => v.clone(),
                _ => String::new(),
            };
            let comments = match record.get_field(FRAGMENT_COMMENTS_COL) {
                Field::String(v) => v.clone(),
                _ => None,
            };
            self.rows.insert(key, FragmentRow { name, comments });
            Ok(())
        }

        fn remove_fragment_record(&mut self, child_id: i64) -> io::Result<bool> {
            Ok(self.rows.remove(&child_id).is_some())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn FragmentDBAdapter> = Box::new(MockFragmentDBAdapter::new());

        assert!(adapter.get_fragment_record(1).unwrap().is_none());

        let rec1 = adapter.create_fragment_record(0, ".text").unwrap();
        let rec2 = adapter.create_fragment_record(0, ".data").unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());

        let fetched = adapter.get_fragment_record_by_name(".text").unwrap();
        assert!(fetched.is_some());

        let mut updated = fetched.unwrap();
        updated.set_string(FRAGMENT_COMMENTS_COL, Some("renamed comment".to_string()));
        adapter.update_fragment_record(&updated).unwrap();

        let refetched = adapter
            .get_fragment_record(match updated.get_key() {
                crate::framework::db::Field::Long(Some(v)) => *v,
                _ => panic!("expected long key"),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            refetched.get_field(FRAGMENT_COMMENTS_COL),
            &crate::framework::db::Field::String(Some("renamed comment".to_string()))
        );

        assert!(adapter
            .remove_fragment_record(match rec2.get_key() {
                crate::framework::db::Field::Long(Some(v)) => *v,
                _ => panic!("expected long key"),
            })
            .unwrap());
        assert!(adapter
            .get_fragment_record_by_name(".data")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_table_name_appends_tree_id() {
        assert_eq!(get_table_name(7), "Fragment Table7");
    }
}
