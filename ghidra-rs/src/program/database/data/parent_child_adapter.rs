//! Port of `ghidra.program.database.data.ParentChildAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`ParentChildDBAdapterV0`/`ParentChildDBAdapterNoTable`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapters. This trait was itself
//! selected as a dependency-cycle cut-point.

use std::collections::HashSet;
use std::io;

/// Name of the database table used to store parent/child datatype associations.
pub const PARENT_CHILD_TABLE_NAME: &str = "DT_PARENT_CHILD";

/// Adapter for the custom parent/child association table.
///
/// Port of `ghidra.program.database.data.ParentChildAdapter`.
pub trait ParentChildAdapter {
    /// Returns `true` if the underlying table still needs to be initialized (e.g. following an
    /// upgrade from a version with no parent/child table at all).
    fn needs_initializing(&self) -> bool;

    /// Create a new parent-child association record.
    fn create_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()>;

    /// Remove a parent-child association record.
    fn remove_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()>;

    /// Get the unique set of child IDs associated with the specified parent ID.
    /// Since a parent may have duplicate parent-child records, this method
    /// avoids returning the same child more than once.
    fn get_child_ids(&self, parent_id: i64) -> io::Result<HashSet<i64>>;

    /// Get the unique set of parent IDs associated with the specified child ID.
    /// Since composite parents may have duplicate parent-child records, this method
    /// avoids returning the same parent more than once.
    fn get_parent_ids(&self, child_id: i64) -> io::Result<HashSet<i64>>;

    /// Determine if there is one or more parents associated with the specified child ID.
    fn has_parent(&self, child_id: i64) -> io::Result<bool>;

    /// Remove all parent-child association records for the specified parent ID.
    fn remove_all_records_for_parent(&mut self, parent_id: i64) -> io::Result<()>;

    /// Remove all parent-child association records for the specified child ID.
    fn remove_all_records_for_child(&mut self, child_id: i64) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct MockParentChildAdapter {
        records: Vec<(i64, i64)>,
        needs_initializing: bool,
    }

    impl MockParentChildAdapter {
        fn new() -> Self {
            MockParentChildAdapter {
                records: Vec::new(),
                needs_initializing: false,
            }
        }
    }

    impl ParentChildAdapter for MockParentChildAdapter {
        fn needs_initializing(&self) -> bool {
            self.needs_initializing
        }

        fn create_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()> {
            self.records.push((parent_id, child_id));
            Ok(())
        }

        fn remove_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()> {
            self.records.retain(|&(p, c)| !(p == parent_id && c == child_id));
            Ok(())
        }

        fn get_child_ids(&self, parent_id: i64) -> io::Result<HashSet<i64>> {
            Ok(self
                .records
                .iter()
                .filter(|&&(p, _)| p == parent_id)
                .map(|&(_, c)| c)
                .collect())
        }

        fn get_parent_ids(&self, child_id: i64) -> io::Result<HashSet<i64>> {
            Ok(self
                .records
                .iter()
                .filter(|&&(_, c)| c == child_id)
                .map(|&(p, _)| p)
                .collect())
        }

        fn has_parent(&self, child_id: i64) -> io::Result<bool> {
            Ok(self.records.iter().any(|&(_, c)| c == child_id))
        }

        fn remove_all_records_for_parent(&mut self, parent_id: i64) -> io::Result<()> {
            self.records.retain(|&(p, _)| p != parent_id);
            Ok(())
        }

        fn remove_all_records_for_child(&mut self, child_id: i64) -> io::Result<()> {
            self.records.retain(|&(_, c)| c != child_id);
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_associations() {
        let mut adapter: Box<dyn ParentChildAdapter> = Box::new(MockParentChildAdapter::new());

        assert!(!adapter.needs_initializing());

        adapter.create_record(1, 10).unwrap();
        adapter.create_record(1, 11).unwrap();
        adapter.create_record(2, 11).unwrap();
        // Duplicate parent-child record; should be deduplicated by the id-set accessors.
        adapter.create_record(1, 10).unwrap();

        let children_of_1: HashSet<i64> = adapter.get_child_ids(1).unwrap();
        assert_eq!(children_of_1, HashSet::from([10, 11]));

        let parents_of_11: HashSet<i64> = adapter.get_parent_ids(11).unwrap();
        assert_eq!(parents_of_11, HashSet::from([1, 2]));

        assert!(adapter.has_parent(10).unwrap());
        assert!(!adapter.has_parent(99).unwrap());

        adapter.remove_record(1, 10).unwrap();
        assert_eq!(adapter.get_child_ids(1).unwrap(), HashSet::from([11]));
        assert!(!adapter.has_parent(10).unwrap());

        adapter.remove_all_records_for_child(11).unwrap();
        assert!(!adapter.has_parent(11).unwrap());
        assert!(adapter.get_child_ids(2).unwrap().is_empty());

        adapter.remove_all_records_for_parent(1).unwrap();
        assert!(adapter.get_child_ids(1).unwrap().is_empty());
    }
}
