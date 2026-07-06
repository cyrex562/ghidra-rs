use crate::framework::model::ChangeSet;

/// Tracks change information on a data type manager.
///
/// Objects implementing this trait track various change information on a data type manager,
/// including which data types, categories, and source archives have been added or modified.
pub trait DataTypeChangeSet: ChangeSet {
    /// Adds the data type ID to the list of changed data types.
    fn data_type_changed(&mut self, id: i64);

    /// Adds the data type ID to the list of added data types.
    fn data_type_added(&mut self, id: i64);

    /// Returns a list of data type IDs that have changed.
    fn get_data_type_changes(&self) -> &[i64];

    /// Returns a list of data type IDs that have been added.
    fn get_data_type_additions(&self) -> &[i64];

    /// Adds the data type category ID to the list of categories that have changed.
    fn category_changed(&mut self, id: i64);

    /// Adds the data type category ID to the list of categories that have been added.
    fn category_added(&mut self, id: i64);

    /// Returns the list of category IDs that have changed.
    fn get_category_changes(&self) -> &[i64];

    /// Returns the list of category IDs that have been added.
    fn get_category_additions(&self) -> &[i64];

    /// Adds the data type source archive ID to the list of changed data type archive IDs.
    fn source_archive_changed(&mut self, id: i64);

    /// Adds the data type source archive ID to the list of added data type archive IDs.
    fn source_archive_added(&mut self, id: i64);

    /// Returns a list of data type source archive IDs that have changed.
    fn get_source_archive_changes(&self) -> &[i64];

    /// Returns a list of data type source archive IDs that have been added.
    fn get_source_archive_additions(&self) -> &[i64];
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleDataTypeChangeSet {
        data_type_changes: Vec<i64>,
        data_type_additions: Vec<i64>,
        category_changes: Vec<i64>,
        category_additions: Vec<i64>,
        source_archive_changes: Vec<i64>,
        source_archive_additions: Vec<i64>,
    }

    impl SimpleDataTypeChangeSet {
        fn new() -> Self {
            Self {
                data_type_changes: Vec::new(),
                data_type_additions: Vec::new(),
                category_changes: Vec::new(),
                category_additions: Vec::new(),
                source_archive_changes: Vec::new(),
                source_archive_additions: Vec::new(),
            }
        }
    }

    impl ChangeSet for SimpleDataTypeChangeSet {}

    impl DataTypeChangeSet for SimpleDataTypeChangeSet {
        fn data_type_changed(&mut self, id: i64) {
            if !self.data_type_changes.contains(&id) {
                self.data_type_changes.push(id);
            }
        }

        fn data_type_added(&mut self, id: i64) {
            if !self.data_type_additions.contains(&id) {
                self.data_type_additions.push(id);
            }
        }

        fn get_data_type_changes(&self) -> &[i64] {
            &self.data_type_changes
        }

        fn get_data_type_additions(&self) -> &[i64] {
            &self.data_type_additions
        }

        fn category_changed(&mut self, id: i64) {
            if !self.category_changes.contains(&id) {
                self.category_changes.push(id);
            }
        }

        fn category_added(&mut self, id: i64) {
            if !self.category_additions.contains(&id) {
                self.category_additions.push(id);
            }
        }

        fn get_category_changes(&self) -> &[i64] {
            &self.category_changes
        }

        fn get_category_additions(&self) -> &[i64] {
            &self.category_additions
        }

        fn source_archive_changed(&mut self, id: i64) {
            if !self.source_archive_changes.contains(&id) {
                self.source_archive_changes.push(id);
            }
        }

        fn source_archive_added(&mut self, id: i64) {
            if !self.source_archive_additions.contains(&id) {
                self.source_archive_additions.push(id);
            }
        }

        fn get_source_archive_changes(&self) -> &[i64] {
            &self.source_archive_changes
        }

        fn get_source_archive_additions(&self) -> &[i64] {
            &self.source_archive_additions
        }
    }

    #[test]
    fn data_type_changed_adds_to_changes_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_changed(42);
        assert_eq!(cs.get_data_type_changes(), &[42]);
    }

    #[test]
    fn data_type_added_adds_to_additions_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_added(100);
        assert_eq!(cs.get_data_type_additions(), &[100]);
    }

    #[test]
    fn data_type_changed_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_changed(42);
        cs.data_type_changed(42);
        assert_eq!(cs.get_data_type_changes(), &[42]);
    }

    #[test]
    fn data_type_added_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_added(100);
        cs.data_type_added(100);
        assert_eq!(cs.get_data_type_additions(), &[100]);
    }

    #[test]
    fn category_changed_adds_to_changes_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_changed(10);
        assert_eq!(cs.get_category_changes(), &[10]);
    }

    #[test]
    fn category_added_adds_to_additions_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_added(20);
        assert_eq!(cs.get_category_additions(), &[20]);
    }

    #[test]
    fn category_changed_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_changed(10);
        cs.category_changed(10);
        assert_eq!(cs.get_category_changes(), &[10]);
    }

    #[test]
    fn category_added_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_added(20);
        cs.category_added(20);
        assert_eq!(cs.get_category_additions(), &[20]);
    }

    #[test]
    fn source_archive_changed_adds_to_changes_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_changed(5);
        assert_eq!(cs.get_source_archive_changes(), &[5]);
    }

    #[test]
    fn source_archive_added_adds_to_additions_list() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_added(15);
        assert_eq!(cs.get_source_archive_additions(), &[15]);
    }

    #[test]
    fn source_archive_changed_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_changed(5);
        cs.source_archive_changed(5);
        assert_eq!(cs.get_source_archive_changes(), &[5]);
    }

    #[test]
    fn source_archive_added_does_not_duplicate() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_added(15);
        cs.source_archive_added(15);
        assert_eq!(cs.get_source_archive_additions(), &[15]);
    }

    #[test]
    fn multiple_data_type_changes() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_changed(1);
        cs.data_type_changed(2);
        cs.data_type_changed(3);
        assert_eq!(cs.get_data_type_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_data_type_additions() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_added(10);
        cs.data_type_added(20);
        cs.data_type_added(30);
        assert_eq!(cs.get_data_type_additions(), &[10, 20, 30]);
    }

    #[test]
    fn multiple_category_changes() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_changed(1);
        cs.category_changed(2);
        cs.category_changed(3);
        assert_eq!(cs.get_category_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_category_additions() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.category_added(10);
        cs.category_added(20);
        cs.category_added(30);
        assert_eq!(cs.get_category_additions(), &[10, 20, 30]);
    }

    #[test]
    fn multiple_source_archive_changes() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_changed(1);
        cs.source_archive_changed(2);
        cs.source_archive_changed(3);
        assert_eq!(cs.get_source_archive_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_source_archive_additions() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.source_archive_added(10);
        cs.source_archive_added(20);
        cs.source_archive_added(30);
        assert_eq!(cs.get_source_archive_additions(), &[10, 20, 30]);
    }

    #[test]
    fn changes_and_additions_independent() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_changed(1);
        cs.data_type_added(2);
        assert_eq!(cs.get_data_type_changes(), &[1]);
        assert_eq!(cs.get_data_type_additions(), &[2]);
    }

    #[test]
    fn all_track_types_independent() {
        let mut cs = SimpleDataTypeChangeSet::new();
        cs.data_type_changed(1);
        cs.category_changed(2);
        cs.source_archive_changed(3);
        assert_eq!(cs.get_data_type_changes(), &[1]);
        assert_eq!(cs.get_category_changes(), &[2]);
        assert_eq!(cs.get_source_archive_changes(), &[3]);
    }

    #[test]
    fn empty_initially() {
        let cs = SimpleDataTypeChangeSet::new();
        assert!(cs.get_data_type_changes().is_empty());
        assert!(cs.get_data_type_additions().is_empty());
        assert!(cs.get_category_changes().is_empty());
        assert!(cs.get_category_additions().is_empty());
        assert!(cs.get_source_archive_changes().is_empty());
        assert!(cs.get_source_archive_additions().is_empty());
    }

    #[test]
    fn trait_object_dispatch() {
        let mut cs: Box<dyn DataTypeChangeSet> = Box::new(SimpleDataTypeChangeSet::new());
        cs.data_type_changed(5);
        cs.data_type_added(10);
        cs.category_changed(15);
        cs.category_added(20);
        cs.source_archive_changed(25);
        cs.source_archive_added(30);
        assert_eq!(cs.get_data_type_changes(), &[5]);
        assert_eq!(cs.get_data_type_additions(), &[10]);
        assert_eq!(cs.get_category_changes(), &[15]);
        assert_eq!(cs.get_category_additions(), &[20]);
        assert_eq!(cs.get_source_archive_changes(), &[25]);
        assert_eq!(cs.get_source_archive_additions(), &[30]);
    }
}
