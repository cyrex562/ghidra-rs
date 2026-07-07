use super::{DataTypeChangeSet, DomainObjectChangeSet};

/// Tracks change information on a data type archive.
///
/// Objects implementing this trait track various change information on a data type archive,
/// including data types, categories, and source archives that have been added or modified.
pub trait DataTypeArchiveChangeSet: DomainObjectChangeSet + DataTypeChangeSet {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::ChangeSet;

    struct TestChangeSet {
        has_changes: bool,
        data_type_changes: Vec<i64>,
    }

    impl DomainObjectChangeSet for TestChangeSet {
        fn has_changes(&self) -> bool {
            self.has_changes
        }
    }

    impl ChangeSet for TestChangeSet {}

    impl DataTypeChangeSet for TestChangeSet {
        fn data_type_changed(&mut self, id: i64) {
            if !self.data_type_changes.contains(&id) {
                self.data_type_changes.push(id);
            }
        }

        fn data_type_added(&mut self, _id: i64) {}

        fn get_data_type_changes(&self) -> &[i64] {
            &self.data_type_changes
        }

        fn get_data_type_additions(&self) -> &[i64] {
            &[]
        }

        fn category_changed(&mut self, _id: i64) {}

        fn category_added(&mut self, _id: i64) {}

        fn get_category_changes(&self) -> &[i64] {
            &[]
        }

        fn get_category_additions(&self) -> &[i64] {
            &[]
        }

        fn source_archive_changed(&mut self, _id: i64) {}

        fn source_archive_added(&mut self, _id: i64) {}

        fn get_source_archive_changes(&self) -> &[i64] {
            &[]
        }

        fn get_source_archive_additions(&self) -> &[i64] {
            &[]
        }
    }

    impl DataTypeArchiveChangeSet for TestChangeSet {}

    #[test]
    fn implements_domain_object_change_set() {
        let cs: TestChangeSet = TestChangeSet {
            has_changes: true,
            data_type_changes: vec![],
        };
        assert!(cs.has_changes());
    }

    #[test]
    fn implements_data_type_change_set() {
        let mut cs: TestChangeSet = TestChangeSet {
            has_changes: false,
            data_type_changes: vec![],
        };
        cs.data_type_changed(42);
        assert_eq!(cs.get_data_type_changes(), &[42]);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut cs: Box<dyn DataTypeArchiveChangeSet> = Box::new(TestChangeSet {
            has_changes: true,
            data_type_changes: vec![],
        });
        cs.data_type_changed(100);
        assert_eq!(cs.get_data_type_changes(), &[100]);
        assert!(cs.has_changes());
    }

    #[test]
    fn combines_both_trait_behaviors() {
        let mut cs: TestChangeSet = TestChangeSet {
            has_changes: true,
            data_type_changes: vec![],
        };
        cs.data_type_changed(1);
        cs.data_type_changed(2);
        assert_eq!(cs.get_data_type_changes(), &[1, 2]);
        assert!(cs.has_changes());
    }
}
