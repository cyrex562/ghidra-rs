use crate::program::model::listing::DataTypeChangeSet;

/// Trait for tracking changes to a trace's data types.
///
/// `TraceChangeSet` extends [`DataTypeChangeSet`] to provide a unified interface for
/// tracking data type changes in trace models, maintaining consistency with the broader
/// change tracking system.
///
/// Port of `ghidra.trace.model.TraceChangeSet`.
pub trait TraceChangeSet: DataTypeChangeSet {}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleTraceChangeSet {
        data_type_changes: Vec<i64>,
        data_type_additions: Vec<i64>,
        category_changes: Vec<i64>,
        category_additions: Vec<i64>,
        source_archive_changes: Vec<i64>,
        source_archive_additions: Vec<i64>,
    }

    impl SimpleTraceChangeSet {
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

    impl crate::framework::model::ChangeSet for SimpleTraceChangeSet {}

    impl DataTypeChangeSet for SimpleTraceChangeSet {
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

    impl TraceChangeSet for SimpleTraceChangeSet {}

    #[test]
    fn trait_object_implements_trace_change_set() {
        let mut cs: Box<dyn TraceChangeSet> = Box::new(SimpleTraceChangeSet::new());
        cs.data_type_changed(42);
        cs.data_type_added(100);
        cs.category_changed(50);
        cs.category_added(75);
        cs.source_archive_changed(10);
        cs.source_archive_added(20);

        assert_eq!(cs.get_data_type_changes(), &[42]);
        assert_eq!(cs.get_data_type_additions(), &[100]);
        assert_eq!(cs.get_category_changes(), &[50]);
        assert_eq!(cs.get_category_additions(), &[75]);
        assert_eq!(cs.get_source_archive_changes(), &[10]);
        assert_eq!(cs.get_source_archive_additions(), &[20]);
    }

    #[test]
    fn trace_change_set_inheritance_works() {
        let mut cs = SimpleTraceChangeSet::new();
        cs.data_type_changed(1);
        cs.data_type_added(2);
        assert_eq!(cs.get_data_type_changes(), &[1]);
        assert_eq!(cs.get_data_type_additions(), &[2]);
    }

    #[test]
    fn multiple_changes_tracked() {
        let mut cs = SimpleTraceChangeSet::new();
        cs.data_type_changed(100);
        cs.data_type_changed(200);
        cs.data_type_changed(300);
        cs.category_changed(10);
        cs.source_archive_changed(5);

        assert_eq!(cs.get_data_type_changes(), &[100, 200, 300]);
        assert_eq!(cs.get_category_changes(), &[10]);
        assert_eq!(cs.get_source_archive_changes(), &[5]);
    }
}
