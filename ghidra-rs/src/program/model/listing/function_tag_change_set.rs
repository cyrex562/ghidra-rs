use crate::framework::model::ChangeSet;

/// Tracks change information on function tags.
///
/// Objects implementing this trait track various change information on function tags,
/// including which tags have been added or modified.
pub trait FunctionTagChangeSet: ChangeSet {
    /// Indicates that a tag has been changed (edited/deleted).
    fn tag_changed(&mut self, id: i64);

    /// Indicates that a tag has been created.
    fn tag_created(&mut self, id: i64);

    /// Returns a list of all tag IDs that have been changed (edited/deleted).
    fn get_tag_changes(&self) -> &[i64];

    /// Returns a list of all tag IDs that have been created.
    fn get_tag_creations(&self) -> &[i64];
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleFunctionTagChangeSet {
        changes: Vec<i64>,
        creations: Vec<i64>,
    }

    impl SimpleFunctionTagChangeSet {
        fn new() -> Self {
            Self {
                changes: Vec::new(),
                creations: Vec::new(),
            }
        }
    }

    impl ChangeSet for SimpleFunctionTagChangeSet {}

    impl FunctionTagChangeSet for SimpleFunctionTagChangeSet {
        fn tag_changed(&mut self, id: i64) {
            if !self.changes.contains(&id) {
                self.changes.push(id);
            }
        }

        fn tag_created(&mut self, id: i64) {
            if !self.creations.contains(&id) {
                self.creations.push(id);
            }
        }

        fn get_tag_changes(&self) -> &[i64] {
            &self.changes
        }

        fn get_tag_creations(&self) -> &[i64] {
            &self.creations
        }
    }

    #[test]
    fn tag_changed_adds_to_changes_list() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_changed(42);
        assert_eq!(cs.get_tag_changes(), &[42]);
    }

    #[test]
    fn tag_created_adds_to_creations_list() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_created(100);
        assert_eq!(cs.get_tag_creations(), &[100]);
    }

    #[test]
    fn tag_changed_does_not_duplicate() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_changed(42);
        cs.tag_changed(42);
        assert_eq!(cs.get_tag_changes(), &[42]);
    }

    #[test]
    fn tag_created_does_not_duplicate() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_created(100);
        cs.tag_created(100);
        assert_eq!(cs.get_tag_creations(), &[100]);
    }

    #[test]
    fn multiple_tag_changes() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_changed(1);
        cs.tag_changed(2);
        cs.tag_changed(3);
        assert_eq!(cs.get_tag_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_tag_creations() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_created(10);
        cs.tag_created(20);
        cs.tag_created(30);
        assert_eq!(cs.get_tag_creations(), &[10, 20, 30]);
    }

    #[test]
    fn changes_and_creations_independent() {
        let mut cs = SimpleFunctionTagChangeSet::new();
        cs.tag_changed(1);
        cs.tag_created(2);
        assert_eq!(cs.get_tag_changes(), &[1]);
        assert_eq!(cs.get_tag_creations(), &[2]);
    }

    #[test]
    fn empty_initially() {
        let cs = SimpleFunctionTagChangeSet::new();
        assert!(cs.get_tag_changes().is_empty());
        assert!(cs.get_tag_creations().is_empty());
    }

    #[test]
    fn trait_object_dispatch() {
        let mut cs: Box<dyn FunctionTagChangeSet> = Box::new(SimpleFunctionTagChangeSet::new());
        cs.tag_changed(5);
        cs.tag_created(10);
        assert_eq!(cs.get_tag_changes(), &[5]);
        assert_eq!(cs.get_tag_creations(), &[10]);
    }
}
