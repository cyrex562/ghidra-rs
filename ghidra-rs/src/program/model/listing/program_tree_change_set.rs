use crate::framework::model::ChangeSet;

/// Tracks change information on a program tree manager.
///
/// Objects implementing this trait track various change information on a program tree manager,
/// including which program trees have been added or modified.
pub trait ProgramTreeChangeSet: ChangeSet {
    /// Adds the program tree ID to the list of trees that have changed.
    fn program_tree_changed(&mut self, id: i64);

    /// Adds the program tree ID to the list of trees that have been added.
    fn program_tree_added(&mut self, id: i64);

    /// Returns the list of program tree IDs that have changed.
    fn get_program_tree_changes(&self) -> &[i64];

    /// Returns the list of program tree IDs that have been added.
    fn get_program_tree_additions(&self) -> &[i64];
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleProgramTreeChangeSet {
        changes: Vec<i64>,
        additions: Vec<i64>,
    }

    impl SimpleProgramTreeChangeSet {
        fn new() -> Self {
            Self {
                changes: Vec::new(),
                additions: Vec::new(),
            }
        }
    }

    impl ChangeSet for SimpleProgramTreeChangeSet {}

    impl ProgramTreeChangeSet for SimpleProgramTreeChangeSet {
        fn program_tree_changed(&mut self, id: i64) {
            if !self.changes.contains(&id) {
                self.changes.push(id);
            }
        }

        fn program_tree_added(&mut self, id: i64) {
            if !self.additions.contains(&id) {
                self.additions.push(id);
            }
        }

        fn get_program_tree_changes(&self) -> &[i64] {
            &self.changes
        }

        fn get_program_tree_additions(&self) -> &[i64] {
            &self.additions
        }
    }

    #[test]
    fn program_tree_changed_adds_to_changes_list() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_changed(42);
        assert_eq!(cs.get_program_tree_changes(), &[42]);
    }

    #[test]
    fn program_tree_added_adds_to_additions_list() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_added(100);
        assert_eq!(cs.get_program_tree_additions(), &[100]);
    }

    #[test]
    fn program_tree_changed_does_not_duplicate() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_changed(42);
        cs.program_tree_changed(42);
        assert_eq!(cs.get_program_tree_changes(), &[42]);
    }

    #[test]
    fn program_tree_added_does_not_duplicate() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_added(100);
        cs.program_tree_added(100);
        assert_eq!(cs.get_program_tree_additions(), &[100]);
    }

    #[test]
    fn multiple_program_tree_changes() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_changed(1);
        cs.program_tree_changed(2);
        cs.program_tree_changed(3);
        assert_eq!(cs.get_program_tree_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_program_tree_additions() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_added(10);
        cs.program_tree_added(20);
        cs.program_tree_added(30);
        assert_eq!(cs.get_program_tree_additions(), &[10, 20, 30]);
    }

    #[test]
    fn changes_and_additions_independent() {
        let mut cs = SimpleProgramTreeChangeSet::new();
        cs.program_tree_changed(1);
        cs.program_tree_added(2);
        assert_eq!(cs.get_program_tree_changes(), &[1]);
        assert_eq!(cs.get_program_tree_additions(), &[2]);
    }

    #[test]
    fn empty_initially() {
        let cs = SimpleProgramTreeChangeSet::new();
        assert!(cs.get_program_tree_changes().is_empty());
        assert!(cs.get_program_tree_additions().is_empty());
    }

    #[test]
    fn trait_object_dispatch() {
        let mut cs: Box<dyn ProgramTreeChangeSet> = Box::new(SimpleProgramTreeChangeSet::new());
        cs.program_tree_changed(5);
        cs.program_tree_added(10);
        assert_eq!(cs.get_program_tree_changes(), &[5]);
        assert_eq!(cs.get_program_tree_additions(), &[10]);
    }
}
