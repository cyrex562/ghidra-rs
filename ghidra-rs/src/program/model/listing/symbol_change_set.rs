use crate::framework::model::ChangeSet;

/// Tracks change information on a symbol manager.
///
/// Objects implementing this trait track various change information on a symbol manager,
/// including which symbols have been added or modified.
pub trait SymbolChangeSet: ChangeSet {
    /// Adds the symbol ID to the list of symbols that have changed.
    fn symbol_changed(&mut self, id: i64);

    /// Adds the symbol ID to the list of symbols that have been added.
    fn symbol_added(&mut self, id: i64);

    /// Returns the list of symbol IDs that have changed.
    fn get_symbol_changes(&self) -> &[i64];

    /// Returns the list of symbol IDs that have been added.
    fn get_symbol_additions(&self) -> &[i64];
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleSymbolChangeSet {
        changes: Vec<i64>,
        additions: Vec<i64>,
    }

    impl SimpleSymbolChangeSet {
        fn new() -> Self {
            Self {
                changes: Vec::new(),
                additions: Vec::new(),
            }
        }
    }

    impl ChangeSet for SimpleSymbolChangeSet {}

    impl SymbolChangeSet for SimpleSymbolChangeSet {
        fn symbol_changed(&mut self, id: i64) {
            if !self.changes.contains(&id) {
                self.changes.push(id);
            }
        }

        fn symbol_added(&mut self, id: i64) {
            if !self.additions.contains(&id) {
                self.additions.push(id);
            }
        }

        fn get_symbol_changes(&self) -> &[i64] {
            &self.changes
        }

        fn get_symbol_additions(&self) -> &[i64] {
            &self.additions
        }
    }

    #[test]
    fn symbol_changed_adds_to_changes_list() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_changed(42);
        assert_eq!(cs.get_symbol_changes(), &[42]);
    }

    #[test]
    fn symbol_added_adds_to_additions_list() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_added(100);
        assert_eq!(cs.get_symbol_additions(), &[100]);
    }

    #[test]
    fn symbol_changed_does_not_duplicate() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_changed(42);
        cs.symbol_changed(42);
        assert_eq!(cs.get_symbol_changes(), &[42]);
    }

    #[test]
    fn symbol_added_does_not_duplicate() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_added(100);
        cs.symbol_added(100);
        assert_eq!(cs.get_symbol_additions(), &[100]);
    }

    #[test]
    fn multiple_symbol_changes() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_changed(1);
        cs.symbol_changed(2);
        cs.symbol_changed(3);
        assert_eq!(cs.get_symbol_changes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_symbol_additions() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_added(10);
        cs.symbol_added(20);
        cs.symbol_added(30);
        assert_eq!(cs.get_symbol_additions(), &[10, 20, 30]);
    }

    #[test]
    fn changes_and_additions_independent() {
        let mut cs = SimpleSymbolChangeSet::new();
        cs.symbol_changed(1);
        cs.symbol_added(2);
        assert_eq!(cs.get_symbol_changes(), &[1]);
        assert_eq!(cs.get_symbol_additions(), &[2]);
    }

    #[test]
    fn empty_initially() {
        let cs = SimpleSymbolChangeSet::new();
        assert!(cs.get_symbol_changes().is_empty());
        assert!(cs.get_symbol_additions().is_empty());
    }

    #[test]
    fn trait_object_dispatch() {
        let mut cs: Box<dyn SymbolChangeSet> = Box::new(SimpleSymbolChangeSet::new());
        cs.symbol_changed(5);
        cs.symbol_added(10);
        assert_eq!(cs.get_symbol_changes(), &[5]);
        assert_eq!(cs.get_symbol_additions(), &[10]);
    }
}
