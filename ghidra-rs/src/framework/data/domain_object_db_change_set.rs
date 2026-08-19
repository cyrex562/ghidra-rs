use super::super::db::DBChangeSet;

/// Extends `DBChangeSet` providing methods which facilitate transaction synchronization
/// with the domain object's DBHandle.
///
/// Port of `ghidra.framework.data.DomainObjectDBChangeSet`.
pub trait DomainObjectDBChangeSet: DBChangeSet {
    /// Resets the change sets after a save.
    fn clear_undo(&mut self, is_checked_out: bool);

    /// Undo the last change data transaction.
    fn undo(&mut self);

    /// Redo the change data transaction associated with the last Undo.
    fn redo(&mut self);

    /// Set the undo/redo stack depth.
    ///
    /// # Arguments
    ///
    /// * `max_undos` - the maximum number of undo operations to retain
    fn set_max_undos(&mut self, max_undos: i32);

    /// Clears the undo/redo stack.
    fn clear_undo_stack(&mut self);

    /// Start change data transaction.
    fn start_transaction(&mut self);

    /// End change data transaction.
    ///
    /// # Arguments
    ///
    /// * `commit` - if true transaction data is committed,
    ///              otherwise transaction data is discarded
    fn end_transaction(&mut self, commit: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;
    use std::io;

    struct MockDomainObjectChangeSet {
        clear_undo_called: Vec<bool>,
        clear_undo_stack_called: bool,
        undo_called: bool,
        redo_called: bool,
        set_max_undos_called: Vec<i32>,
        start_transaction_called: bool,
        end_transaction_calls: Vec<bool>,
    }

    impl MockDomainObjectChangeSet {
        fn new() -> Self {
            Self {
                clear_undo_called: Vec::new(),
                clear_undo_stack_called: false,
                undo_called: false,
                redo_called: false,
                set_max_undos_called: Vec::new(),
                start_transaction_called: false,
                end_transaction_calls: Vec::new(),
            }
        }
    }

    impl DBChangeSet for MockDomainObjectChangeSet {
        fn read(&mut self, _dbh: &DBHandle) -> io::Result<()> {
            Ok(())
        }

        fn write(&mut self, _dbh: &DBHandle, _is_recovery_save: bool) -> io::Result<()> {
            Ok(())
        }
    }

    impl DomainObjectDBChangeSet for MockDomainObjectChangeSet {
        fn clear_undo(&mut self, is_checked_out: bool) {
            self.clear_undo_called.push(is_checked_out);
        }

        fn undo(&mut self) {
            self.undo_called = true;
        }

        fn redo(&mut self) {
            self.redo_called = true;
        }

        fn set_max_undos(&mut self, max_undos: i32) {
            self.set_max_undos_called.push(max_undos);
        }

        fn clear_undo_stack(&mut self) {
            self.clear_undo_stack_called = true;
        }

        fn start_transaction(&mut self) {
            self.start_transaction_called = true;
        }

        fn end_transaction(&mut self, commit: bool) {
            self.end_transaction_calls.push(commit);
        }
    }

    #[test]
    fn clear_undo_with_checked_out_true() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.clear_undo(true);
        assert_eq!(mock.clear_undo_called.len(), 1);
        assert_eq!(mock.clear_undo_called[0], true);
    }

    #[test]
    fn clear_undo_with_checked_out_false() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.clear_undo(false);
        assert_eq!(mock.clear_undo_called.len(), 1);
        assert_eq!(mock.clear_undo_called[0], false);
    }

    #[test]
    fn clear_undo_stack() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.clear_undo_stack();
        assert!(mock.clear_undo_stack_called);
    }

    #[test]
    fn undo() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.undo();
        assert!(mock.undo_called);
    }

    #[test]
    fn redo() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.redo();
        assert!(mock.redo_called);
    }

    #[test]
    fn set_max_undos() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.set_max_undos(10);
        assert_eq!(mock.set_max_undos_called.len(), 1);
        assert_eq!(mock.set_max_undos_called[0], 10);
    }

    #[test]
    fn set_max_undos_zero() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.set_max_undos(0);
        assert_eq!(mock.set_max_undos_called.len(), 1);
        assert_eq!(mock.set_max_undos_called[0], 0);
    }

    #[test]
    fn start_transaction() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.start_transaction();
        assert!(mock.start_transaction_called);
    }

    #[test]
    fn end_transaction_with_commit_true() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.end_transaction(true);
        assert_eq!(mock.end_transaction_calls.len(), 1);
        assert_eq!(mock.end_transaction_calls[0], true);
    }

    #[test]
    fn end_transaction_with_commit_false() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.end_transaction(false);
        assert_eq!(mock.end_transaction_calls.len(), 1);
        assert_eq!(mock.end_transaction_calls[0], false);
    }

    #[test]
    fn transaction_sequence() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.start_transaction();
        mock.end_transaction(true);
        assert!(mock.start_transaction_called);
        assert_eq!(mock.end_transaction_calls.len(), 1);
        assert_eq!(mock.end_transaction_calls[0], true);
    }

    #[test]
    fn multiple_undo_redo() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.undo();
        mock.redo();
        mock.undo();
        assert!(mock.undo_called);
        assert!(mock.redo_called);
    }

    #[test]
    fn all_methods_together() {
        let mut mock = MockDomainObjectChangeSet::new();
        mock.start_transaction();
        mock.end_transaction(true);
        mock.set_max_undos(50);
        mock.undo();
        mock.redo();
        mock.clear_undo(false);
        mock.clear_undo_stack();

        assert!(mock.start_transaction_called);
        assert_eq!(mock.end_transaction_calls.len(), 1);
        assert_eq!(mock.set_max_undos_called.len(), 1);
        assert!(mock.undo_called);
        assert!(mock.redo_called);
        assert_eq!(mock.clear_undo_called.len(), 1);
        assert!(mock.clear_undo_stack_called);
    }
}
