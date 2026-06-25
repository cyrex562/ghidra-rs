/// Listener for lock/unlock state changes in a composite data type editor.
///
/// This trait provides a notification method for the lock/unlock mode of the
/// composite data editor. The lock/unlock mode controls whether or not the size
/// of the composite data type being edited can change.
pub trait CompositeEditorLockListener {
    /// Lock state constant indicating the editor is locked.
    const EDITOR_LOCKED: i32 = 1;

    /// Lock state constant indicating the editor is unlocked.
    const EDITOR_UNLOCKED: i32 = 2;

    /// Called whenever the composite data type editor lock/unlock state changes.
    ///
    /// # Arguments
    /// * `lock_type` - The type of state change: `EDITOR_LOCKED` or `EDITOR_UNLOCKED`
    fn lock_state_changed(&self, lock_type: i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockLockListener {
        lock_state_changes: RefCell<Vec<i32>>,
    }

    impl MockLockListener {
        fn new() -> Self {
            Self {
                lock_state_changes: RefCell::new(Vec::new()),
            }
        }

        fn get_lock_state_changes(&self) -> Vec<i32> {
            self.lock_state_changes.borrow().clone()
        }
    }

    impl CompositeEditorLockListener for MockLockListener {
        fn lock_state_changed(&self, lock_type: i32) {
            self.lock_state_changes.borrow_mut().push(lock_type);
        }
    }

    #[test]
    fn test_editor_locked_constant() {
        assert_eq!(MockLockListener::EDITOR_LOCKED, 1);
    }

    #[test]
    fn test_editor_unlocked_constant() {
        assert_eq!(MockLockListener::EDITOR_UNLOCKED, 2);
    }

    #[test]
    fn test_lock_state_changed_locked() {
        let listener = MockLockListener::new();
        listener.lock_state_changed(MockLockListener::EDITOR_LOCKED);
        assert_eq!(listener.get_lock_state_changes(), vec![1]);
    }

    #[test]
    fn test_lock_state_changed_unlocked() {
        let listener = MockLockListener::new();
        listener.lock_state_changed(MockLockListener::EDITOR_UNLOCKED);
        assert_eq!(listener.get_lock_state_changes(), vec![2]);
    }

    #[test]
    fn test_lock_state_changed_multiple_transitions() {
        let listener = MockLockListener::new();
        listener.lock_state_changed(MockLockListener::EDITOR_LOCKED);
        listener.lock_state_changed(MockLockListener::EDITOR_UNLOCKED);
        listener.lock_state_changed(MockLockListener::EDITOR_LOCKED);
        assert_eq!(
            listener.get_lock_state_changes(),
            vec![1, 2, 1]
        );
    }
}
