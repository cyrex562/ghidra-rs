/// Listener notified when a move-block operation changes state or completes.
///
/// The generic parameter `Task` is the concrete task type (e.g. `MoveBlockTask`)
/// so the trait can be defined without requiring that type to already exist in
/// the module tree.
pub trait MoveBlockListener<Task> {
    /// Called whenever something about the move operation has changed.
    fn state_changed(&mut self);

    /// Called after the move-block task finishes.
    ///
    /// Inspect `task` to determine whether the move succeeded and retrieve
    /// any status message.
    fn move_block_completed(&mut self, task: &Task);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTask {
        success: bool,
    }

    struct RecordingListener {
        state_changes: u32,
        completed_calls: Vec<bool>,
    }

    impl MoveBlockListener<FakeTask> for RecordingListener {
        fn state_changed(&mut self) {
            self.state_changes += 1;
        }

        fn move_block_completed(&mut self, task: &FakeTask) {
            self.completed_calls.push(task.success);
        }
    }

    fn make_listener() -> RecordingListener {
        RecordingListener {
            state_changes: 0,
            completed_calls: vec![],
        }
    }

    #[test]
    fn state_changed_is_called() {
        let mut listener = make_listener();
        listener.state_changed();
        assert_eq!(listener.state_changes, 1);
    }

    #[test]
    fn state_changed_can_be_called_multiple_times() {
        let mut listener = make_listener();
        listener.state_changed();
        listener.state_changed();
        listener.state_changed();
        assert_eq!(listener.state_changes, 3);
    }

    #[test]
    fn move_block_completed_success() {
        let mut listener = make_listener();
        let task = FakeTask { success: true };
        listener.move_block_completed(&task);
        assert_eq!(listener.completed_calls, vec![true]);
    }

    #[test]
    fn move_block_completed_failure() {
        let mut listener = make_listener();
        let task = FakeTask { success: false };
        listener.move_block_completed(&task);
        assert_eq!(listener.completed_calls, vec![false]);
    }

    #[test]
    fn listener_can_receive_state_change_then_completion() {
        let mut listener = make_listener();
        listener.state_changed();
        let task = FakeTask { success: true };
        listener.move_block_completed(&task);
        assert_eq!(listener.state_changes, 1);
        assert_eq!(listener.completed_calls, vec![true]);
    }

    #[test]
    fn move_block_completed_can_be_called_multiple_times() {
        let mut listener = make_listener();
        listener.move_block_completed(&FakeTask { success: true });
        listener.move_block_completed(&FakeTask { success: false });
        assert_eq!(listener.completed_calls, vec![true, false]);
    }
}
