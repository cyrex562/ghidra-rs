/// Listener notified when a delete-block command completes.
///
/// The generic parameter `Cmd` is the concrete command type (e.g.
/// `DeleteBlockCmd`) so the trait can be defined without requiring that type
/// to already exist in the module tree.
pub trait DeleteBlockListener<Cmd> {
    /// Called after the delete-block command finishes.
    ///
    /// Inspect `cmd` to determine whether the delete succeeded and retrieve
    /// any status message.
    fn delete_block_completed(&mut self, cmd: &Cmd);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeCmd {
        success: bool,
    }

    struct RecordingListener {
        calls: Vec<bool>,
    }

    impl DeleteBlockListener<FakeCmd> for RecordingListener {
        fn delete_block_completed(&mut self, cmd: &FakeCmd) {
            self.calls.push(cmd.success);
        }
    }

    #[test]
    fn listener_is_called_with_cmd() {
        let mut listener = RecordingListener { calls: vec![] };
        let cmd = FakeCmd { success: true };
        listener.delete_block_completed(&cmd);
        assert_eq!(listener.calls, vec![true]);
    }

    #[test]
    fn listener_receives_failure_status() {
        let mut listener = RecordingListener { calls: vec![] };
        let cmd = FakeCmd { success: false };
        listener.delete_block_completed(&cmd);
        assert_eq!(listener.calls, vec![false]);
    }

    #[test]
    fn listener_can_be_called_multiple_times() {
        let mut listener = RecordingListener { calls: vec![] };
        listener.delete_block_completed(&FakeCmd { success: true });
        listener.delete_block_completed(&FakeCmd { success: false });
        listener.delete_block_completed(&FakeCmd { success: true });
        assert_eq!(listener.calls, vec![true, false, true]);
    }
}
