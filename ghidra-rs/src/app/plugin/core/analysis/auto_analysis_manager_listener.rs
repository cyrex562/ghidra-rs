/// Callback invoked when an auto-analysis session ends.
///
/// The generic parameter `Manager` is the concrete manager type (e.g.
/// `AutoAnalysisManager`) so the trait can be defined without requiring that
/// type to already exist in the module tree.
///
/// Maps to `ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener`.
pub trait AutoAnalysisManagerListener<Manager> {
    /// Called after an auto-analysis session finishes.
    ///
    /// `manager` is the manager that coordinated the analysis session.
    /// `is_cancelled` is `true` if the session was cancelled before it could
    /// complete normally.
    fn analysis_ended(&mut self, manager: &Manager, is_cancelled: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeManager {
        name: &'static str,
    }

    struct RecordingListener {
        calls: Vec<(&'static str, bool)>,
    }

    impl AutoAnalysisManagerListener<FakeManager> for RecordingListener {
        fn analysis_ended(&mut self, manager: &FakeManager, is_cancelled: bool) {
            self.calls.push((manager.name, is_cancelled));
        }
    }

    fn make_listener() -> RecordingListener {
        RecordingListener { calls: vec![] }
    }

    #[test]
    fn called_with_manager_and_not_cancelled() {
        let mut listener = make_listener();
        let manager = FakeManager { name: "main" };
        listener.analysis_ended(&manager, false);
        assert_eq!(listener.calls, vec![("main", false)]);
    }

    #[test]
    fn called_with_cancelled_true() {
        let mut listener = make_listener();
        let manager = FakeManager { name: "main" };
        listener.analysis_ended(&manager, true);
        assert_eq!(listener.calls, vec![("main", true)]);
    }

    #[test]
    fn can_be_called_multiple_times() {
        let mut listener = make_listener();
        let m1 = FakeManager { name: "first" };
        let m2 = FakeManager { name: "second" };
        listener.analysis_ended(&m1, false);
        listener.analysis_ended(&m2, true);
        assert_eq!(listener.calls, vec![("first", false), ("second", true)]);
    }
}
