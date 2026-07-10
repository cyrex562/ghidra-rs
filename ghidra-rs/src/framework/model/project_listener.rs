use crate::framework::seam_stubs::Project;

/// Listener that is notified when a project is opened or closed.
///
/// Port of `ghidra.framework.model.ProjectListener`.
pub trait ProjectListener {
    /// Notification that the given project is open.
    fn project_opened(&mut self, project: &dyn Project);

    /// Notification that the given project is closed.
    fn project_closed(&mut self, project: &dyn Project);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProject;
    impl Project for MockProject {}

    struct RecordingListener {
        opened_count: usize,
        closed_count: usize,
    }

    impl ProjectListener for RecordingListener {
        fn project_opened(&mut self, _project: &dyn Project) {
            self.opened_count += 1;
        }

        fn project_closed(&mut self, _project: &dyn Project) {
            self.closed_count += 1;
        }
    }

    #[test]
    fn notifies_open_and_close() {
        let mut listener = RecordingListener { opened_count: 0, closed_count: 0 };
        let project = MockProject;

        listener.project_opened(&project);
        listener.project_closed(&project);

        assert_eq!(listener.opened_count, 1);
        assert_eq!(listener.closed_count, 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener = RecordingListener { opened_count: 0, closed_count: 0 };
        let project = MockProject;
        let dyn_listener: &mut dyn ProjectListener = &mut listener;

        dyn_listener.project_opened(&project);

        assert_eq!(listener.opened_count, 1);
        assert_eq!(listener.closed_count, 0);
    }
}
