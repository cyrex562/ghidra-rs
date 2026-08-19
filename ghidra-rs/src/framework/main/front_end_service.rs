use crate::framework::model::ProjectListener;

/// Interface for accessing front-end functionality.
///
/// Port of `ghidra.framework.main.FrontEndService`.
pub trait FrontEndService {
    /// Adds the specified listener to the front-end tool.
    fn add_project_listener(&mut self, listener: Box<dyn ProjectListener>);

    /// Removes the specified listener from the front-end tool.
    fn remove_project_listener(&mut self, listener: &dyn ProjectListener);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::Project;

    struct MockProject;
    impl Project for MockProject {}

    struct RecordingProjectListener {
        opened_count: usize,
        closed_count: usize,
    }

    impl ProjectListener for RecordingProjectListener {
        fn project_opened(&mut self, _project: &dyn Project) {
            self.opened_count += 1;
        }

        fn project_closed(&mut self, _project: &dyn Project) {
            self.closed_count += 1;
        }
    }

    struct TestFrontEnd {
        listeners: Vec<Box<dyn ProjectListener>>,
    }

    impl TestFrontEnd {
        fn new() -> Self {
            Self { listeners: Vec::new() }
        }
    }

    impl FrontEndService for TestFrontEnd {
        fn add_project_listener(&mut self, listener: Box<dyn ProjectListener>) {
            self.listeners.push(listener);
        }

        fn remove_project_listener(&mut self, _listener: &dyn ProjectListener) {
            self.listeners.pop();
        }
    }

    #[test]
    fn can_add_project_listener() {
        let mut front_end = TestFrontEnd::new();
        let listener = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });

        front_end.add_project_listener(listener);
        assert_eq!(front_end.listeners.len(), 1);
    }

    #[test]
    fn can_remove_project_listener() {
        let mut front_end = TestFrontEnd::new();
        let listener = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });

        front_end.add_project_listener(listener);
        assert_eq!(front_end.listeners.len(), 1);

        front_end.remove_project_listener(&RecordingProjectListener { opened_count: 0, closed_count: 0 });
        assert_eq!(front_end.listeners.len(), 0);
    }

    #[test]
    fn can_add_multiple_listeners() {
        let mut front_end = TestFrontEnd::new();
        let listener1 = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });
        let listener2 = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });

        front_end.add_project_listener(listener1);
        front_end.add_project_listener(listener2);
        assert_eq!(front_end.listeners.len(), 2);
    }

    #[test]
    fn remove_project_listener_removes_from_collection() {
        let mut front_end = TestFrontEnd::new();
        let listener1 = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });
        let listener2 = Box::new(RecordingProjectListener { opened_count: 0, closed_count: 0 });

        front_end.add_project_listener(listener1);
        front_end.add_project_listener(listener2);
        front_end.remove_project_listener(&RecordingProjectListener { opened_count: 0, closed_count: 0 });

        assert_eq!(front_end.listeners.len(), 1);
    }
}
