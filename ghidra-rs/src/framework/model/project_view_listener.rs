/// Listener for project views added and removed from the associated project.
///
/// NOTE: notification callbacks are not guaranteed to occur on the main thread.
pub trait ProjectViewListener {
    /// Called when a read-only viewed project has been added and is intended to be visible.
    ///
    /// Notifications for hidden viewed projects are not provided.
    fn viewed_project_added(&mut self, project_view: &str);

    /// Called when a viewed project is being removed from the project.
    ///
    /// Notifications for hidden viewed project removal are not provided.
    fn viewed_project_removed(&mut self, project_view: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        added: Vec<String>,
        removed: Vec<String>,
    }

    impl ProjectViewListener for RecordingListener {
        fn viewed_project_added(&mut self, project_view: &str) {
            self.added.push(project_view.to_string());
        }

        fn viewed_project_removed(&mut self, project_view: &str) {
            self.removed.push(project_view.to_string());
        }
    }

    #[test]
    fn test_viewed_project_added() {
        let mut listener = RecordingListener { added: Vec::new(), removed: Vec::new() };
        listener.viewed_project_added("ghidra://localhost/myproject");
        assert_eq!(listener.added, vec!["ghidra://localhost/myproject"]);
        assert!(listener.removed.is_empty());
    }

    #[test]
    fn test_viewed_project_removed() {
        let mut listener = RecordingListener { added: Vec::new(), removed: Vec::new() };
        listener.viewed_project_removed("ghidra://localhost/myproject");
        assert!(listener.added.is_empty());
        assert_eq!(listener.removed, vec!["ghidra://localhost/myproject"]);
    }

    #[test]
    fn test_multiple_add_and_remove_events() {
        let mut listener = RecordingListener { added: Vec::new(), removed: Vec::new() };
        listener.viewed_project_added("ghidra://host1/proj1");
        listener.viewed_project_added("ghidra://host2/proj2");
        listener.viewed_project_removed("ghidra://host1/proj1");
        assert_eq!(listener.added, vec!["ghidra://host1/proj1", "ghidra://host2/proj2"]);
        assert_eq!(listener.removed, vec!["ghidra://host1/proj1"]);
    }

    #[test]
    fn test_add_and_remove_same_url() {
        let mut listener = RecordingListener { added: Vec::new(), removed: Vec::new() };
        let url = "ghidra://server/project";
        listener.viewed_project_added(url);
        listener.viewed_project_removed(url);
        assert_eq!(listener.added, vec![url]);
        assert_eq!(listener.removed, vec![url]);
    }
}
