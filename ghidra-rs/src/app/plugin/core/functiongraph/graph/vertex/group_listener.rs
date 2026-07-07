/// Listener notified when a group vertex's description text changes.
///
/// Maps to `ghidra.app.plugin.core.functiongraph.graph.vertex.GroupListener`.
pub trait GroupListener {
    fn group_description_changed(&mut self, old_text: &str, new_text: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        old: String,
        new: String,
        call_count: usize,
    }

    impl GroupListener for RecordingListener {
        fn group_description_changed(&mut self, old_text: &str, new_text: &str) {
            self.old = old_text.to_string();
            self.new = new_text.to_string();
            self.call_count += 1;
        }
    }

    #[test]
    fn records_description_change() {
        let mut listener = RecordingListener {
            old: String::new(),
            new: String::new(),
            call_count: 0,
        };
        listener.group_description_changed("foo", "bar");
        assert_eq!(listener.old, "foo");
        assert_eq!(listener.new, "bar");
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn multiple_changes_tracked_separately() {
        let mut listener = RecordingListener {
            old: String::new(),
            new: String::new(),
            call_count: 0,
        };
        listener.group_description_changed("a", "b");
        listener.group_description_changed("b", "c");
        assert_eq!(listener.old, "b");
        assert_eq!(listener.new, "c");
        assert_eq!(listener.call_count, 2);
    }

    #[test]
    fn empty_strings_are_valid() {
        let mut listener = RecordingListener {
            old: String::new(),
            new: String::new(),
            call_count: 0,
        };
        listener.group_description_changed("", "");
        assert_eq!(listener.old, "");
        assert_eq!(listener.new, "");
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn trait_object_dispatch_works() {
        let mut listener: Box<dyn GroupListener> = Box::new(RecordingListener {
            old: String::new(),
            new: String::new(),
            call_count: 0,
        });
        listener.group_description_changed("x", "y");
    }
}
