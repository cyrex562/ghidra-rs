/// Listener notified when a menu group assignment changes.
///
/// Corresponds to `docking.menu.MenuGroupListener`.
pub trait MenuGroupListener {
    /// Called when the group for the given menu path changes.
    fn menu_group_changed(&mut self, menu_path: &[&str], group: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        last_path: Vec<String>,
        last_group: String,
    }

    impl MenuGroupListener for TestListener {
        fn menu_group_changed(&mut self, menu_path: &[&str], group: &str) {
            self.last_path = menu_path.iter().map(|s| s.to_string()).collect();
            self.last_group = group.to_string();
        }
    }

    #[test]
    fn menu_group_changed_records_path_and_group() {
        let mut listener = TestListener {
            last_path: Vec::new(),
            last_group: String::new(),
        };
        listener.menu_group_changed(&["File", "Open"], "fileGroup");
        assert_eq!(listener.last_path, vec!["File", "Open"]);
        assert_eq!(listener.last_group, "fileGroup");
    }

    #[test]
    fn menu_group_changed_empty_path() {
        let mut listener = TestListener {
            last_path: Vec::new(),
            last_group: String::new(),
        };
        listener.menu_group_changed(&[], "emptyGroup");
        assert!(listener.last_path.is_empty());
        assert_eq!(listener.last_group, "emptyGroup");
    }

    #[test]
    fn menu_group_changed_single_path_element() {
        let mut listener = TestListener {
            last_path: Vec::new(),
            last_group: String::new(),
        };
        listener.menu_group_changed(&["Edit"], "editGroup");
        assert_eq!(listener.last_path, vec!["Edit"]);
        assert_eq!(listener.last_group, "editGroup");
    }
}
