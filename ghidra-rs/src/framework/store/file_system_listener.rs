/// Provides a listener the ability to be notified of folder and file
/// changes within a FileSystem.
pub trait FileSystemListener {
    /// Notification that a new folder was created.
    /// `parent_path` is the path of the folder that contains the new folder.
    /// `name` is the name of the new folder.
    fn folder_created(&self, parent_path: &str, name: &str);

    /// Notification that a new folder item was created.
    /// `parent_path` is the path of the folder that contains the new item.
    /// `name` is the name of the new item.
    fn item_created(&self, parent_path: &str, name: &str);

    /// Notification that a folder was deleted.
    /// `parent_path` is the path of the folder that contained the deleted folder.
    /// `folder_name` is the name of the folder that was deleted.
    fn folder_deleted(&self, parent_path: &str, folder_name: &str);

    /// Notification that a folder was moved.
    /// `parent_path` is the path of the folder that used to contain the moved folder.
    /// `folder_name` is the name of the folder that was moved.
    /// `new_parent_path` is the path of the folder that now contains the moved folder.
    fn folder_moved(&self, parent_path: &str, folder_name: &str, new_parent_path: &str);

    /// Notification that a folder was renamed.
    /// `parent_path` is the path of the folder containing the folder that was renamed.
    /// `old_folder_name` is the old name of the folder.
    /// `new_folder_name` is the new name of the folder.
    fn folder_renamed(&self, parent_path: &str, old_folder_name: &str, new_folder_name: &str);

    /// Notification that a folder item was deleted.
    /// `folder_path` is the path of the folder that contained the deleted item.
    /// `item_name` is the name of the item that was deleted.
    fn item_deleted(&self, folder_path: &str, item_name: &str);

    /// Notification that an item was renamed.
    /// `folder_path` is the path of the folder that contains the renamed item.
    /// `old_item_name` is the old name of the item.
    /// `new_item_name` is the new name of the item.
    fn item_renamed(&self, folder_path: &str, old_item_name: &str, new_item_name: &str);

    /// Notification that an item was moved.
    /// `parent_path` is the path of the folder that used to contain the item.
    /// `name` is the name of the item that was moved.
    /// `new_parent_path` is the path of the folder that the item was moved to.
    /// `new_name` is the new name of the item.
    fn item_moved(&self, parent_path: &str, name: &str, new_parent_path: &str, new_name: &str);

    /// Notification that an item's state has changed.
    /// `parent_path` is the path of the folder containing the item.
    /// `item_name` is the name of the item that has changed.
    fn item_changed(&self, parent_path: &str, item_name: &str);

    /// Perform a full refresh / synchronization.
    fn synchronize(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MockListener {
        events: RefCell<Vec<String>>,
    }

    impl FileSystemListener for MockListener {
        fn folder_created(&self, parent_path: &str, name: &str) {
            self.events
                .borrow_mut()
                .push(format!("folder_created:{parent_path}:{name}"));
        }

        fn item_created(&self, parent_path: &str, name: &str) {
            self.events
                .borrow_mut()
                .push(format!("item_created:{parent_path}:{name}"));
        }

        fn folder_deleted(&self, parent_path: &str, folder_name: &str) {
            self.events
                .borrow_mut()
                .push(format!("folder_deleted:{parent_path}:{folder_name}"));
        }

        fn folder_moved(&self, parent_path: &str, folder_name: &str, new_parent_path: &str) {
            self.events.borrow_mut().push(format!(
                "folder_moved:{parent_path}:{folder_name}:{new_parent_path}"
            ));
        }

        fn folder_renamed(&self, parent_path: &str, old_folder_name: &str, new_folder_name: &str) {
            self.events.borrow_mut().push(format!(
                "folder_renamed:{parent_path}:{old_folder_name}:{new_folder_name}"
            ));
        }

        fn item_deleted(&self, folder_path: &str, item_name: &str) {
            self.events
                .borrow_mut()
                .push(format!("item_deleted:{folder_path}:{item_name}"));
        }

        fn item_renamed(&self, folder_path: &str, old_item_name: &str, new_item_name: &str) {
            self.events.borrow_mut().push(format!(
                "item_renamed:{folder_path}:{old_item_name}:{new_item_name}"
            ));
        }

        fn item_moved(&self, parent_path: &str, name: &str, new_parent_path: &str, new_name: &str) {
            self.events.borrow_mut().push(format!(
                "item_moved:{parent_path}:{name}:{new_parent_path}:{new_name}"
            ));
        }

        fn item_changed(&self, parent_path: &str, item_name: &str) {
            self.events
                .borrow_mut()
                .push(format!("item_changed:{parent_path}:{item_name}"));
        }

        fn synchronize(&self) {
            self.events.borrow_mut().push("synchronize".to_string());
        }
    }

    #[test]
    fn test_object_safe_dyn_usage_and_event_sequence() {
        let listener: Box<dyn FileSystemListener> = Box::new(MockListener::default());

        listener.folder_created("/a", "b");
        listener.item_created("/a/b", "c.txt");
        listener.folder_renamed("/a", "b", "b2");
        listener.item_moved("/a/b2", "c.txt", "/a", "c.txt");
        listener.item_changed("/a", "c.txt");
        listener.item_deleted("/a", "c.txt");
        listener.folder_deleted("/a", "b2");
        listener.synchronize();

        let mock = MockListener::default();
        mock.folder_moved("/x", "y", "/z");
        mock.item_renamed("/x", "old", "new");

        assert_eq!(
            mock.events.borrow().as_slice(),
            &[
                "folder_moved:/x:y:/z".to_string(),
                "item_renamed:/x:old:new".to_string(),
            ]
        );
    }
}
