use crate::framework::model::{DomainFile, DomainFolder};

/// Listener for notifications when changes are made to a domain folder or a domain file.
///
/// Port of `ghidra.framework.model.DomainFolderChangeListener`.
pub trait DomainFolderChangeListener {
    /// Notification that a folder is added to parent.
    fn domain_folder_added(&mut self, folder: &dyn DomainFolder) {}

    /// Notification that a file is added to parent folder.
    /// You can get the parent from the file.
    fn domain_file_added(&mut self, file: &dyn DomainFile) {}

    /// Notification that a domain folder is removed.
    ///
    /// # Arguments
    /// * `parent` - domain folder which contained the folder that was just removed
    /// * `name` - the name of the folder that was removed
    fn domain_folder_removed(&mut self, parent: &dyn DomainFolder, name: &str) {}

    /// Notification that a file was removed.
    ///
    /// # Arguments
    /// * `parent` - domain folder which contained the file that was just removed
    /// * `name` - the name of the file that was removed
    /// * `file_id` - file ID or None
    fn domain_file_removed(&mut self, parent: &dyn DomainFolder, name: &str, file_id: Option<&str>) {}

    /// Notification when a domain folder is renamed.
    ///
    /// NOTE: Only a single event will be sent for the specific folder renamed and not its children.
    /// If the listener cares about the impact of this event on the folder's children it will need
    /// to process accordingly.
    ///
    /// # Arguments
    /// * `folder` - folder that was renamed
    /// * `old_name` - old name of folder
    fn domain_folder_renamed(&mut self, folder: &dyn DomainFolder, old_name: &str) {}

    /// Notification that the domain file was renamed.
    ///
    /// # Arguments
    /// * `file` - file that was renamed
    /// * `old_name` - old name of the file
    fn domain_file_renamed(&mut self, file: &dyn DomainFile, old_name: &str) {}

    /// Notification that the domain folder was moved.
    ///
    /// NOTE: Only a single event will be sent for the specific folder moved and not its children.
    /// If the listener cares about the impact of this event on the folder's children it will need
    /// to process accordingly.
    ///
    /// # Arguments
    /// * `folder` - the folder (after move)
    /// * `old_parent` - original parent folder
    fn domain_folder_moved(&mut self, folder: &dyn DomainFolder, old_parent: &dyn DomainFolder) {}

    /// Notification that the domain file was moved.
    ///
    /// # Arguments
    /// * `file` - the file (after move)
    /// * `old_parent` - original parent folder
    /// * `old_name` - file name prior to move
    fn domain_file_moved(
        &mut self,
        file: &dyn DomainFile,
        old_parent: &dyn DomainFolder,
        old_name: &str,
    ) {
    }

    /// Notification that the setActive() method on the folder was called.
    ///
    /// # Arguments
    /// * `folder` - folder which was activated/visited
    fn domain_folder_set_active(&mut self, folder: &dyn DomainFolder) {}

    /// Notification that the status for a domain file has changed.
    ///
    /// # Arguments
    /// * `file` - file whose status has changed
    /// * `file_id_set` - if true indicates that the previously missing fileID has been
    ///   established for the specified file
    fn domain_file_status_changed(&mut self, file: &dyn DomainFile, file_id_set: bool) {}

    /// Notification that a domain file has been opened for update.
    ///
    /// # Arguments
    /// * `file` - domain file
    /// * `object` - domain object open for update
    fn domain_file_object_opened_for_update(
        &mut self,
        file: &dyn DomainFile,
        object: &dyn crate::framework::model::DomainObject,
    ) {
    }

    /// Notification that a domain file previously open for update is in the process of closing.
    ///
    /// # Arguments
    /// * `file` - domain file
    /// * `object` - domain object which was open for update
    fn domain_file_object_closed(
        &mut self,
        file: &dyn DomainFile,
        object: &dyn crate::framework::model::DomainObject,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockDomainFolder {
        name: String,
    }

    impl DomainFolder for MockDomainFolder {}

    struct MockDomainFile {
        name: String,
    }

    impl DomainFile for MockDomainFile {}

    struct RecordingListener {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl DomainFolderChangeListener for RecordingListener {
        fn domain_folder_added(&mut self, folder: &dyn DomainFolder) {
            self.events.borrow_mut().push("domain_folder_added".to_string());
        }

        fn domain_file_added(&mut self, file: &dyn DomainFile) {
            self.events.borrow_mut().push("domain_file_added".to_string());
        }

        fn domain_folder_removed(&mut self, _parent: &dyn DomainFolder, name: &str) {
            self.events
                .borrow_mut()
                .push(format!("domain_folder_removed:{}", name));
        }

        fn domain_file_removed(&mut self, _parent: &dyn DomainFolder, name: &str, file_id: Option<&str>) {
            let id_part = file_id.unwrap_or("none");
            self.events
                .borrow_mut()
                .push(format!("domain_file_removed:{}:{}", name, id_part));
        }

        fn domain_folder_renamed(&mut self, _folder: &dyn DomainFolder, old_name: &str) {
            self.events
                .borrow_mut()
                .push(format!("domain_folder_renamed:{}", old_name));
        }

        fn domain_file_renamed(&mut self, _file: &dyn DomainFile, old_name: &str) {
            self.events
                .borrow_mut()
                .push(format!("domain_file_renamed:{}", old_name));
        }

        fn domain_folder_moved(&mut self, _folder: &dyn DomainFolder, _old_parent: &dyn DomainFolder) {
            self.events.borrow_mut().push("domain_folder_moved".to_string());
        }

        fn domain_file_moved(
            &mut self,
            _file: &dyn DomainFile,
            _old_parent: &dyn DomainFolder,
            old_name: &str,
        ) {
            self.events
                .borrow_mut()
                .push(format!("domain_file_moved:{}", old_name));
        }

        fn domain_folder_set_active(&mut self, _folder: &dyn DomainFolder) {
            self.events
                .borrow_mut()
                .push("domain_folder_set_active".to_string());
        }

        fn domain_file_status_changed(&mut self, _file: &dyn DomainFile, file_id_set: bool) {
            self.events
                .borrow_mut()
                .push(format!("domain_file_status_changed:{}", file_id_set));
        }

        fn domain_file_object_opened_for_update(
            &mut self,
            _file: &dyn DomainFile,
            _object: &dyn crate::framework::model::DomainObject,
        ) {
            self.events
                .borrow_mut()
                .push("domain_file_object_opened_for_update".to_string());
        }

        fn domain_file_object_closed(
            &mut self,
            _file: &dyn DomainFile,
            _object: &dyn crate::framework::model::DomainObject,
        ) {
            self.events
                .borrow_mut()
                .push("domain_file_object_closed".to_string());
        }
    }

    #[test]
    fn test_domain_folder_added() {
        let mut listener = RecordingListener::new();
        let folder = MockDomainFolder {
            name: "folder1".to_string(),
        };
        listener.domain_folder_added(&folder);
        assert_eq!(listener.events(), vec!["domain_folder_added"]);
    }

    #[test]
    fn test_domain_file_added() {
        let mut listener = RecordingListener::new();
        let file = MockDomainFile {
            name: "file1".to_string(),
        };
        listener.domain_file_added(&file);
        assert_eq!(listener.events(), vec!["domain_file_added"]);
    }

    #[test]
    fn test_domain_folder_removed() {
        let mut listener = RecordingListener::new();
        let parent = MockDomainFolder {
            name: "parent".to_string(),
        };
        listener.domain_folder_removed(&parent, "removed_folder");
        assert_eq!(listener.events(), vec!["domain_folder_removed:removed_folder"]);
    }

    #[test]
    fn test_domain_file_removed_with_id() {
        let mut listener = RecordingListener::new();
        let parent = MockDomainFolder {
            name: "parent".to_string(),
        };
        listener.domain_file_removed(&parent, "file.bin", Some("file123"));
        assert_eq!(listener.events(), vec!["domain_file_removed:file.bin:file123"]);
    }

    #[test]
    fn test_domain_file_removed_without_id() {
        let mut listener = RecordingListener::new();
        let parent = MockDomainFolder {
            name: "parent".to_string(),
        };
        listener.domain_file_removed(&parent, "file.bin", None);
        assert_eq!(listener.events(), vec!["domain_file_removed:file.bin:none"]);
    }

    #[test]
    fn test_domain_folder_renamed() {
        let mut listener = RecordingListener::new();
        let folder = MockDomainFolder {
            name: "new_name".to_string(),
        };
        listener.domain_folder_renamed(&folder, "old_name");
        assert_eq!(listener.events(), vec!["domain_folder_renamed:old_name"]);
    }

    #[test]
    fn test_domain_file_renamed() {
        let mut listener = RecordingListener::new();
        let file = MockDomainFile {
            name: "newname.bin".to_string(),
        };
        listener.domain_file_renamed(&file, "oldname.bin");
        assert_eq!(listener.events(), vec!["domain_file_renamed:oldname.bin"]);
    }

    #[test]
    fn test_domain_folder_moved() {
        let mut listener = RecordingListener::new();
        let folder = MockDomainFolder {
            name: "folder".to_string(),
        };
        let old_parent = MockDomainFolder {
            name: "old_parent".to_string(),
        };
        listener.domain_folder_moved(&folder, &old_parent);
        assert_eq!(listener.events(), vec!["domain_folder_moved"]);
    }

    #[test]
    fn test_domain_file_moved() {
        let mut listener = RecordingListener::new();
        let file = MockDomainFile {
            name: "file.bin".to_string(),
        };
        let old_parent = MockDomainFolder {
            name: "old_parent".to_string(),
        };
        listener.domain_file_moved(&file, &old_parent, "oldlocation.bin");
        assert_eq!(listener.events(), vec!["domain_file_moved:oldlocation.bin"]);
    }

    #[test]
    fn test_domain_folder_set_active() {
        let mut listener = RecordingListener::new();
        let folder = MockDomainFolder {
            name: "active".to_string(),
        };
        listener.domain_folder_set_active(&folder);
        assert_eq!(listener.events(), vec!["domain_folder_set_active"]);
    }

    #[test]
    fn test_domain_file_status_changed_with_id_set() {
        let mut listener = RecordingListener::new();
        let file = MockDomainFile {
            name: "file.bin".to_string(),
        };
        listener.domain_file_status_changed(&file, true);
        assert_eq!(listener.events(), vec!["domain_file_status_changed:true"]);
    }

    #[test]
    fn test_domain_file_status_changed_without_id_set() {
        let mut listener = RecordingListener::new();
        let file = MockDomainFile {
            name: "file.bin".to_string(),
        };
        listener.domain_file_status_changed(&file, false);
        assert_eq!(listener.events(), vec!["domain_file_status_changed:false"]);
    }

    #[test]
    fn test_multiple_events() {
        let mut listener = RecordingListener::new();
        let folder = MockDomainFolder {
            name: "folder".to_string(),
        };
        let file = MockDomainFile {
            name: "file.bin".to_string(),
        };
        listener.domain_folder_added(&folder);
        listener.domain_file_added(&file);
        listener.domain_folder_set_active(&folder);
        assert_eq!(
            listener.events(),
            vec![
                "domain_folder_added",
                "domain_file_added",
                "domain_folder_set_active"
            ]
        );
    }
}
