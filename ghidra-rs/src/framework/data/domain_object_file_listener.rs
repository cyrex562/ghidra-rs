use crate::framework::model::DomainObject;

/// Listener for when the [`DomainFile`](crate::framework::model::DomainFile) associated with a
/// [`DomainObject`] changes, such as when a 'Save As' action occurs. Unlike DomainObject events,
/// these callbacks are not buffered and happen immediately when the DomainFile is changed.
///
/// Port of `ghidra.framework.data.DomainObjectFileListener`.
pub trait DomainObjectFileListener {
    /// Notification that the DomainFile for the given DomainObject has changed.
    fn domain_file_changed(&mut self, domain_object: &dyn DomainObject);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainObject {
        name: String,
    }

    impl DomainObject for MockDomainObject {}

    struct RecordingListener {
        file_change_count: usize,
        changed_names: Vec<String>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                file_change_count: 0,
                changed_names: Vec::new(),
            }
        }
    }

    impl DomainObjectFileListener for RecordingListener {
        fn domain_file_changed(&mut self, domain_object: &dyn DomainObject) {
            self.file_change_count += 1;
            self.changed_names.push(
                domain_object
                    .get_domain_file()
                    .map(|df| df.get_name())
                    .unwrap_or_else(|| "unnamed".to_string()),
            );
        }
    }

    #[test]
    fn test_domain_file_changed_called() {
        let mut listener = RecordingListener::new();
        let obj = MockDomainObject {
            name: "test_object".to_string(),
        };
        listener.domain_file_changed(&obj);
        assert_eq!(listener.file_change_count, 1);
        assert_eq!(listener.changed_names.len(), 1);
    }

    #[test]
    fn test_multiple_file_changes() {
        let mut listener = RecordingListener::new();
        let obj1 = MockDomainObject {
            name: "object1".to_string(),
        };
        let obj2 = MockDomainObject {
            name: "object2".to_string(),
        };
        listener.domain_file_changed(&obj1);
        listener.domain_file_changed(&obj2);
        assert_eq!(listener.file_change_count, 2);
        assert_eq!(listener.changed_names.len(), 2);
    }

    #[test]
    fn test_file_change_same_object_multiple_times() {
        let mut listener = RecordingListener::new();
        let obj = MockDomainObject {
            name: "repeated".to_string(),
        };
        listener.domain_file_changed(&obj);
        listener.domain_file_changed(&obj);
        listener.domain_file_changed(&obj);
        assert_eq!(listener.file_change_count, 3);
        assert_eq!(listener.changed_names.len(), 3);
    }
}
