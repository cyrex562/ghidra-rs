use crate::framework::model::DomainObject;

/// Listener notified when a [`DomainObject`] is closed.
///
/// Port of `ghidra.framework.model.DomainObjectClosedListener`.
pub trait DomainObjectClosedListener {
    /// Called when the specified domain object has been closed.
    fn domain_object_closed(&mut self, domain_object: &dyn DomainObject);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainObject {
        name: String,
    }

    impl DomainObject for MockDomainObject {}

    struct RecordingListener {
        closed_names: Vec<String>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                closed_names: Vec::new(),
            }
        }
    }

    impl DomainObjectClosedListener for RecordingListener {
        fn domain_object_closed(&mut self, domain_object: &dyn DomainObject) {
            self.closed_names.push(
                domain_object
                    .get_domain_file()
                    .map(|df| df.get_name())
                    .unwrap_or_else(|| "unnamed".to_string()),
            );
        }
    }

    #[test]
    fn test_domain_object_closed_called() {
        let mut listener = RecordingListener::new();
        let obj = MockDomainObject {
            name: "test_object".to_string(),
        };
        listener.domain_object_closed(&obj);
        assert_eq!(listener.closed_names.len(), 1);
    }

    #[test]
    fn test_multiple_domain_objects_closed() {
        let mut listener = RecordingListener::new();
        let obj1 = MockDomainObject {
            name: "object1".to_string(),
        };
        let obj2 = MockDomainObject {
            name: "object2".to_string(),
        };
        listener.domain_object_closed(&obj1);
        listener.domain_object_closed(&obj2);
        assert_eq!(listener.closed_names.len(), 2);
    }

    #[test]
    fn test_close_same_object_multiple_times() {
        let mut listener = RecordingListener::new();
        let obj = MockDomainObject {
            name: "repeated".to_string(),
        };
        listener.domain_object_closed(&obj);
        listener.domain_object_closed(&obj);
        listener.domain_object_closed(&obj);
        assert_eq!(listener.closed_names.len(), 3);
    }
}
