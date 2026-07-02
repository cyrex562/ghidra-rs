use std::any::{Any, TypeId};
use std::sync::Arc;

/// Trait for receiving notifications when services are added to or removed from a PluginTool.
///
/// Mirrors `ghidra.framework.plugintool.util.ServiceListener`.
pub trait ServiceListener: Send + Sync {
    /// Called when a service is added to the tool.
    ///
    /// # Arguments
    ///
    /// * `interface_class` - The `TypeId` of the interface class that the service implements
    /// * `service` - The service implementation, type-erased as `dyn Any`
    fn service_added(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>);

    /// Called when a service is removed from the tool.
    ///
    /// # Arguments
    ///
    /// * `interface_class` - The `TypeId` of the interface class that the service implements
    /// * `service` - The service implementation, type-erased as `dyn Any`
    fn service_removed(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestListener {
        added_calls: Mutex<Vec<(TypeId, bool)>>,
        removed_calls: Mutex<Vec<(TypeId, bool)>>,
    }

    impl TestListener {
        fn new() -> Self {
            TestListener {
                added_calls: Mutex::new(Vec::new()),
                removed_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ServiceListener for TestListener {
        fn service_added(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>) {
            let is_string = service.downcast_ref::<String>().is_some();
            self.added_calls.lock().unwrap().push((interface_class, is_string));
        }

        fn service_removed(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>) {
            let is_string = service.downcast_ref::<String>().is_some();
            self.removed_calls.lock().unwrap().push((interface_class, is_string));
        }
    }

    #[test]
    fn trait_object_implements_service_listener() {
        let listener: Box<dyn ServiceListener> = Box::new(TestListener::new());
        let service: Arc<dyn Any + Send + Sync> = Arc::new("test".to_string());
        let type_id = TypeId::of::<String>();

        listener.service_added(type_id, service.clone());
        listener.service_removed(type_id, service);
    }

    #[test]
    fn service_added_callback_receives_correct_typeid() {
        let listener = TestListener::new();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("test_service".to_string());
        let expected_type_id = TypeId::of::<String>();

        listener.service_added(expected_type_id, service);

        let calls = listener.added_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, expected_type_id);
        assert!(calls[0].1);
    }

    #[test]
    fn service_removed_callback_receives_correct_typeid() {
        let listener = TestListener::new();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("test_service".to_string());
        let expected_type_id = TypeId::of::<String>();

        listener.service_removed(expected_type_id, service);

        let calls = listener.removed_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, expected_type_id);
        assert!(calls[0].1);
    }

    #[test]
    fn multiple_calls_tracked_independently() {
        let listener = TestListener::new();
        let service1: Arc<dyn Any + Send + Sync> = Arc::new("service1".to_string());
        let service2: Arc<dyn Any + Send + Sync> = Arc::new("service2".to_string());
        let string_type_id = TypeId::of::<String>();

        listener.service_added(string_type_id, service1.clone());
        listener.service_added(string_type_id, service2);
        listener.service_removed(string_type_id, service1);

        let added = listener.added_calls.lock().unwrap();
        assert_eq!(added.len(), 2);

        let removed = listener.removed_calls.lock().unwrap();
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn listener_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Box<dyn ServiceListener>>();
        assert_sync::<Box<dyn ServiceListener>>();
    }

    #[test]
    fn service_downcast_works_for_correct_type() {
        let listener = TestListener::new();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("my_string".to_string());
        let string_type_id = TypeId::of::<String>();

        listener.service_added(string_type_id, service);

        let calls = listener.added_calls.lock().unwrap();
        assert!(calls[0].1);
    }

    #[test]
    fn service_downcast_fails_for_wrong_type() {
        let listener = TestListener::new();
        let service: Arc<dyn Any + Send + Sync> = Arc::new(42i32);
        let string_type_id = TypeId::of::<String>();

        listener.service_added(string_type_id, service);

        let calls = listener.added_calls.lock().unwrap();
        assert!(!calls[0].1);
    }
}
