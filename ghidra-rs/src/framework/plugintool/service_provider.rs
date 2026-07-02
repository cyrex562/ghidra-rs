use std::any::Any;
use crate::framework::plugintool::util::ServiceListener;

/// Trait for providing services to plugins.
///
/// Mirrors `ghidra.framework.plugintool.ServiceProvider`.
///
/// Defines the interface for accessing services and managing service listeners.
/// Implementations of this trait provide a way for plugins to retrieve service
/// implementations by their interface type and to listen for changes in available services.
pub trait ServiceProvider: Send + Sync {
    /// Returns the service object that implements the given service interface.
    ///
    /// # Arguments
    ///
    /// * `service_class` - The interface class type id and name
    ///
    /// # Returns
    ///
    /// The service implementation if available, or `None` if no service
    /// implements the given interface.
    fn get_service(&self, service_class: &str) -> Option<Box<dyn Any + Send + Sync>>;

    /// Adds a listener that will be called when services are added and removed.
    ///
    /// # Arguments
    ///
    /// * `listener` - The service listener to add
    fn add_service_listener(&mut self, listener: Box<dyn ServiceListener>);

    /// Removes the given listener from this ServiceProvider.
    ///
    /// This method does nothing if the given listener is not contained by
    /// this ServiceProvider.
    ///
    /// # Arguments
    ///
    /// * `listener` - The service listener to remove
    fn remove_service_listener(&mut self, listener: Box<dyn ServiceListener>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::sync::Arc;

    struct MockServiceProvider {
        services: Vec<String>,
        listeners: Vec<String>,
    }

    impl MockServiceProvider {
        fn new() -> Self {
            MockServiceProvider {
                services: Vec::new(),
                listeners: Vec::new(),
            }
        }
    }

    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, service_class: &str) -> Option<Box<dyn Any + Send + Sync>> {
            if self.services.contains(&service_class.to_string()) {
                Some(Box::new(service_class.to_string()))
            } else {
                None
            }
        }

        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {
            self.listeners.push("added".to_string());
        }

        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {
            self.listeners.pop();
        }
    }

    #[test]
    fn get_service_returns_none_for_missing_service() {
        let provider = MockServiceProvider::new();
        assert!(provider.get_service("NonExistentService").is_none());
    }

    #[test]
    fn get_service_returns_service_when_available() {
        let mut provider = MockServiceProvider::new();
        provider.services.push("MyService".to_string());

        let service = provider.get_service("MyService");
        assert!(service.is_some());

        if let Some(svc) = service {
            if let Some(name) = svc.downcast_ref::<String>() {
                assert_eq!(name, "MyService");
            } else {
                panic!("Failed to downcast service");
            }
        }
    }

    #[test]
    fn add_service_listener_increases_count() {
        let mut provider = MockServiceProvider::new();

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        provider.add_service_listener(listener);

        assert_eq!(provider.listeners.len(), 1);
    }

    #[test]
    fn remove_service_listener_decreases_count() {
        let mut provider = MockServiceProvider::new();

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        provider.add_service_listener(listener);
        assert_eq!(provider.listeners.len(), 1);

        let listener2 = Box::new(DummyListener);
        provider.remove_service_listener(listener2);
        assert_eq!(provider.listeners.len(), 0);
    }

    #[test]
    fn service_provider_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Box<dyn ServiceProvider>>();
        assert_sync::<Box<dyn ServiceProvider>>();
    }

    #[test]
    fn get_service_is_case_sensitive() {
        let mut provider = MockServiceProvider::new();
        provider.services.push("MyService".to_string());

        assert!(provider.get_service("MyService").is_some());
        assert!(provider.get_service("myservice").is_none());
        assert!(provider.get_service("MYSERVICE").is_none());
    }

    #[test]
    fn multiple_services_can_be_retrieved() {
        let mut provider = MockServiceProvider::new();
        provider.services.push("Service1".to_string());
        provider.services.push("Service2".to_string());
        provider.services.push("Service3".to_string());

        assert!(provider.get_service("Service1").is_some());
        assert!(provider.get_service("Service2").is_some());
        assert!(provider.get_service("Service3").is_some());
    }

    #[test]
    fn multiple_listeners_can_be_added() {
        let mut provider = MockServiceProvider::new();

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
        }

        let listener1 = Box::new(DummyListener);
        let listener2 = Box::new(DummyListener);
        let listener3 = Box::new(DummyListener);

        provider.add_service_listener(listener1);
        provider.add_service_listener(listener2);
        provider.add_service_listener(listener3);

        assert_eq!(provider.listeners.len(), 3);
    }
}
