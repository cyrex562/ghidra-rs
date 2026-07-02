use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use crate::framework::plugintool::{ServiceProvider, ServiceProviderStub};
use crate::framework::plugintool::util::ServiceListener;

/// A decorator that wraps a ServiceProvider and allows overriding specific services.
///
/// Mirrors `ghidra.framework.plugintool.ServiceProviderDecorator`.
///
/// This decorator allows you to override specific services while delegating to an underlying
/// ServiceProvider for all other services. Services added via `override_service` take precedence
/// over services from the delegate provider.
pub struct ServiceProviderDecorator {
    delegate: Box<dyn ServiceProvider>,
    overridden_services: HashMap<String, Arc<dyn Any + Send + Sync>>,
}

impl ServiceProviderDecorator {
    /// Creates a new ServiceProviderDecorator that wraps the given delegate provider.
    ///
    /// # Arguments
    ///
    /// * `delegate` - The underlying ServiceProvider to delegate to for non-overridden services
    pub fn decorate(delegate: Box<dyn ServiceProvider>) -> Self {
        ServiceProviderDecorator {
            delegate,
            overridden_services: HashMap::new(),
        }
    }

    /// Creates a new ServiceProviderDecorator with an empty stub provider.
    ///
    /// This is useful for creating a decorator that only provides overridden services.
    pub fn create_empty_decorator() -> Self {
        ServiceProviderDecorator {
            delegate: Box::new(ServiceProviderStub),
            overridden_services: HashMap::new(),
        }
    }

    /// Adds a service that will override any service contained in the delegate ServiceProvider.
    ///
    /// Note: this will not notify any clients that services have been changed. This means
    /// that you should call this method before passing this service provider on to your clients.
    ///
    /// # Arguments
    ///
    /// * `service_class` - The service class identifier (typically a fully qualified class name)
    /// * `service` - The service implementation, wrapped in Arc for shared ownership
    pub fn override_service(
        &mut self,
        service_class: String,
        service: Arc<dyn Any + Send + Sync>,
    ) {
        self.overridden_services.insert(service_class, service);
    }
}

impl ServiceProvider for ServiceProviderDecorator {
    fn get_service(&self, service_class: &str) -> Option<Box<dyn Any + Send + Sync>> {
        if let Some(service) = self.overridden_services.get(service_class) {
            Some(Box::new(service.clone()))
        } else {
            self.delegate.get_service(service_class)
        }
    }

    fn add_service_listener(&mut self, listener: Box<dyn ServiceListener>) {
        self.delegate.add_service_listener(listener);
    }

    fn remove_service_listener(&mut self, listener: Box<dyn ServiceListener>) {
        self.delegate.remove_service_listener(listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    struct MockServiceProvider {
        services: Vec<(String, Arc<dyn Any + Send + Sync>)>,
    }

    impl MockServiceProvider {
        fn new() -> Self {
            MockServiceProvider {
                services: Vec::new(),
            }
        }

        fn with_service(mut self, name: String, service: Arc<dyn Any + Send + Sync>) -> Self {
            self.services.push((name, service));
            self
        }
    }

    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, service_class: &str) -> Option<Box<dyn Any + Send + Sync>> {
            self.services
                .iter()
                .find(|(name, _)| name == service_class)
                .map(|(_, service)| Box::new(service.clone()))
        }

        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}

        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    #[test]
    fn decorate_returns_new_decorator() {
        let delegate = Box::new(ServiceProviderStub);
        let decorator = ServiceProviderDecorator::decorate(delegate);
        assert_eq!(decorator.overridden_services.len(), 0);
    }

    #[test]
    fn create_empty_decorator_returns_decorator_with_stub() {
        let decorator = ServiceProviderDecorator::create_empty_decorator();
        assert_eq!(decorator.overridden_services.len(), 0);
    }

    #[test]
    fn override_service_stores_service() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("test_service".to_string());
        decorator.override_service("TestService".to_string(), service);
        assert_eq!(decorator.overridden_services.len(), 1);
    }

    #[test]
    fn get_service_returns_overridden_service_when_present() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("overridden_value".to_string());
        decorator.override_service("TestService".to_string(), service);

        let result = decorator.get_service("TestService");
        assert!(result.is_some());
    }

    #[test]
    fn get_service_delegates_to_provider_when_not_overridden() {
        let delegate = Box::new(
            MockServiceProvider::new()
                .with_service("DelegateService".to_string(), Arc::new("delegate_value".to_string())),
        );
        let decorator = ServiceProviderDecorator::decorate(delegate);
        let result = decorator.get_service("DelegateService");
        assert!(result.is_some());
    }

    #[test]
    fn get_service_returns_none_for_missing_service() {
        let decorator = ServiceProviderDecorator::create_empty_decorator();
        let result = decorator.get_service("NonExistentService");
        assert!(result.is_none());
    }

    #[test]
    fn override_replaces_delegate_service() {
        let delegate = Box::new(
            MockServiceProvider::new()
                .with_service("SharedService".to_string(), Arc::new("delegate_value".to_string())),
        );
        let mut decorator = ServiceProviderDecorator::decorate(delegate);

        let override_service: Arc<dyn Any + Send + Sync> = Arc::new("override_value".to_string());
        decorator.override_service("SharedService".to_string(), override_service);

        let result = decorator.get_service("SharedService");
        assert!(result.is_some());
    }

    #[test]
    fn multiple_overrides_can_be_added() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();

        let service1: Arc<dyn Any + Send + Sync> = Arc::new("service1".to_string());
        let service2: Arc<dyn Any + Send + Sync> = Arc::new("service2".to_string());
        let service3: Arc<dyn Any + Send + Sync> = Arc::new("service3".to_string());

        decorator.override_service("Service1".to_string(), service1);
        decorator.override_service("Service2".to_string(), service2);
        decorator.override_service("Service3".to_string(), service3);

        assert_eq!(decorator.overridden_services.len(), 3);
    }

    #[test]
    fn get_service_is_case_sensitive() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();
        let service: Arc<dyn Any + Send + Sync> = Arc::new("test".to_string());
        decorator.override_service("TestService".to_string(), service);

        assert!(decorator.get_service("TestService").is_some());
        assert!(decorator.get_service("testservice").is_none());
        assert!(decorator.get_service("TESTSERVICE").is_none());
    }

    #[test]
    fn add_service_listener_delegates_to_provider() {
        let delegate = Box::new(ServiceProviderStub);
        let mut decorator = ServiceProviderDecorator::decorate(delegate);

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        decorator.add_service_listener(listener);
    }

    #[test]
    fn remove_service_listener_delegates_to_provider() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        decorator.remove_service_listener(listener);
    }

    #[test]
    fn override_same_service_twice_replaces_first() {
        let mut decorator = ServiceProviderDecorator::create_empty_decorator();

        let service1: Arc<dyn Any + Send + Sync> = Arc::new("first".to_string());
        let service2: Arc<dyn Any + Send + Sync> = Arc::new("second".to_string());

        decorator.override_service("Service".to_string(), service1);
        decorator.override_service("Service".to_string(), service2);

        assert_eq!(decorator.overridden_services.len(), 1);
    }

    #[test]
    fn decorator_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ServiceProviderDecorator>();
        assert_sync::<ServiceProviderDecorator>();
    }
}
