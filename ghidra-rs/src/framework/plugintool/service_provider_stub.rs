use crate::framework::plugintool::ServiceProvider;
use crate::framework::plugintool::util::ServiceListener;

/// A stub implementation of ServiceProvider for basic use cases.
///
/// Mirrors `ghidra.framework.plugintool.ServiceProviderStub`.
/// This is a minimal implementation that implements the ServiceProvider trait
/// but does not provide any actual services or handle listeners.
pub struct ServiceProviderStub;

impl ServiceProvider for ServiceProviderStub {
    fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
        None
    }

    fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {
        // stub
    }

    fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {
        // stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::sync::Arc;

    #[test]
    fn get_service_always_returns_none() {
        let provider = ServiceProviderStub;
        assert!(provider.get_service("any_service").is_none());
        assert!(provider.get_service("AnyService").is_none());
        assert!(provider.get_service("").is_none());
    }

    #[test]
    fn get_service_with_various_inputs() {
        let provider = ServiceProviderStub;
        assert!(provider.get_service("ServiceA").is_none());
        assert!(provider.get_service("ServiceB").is_none());
        assert!(provider.get_service("NonExistentService").is_none());
    }

    #[test]
    fn add_service_listener_is_no_op() {
        let mut provider = ServiceProviderStub;

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        provider.add_service_listener(listener);
    }

    #[test]
    fn remove_service_listener_is_no_op() {
        let mut provider = ServiceProviderStub;

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
        }

        let listener = Box::new(DummyListener);
        provider.remove_service_listener(listener);
    }

    #[test]
    fn multiple_listener_operations_are_no_ops() {
        let mut provider = ServiceProviderStub;

        struct DummyListener;
        impl ServiceListener for DummyListener {
            fn service_added(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
            fn service_removed(&self, _: TypeId, _: Arc<dyn std::any::Any + Send + Sync>) {}
        }

        let listener1 = Box::new(DummyListener);
        let listener2 = Box::new(DummyListener);

        provider.add_service_listener(listener1);
        provider.add_service_listener(listener2);
        provider.remove_service_listener(listener2);
    }

    #[test]
    fn provider_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ServiceProviderStub>();
        assert_sync::<ServiceProviderStub>();
    }
}
