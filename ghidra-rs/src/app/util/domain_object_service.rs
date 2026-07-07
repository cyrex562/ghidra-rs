use crate::framework::model::DomainObject;
use std::sync::Arc;

/// Simple interface for getting a DomainObject. This is used to delay the opening of
/// a domainObject until it is needed.
pub trait DomainObjectService {
    /// Get the domain object to be exported
    /// Returns domain object or None if export limited to domain file
    fn get_domain_object(&self) -> Option<Arc<dyn DomainObject>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDomainObjectService {
        domain_object: Option<Arc<dyn DomainObject>>,
    }

    impl TestDomainObjectService {
        fn new(domain_object: Option<Arc<dyn DomainObject>>) -> Self {
            Self { domain_object }
        }
    }

    impl DomainObjectService for TestDomainObjectService {
        fn get_domain_object(&self) -> Option<Arc<dyn DomainObject>> {
            self.domain_object.clone()
        }
    }

    #[test]
    fn test_get_domain_object_none() {
        let service = TestDomainObjectService::new(None);
        assert_eq!(service.get_domain_object().is_none(), true);
    }

    #[test]
    fn test_service_returns_domain_object_on_demand() {
        let service = TestDomainObjectService::new(None);
        let result = service.get_domain_object();
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_calls_return_same_reference() {
        let service = TestDomainObjectService::new(None);
        let result1 = service.get_domain_object();
        let result2 = service.get_domain_object();
        assert_eq!(result1.is_none(), result2.is_none());
    }
}
