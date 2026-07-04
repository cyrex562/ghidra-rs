use crate::program::model::address::AddressFactory;
use std::sync::Arc;

/// Simple interface for getting an address factory. This is used to delay the opening of
/// a program until it is needed.
pub trait AddressFactoryService {
    /// Returns the address factory for this service.
    fn get_address_factory(&self) -> Arc<dyn AddressFactory>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    struct TestAddressFactoryService {
        factory: Arc<dyn AddressFactory>,
    }

    impl TestAddressFactoryService {
        fn new(factory: Arc<dyn AddressFactory>) -> Self {
            Self { factory }
        }
    }

    impl AddressFactoryService for TestAddressFactoryService {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }
    }

    #[test]
    fn test_get_address_factory() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        let service = TestAddressFactoryService::new(factory.clone());

        let retrieved_factory = service.get_address_factory();
        assert_eq!(retrieved_factory.get_num_address_spaces(), 1);
    }

    #[test]
    fn test_service_delays_factory_access() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        let service = TestAddressFactoryService::new(factory.clone());

        // Service provides factory on demand
        let factory_from_service = service.get_address_factory();
        assert!(factory_from_service.get_default_address_space().is_some());
    }

    #[test]
    fn test_multiple_calls_return_same_factory() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        let service = TestAddressFactoryService::new(factory.clone());

        let factory1 = service.get_address_factory();
        let factory2 = service.get_address_factory();

        assert_eq!(factory1.get_num_address_spaces(), factory2.get_num_address_spaces());
    }
}
