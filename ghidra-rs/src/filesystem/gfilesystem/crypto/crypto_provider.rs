use std::any::Any;

/// Common interface for provider interfaces that provide crypto information.
///
/// Implementors may be used as identity-keyed state owners in a [`Session`].
/// The `Any` supertrait enables downcasting from `dyn CryptoProvider` to concrete types,
/// mirroring the Java `instanceof`/cast pattern used in `CryptoProviders`.
pub trait CryptoProvider: Any {}

/// A session for crypto operations, scoped to a single open/decrypt cycle.
///
/// The type parameter `CP` represents the `CryptoProviders` registry; it will be
/// instantiated with the concrete Rust port of `CryptoProviders` once that class is ported.
pub trait Session<CP> {
    /// Saves a state object into the session, keyed by `crypto_provider` identity.
    fn set_state_value(&mut self, crypto_provider: &dyn CryptoProvider, value: Box<dyn Any>);

    /// Retrieves a state object from the session, keyed by `crypto_provider` identity.
    ///
    /// If no value is stored for the given provider, `state_factory` is called to create one,
    /// which is then stored and returned.
    fn get_state_value<T: 'static>(
        &mut self,
        crypto_provider: &dyn CryptoProvider,
        state_factory: impl FnOnce() -> T,
    ) -> T;

    /// Returns the [`CryptoProviders`] instance that created this session.
    fn get_crypto_providers(&self) -> &CP;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestProvider {
        id: u32,
    }
    impl CryptoProvider for TestProvider {}

    struct MockProviders {
        id: u32,
    }

    struct MockSession {
        providers: MockProviders,
        state: HashMap<usize, Box<dyn Any>>,
    }

    impl MockSession {
        fn new(providers: MockProviders) -> Self {
            MockSession { providers, state: HashMap::new() }
        }
    }

    fn provider_key(p: &dyn CryptoProvider) -> usize {
        p as *const dyn CryptoProvider as *const () as usize
    }

    impl Session<MockProviders> for MockSession {
        fn set_state_value(&mut self, crypto_provider: &dyn CryptoProvider, value: Box<dyn Any>) {
            self.state.insert(provider_key(crypto_provider), value);
        }

        fn get_state_value<T: 'static>(
            &mut self,
            crypto_provider: &dyn CryptoProvider,
            state_factory: impl FnOnce() -> T,
        ) -> T {
            let key = provider_key(crypto_provider);
            match self.state.remove(&key) {
                Some(boxed) => *boxed.downcast::<T>().expect("type mismatch in get_state_value"),
                None => {
                    let val = state_factory();
                    self.state.insert(key, Box::new(()));
                    val
                }
            }
        }

        fn get_crypto_providers(&self) -> &MockProviders {
            &self.providers
        }
    }

    #[test]
    fn get_crypto_providers_returns_the_registry() {
        let session = MockSession::new(MockProviders { id: 42 });
        assert_eq!(session.get_crypto_providers().id, 42);
    }

    #[test]
    fn factory_called_when_no_state_set() {
        let mut session = MockSession::new(MockProviders { id: 1 });
        let provider = TestProvider { id: 0 };
        let val = session.get_state_value(&provider, || 99_i32);
        assert_eq!(val, 99);
    }

    #[test]
    fn stored_value_returned_by_get_state_value() {
        let mut session = MockSession::new(MockProviders { id: 1 });
        let provider = TestProvider { id: 0 };
        session.set_state_value(&provider, Box::new(7_i32));
        let val = session.get_state_value::<i32>(&provider, || 0);
        assert_eq!(val, 7);
    }

    #[test]
    fn different_providers_have_independent_state() {
        let mut session = MockSession::new(MockProviders { id: 1 });
        let p1 = TestProvider { id: 1 };
        let p2 = TestProvider { id: 2 };
        session.set_state_value(&p1, Box::new(10_i32));
        session.set_state_value(&p2, Box::new(20_i32));
        assert_eq!(session.get_state_value::<i32>(&p1, || 0), 10);
        assert_eq!(session.get_state_value::<i32>(&p2, || 0), 20);
    }

    #[test]
    fn factory_not_called_when_state_already_set() {
        let mut session = MockSession::new(MockProviders { id: 1 });
        let provider = TestProvider { id: 0 };
        let mut factory_called = false;
        session.set_state_value(&provider, Box::new(5_i32));
        let _val = session.get_state_value::<i32>(&provider, || {
            factory_called = true;
            0
        });
        assert!(!factory_called);
    }

    #[test]
    fn crypto_provider_is_any() {
        let p: Box<dyn CryptoProvider> = Box::new(TestProvider { id: 0 });
        let as_any: &dyn Any = p.as_ref();
        assert!(as_any.downcast_ref::<TestProvider>().is_some());
    }
}
