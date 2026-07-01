pub mod caching_pool;
pub mod weak_reference_cache;

pub trait Factory<K, V>: Send + Sync {
    fn get(&self, key: K) -> V;
}

pub trait BasicFactory<T>: Send + Sync {
    fn create(&self) -> Result<T, anyhow::Error>;
    fn dispose(&self, item: T);
}

/// Abstract factory trait for creating and disposing items with automatic item number tracking.
///
/// Implementers must provide `do_create` and `do_dispose` methods. The `create` and `dispose`
/// methods are automatically provided and handle counter increments.
pub trait CountingBasicFactory<T>: Send + Sync {
    /// Called to create an item with the given one-based item number.
    fn do_create(&self, item_number: usize) -> Result<T, anyhow::Error>;

    /// Called to dispose an item.
    fn do_dispose(&self, item: T);

    /// Returns a reference to the creation counter.
    fn counter(&self) -> &std::sync::atomic::AtomicUsize;

    /// Returns a reference to the disposal counter.
    fn disposed_count_ref(&self) -> &std::sync::atomic::AtomicUsize;

    /// Returns the number of items created.
    fn created_count(&self) -> usize {
        self.counter().load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the number of items disposed.
    fn disposed_count(&self) -> usize {
        self.disposed_count_ref().load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Automatic implementation of BasicFactory for types implementing CountingBasicFactory.
impl<T, F: CountingBasicFactory<T>> BasicFactory<T> for F {
    fn create(&self) -> Result<T, anyhow::Error> {
        let item_number = self.counter().fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.do_create(item_number)
    }

    fn dispose(&self, item: T) {
        self.disposed_count_ref().fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.do_dispose(item);
    }
}

pub use caching_pool::CachingPool;
pub use weak_reference_cache::WeakReferenceCache;

#[cfg(test)]
mod tests {
    use super::{BasicFactory, CountingBasicFactory, Factory};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct DoubleFactory;

    impl Factory<i32, i32> for DoubleFactory {
        fn get(&self, key: i32) -> i32 {
            key * 2
        }
    }

    struct EchoFactory;

    impl Factory<String, String> for EchoFactory {
        fn get(&self, key: String) -> String {
            key
        }
    }

    #[test]
    fn factory_get_returns_computed_value() {
        let f = DoubleFactory;
        assert_eq!(f.get(3), 6);
        assert_eq!(f.get(0), 0);
        assert_eq!(f.get(-5), -10);
    }

    #[test]
    fn factory_get_with_string_key() {
        let f = EchoFactory;
        assert_eq!(f.get("hello".to_string()), "hello");
    }

    #[test]
    fn factory_as_trait_object() {
        let f: Box<dyn Factory<i32, i32>> = Box::new(DoubleFactory);
        assert_eq!(f.get(7), 14);
    }

    struct SimpleFactory;

    impl BasicFactory<String> for SimpleFactory {
        fn create(&self) -> Result<String, anyhow::Error> {
            Ok("item".to_string())
        }
        fn dispose(&self, _item: String) {}
    }

    struct FailingFactory;

    impl BasicFactory<String> for FailingFactory {
        fn create(&self) -> Result<String, anyhow::Error> {
            Err(anyhow::anyhow!("creation failed"))
        }
        fn dispose(&self, _item: String) {}
    }

    struct TrackingFactory {
        dispose_count: AtomicUsize,
    }

    impl TrackingFactory {
        fn new() -> Self {
            Self { dispose_count: AtomicUsize::new(0) }
        }
    }

    impl BasicFactory<i32> for TrackingFactory {
        fn create(&self) -> Result<i32, anyhow::Error> {
            Ok(42)
        }
        fn dispose(&self, _item: i32) {
            self.dispose_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn create_returns_item() {
        let factory = SimpleFactory;
        let item = factory.create().unwrap();
        assert_eq!(item, "item");
    }

    #[test]
    fn create_propagates_error() {
        let factory = FailingFactory;
        let result = factory.create();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("creation failed"));
    }

    #[test]
    fn dispose_is_invoked() {
        let factory = TrackingFactory::new();
        let item = factory.create().unwrap();
        assert_eq!(item, 42);
        factory.dispose(item);
        assert_eq!(factory.dispose_count.load(Ordering::SeqCst), 1);
        factory.dispose(factory.create().unwrap());
        assert_eq!(factory.dispose_count.load(Ordering::SeqCst), 2);
    }

    struct TestCountingFactory {
        counter: AtomicUsize,
        disposed_count: AtomicUsize,
        created_items: Arc<Mutex<Vec<(usize, String)>>>,
    }

    impl TestCountingFactory {
        fn new() -> Self {
            Self {
                counter: AtomicUsize::new(0),
                disposed_count: AtomicUsize::new(0),
                created_items: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl CountingBasicFactory<String> for TestCountingFactory {
        fn do_create(&self, item_number: usize) -> Result<String, anyhow::Error> {
            let item = format!("item_{}", item_number);
            self.created_items.lock().unwrap().push((item_number, item.clone()));
            Ok(item)
        }

        fn do_dispose(&self, _item: String) {}

        fn counter(&self) -> &AtomicUsize {
            &self.counter
        }

        fn disposed_count_ref(&self) -> &AtomicUsize {
            &self.disposed_count
        }
    }

    #[test]
    fn counting_factory_increments_counter() {
        let factory = TestCountingFactory::new();
        assert_eq!(factory.created_count(), 0);

        let item1 = factory.create().unwrap();
        assert_eq!(item1, "item_1");
        assert_eq!(factory.created_count(), 1);

        let item2 = factory.create().unwrap();
        assert_eq!(item2, "item_2");
        assert_eq!(factory.created_count(), 2);
    }

    #[test]
    fn counting_factory_item_numbers_are_one_based() {
        let factory = TestCountingFactory::new();
        factory.create().unwrap();
        factory.create().unwrap();
        factory.create().unwrap();

        let items = factory.created_items.lock().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, 1);
        assert_eq!(items[1].0, 2);
        assert_eq!(items[2].0, 3);
    }

    #[test]
    fn counting_factory_increments_disposed_count() {
        let factory = TestCountingFactory::new();
        assert_eq!(factory.disposed_count(), 0);

        let item1 = factory.create().unwrap();
        factory.dispose(item1);
        assert_eq!(factory.disposed_count(), 1);

        let item2 = factory.create().unwrap();
        factory.dispose(item2);
        assert_eq!(factory.disposed_count(), 2);
    }

    #[test]
    fn counting_factory_as_basic_factory_trait_object() {
        let factory = TestCountingFactory::new();
        let basic: Box<dyn BasicFactory<String>> = Box::new(factory);

        let item = basic.create().unwrap();
        assert_eq!(item, "item_1");
    }

    struct FailingCountingFactory {
        counter: AtomicUsize,
        disposed_count: AtomicUsize,
    }

    impl CountingBasicFactory<i32> for FailingCountingFactory {
        fn do_create(&self, _item_number: usize) -> Result<i32, anyhow::Error> {
            Err(anyhow::anyhow!("creation failed"))
        }

        fn do_dispose(&self, _item: i32) {}

        fn counter(&self) -> &AtomicUsize {
            &self.counter
        }

        fn disposed_count_ref(&self) -> &AtomicUsize {
            &self.disposed_count
        }
    }

    #[test]
    fn counting_factory_propagates_creation_errors() {
        let factory = FailingCountingFactory {
            counter: AtomicUsize::new(0),
            disposed_count: AtomicUsize::new(0),
        };

        let result = factory.create();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("creation failed"));
        assert_eq!(factory.created_count(), 1);
    }

    #[test]
    fn counting_factory_do_dispose_called_before_disposed_increment() {
        struct TrackingDisposalFactory {
            counter: AtomicUsize,
            disposed_count: AtomicUsize,
            disposed_items: Arc<Mutex<Vec<i32>>>,
        }

        impl CountingBasicFactory<i32> for TrackingDisposalFactory {
            fn do_create(&self, _item_number: usize) -> Result<i32, anyhow::Error> {
                Ok(42)
            }

            fn do_dispose(&self, item: i32) {
                self.disposed_items.lock().unwrap().push(item);
            }

            fn counter(&self) -> &AtomicUsize {
                &self.counter
            }

            fn disposed_count_ref(&self) -> &AtomicUsize {
                &self.disposed_count
            }
        }

        let factory = TrackingDisposalFactory {
            counter: AtomicUsize::new(0),
            disposed_count: AtomicUsize::new(0),
            disposed_items: Arc::new(Mutex::new(Vec::new())),
        };

        factory.dispose(42);
        let items = factory.disposed_items.lock().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], 42);
        assert_eq!(factory.disposed_count(), 1);
    }
}
