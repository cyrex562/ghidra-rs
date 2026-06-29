pub mod caching_pool;
pub mod weak_reference_cache;

pub trait Factory<K, V>: Send + Sync {
    fn get(&self, key: K) -> V;
}

pub trait BasicFactory<T>: Send + Sync {
    fn create(&self) -> Result<T, anyhow::Error>;
    fn dispose(&self, item: T);
}

pub struct CountingBasicFactory<T> {
    counter: std::sync::atomic::AtomicUsize,
    disposed_count: std::sync::atomic::AtomicUsize,
    _marker: std::marker::PhantomData<T>,
}

impl<T> CountingBasicFactory<T> {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicUsize::new(0),
            disposed_count: std::sync::atomic::AtomicUsize::new(0),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn increment_counter(&self) -> usize {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }

    pub fn increment_disposed(&self) {
        self.disposed_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn created_count(&self) -> usize {
        self.counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn disposed_count(&self) -> usize {
        self.disposed_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T> Default for CountingBasicFactory<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub use caching_pool::CachingPool;
pub use weak_reference_cache::WeakReferenceCache;

#[cfg(test)]
mod tests {
    use super::BasicFactory;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
