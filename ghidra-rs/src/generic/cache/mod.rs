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
