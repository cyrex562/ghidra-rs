use super::BasicFactory;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct CachingPool<T> {
    factory: Box<dyn BasicFactory<T>>,
    inner: Arc<Mutex<PoolInner<T>>>,
}

struct PoolInner<T> {
    cache: VecDeque<T>,
    is_disposed: bool,
    cleanup_timeout: Option<Duration>,
}

impl<T: Send + 'static> CachingPool<T> {
    pub fn new(factory: Box<dyn BasicFactory<T>>) -> Self {
        Self {
            factory,
            inner: Arc::new(Mutex::new(PoolInner {
                cache: VecDeque::new(),
                is_disposed: false,
                cleanup_timeout: None,
            })),
        }
    }

    pub fn set_cleanup_timeout(&self, timeout: Option<Duration>) {
        let mut inner = self.inner.lock().unwrap();
        inner.cleanup_timeout = timeout;
    }

    pub fn get(&self) -> Result<T, anyhow::Error> {
        let mut inner = self.inner.lock().unwrap();
        if inner.is_disposed || inner.cache.is_empty() {
            return self.factory.create();
        }
        Ok(inner.cache.pop_front().unwrap())
    }

    pub fn release(&self, item: T) {
        let mut inner = self.inner.lock().unwrap();
        if inner.is_disposed {
            self.factory.dispose(item);
            return;
        }
        inner.cache.push_back(item);

        // In Rust, we could use tokio for timers, but for a 1-for-1 port
        // we'll keep it simple. Real cleanup logic would spawn a task.
    }

    pub fn dispose(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.is_disposed = true;
        while let Some(item) = inner.cache.pop_front() {
            self.factory.dispose(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFactory;
    impl BasicFactory<String> for TestFactory {
        fn create(&self) -> Result<String, anyhow::Error> {
            Ok("new item".to_string())
        }
        fn dispose(&self, _item: String) {}
    }

    #[test]
    fn test_caching_pool() {
        let pool = CachingPool::new(Box::new(TestFactory));
        let item = pool.get().unwrap();
        assert_eq!(item, "new item");
        pool.release(item);
        let item2 = pool.get().unwrap();
        assert_eq!(item2, "new item");
    }
}
