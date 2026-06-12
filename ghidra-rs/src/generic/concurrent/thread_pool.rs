use rayon::{ThreadPool, ThreadPoolBuilder};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

pub struct GThreadPool {
    name: String,
    pool: ThreadPool,
}

static SHARED_POOLS: OnceLock<RwLock<HashMap<String, Arc<GThreadPool>>>> = OnceLock::new();

fn get_shared_pools() -> &'static RwLock<HashMap<String, Arc<GThreadPool>>> {
    SHARED_POOLS.get_or_init(|| RwLock::new(HashMap::new()))
}

impl GThreadPool {
    pub fn get_shared_thread_pool(name: &str) -> Arc<Self> {
        let pools = get_shared_pools();
        {
            let lock = pools.read().unwrap();
            if let Some(pool) = lock.get(name) {
                return pool.clone();
            }
        }

        let mut lock = pools.write().unwrap();
        lock.entry(name.to_string())
            .or_insert_with(|| Arc::new(Self::new(name)))
            .clone()
    }

    pub fn get_private_thread_pool(name: &str) -> Self {
        Self::new(name)
    }

    fn new(name: &str) -> Self {
        let name_clone = name.to_string();
        let pool = ThreadPoolBuilder::new()
            .thread_name(move |i| format!("{}-{}", name_clone, i))
            .build()
            .unwrap();
        Self {
            name: name.to_string(),
            pool,
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.pool.spawn(f);
    }

    pub fn spawn<F, R>(&self, f: F) -> tokio::sync::oneshot::Receiver<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pool.spawn(move || {
            let res = f();
            let _ = tx.send(res);
        });
        rx
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_pool() {
        let pool = GThreadPool::get_shared_thread_pool("test_pool");
        let (tx, rx) = std::sync::mpsc::channel();

        pool.execute(move || {
            tx.send("hello").unwrap();
        });

        assert_eq!(rx.recv().unwrap(), "hello");
    }
}
