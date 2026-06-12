use dashmap::DashSet;

#[derive(Debug, Default)]
pub struct ConcurrentListenerSet<T>
where
    T: Eq + std::hash::Hash + Send + Sync + 'static,
{
    storage: DashSet<T>,
}

impl<T> ConcurrentListenerSet<T>
where
    T: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            storage: DashSet::new(),
        }
    }

    pub fn add(&self, t: T) {
        self.storage.insert(t);
    }

    pub fn remove(&self, t: &T) {
        self.storage.remove(t);
    }

    pub fn clear(&self) {
        self.storage.clear();
    }

    pub fn as_vec(&self) -> Vec<T> {
        self.storage.iter().map(|r| r.key().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listener_set() {
        let set: ConcurrentListenerSet<String> = ConcurrentListenerSet::new();
        set.add("listener1".to_string());
        set.add("listener2".to_string());

        let vec = set.as_vec();
        assert_eq!(vec.len(), 2);
    }
}
