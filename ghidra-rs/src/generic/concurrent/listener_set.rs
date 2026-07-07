use dashmap::DashSet;
use std::fmt;

/// A listener set that is weakly consistent.  This allows for iteration of the set while other
/// threads modify the set.
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

    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.storage.iter().map(|r| r.key().clone())
    }
}

impl<T> fmt::Display for ConcurrentListenerSet<T>
where
    T: Clone + Eq + std::hash::Hash + Send + Sync + fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_contains() {
        let set: ConcurrentListenerSet<String> = ConcurrentListenerSet::new();
        set.add("listener1".to_string());
        set.add("listener2".to_string());

        let vec = set.as_vec();
        assert_eq!(vec.len(), 2);
        assert!(vec.contains(&"listener1".to_string()));
        assert!(vec.contains(&"listener2".to_string()));
    }

    #[test]
    fn test_add_duplicate_ignored() {
        let set: ConcurrentListenerSet<i32> = ConcurrentListenerSet::new();
        set.add(1);
        set.add(1);
        assert_eq!(set.as_vec().len(), 1);
    }

    #[test]
    fn test_remove() {
        let set: ConcurrentListenerSet<String> = ConcurrentListenerSet::new();
        set.add("a".to_string());
        set.add("b".to_string());
        set.remove(&"a".to_string());

        let vec = set.as_vec();
        assert_eq!(vec.len(), 1);
        assert!(vec.contains(&"b".to_string()));
        assert!(!vec.contains(&"a".to_string()));
    }

    #[test]
    fn test_remove_nonexistent_is_noop() {
        let set: ConcurrentListenerSet<i32> = ConcurrentListenerSet::new();
        set.add(42);
        set.remove(&99);
        assert_eq!(set.as_vec().len(), 1);
    }

    #[test]
    fn test_clear() {
        let set: ConcurrentListenerSet<i32> = ConcurrentListenerSet::new();
        set.add(1);
        set.add(2);
        set.add(3);
        set.clear();
        assert!(set.as_vec().is_empty());
    }

    #[test]
    fn test_iter() {
        let set: ConcurrentListenerSet<i32> = ConcurrentListenerSet::new();
        set.add(10);
        set.add(20);

        let mut collected: Vec<i32> = set.iter().collect();
        collected.sort();
        assert_eq!(collected, vec![10, 20]);
    }

    #[test]
    fn test_display() {
        let set: ConcurrentListenerSet<i32> = ConcurrentListenerSet::new();
        set.add(5);
        let s = format!("{}", set);
        assert!(s.contains('5'));
    }

    #[test]
    fn test_empty_set() {
        let set: ConcurrentListenerSet<String> = ConcurrentListenerSet::new();
        assert!(set.as_vec().is_empty());
        assert_eq!(set.iter().count(), 0);
    }
}
