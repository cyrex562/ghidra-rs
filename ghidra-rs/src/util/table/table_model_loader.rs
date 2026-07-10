use crate::util::datastruct::Accumulator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Allows clients to create a table model that will call them back via this trait so
/// that they may perform their own loading.
pub trait TableModelLoader<T> {
    /// Loads data by adding items to the given accumulator while monitoring progress.
    fn load(
        &mut self,
        accumulator: &mut impl Accumulator<T>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockAccumulator {
        items: Arc<Mutex<Vec<String>>>,
    }

    impl Accumulator<String> for MockAccumulator {
        fn add(&mut self, item: String) {
            self.items.lock().unwrap().push(item);
        }

        fn get_progress(&self) -> usize {
            self.items.lock().unwrap().len()
        }
    }

    struct SimpleLoader {
        data: Vec<String>,
    }

    impl TableModelLoader<String> for SimpleLoader {
        fn load(
            &mut self,
            accumulator: &mut impl Accumulator<String>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for item in self.data.drain(..) {
                accumulator.add(item);
            }
            Ok(())
        }
    }

    #[test]
    fn loader_adds_items_to_accumulator() {
        let mut loader = SimpleLoader {
            data: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };

        let items = Arc::new(Mutex::new(Vec::new()));
        let mut acc = MockAccumulator {
            items: Arc::clone(&items),
        };

        let monitor = crate::util::task::DummyMonitor;
        loader.load(&mut acc, &monitor).unwrap();

        let loaded = items.lock().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0], "a");
        assert_eq!(loaded[1], "b");
        assert_eq!(loaded[2], "c");
    }

    #[test]
    fn loader_accumulator_progress_matches_items() {
        let mut loader = SimpleLoader {
            data: vec!["x".to_string(), "y".to_string()],
        };

        let items = Arc::new(Mutex::new(Vec::new()));
        let mut acc = MockAccumulator {
            items: Arc::clone(&items),
        };

        let monitor = crate::util::task::DummyMonitor;
        loader.load(&mut acc, &monitor).unwrap();

        assert_eq!(acc.get_progress(), 2);
    }

    struct CancellingLoader;

    impl TableModelLoader<String> for CancellingLoader {
        fn load(
            &mut self,
            _accumulator: &mut impl Accumulator<String>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Err(CancelledException::new("User cancelled"))
        }
    }

    #[test]
    fn loader_can_return_cancelled_error() {
        let mut loader = CancellingLoader;

        let items = Arc::new(Mutex::new(Vec::new()));
        let mut acc = MockAccumulator {
            items: Arc::clone(&items),
        };

        let monitor = crate::util::task::DummyMonitor;
        let result = loader.load(&mut acc, &monitor);

        assert!(result.is_err());
        match result {
            Err(e) => assert_eq!(e.0, "User cancelled"),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn loader_with_empty_data() {
        let mut loader = SimpleLoader {
            data: Vec::new(),
        };

        let items = Arc::new(Mutex::new(Vec::new()));
        let mut acc = MockAccumulator {
            items: Arc::clone(&items),
        };

        let monitor = crate::util::task::DummyMonitor;
        loader.load(&mut acc, &monitor).unwrap();

        assert_eq!(acc.get_progress(), 0);
    }
}
