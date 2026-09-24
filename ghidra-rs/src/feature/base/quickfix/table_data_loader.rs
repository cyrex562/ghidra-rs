//! Port of `ghidra.features.base.quickfix.TableDataLoader`.

use crate::util::datastruct::Accumulator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Generates table data for a threaded table model.
///
/// Rather than subclassing a table model to override its `doLoad()` method, a general table
/// model can be handed a `TableDataLoader` that supplies its data. The loader also reports on
/// the outcome of the load, via [`did_produce_data`](Self::did_produce_data) and
/// [`max_data_size_reached`](Self::max_data_size_reached).
///
/// This is an open extension point: the quick-fix table model stores whichever loader its
/// client supplies, so the trait stays object-safe (`dyn TableDataLoader<T>`), which is why
/// [`load_data`](Self::load_data) takes `&mut dyn Accumulator<T>` rather than a generic.
///
/// `T` is the type of objects loaded into the table model.
pub trait TableDataLoader<T> {
    /// Loads data into the given accumulator.
    ///
    /// # Errors
    ///
    /// Returns [`CancelledException`] if the operation is cancelled via `monitor`.
    fn load_data(
        &mut self,
        accumulator: &mut dyn Accumulator<T>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Returns true if at least one item was added to the accumulator.
    fn did_produce_data(&self) -> bool;

    /// Returns true if the load was terminated because the maximum number of items was reached.
    fn max_data_size_reached(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::datastruct::ListAccumulator;
    use crate::util::task::DummyMonitor;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A loader modeled on Java's `SearchAndReplaceQuckFixTableLoader`: it adds items up to a
    /// maximum, recording whether it produced anything and whether it hit the limit.
    struct LimitedLoader {
        source: Vec<u32>,
        max: usize,
        produced: bool,
        hit_max: bool,
    }

    impl TableDataLoader<u32> for LimitedLoader {
        fn load_data(
            &mut self,
            accumulator: &mut dyn Accumulator<u32>,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for &item in &self.source {
                monitor.check_cancelled()?;
                if accumulator.get_progress() >= self.max {
                    self.hit_max = true;
                    break;
                }
                accumulator.add(item);
                self.produced = true;
            }
            Ok(())
        }

        fn did_produce_data(&self) -> bool {
            self.produced
        }

        fn max_data_size_reached(&self) -> bool {
            self.hit_max
        }
    }

    #[test]
    fn loads_all_items_below_limit() {
        let mut loader = LimitedLoader { source: vec![1, 2, 3], max: 10, produced: false, hit_max: false };
        let mut acc = ListAccumulator::new();
        loader.load_data(&mut acc, &DummyMonitor).unwrap();
        assert_eq!(acc.get_progress(), 3);
        assert!(loader.did_produce_data());
        assert!(!loader.max_data_size_reached());
    }

    #[test]
    fn stops_at_max_and_reports_it() {
        let mut loader = LimitedLoader { source: vec![1, 2, 3, 4], max: 2, produced: false, hit_max: false };
        let mut acc = ListAccumulator::new();
        loader.load_data(&mut acc, &DummyMonitor).unwrap();
        assert_eq!(acc.get_progress(), 2);
        assert!(loader.max_data_size_reached());
    }

    #[test]
    fn empty_source_produces_no_data() {
        // Usable through a trait object, as the quick-fix table model holds its loader.
        let mut loader: Box<dyn TableDataLoader<u32>> =
            Box::new(LimitedLoader { source: vec![], max: 5, produced: false, hit_max: false });
        let mut acc = ListAccumulator::new();
        loader.load_data(&mut acc, &DummyMonitor).unwrap();
        assert!(!loader.did_produce_data());
        assert!(!loader.max_data_size_reached());
    }

    /// A monitor whose only live state is its cancelled flag.
    struct CancellableMonitor(AtomicBool);

    impl TaskMonitor for CancellableMonitor {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.is_cancelled() {
                Err(CancelledException::default())
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn cancellation_propagates_as_error() {
        let mut loader = LimitedLoader { source: vec![1], max: 5, produced: false, hit_max: false };
        let mut acc = ListAccumulator::new();
        let monitor = CancellableMonitor(AtomicBool::new(false));
        monitor.cancel();
        let result = loader.load_data(&mut acc, &monitor);
        assert!(result.is_err());
        assert_eq!(acc.get_progress(), 0);
        assert!(!loader.did_produce_data());
    }
}
