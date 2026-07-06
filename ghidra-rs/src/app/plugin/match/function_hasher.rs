use crate::program::model::listing::Function;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Computes hashes for functions and counts common bits between function hashes.
///
/// Ported from `ghidra.app.plugin.match.FunctionHasher`.
pub trait FunctionHasher: Send + Sync {
    /// Computes a 64-bit hash for the given function.
    ///
    /// # Arguments
    ///
    /// * `function` - The function to hash.
    /// * `monitor` - A task monitor for cancellation checking.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the operation is cancelled via the monitor.
    fn hash(&self, function: &dyn Function, monitor: &dyn TaskMonitor) -> Result<i64, CancelledException>;

    /// Counts the number of common bit positions between hashes of two functions.
    ///
    /// # Arguments
    ///
    /// * `func_a` - The first function.
    /// * `func_b` - The second function.
    /// * `monitor` - A task monitor.
    ///
    /// # Returns
    ///
    /// The count of common bits in the hashes of the two functions.
    fn common_bit_count(
        &self,
        func_a: &dyn Function,
        func_b: &dyn Function,
        monitor: &dyn TaskMonitor,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHasher;

    impl FunctionHasher for TestHasher {
        fn hash(&self, _function: &dyn Function, _monitor: &dyn TaskMonitor) -> Result<i64, CancelledException> {
            Ok(0x1234567890ABCDEF)
        }

        fn common_bit_count(
            &self,
            _func_a: &dyn Function,
            _func_b: &dyn Function,
            _monitor: &dyn TaskMonitor,
        ) -> i32 {
            32
        }
    }

    #[test]
    fn trait_is_implementable() {
        let _: &dyn FunctionHasher = &TestHasher;
    }

    #[test]
    fn hash_returns_result() {
        let hasher = TestHasher;
        let mock_function: &dyn Function = &MockFunction;
        let mock_monitor: &dyn TaskMonitor = &MockMonitor;

        let result = hasher.hash(mock_function, mock_monitor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1234567890ABCDEF);
    }

    #[test]
    fn common_bit_count_returns_count() {
        let hasher = TestHasher;
        let mock_function_a: &dyn Function = &MockFunction;
        let mock_function_b: &dyn Function = &MockFunction;
        let mock_monitor: &dyn TaskMonitor = &MockMonitor;

        let count = hasher.common_bit_count(mock_function_a, mock_function_b, mock_monitor);
        assert_eq!(count, 32);
    }

    struct MockFunction;
    impl Function for MockFunction {}

    struct MockMonitor;
    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn set_cancelled(&self, _cancel: bool) {}

        fn set_show_progress_value(&self, _show: bool) {}

        fn set_message(&self, _message: impl Into<String>) {}

        fn get_message(&self) -> String {
            String::new()
        }

        fn set_progress_value(&self, _value: i64) {}

        fn get_progress_value(&self) -> i64 {
            0
        }

        fn set_maximum(&self, _max: i64) {}

        fn get_maximum(&self) -> i64 {
            0
        }

        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }

        fn set_indent(&self, _indent: bool) {}

        fn add_cancel_listener(&self, _listener: Box<dyn Fn() + Send + Sync>) {}
    }
}
