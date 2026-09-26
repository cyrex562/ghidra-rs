use crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus;
use crate::util::task::TaskMonitor;

/// Base trait for objects that can provide DWARF debug files.
/// See [`DebugFileProvider`] or [`DebugStreamProvider`].
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugInfoProvider`.
pub trait DebugInfoProvider: Send + Sync {
    /// Returns the name of this instance, which should be a serialized copy of this instance,
    /// typically like "something://serialized_data".
    fn get_name(&self) -> String;

    /// Returns a human formatted string describing this provider, used in UI prompts or lists.
    fn get_descriptive_name(&self) -> String;

    /// Returns the current status of this provider.
    fn get_status(&self, monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDebugInfoProvider {
        name: String,
        descriptive_name: String,
        status: DebugInfoProviderStatus,
    }

    impl DebugInfoProvider for MockDebugInfoProvider {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_descriptive_name(&self) -> String {
            self.descriptive_name.clone()
        }

        fn get_status(&self, _monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus {
            self.status
        }
    }

    struct MockTaskMonitor;

    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            false
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

        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }

        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }

        fn clear_cancelled(&self) {}
    }

    #[test]
    fn get_name_returns_correct_value() {
        let provider = MockDebugInfoProvider {
            name: "test://data".to_string(),
            descriptive_name: "Test Provider".to_string(),
            status: DebugInfoProviderStatus::Valid,
        };

        assert_eq!(provider.get_name(), "test://data");
    }

    #[test]
    fn get_descriptive_name_returns_correct_value() {
        let provider = MockDebugInfoProvider {
            name: "test://data".to_string(),
            descriptive_name: "Test Provider".to_string(),
            status: DebugInfoProviderStatus::Valid,
        };

        assert_eq!(provider.get_descriptive_name(), "Test Provider");
    }

    #[test]
    fn get_status_returns_correct_status() {
        let provider = MockDebugInfoProvider {
            name: "test://data".to_string(),
            descriptive_name: "Test Provider".to_string(),
            status: DebugInfoProviderStatus::Valid,
        };

        let monitor = MockTaskMonitor;
        assert_eq!(provider.get_status(&monitor), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn status_transitions() {
        let statuses = vec![
            DebugInfoProviderStatus::Unknown,
            DebugInfoProviderStatus::Valid,
            DebugInfoProviderStatus::Invalid,
        ];

        for status in statuses {
            let provider = MockDebugInfoProvider {
                name: "test://data".to_string(),
                descriptive_name: "Test Provider".to_string(),
                status,
            };

            let monitor = MockTaskMonitor;
            assert_eq!(provider.get_status(&monitor), status);
        }
    }
}
