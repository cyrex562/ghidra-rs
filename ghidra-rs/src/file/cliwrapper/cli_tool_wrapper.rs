use crate::util::task::TaskMonitor;

/// Common interface for CLI tools.
///
/// Mirrors `ghidra.file.cliwrapper.CliToolWrapper`.
pub trait CliToolWrapper {
    /// Validates whether this CLI tool is valid.
    ///
    /// # Arguments
    ///
    /// * `monitor` - Task monitor for progress tracking and cancellation.
    ///
    /// # Returns
    ///
    /// `true` if this CLI tool is valid, `false` otherwise.
    fn is_valid(&self, monitor: &dyn TaskMonitor) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCliToolWrapper {
        valid: bool,
    }

    impl CliToolWrapper for MockCliToolWrapper {
        fn is_valid(&self, _monitor: &dyn TaskMonitor) -> bool {
            self.valid
        }
    }

    #[test]
    fn trait_object_construction() {
        let mock = MockCliToolWrapper { valid: true };
        let _: &dyn CliToolWrapper = &mock;
    }

    #[test]
    fn is_valid_returns_true() {
        let mock = MockCliToolWrapper { valid: true };
        let monitor = crate::util::task::DummyMonitor;
        assert!(mock.is_valid(&monitor));
    }

    #[test]
    fn is_valid_returns_false() {
        let mock = MockCliToolWrapper { valid: false };
        let monitor = crate::util::task::DummyMonitor;
        assert!(!mock.is_valid(&monitor));
    }

    #[test]
    fn multiple_trait_objects() {
        let valid = MockCliToolWrapper { valid: true };
        let invalid = MockCliToolWrapper { valid: false };
        let monitor = crate::util::task::DummyMonitor;

        let tools: Vec<&dyn CliToolWrapper> = vec![&valid, &invalid];
        assert_eq!(tools[0].is_valid(&monitor), true);
        assert_eq!(tools[1].is_valid(&monitor), false);
    }
}
