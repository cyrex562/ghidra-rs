use crate::util::task::TaskMonitor;

/// Interface for resolving domain object merge conflicts.
///
/// Mirrors `ghidra.app.merge.MergeResolver`. Defines the contract for merge operations,
/// including progress tracking via `TaskMonitor`, phase management, and conflict resolution.
pub trait MergeResolver {
    /// Get the name of this MergeResolver.
    fn get_name(&self) -> String;

    /// Get the description of what this MergeResolver does.
    fn get_description(&self) -> String;

    /// Notification that the apply button was hit.
    fn apply(&self);

    /// Notification that the merge process was canceled.
    fn cancel(&self);

    /// Perform the merge process.
    ///
    /// # Arguments
    ///
    /// * `monitor` – monitor that allows the user to cancel the merge operation
    ///
    /// # Errors
    ///
    /// Returns an error if the merge encounters an issue and the merge process
    /// should not continue.
    fn merge(&self, monitor: &dyn TaskMonitor) -> Result<(), Box<dyn std::error::Error>>;

    /// Gets identifiers for the merge phases handled by this MergeResolver.
    ///
    /// If the merge has no sub-phases then return a vector with a single inner vector.
    /// Each inner vector indicates a path for a single merge phase.
    /// Each outer vector element represents a phase whose progress we wish to indicate.
    ///
    /// Examples:
    /// - For a simple phase with no sub-phases: `vec![vec!["Phase A".to_string()]]`
    /// - For a phase with 2 sub-phases: `vec![
    ///     vec!["Phase A".to_string()],
    ///     vec!["Phase A".to_string(), "Sub-Phase 1".to_string()],
    ///     vec!["Phase A".to_string(), "Sub-Phase 2".to_string()],
    ///   ]`
    fn get_phases(&self) -> Vec<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use std::sync::{Arc, Mutex};

    struct TestMergeResolver {
        name: String,
        description: String,
        phases: Vec<Vec<String>>,
        applied: Arc<Mutex<bool>>,
        cancelled: Arc<Mutex<bool>>,
        merge_called: Arc<Mutex<bool>>,
    }

    impl TestMergeResolver {
        fn new(name: &str, description: &str) -> Self {
            Self {
                name: name.to_string(),
                description: description.to_string(),
                phases: vec![vec!["Phase A".to_string()]],
                applied: Arc::new(Mutex::new(false)),
                cancelled: Arc::new(Mutex::new(false)),
                merge_called: Arc::new(Mutex::new(false)),
            }
        }
    }

    impl MergeResolver for TestMergeResolver {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }

        fn apply(&self) {
            *self.applied.lock().unwrap() = true;
        }

        fn cancel(&self) {
            *self.cancelled.lock().unwrap() = true;
        }

        fn merge(&self, _monitor: &dyn TaskMonitor) -> Result<(), Box<dyn std::error::Error>> {
            *self.merge_called.lock().unwrap() = true;
            Ok(())
        }

        fn get_phases(&self) -> Vec<Vec<String>> {
            self.phases.clone()
        }
    }

    #[test]
    fn get_name_returns_stored_name() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        assert_eq!(resolver.get_name(), "TestResolver");
    }

    #[test]
    fn get_description_returns_stored_description() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        assert_eq!(resolver.get_description(), "Test Description");
    }

    #[test]
    fn apply_updates_state() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        assert!(!*resolver.applied.lock().unwrap());
        resolver.apply();
        assert!(*resolver.applied.lock().unwrap());
    }

    #[test]
    fn cancel_updates_state() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        assert!(!*resolver.cancelled.lock().unwrap());
        resolver.cancel();
        assert!(*resolver.cancelled.lock().unwrap());
    }

    #[test]
    fn merge_succeeds_with_monitor() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        let monitor = crate::util::task::DummyMonitor;
        let result = resolver.merge(&monitor);
        assert!(result.is_ok());
        assert!(*resolver.merge_called.lock().unwrap());
    }

    #[test]
    fn get_phases_returns_phases() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        let phases = resolver.get_phases();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0], vec!["Phase A".to_string()]);
    }

    #[test]
    fn trait_object_is_constructable() {
        let resolver = TestMergeResolver::new("TestResolver", "Test Description");
        let _: &dyn MergeResolver = &resolver;
    }

    #[test]
    fn multiple_phases_supported() {
        let mut resolver = TestMergeResolver::new("MultiPhase", "Multi-Phase Resolver");
        resolver.phases = vec![
            vec!["Phase A".to_string()],
            vec!["Phase A".to_string(), "Sub-Phase 1".to_string()],
            vec!["Phase A".to_string(), "Sub-Phase 2".to_string()],
        ];
        let phases = resolver.get_phases();
        assert_eq!(phases.len(), 3);
        assert_eq!(phases[1], vec!["Phase A".to_string(), "Sub-Phase 1".to_string()]);
    }

    #[test]
    fn merge_error_handling() {
        struct ErrorResolver;
        impl MergeResolver for ErrorResolver {
            fn get_name(&self) -> String {
                "ErrorResolver".to_string()
            }
            fn get_description(&self) -> String {
                "Error Description".to_string()
            }
            fn apply(&self) {}
            fn cancel(&self) {}
            fn merge(&self, _monitor: &dyn TaskMonitor) -> Result<(), Box<dyn std::error::Error>> {
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Merge failed",
                )))
            }
            fn get_phases(&self) -> Vec<Vec<String>> {
                vec![]
            }
        }

        let resolver = ErrorResolver;
        let monitor = crate::util::task::DummyMonitor;
        let result = resolver.merge(&monitor);
        assert!(result.is_err());
    }

    #[test]
    fn empty_name_and_description_allowed() {
        let resolver = TestMergeResolver::new("", "");
        assert_eq!(resolver.get_name(), "");
        assert_eq!(resolver.get_description(), "");
    }
}
