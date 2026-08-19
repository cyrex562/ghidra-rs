use crate::framework::seam_stubs::TempDatabaseCleaner;

/// Port of `ghidra.framework.store.FileSystemInitializer`.
///
/// The Java class implements `ModuleInitializer` and, in `run()`, calls the static
/// `PackedDatabase.cleanupOldTempDatabases()` utility method. The existing
/// [`PackedDatabase`](crate::framework::store::db::PackedDatabase) trait intentionally omits
/// static/factory methods to remain object-safe (see its doc comment), so there is no trait
/// method to invoke directly. Depending on a concrete `store::db` implementation type here would
/// recreate the `store` <-> `store::db` coupling this type was selected to cut, so the cleanup
/// capability is instead expressed as the minimal [`TempDatabaseCleaner`] seam trait, supplied by
/// the implementor.
///
/// Implementors are also expected to implement
/// [`ModuleInitializer`](crate::framework::ModuleInitializer); that supertrait isn't required
/// here so this trait stays free of the coupling being cut.
pub trait FileSystemInitializer {
    /// Returns the temp-database cleanup seam used by [`run`](Self::run).
    fn cleaner(&self) -> &dyn TempDatabaseCleaner;

    /// Port of `FileSystemInitializer.run()`.
    fn run(&self) {
        self.cleaner().cleanup_old_temp_databases();
    }

    /// Port of `FileSystemInitializer.getName()`.
    fn get_name(&self) -> String {
        "FileSystem Module".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct MockCleaner {
        called: Cell<bool>,
    }

    impl TempDatabaseCleaner for MockCleaner {
        fn cleanup_old_temp_databases(&self) {
            self.called.set(true);
        }
    }

    struct TestInitializer {
        cleaner: MockCleaner,
    }

    impl FileSystemInitializer for TestInitializer {
        fn cleaner(&self) -> &dyn TempDatabaseCleaner {
            &self.cleaner
        }
    }

    #[test]
    fn run_delegates_to_cleaner() {
        let initializer = TestInitializer {
            cleaner: MockCleaner {
                called: Cell::new(false),
            },
        };

        assert!(!initializer.cleaner.called.get());
        initializer.run();
        assert!(initializer.cleaner.called.get());
    }

    #[test]
    fn get_name_matches_java_module_name() {
        let initializer = TestInitializer {
            cleaner: MockCleaner {
                called: Cell::new(false),
            },
        };

        assert_eq!(initializer.get_name(), "FileSystem Module");
    }

    #[test]
    fn is_object_safe() {
        let initializer = TestInitializer {
            cleaner: MockCleaner {
                called: Cell::new(false),
            },
        };
        let dyn_initializer: &dyn FileSystemInitializer = &initializer;

        assert_eq!(dyn_initializer.get_name(), "FileSystem Module");
        dyn_initializer.run();
        assert!(initializer.cleaner.called.get());
    }
}
