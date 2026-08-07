//! Common interface for trace sub-managers, backed by the trace database.
//!
//! Port of `ghidra.trace.database.DBTraceManager`.

use crate::framework::db::util::error_handler::ErrorHandler;

/// Common lifecycle contract shared by the trace database's sub-managers (memory, modules,
/// symbols, etc).
///
/// Port of `ghidra.trace.database.DBTraceManager`, which extends `db.util.ErrorHandler`. This
/// interface was selected as a dependency-cycle cut-point, so it is kept as a small, object-safe
/// trait: any core type can hold a `Box<dyn DBTraceManager>` (or a collection of them) without
/// creating a compile-time type cycle back to the concrete trace/manager structs.
pub trait DBTraceManager: ErrorHandler {
    /// Invalidate this manager's caches.
    ///
    /// `all` - probably nothing. Check out implementations of
    /// [`ManagerDB::invalidate_cache`](crate::program::database::manager_db::ManagerDB::invalidate_cache).
    fn invalidate_cache(&mut self, all: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of [`DBTraceManager`], proving the trait (with its [`ErrorHandler`]
    /// supertrait) is object-safe and can be driven through a `Box<dyn DBTraceManager>`.
    #[derive(Default)]
    struct MockTraceManager {
        invalidate_calls: Vec<bool>,
        last_error: std::cell::RefCell<Option<String>>,
    }

    impl ErrorHandler for MockTraceManager {
        fn db_error(&self, e: std::io::Error) {
            *self.last_error.borrow_mut() = Some(e.to_string());
        }
    }

    impl DBTraceManager for MockTraceManager {
        fn invalidate_cache(&mut self, all: bool) {
            self.invalidate_calls.push(all);
        }
    }

    #[test]
    fn drives_invalidate_and_error_reporting_through_trait_object() {
        let mut mgr: Box<dyn DBTraceManager> = Box::new(MockTraceManager::default());

        mgr.invalidate_cache(false);
        mgr.invalidate_cache(true);
        mgr.db_error(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));

        // Downcast isn't available through the trait object, so verify behavior via a
        // concretely-typed instance driven the same way.
        let mut concrete = MockTraceManager::default();
        concrete.invalidate_cache(false);
        concrete.invalidate_cache(true);
        concrete.db_error(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));

        assert_eq!(concrete.invalidate_calls, vec![false, true]);
        assert_eq!(concrete.last_error.borrow().as_deref(), Some("disk full"));
    }
}
