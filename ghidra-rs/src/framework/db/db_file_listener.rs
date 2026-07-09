use crate::framework::seam_stubs::Database;

/// Facilitates listener notification when new database versions are created.
pub trait DBFileListener {
    /// A new database version has been created.
    fn version_created(&self, db: &dyn Database, version: i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubDatabase;
    impl Database for StubDatabase {}

    struct MockListener {
        last_version: std::cell::Cell<Option<i32>>,
    }

    impl DBFileListener for MockListener {
        fn version_created(&self, _db: &dyn Database, version: i32) {
            self.last_version.set(Some(version));
        }
    }

    #[test]
    fn test_object_safe_dyn_usage() {
        let listener: Box<dyn DBFileListener> =
            Box::new(MockListener { last_version: std::cell::Cell::new(None) });
        let db = StubDatabase;
        listener.version_created(&db, 3);
    }

    #[test]
    fn test_mock_records_version() {
        let listener = MockListener { last_version: std::cell::Cell::new(None) };
        let db = StubDatabase;
        listener.version_created(&db, 7);
        assert_eq!(listener.last_version.get(), Some(7));
    }
}
