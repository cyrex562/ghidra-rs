use crate::framework::db::database::Database;

/// Facilitates listener notification when new database versions are created.
pub trait DBFileListener {
    /// A new database version has been created.
    fn version_created(&self, db: &dyn Database, version: i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::database::OpenError;
    use crate::framework::db::db_handle::DBHandle;
    use crate::util::task::TaskMonitor;
    use std::io;

    struct StubDatabase;
    impl Database for StubDatabase {
        fn last_modified(&self) -> i64 {
            0
        }

        fn get_current_version(&self) -> i32 {
            0
        }

        fn open(&self, _monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError> {
            Ok(DBHandle::new()?)
        }

        fn open_for_update(
            &self,
            _monitor: Option<&dyn TaskMonitor>,
        ) -> Result<DBHandle, OpenError> {
            Err(OpenError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Update use not permitted",
            )))
        }

        fn length(&self) -> io::Result<u64> {
            Ok(0)
        }

        fn refresh(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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
