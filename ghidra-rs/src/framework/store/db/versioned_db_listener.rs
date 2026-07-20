use crate::framework::seam_stubs::VersionedDatabase;

/// Provides listeners the ability to be notified when changes occur to a versioned database.
pub trait VersionedDBListener {
    /// Available database versions have been modified.
    /// This method is not invoked when a new version is created.
    fn versions_changed(&self, min_version: i32, current_version: i32);

    /// A new database version has been created.
    /// Returns true if the version is allowed; if false is returned, the version will be
    /// removed.
    fn version_created(
        &self,
        db: &dyn VersionedDatabase,
        version: i32,
        time: i64,
        comment: &str,
        checkin_id: i64,
    ) -> bool;

    /// A version has been deleted.
    fn version_deleted(&self, version: i32);

    /// Returns the checkout version associated with the specified checkout id. A returned
    /// version of -1 indicates that the checkout id is not valid.
    fn get_checkout_version(&self, checkout_id: i64) -> std::io::Result<i32>;

    /// Terminate the specified checkout. A new version may or may not have been created.
    fn checkin_completed(&self, checkout_id: i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    struct StubDatabase;
    impl VersionedDatabase for StubDatabase {}

    #[derive(Default)]
    struct MockListener {
        min_version: Cell<i32>,
        current_version: Cell<i32>,
        deleted_versions: RefCell<Vec<i32>>,
        allow_new_versions: Cell<bool>,
        completed_checkins: RefCell<Vec<i64>>,
    }

    impl VersionedDBListener for MockListener {
        fn versions_changed(&self, min_version: i32, current_version: i32) {
            self.min_version.set(min_version);
            self.current_version.set(current_version);
        }

        fn version_created(
            &self,
            _db: &dyn VersionedDatabase,
            _version: i32,
            _time: i64,
            _comment: &str,
            _checkin_id: i64,
        ) -> bool {
            self.allow_new_versions.get()
        }

        fn version_deleted(&self, version: i32) {
            self.deleted_versions.borrow_mut().push(version);
        }

        fn get_checkout_version(&self, checkout_id: i64) -> std::io::Result<i32> {
            if checkout_id < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid checkout id",
                ));
            }
            Ok(checkout_id as i32)
        }

        fn checkin_completed(&self, checkout_id: i64) {
            self.completed_checkins.borrow_mut().push(checkout_id);
        }
    }

    #[test]
    fn test_object_safe_dyn_usage_and_version_lifecycle() {
        let listener: Box<dyn VersionedDBListener> = Box::new(MockListener {
            allow_new_versions: Cell::new(false),
            ..Default::default()
        });
        let db = StubDatabase;

        listener.versions_changed(1, 5);
        assert!(!listener.version_created(&db, 6, 1000, "checkin", 42));
        listener.version_deleted(6);

        assert_eq!(listener.get_checkout_version(7).unwrap(), 7);
        assert!(listener.get_checkout_version(-1).is_err());

        listener.checkin_completed(7);
    }

    #[test]
    fn test_mock_records_version_deletion_and_checkin_sequence() {
        let listener = MockListener {
            allow_new_versions: Cell::new(true),
            ..Default::default()
        };
        let db = StubDatabase;

        assert!(listener.version_created(&db, 2, 100, "first", 1));
        listener.version_deleted(1);
        listener.version_deleted(2);
        listener.checkin_completed(1);

        assert_eq!(listener.deleted_versions.borrow().as_slice(), &[1, 2]);
        assert_eq!(listener.completed_checkins.borrow().as_slice(), &[1]);
    }
}
