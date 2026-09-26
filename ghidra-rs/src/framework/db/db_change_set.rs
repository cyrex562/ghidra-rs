use super::db_handle::DBHandle;
use std::io;

/// Facilitates the reading and writing of application level change data
/// associated with a `BufferFile`.
pub trait DBChangeSet {
    /// Read into this change set from the specified database handle.
    /// The database handle will not be retained and should be closed
    /// by the invoker of this method.
    fn read(&mut self, dbh: &DBHandle) -> io::Result<()>;

    /// Write this change set to the specified database handle.
    /// The database handle will not be retained and should be closed
    /// by the invoker of this method.
    ///
    /// `is_recovery_save` is `true` if this write is because of a recovery
    /// snapshot, or `false` if due to a user save action.
    fn write(&mut self, dbh: &DBHandle, is_recovery_save: bool) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockChangeSet {
        read_count: u32,
        last_recovery_save: Option<bool>,
    }

    impl DBChangeSet for MockChangeSet {
        fn read(&mut self, _dbh: &DBHandle) -> io::Result<()> {
            self.read_count += 1;
            Ok(())
        }

        fn write(&mut self, _dbh: &DBHandle, is_recovery_save: bool) -> io::Result<()> {
            self.last_recovery_save = Some(is_recovery_save);
            Ok(())
        }
    }

    #[test]
    fn test_object_safe_dyn_usage() {
        let dbh = DBHandle::new().unwrap();
        let mut cs: Box<dyn DBChangeSet> =
            Box::new(MockChangeSet { read_count: 0, last_recovery_save: None });

        cs.read(&dbh).unwrap();
        cs.write(&dbh, true).unwrap();
    }

    #[test]
    fn test_mock_impl_records_calls() {
        let dbh = DBHandle::new().unwrap();
        let mut cs = MockChangeSet { read_count: 0, last_recovery_save: None };

        cs.read(&dbh).unwrap();
        cs.write(&dbh, false).unwrap();

        assert_eq!(cs.read_count, 1);
        assert_eq!(cs.last_recovery_save, Some(false));
    }
}
