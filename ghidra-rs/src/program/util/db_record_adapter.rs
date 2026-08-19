use std::io;

use crate::framework::db::RecordIterator;

/// Adapter interface to get a record iterator.
///
/// Port of `ghidra.program.database.util.DBRecordAdapter`.
pub trait DBRecordAdapter {
    /// Get a record iterator for all records.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get the number of record datatype records.
    ///
    /// # Returns
    ///
    /// The total record count.
    fn get_record_count(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockRecordIterator;

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<crate::framework::db::DBRecord>> {
            Ok(None)
        }

        fn has_next(&self) -> bool {
            false
        }
    }

    struct MockDBRecordAdapter {
        record_count: usize,
    }

    impl MockDBRecordAdapter {
        fn new(record_count: usize) -> Self {
            Self { record_count }
        }
    }

    impl DBRecordAdapter for MockDBRecordAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator))
        }

        fn get_record_count(&self) -> usize {
            self.record_count
        }
    }

    #[test]
    fn test_get_record_count() {
        let adapter = MockDBRecordAdapter::new(42);
        assert_eq!(adapter.get_record_count(), 42);
    }

    #[test]
    fn test_get_records() {
        let adapter = MockDBRecordAdapter::new(10);
        let result = adapter.get_records();
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_record_count() {
        let adapter = MockDBRecordAdapter::new(0);
        assert_eq!(adapter.get_record_count(), 0);
    }
}
