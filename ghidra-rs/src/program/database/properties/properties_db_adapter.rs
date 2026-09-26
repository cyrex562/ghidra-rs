use std::io;

use crate::framework::db::RecordIterator;

/// Adapter interface for accessing property definitions in the database.
///
/// This trait defines the contract for managing property map definitions stored
/// in a database table. Implementations handle version-specific schema variations.
///
/// Port of `ghidra.program.database.properties.PropertiesDBAdapter`.
pub trait PropertiesDBAdapter {
    /// Iterate over the records contained within the Properties table.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Create a new property map definition record.
    ///
    /// # Arguments
    /// * `property_name` - Unique property name
    /// * `type_byte` - Property map type as a byte
    /// * `obj_class_name` - Full class name for Saveable objects when type is OBJECT_PROPERTY_TYPE,
    ///                      otherwise None
    fn put_record(&mut self, property_name: &str, type_byte: u8, obj_class_name: Option<&str>) -> io::Result<()>;

    /// Remove a specific property map definition record.
    fn remove_record(&mut self, property_name: &str) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockPropertiesDBAdapter {
        records_called: RefCell<bool>,
        put_record_calls: RefCell<Vec<(String, u8, Option<String>)>>,
        remove_record_calls: RefCell<Vec<String>>,
    }

    impl MockPropertiesDBAdapter {
        fn new() -> Self {
            Self {
                records_called: RefCell::new(false),
                put_record_calls: RefCell::new(Vec::new()),
                remove_record_calls: RefCell::new(Vec::new()),
            }
        }
    }

    struct MockRecordIterator;

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<crate::framework::db::DBRecord>> {
            Ok(None)
        }

        fn has_next(&self) -> bool {
            false
        }
    }

    impl PropertiesDBAdapter for MockPropertiesDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            *self.records_called.borrow_mut() = true;
            Ok(Box::new(MockRecordIterator))
        }

        fn put_record(&mut self, property_name: &str, type_byte: u8, obj_class_name: Option<&str>) -> io::Result<()> {
            self.put_record_calls.borrow_mut().push((
                property_name.to_string(),
                type_byte,
                obj_class_name.map(|s| s.to_string()),
            ));
            Ok(())
        }

        fn remove_record(&mut self, property_name: &str) -> io::Result<()> {
            self.remove_record_calls.borrow_mut().push(property_name.to_string());
            Ok(())
        }
    }

    #[test]
    fn get_records_can_be_called() {
        let adapter = MockPropertiesDBAdapter::new();
        let result = adapter.get_records();
        assert!(result.is_ok());
        assert!(adapter.records_called.borrow().clone());
    }

    #[test]
    fn put_record_with_obj_class_name() {
        let mut adapter = MockPropertiesDBAdapter::new();
        let result = adapter.put_record("myProperty", 42, Some("com.example.MyClass"));
        assert!(result.is_ok());

        let calls = adapter.put_record_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "myProperty");
        assert_eq!(calls[0].1, 42);
        assert_eq!(calls[0].2, Some("com.example.MyClass".to_string()));
    }

    #[test]
    fn put_record_without_obj_class_name() {
        let mut adapter = MockPropertiesDBAdapter::new();
        let result = adapter.put_record("simpleProperty", 10, None);
        assert!(result.is_ok());

        let calls = adapter.put_record_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "simpleProperty");
        assert_eq!(calls[0].1, 10);
        assert_eq!(calls[0].2, None);
    }

    #[test]
    fn remove_record() {
        let mut adapter = MockPropertiesDBAdapter::new();
        let result = adapter.remove_record("propertyToRemove");
        assert!(result.is_ok());

        let calls = adapter.remove_record_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "propertyToRemove");
    }

    #[test]
    fn multiple_operations_in_sequence() {
        let mut adapter = MockPropertiesDBAdapter::new();

        adapter.put_record("prop1", 1, None).unwrap();
        adapter.put_record("prop2", 2, Some("ClassName")).unwrap();
        adapter.remove_record("prop1").unwrap();
        let _ = adapter.get_records();

        assert_eq!(adapter.put_record_calls.borrow().len(), 2);
        assert_eq!(adapter.remove_record_calls.borrow().len(), 1);
        assert!(adapter.records_called.borrow().clone());
    }
}
