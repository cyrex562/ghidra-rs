use std::cmp::Ordering;
use crate::app::tablechooser::AddressableRowObject;
use crate::app::seam_stubs::GColumnRenderer;

/// Allows users to add custom columns to the TableChooserDialog.
///
/// Implementations define the column type T, provide the value for each row,
/// and implement comparison logic for sorting.
pub trait ColumnDisplay<T: 'static + Send + Sync>: Send + Sync {
    /// Gets the value to display in this column for the given row object.
    fn get_column_value(&self, row_object: &dyn AddressableRowObject) -> T;

    /// Gets the name of this column.
    fn get_column_name(&self) -> String;

    /// Gets the type name of the column values.
    fn get_column_class(&self) -> String;

    /// Compares two row objects for sorting purposes.
    fn compare(&self, o1: &dyn AddressableRowObject, o2: &dyn AddressableRowObject) -> Ordering;

    /// Returns a custom renderer for this column's cells.
    ///
    /// The default implementation returns None, which means the table will use
    /// its default rendering for this column.
    fn get_renderer(&self) -> Option<Box<dyn GColumnRenderer>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct TestRowObject {
        address: Address,
        value: i32,
    }

    impl AddressableRowObject for TestRowObject {
        fn get_address(&self) -> &Address {
            &self.address
        }
    }

    struct TestColumnDisplay;

    impl ColumnDisplay<i32> for TestColumnDisplay {
        fn get_column_value(&self, row_object: &dyn AddressableRowObject) -> i32 {
            // In a real implementation, we'd cast row_object to TestRowObject
            // For this test, we just return a fixed value
            42
        }

        fn get_column_name(&self) -> String {
            "Test Column".to_string()
        }

        fn get_column_class(&self) -> String {
            "i32".to_string()
        }

        fn compare(&self, o1: &dyn AddressableRowObject, o2: &dyn AddressableRowObject) -> Ordering {
            o1.get_address().cmp(o2.get_address())
        }
    }

    #[test]
    fn test_get_column_name() {
        let col = TestColumnDisplay;
        assert_eq!(col.get_column_name(), "Test Column");
    }

    #[test]
    fn test_get_column_class() {
        let col = TestColumnDisplay;
        assert_eq!(col.get_column_class(), "i32");
    }

    #[test]
    fn test_get_column_value() {
        let col = TestColumnDisplay;
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x1000);
        let row = TestRowObject {
            address: addr,
            value: 99,
        };

        let val = col.get_column_value(&row);
        assert_eq!(val, 42);
    }

    #[test]
    fn test_compare_rows() {
        let col = TestColumnDisplay;
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr1 = Address::new(space.clone(), 0x1000);
        let addr2 = Address::new(space, 0x2000);

        let row1 = TestRowObject {
            address: addr1,
            value: 1,
        };
        let row2 = TestRowObject {
            address: addr2,
            value: 2,
        };

        assert_eq!(col.compare(&row1, &row2), Ordering::Less);
        assert_eq!(col.compare(&row2, &row1), Ordering::Greater);
        assert_eq!(col.compare(&row1, &row1), Ordering::Equal);
    }

    #[test]
    fn test_get_renderer_default() {
        let col = TestColumnDisplay;
        assert!(col.get_renderer().is_none());
    }
}
