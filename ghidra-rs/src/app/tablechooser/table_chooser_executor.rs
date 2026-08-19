use crate::app::tablechooser::AddressableRowObject;
use crate::util::task::TaskMonitor;

/// The interface clients must implement to use the `TableChooserDialog`. This trait is the
/// callback that is used to process items from the dialog's table as users select one or more
/// rows in the table and then press the table's "apply" button.
pub trait TableChooserExecutor {
    /// A short name suitable for display in the "apply" button that indicates what the "apply"
    /// action does.
    fn get_button_name(&self) -> String;

    /// Applies this executor's action to the given row object. Return true if the given object
    /// should be removed from the table.
    ///
    /// This method call will be wrapped in a transaction so the client does not have to do so.
    /// Multiple selected rows will all be processed in a single transaction.
    fn execute(&self, row_object: &dyn AddressableRowObject) -> bool;

    /// A callback that clients can choose to use instead of [`execute`](Self::execute).
    ///
    /// To use this method, simply override it to perform work on each item passed in. Due to
    /// supporting backward compatibility, clients still have to implement
    /// [`execute`](Self::execute). When using `execute_in_bulk`, simply implement `execute` as a
    /// do-nothing method.
    ///
    /// You are responsible for checking the cancelled state of the task monitor by calling
    /// `TaskMonitor::is_cancelled`. This allows long-running operations to be cancelled. You
    /// should also call `TaskMonitor::increment_progress` as you process each item in order to
    /// show progress in the UI.
    ///
    /// Note: [`execute`](Self::execute) is only called with items that are still in the dialog's
    /// table model. Some clients may programmatically manipulate the table model by removing row
    /// objects via the dialog's add/remove methods. `execute` is only called for items that still
    /// exist in the model. Contrastingly, this version offers no such protection. Thus, if you
    /// manipulate the table model yourself, you also need to ensure that any items you process in
    /// this method are still in the dialog. To see if the item is still in the dialog, call the
    /// dialog's `contains` method.
    ///
    /// Returns true if you wish to execute items in bulk; always return true from this method if
    /// you override it.
    fn execute_in_bulk(
        &self,
        row_objects: &[Box<dyn AddressableRowObject>],
        deleted: &mut Vec<Box<dyn AddressableRowObject>>,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        let _ = (row_objects, deleted, monitor);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct TestRowObject {
        address: Address,
    }

    impl AddressableRowObject for TestRowObject {
        fn get_address(&self) -> &Address {
            &self.address
        }
    }

    /// Mirrors Java's default `executeInBulk`, which always returns `false`, and an `execute`
    /// that removes the row (return `true`) unconditionally.
    struct RemoveAllExecutor;

    impl TableChooserExecutor for RemoveAllExecutor {
        fn get_button_name(&self) -> String {
            "Remove".to_string()
        }

        fn execute(&self, _row_object: &dyn AddressableRowObject) -> bool {
            true
        }
    }

    fn make_row(offset: i64) -> TestRowObject {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        TestRowObject {
            address: Address::new(space, offset),
        }
    }

    #[test]
    fn test_get_button_name() {
        let executor = RemoveAllExecutor;
        assert_eq!(executor.get_button_name(), "Remove");
    }

    #[test]
    fn test_execute_returns_true_to_remove_row() {
        let executor = RemoveAllExecutor;
        let row = make_row(0x1000);
        assert!(executor.execute(&row));
    }

    #[test]
    fn test_execute_in_bulk_default_returns_false() {
        let executor = RemoveAllExecutor;
        let rows: Vec<Box<dyn AddressableRowObject>> = vec![Box::new(make_row(0x1000))];
        let mut deleted: Vec<Box<dyn AddressableRowObject>> = Vec::new();
        let monitor = crate::util::task::DummyMonitor;

        assert!(!executor.execute_in_bulk(&rows, &mut deleted, &monitor));
        assert!(deleted.is_empty());
    }
}
