// Port of ghidra.app.plugin.core.function.editor.ModelChangeListener

/// Trait for listening to model changes in the function editor.
pub trait ModelChangeListener {
    /// Tell the GUI to refresh its data.
    fn data_changed(&self);

    /// Tell the GUI that row indexes are invalid so that cell editors can be cancelled.
    fn table_rows_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple test implementation of ModelChangeListener to verify the trait works.
    struct TestListener {
        data_changed_called: bool,
        table_rows_changed_called: bool,
    }

    impl TestListener {
        fn new() -> Self {
            TestListener {
                data_changed_called: false,
                table_rows_changed_called: false,
            }
        }
    }

    impl ModelChangeListener for TestListener {
        fn data_changed(&self) {
            // Would normally update internal state, but since we need &self not &mut self,
            // this simulates the contract
        }

        fn table_rows_changed(&self) {
            // Would normally update internal state, but since we need &self not &mut self,
            // this simulates the contract
        }
    }

    #[test]
    fn test_listener_can_be_implemented() {
        let listener = TestListener::new();
        listener.data_changed();
        listener.table_rows_changed();
    }

    #[test]
    fn test_listener_trait_object() {
        let listener: Box<dyn ModelChangeListener> = Box::new(TestListener::new());
        listener.data_changed();
        listener.table_rows_changed();
    }

    /// A mutable test implementation to verify the listener can track state changes.
    struct MutableTestListener {
        data_changed_count: usize,
        table_rows_changed_count: usize,
    }

    impl MutableTestListener {
        fn new() -> Self {
            MutableTestListener {
                data_changed_count: 0,
                table_rows_changed_count: 0,
            }
        }

        fn data_changed_mut(&mut self) {
            self.data_changed_count += 1;
        }

        fn table_rows_changed_mut(&mut self) {
            self.table_rows_changed_count += 1;
        }
    }

    #[test]
    fn test_mutable_listener_tracking() {
        let mut listener = MutableTestListener::new();
        listener.data_changed_mut();
        listener.data_changed_mut();
        listener.table_rows_changed_mut();

        assert_eq!(listener.data_changed_count, 2);
        assert_eq!(listener.table_rows_changed_count, 1);
    }
}
