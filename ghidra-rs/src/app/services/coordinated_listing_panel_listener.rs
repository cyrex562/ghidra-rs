use crate::program::model::listing::Program;

/// Listener for coordinated listing panel events.
///
/// Implementations of this trait can register to receive notifications when
/// the associated listing panel should be closed or when the active program changes.
pub trait CoordinatedListingPanelListener {
    /// Notifies the listener that its associated listing panel should be closed.
    ///
    /// # Returns
    /// `true` if the listener actually closes a listing panel, `false` otherwise.
    fn listing_closed(&self) -> bool;

    /// Notifies the listener that the active program has changed.
    ///
    /// # Arguments
    /// * `active_program` - The new active program
    fn active_program_changed(&self, active_program: &dyn Program);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockProgram {
        name: String,
    }

    impl Program for MockProgram {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_language_id(&self) -> &str {
            "x86:LE:64:default"
        }
    }

    struct MockCoordinatedListingPanelListener {
        listing_closed_called: RefCell<bool>,
        active_program_changed_called: RefCell<bool>,
        active_program_name: RefCell<String>,
    }

    impl MockCoordinatedListingPanelListener {
        fn new() -> Self {
            MockCoordinatedListingPanelListener {
                listing_closed_called: RefCell::new(false),
                active_program_changed_called: RefCell::new(false),
                active_program_name: RefCell::new(String::new()),
            }
        }
    }

    impl CoordinatedListingPanelListener for MockCoordinatedListingPanelListener {
        fn listing_closed(&self) -> bool {
            *self.listing_closed_called.borrow_mut() = true;
            true
        }

        fn active_program_changed(&self, active_program: &dyn Program) {
            *self.active_program_changed_called.borrow_mut() = true;
            *self.active_program_name.borrow_mut() = active_program.get_name().to_string();
        }
    }

    #[test]
    fn test_listing_closed_returns_true() {
        let listener = MockCoordinatedListingPanelListener::new();
        assert!(listener.listing_closed());
        assert!(*listener.listing_closed_called.borrow());
    }

    #[test]
    fn test_listing_closed_multiple_calls() {
        let listener = MockCoordinatedListingPanelListener::new();
        listener.listing_closed();
        listener.listing_closed();
        listener.listing_closed();
        assert!(*listener.listing_closed_called.borrow());
    }

    #[test]
    fn test_active_program_changed_updates_program() {
        let listener = MockCoordinatedListingPanelListener::new();
        let program = MockProgram {
            name: "test_program".to_string(),
        };

        listener.active_program_changed(&program);

        assert!(*listener.active_program_changed_called.borrow());
        assert_eq!(
            *listener.active_program_name.borrow(),
            "test_program"
        );
    }

    #[test]
    fn test_active_program_changed_with_different_programs() {
        let listener = MockCoordinatedListingPanelListener::new();
        let program1 = MockProgram {
            name: "program1".to_string(),
        };
        let program2 = MockProgram {
            name: "program2".to_string(),
        };

        listener.active_program_changed(&program1);
        assert_eq!(
            *listener.active_program_name.borrow(),
            "program1"
        );

        listener.active_program_changed(&program2);
        assert_eq!(
            *listener.active_program_name.borrow(),
            "program2"
        );
    }

    #[test]
    fn test_both_methods_can_be_called() {
        let listener = MockCoordinatedListingPanelListener::new();
        let program = MockProgram {
            name: "test_program".to_string(),
        };

        listener.active_program_changed(&program);
        let closed = listener.listing_closed();

        assert!(*listener.active_program_changed_called.borrow());
        assert!(*listener.listing_closed_called.borrow());
        assert!(closed);
    }

    #[test]
    fn test_program_name_preserved_correctly() {
        let listener = MockCoordinatedListingPanelListener::new();
        let program = MockProgram {
            name: "my_complex_program_name_123".to_string(),
        };

        listener.active_program_changed(&program);

        assert_eq!(
            *listener.active_program_name.borrow(),
            "my_complex_program_name_123"
        );
    }
}
