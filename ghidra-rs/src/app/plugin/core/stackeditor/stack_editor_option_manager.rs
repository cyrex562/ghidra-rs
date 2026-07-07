/// Provides configuration options for the stack editor.
pub trait StackEditorOptionManager {
    /// Returns whether stack numbers should be displayed in hexadecimal format.
    fn show_stack_numbers_in_hex(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStackEditorOptionManager {
        show_hex: bool,
    }

    impl MockStackEditorOptionManager {
        fn new(show_hex: bool) -> Self {
            Self { show_hex }
        }
    }

    impl StackEditorOptionManager for MockStackEditorOptionManager {
        fn show_stack_numbers_in_hex(&self) -> bool {
            self.show_hex
        }
    }

    #[test]
    fn test_show_stack_numbers_in_hex_true() {
        let manager = MockStackEditorOptionManager::new(true);
        assert!(manager.show_stack_numbers_in_hex());
    }

    #[test]
    fn test_show_stack_numbers_in_hex_false() {
        let manager = MockStackEditorOptionManager::new(false);
        assert!(!manager.show_stack_numbers_in_hex());
    }
}
