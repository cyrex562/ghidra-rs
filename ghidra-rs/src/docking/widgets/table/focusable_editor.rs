/// Trait for cell editors that wish to be notified when editing begins so they
/// can request focus on the appropriate widget.
///
/// Corresponds to `docking.widgets.table.FocusableEditor` in the Java source.
pub trait FocusableEditor {
    /// Called when the editor should take focus.
    fn focus_editor(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEditor {
        focus_called: bool,
    }

    impl FocusableEditor for MockEditor {
        fn focus_editor(&mut self) {
            self.focus_called = true;
        }
    }

    #[test]
    fn focus_editor_is_called() {
        let mut editor = MockEditor { focus_called: false };
        editor.focus_editor();
        assert!(editor.focus_called);
    }

    #[test]
    fn focus_editor_can_be_called_multiple_times() {
        let mut editor = MockEditor { focus_called: false };
        editor.focus_editor();
        editor.focus_editor();
        assert!(editor.focus_called);
    }

    #[test]
    fn trait_object_usable() {
        let mut editor: Box<dyn FocusableEditor> = Box::new(MockEditor { focus_called: false });
        editor.focus_editor();
    }
}
