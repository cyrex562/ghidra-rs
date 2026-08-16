//! Listener interface for theme changes.
//!
//! Mirrors `generic.theme.ThemeListener` from Ghidra.

use crate::generic::seam_stubs::ThemeEvent;

/// Listener interface for theme changes.
pub trait ThemeListener: Send + Sync {
    /// Called when the theme or any of its values change.
    fn theme_changed(&self, event: &dyn ThemeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockThemeEvent {
        color_changed: bool,
        font_changed: bool,
        icon_changed: bool,
    }

    impl ThemeEvent for MockThemeEvent {
        fn is_color_changed(&self, _id: &str) -> bool {
            self.color_changed
        }

        fn is_font_changed(&self, _id: &str) -> bool {
            self.font_changed
        }

        fn is_icon_changed(&self, _id: &str) -> bool {
            self.icon_changed
        }

        fn is_look_and_feel_changed(&self) -> bool {
            false
        }

        fn has_any_color_changed(&self) -> bool {
            self.color_changed
        }

        fn has_any_font_changed(&self) -> bool {
            self.font_changed
        }

        fn has_any_icon_changed(&self) -> bool {
            self.icon_changed
        }

        fn have_all_values_changed(&self) -> bool {
            self.color_changed && self.font_changed && self.icon_changed
        }
    }

    struct MockThemeListener {
        called: Arc<Mutex<bool>>,
    }

    impl ThemeListener for MockThemeListener {
        fn theme_changed(&self, _event: &dyn ThemeEvent) {
            *self.called.lock().unwrap() = true;
        }
    }

    #[test]
    fn test_theme_listener_is_called_with_event() {
        let called = Arc::new(Mutex::new(false));
        let listener = MockThemeListener {
            called: called.clone(),
        };

        let event = MockThemeEvent {
            color_changed: true,
            font_changed: false,
            icon_changed: false,
        };

        listener.theme_changed(&event);
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_theme_event_color_changed_detection() {
        let event = MockThemeEvent {
            color_changed: true,
            font_changed: false,
            icon_changed: false,
        };

        assert!(event.is_color_changed("theme.color"));
        assert!(!event.is_font_changed("theme.font"));
        assert!(!event.is_icon_changed("theme.icon"));
        assert!(event.has_any_color_changed());
        assert!(!event.has_any_font_changed());
        assert!(!event.has_any_icon_changed());
    }

    #[test]
    fn test_theme_event_all_values_changed() {
        let event = MockThemeEvent {
            color_changed: true,
            font_changed: true,
            icon_changed: true,
        };

        assert!(event.have_all_values_changed());
    }
}
