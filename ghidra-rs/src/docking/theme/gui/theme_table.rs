/// A common interface for theme tables.
///
/// Corresponds to `docking.theme.gui.ThemeTable`.
pub trait ThemeTable {
    /// Sets whether to show IDs used for system values.
    fn set_show_system_values(&mut self, show: bool);

    /// Returns `true` if system IDs are currently being shown.
    fn is_showing_system_values(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockThemeTable {
        show_system_values: bool,
    }

    impl ThemeTable for MockThemeTable {
        fn set_show_system_values(&mut self, show: bool) {
            self.show_system_values = show;
        }

        fn is_showing_system_values(&self) -> bool {
            self.show_system_values
        }
    }

    #[test]
    fn defaults_to_false() {
        let table = MockThemeTable { show_system_values: false };
        assert!(!table.is_showing_system_values());
    }

    #[test]
    fn set_show_system_values_true() {
        let mut table = MockThemeTable { show_system_values: false };
        table.set_show_system_values(true);
        assert!(table.is_showing_system_values());
    }

    #[test]
    fn set_show_system_values_false() {
        let mut table = MockThemeTable { show_system_values: true };
        table.set_show_system_values(false);
        assert!(!table.is_showing_system_values());
    }

    #[test]
    fn toggle_show_system_values() {
        let mut table = MockThemeTable { show_system_values: false };
        table.set_show_system_values(true);
        assert!(table.is_showing_system_values());
        table.set_show_system_values(false);
        assert!(!table.is_showing_system_values());
    }
}
