/// Signals where windows should be placed when shown for the first time.
///
/// After being shown, a window's location is remembered, so this value is no longer used.
///
/// Corresponds to `docking.WindowPosition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowPosition {
    Top,
    Bottom,
    Left,
    Right,
    /// Signals that a window should not be placed next to windows in other groups, but should
    /// be placed into its own window.
    ///
    /// This position is ignored when used with components that share the same group.
    Window,
    /// Signals that windows should be stacked with other windows within the same group.
    Stack,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            WindowPosition::Top,
            WindowPosition::Bottom,
            WindowPosition::Left,
            WindowPosition::Right,
            WindowPosition::Window,
            WindowPosition::Stack,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn copy_and_clone() {
        let pos = WindowPosition::Top;
        let copied = pos;
        let cloned = pos.clone();
        assert_eq!(pos, copied);
        assert_eq!(pos, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", WindowPosition::Window), "Window");
        assert_eq!(format!("{:?}", WindowPosition::Stack), "Stack");
    }
}
