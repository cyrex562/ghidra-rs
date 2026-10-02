//! Port of `docking.KeyBindingPrecedence`.

/// Where a key binding is processed relative to Swing's own key handling.
/// Declaration order is priority order (earlier = processed first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyBindingPrecedence {
    /// Reserved for system actions (not settable by clients).
    SystemActionsLevel,
    /// Before key listeners.
    KeyListenerLevel,
    /// Before the component action map.
    ActionMapLevel,
    /// Normal tool action processing.
    DefaultLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_order_is_priority_order() {
        assert!(KeyBindingPrecedence::SystemActionsLevel < KeyBindingPrecedence::KeyListenerLevel);
        assert!(KeyBindingPrecedence::ActionMapLevel < KeyBindingPrecedence::DefaultLevel);
    }
}
