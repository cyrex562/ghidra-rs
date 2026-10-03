//! Port of `docking.action.KeyBindingType`.

/// How an action participates in key bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyBindingType {
    /// The action cannot have a key binding.
    Unsupported,
    /// The action has its own, user-editable key binding.
    Individual,
    /// The action shares a key binding with same-named actions.
    Shared,
}

impl KeyBindingType {
    /// `supportsKeyBindings()`
    pub fn supports_key_bindings(self) -> bool {
        self != KeyBindingType::Unsupported
    }

    /// `isShared()`
    pub fn is_shared(self) -> bool {
        self == KeyBindingType::Shared
    }

    /// `isManaged()`: the tool manages this action's binding individually.
    pub fn is_managed(self) -> bool {
        self == KeyBindingType::Individual
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicates_match_java() {
        assert!(!KeyBindingType::Unsupported.supports_key_bindings());
        assert!(KeyBindingType::Individual.supports_key_bindings());
        assert!(KeyBindingType::Shared.is_shared());
        assert!(KeyBindingType::Individual.is_managed());
        assert!(!KeyBindingType::Shared.is_managed());
    }
}
