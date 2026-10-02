//! Port of `ghidra.framework.options.ActionTrigger`: the key stroke and/or
//! mouse binding that fires an action.

use crate::docking::MouseBinding;
use crate::util::awt::KeyStroke;

/// Error for an [`ActionTrigger`] with neither a key stroke nor a mouse binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyActionTrigger;

impl std::fmt::Display for EmptyActionTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Both the key stroke and mouse binding cannot be null")
    }
}

impl std::error::Error for EmptyActionTrigger {}

/// The key stroke and/or mouse binding that triggers an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionTrigger {
    key_stroke: Option<KeyStroke>,
    mouse_binding: Option<MouseBinding>,
}

impl ActionTrigger {
    /// `new ActionTrigger(keyStroke, mouseBinding)`; at least one is required.
    pub fn new(
        key_stroke: Option<KeyStroke>,
        mouse_binding: Option<MouseBinding>,
    ) -> Result<Self, EmptyActionTrigger> {
        if key_stroke.is_none() && mouse_binding.is_none() {
            return Err(EmptyActionTrigger);
        }
        Ok(Self { key_stroke, mouse_binding })
    }

    /// The key stroke, if any.
    pub fn key_stroke(&self) -> Option<KeyStroke> {
        self.key_stroke
    }

    /// The mouse binding, if any.
    pub fn mouse_binding(&self) -> Option<MouseBinding> {
        self.mouse_binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};

    #[test]
    fn requires_at_least_one_trigger() {
        assert!(ActionTrigger::new(None, None).is_err());
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        let t = ActionTrigger::new(Some(ks), None).unwrap();
        assert_eq!(t.key_stroke(), Some(ks));
        assert_eq!(t.mouse_binding(), None);
    }
}
