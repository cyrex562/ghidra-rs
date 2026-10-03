//! Port of `docking.action.KeyBindingData`.

use std::fmt;

use crate::docking::{KeyBindingPrecedence, MouseBinding};
use crate::framework::options::ActionTrigger;
use crate::util::awt::KeyStroke;

/// Errors constructing a [`KeyBindingData`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBindingError {
    /// Clients may not use `SystemActionsLevel` precedence.
    SystemPrecedence,
    /// The keystroke string did not parse.
    InvalidKeyStroke(String),
}

impl fmt::Display for KeyBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemPrecedence => f.write_str("Can't set precedence to System KeyBindingPrecedence"),
            Self::InvalidKeyStroke(s) => write!(f, "Invalid keystroke string: {s}"),
        }
    }
}

impl std::error::Error for KeyBindingError {}

/// A key stroke and/or mouse binding for an action, with its precedence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyBindingData {
    key_stroke: Option<KeyStroke>,
    precedence: KeyBindingPrecedence,
    mouse_binding: Option<MouseBinding>,
}

impl KeyBindingData {
    /// `new KeyBindingData(keyStroke)` at default precedence.
    pub fn new(key_stroke: KeyStroke) -> Self {
        Self { key_stroke: Some(key_stroke), precedence: KeyBindingPrecedence::DefaultLevel, mouse_binding: None }
    }

    /// `new KeyBindingData(keyStroke, precedence)`; system precedence is rejected.
    pub fn with_precedence(key_stroke: KeyStroke, precedence: KeyBindingPrecedence) -> Result<Self, KeyBindingError> {
        if precedence == KeyBindingPrecedence::SystemActionsLevel {
            return Err(KeyBindingError::SystemPrecedence);
        }
        Ok(Self { key_stroke: Some(key_stroke), precedence, mouse_binding: None })
    }

    /// `new KeyBindingData(mouseBinding)`.
    pub fn from_mouse(mouse_binding: MouseBinding) -> Self {
        Self { key_stroke: None, precedence: KeyBindingPrecedence::DefaultLevel, mouse_binding: Some(mouse_binding) }
    }

    /// `new KeyBindingData(actionTrigger)`.
    pub fn from_trigger(trigger: &ActionTrigger) -> Self {
        Self {
            key_stroke: trigger.key_stroke(),
            precedence: KeyBindingPrecedence::DefaultLevel,
            mouse_binding: trigger.mouse_binding(),
        }
    }

    /// `new KeyBindingData(String)`, via `KeyBindingUtils.parseKeyStroke`.
    pub fn parse(text: &str) -> Result<Self, KeyBindingError> {
        KeyStroke::parse(text).map(Self::new).ok_or_else(|| KeyBindingError::InvalidKeyStroke(text.to_owned()))
    }

    /// `createSystemKeyBindingData`: framework-only system precedence.
    pub(crate) fn system(key_stroke: KeyStroke) -> Self {
        Self { key_stroke: Some(key_stroke), precedence: KeyBindingPrecedence::SystemActionsLevel, mouse_binding: None }
    }

    /// `KeyBindingData.update(kbData, newTrigger)`.
    pub fn update(existing: Option<&KeyBindingData>, new_trigger: Option<&ActionTrigger>) -> Option<KeyBindingData> {
        match (existing, new_trigger) {
            (_, None) => None,
            (None, Some(t)) => Some(Self::from_trigger(t)),
            (Some(d), Some(t)) if d.action_trigger() == *t => Some(d.clone()),
            (Some(_), Some(t)) => Some(Self::from_trigger(t)),
        }
    }

    /// `getKeyBinding()`
    pub fn key_binding(&self) -> Option<KeyStroke> {
        self.key_stroke
    }

    /// `getKeyBindingPrecedence()`
    pub fn precedence(&self) -> KeyBindingPrecedence {
        self.precedence
    }

    /// `getMouseBinding()`
    pub fn mouse_binding(&self) -> Option<MouseBinding> {
        self.mouse_binding
    }

    /// `getActionTrigger()`
    pub fn action_trigger(&self) -> ActionTrigger {
        ActionTrigger::new(self.key_stroke, self.mouse_binding)
            .expect("KeyBindingData always has a key stroke or a mouse binding")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};

    #[test]
    fn system_precedence_is_rejected_for_clients() {
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        assert!(KeyBindingData::with_precedence(ks, KeyBindingPrecedence::SystemActionsLevel).is_err());
        assert_eq!(KeyBindingData::new(ks).precedence(), KeyBindingPrecedence::DefaultLevel);
        assert_eq!(KeyBindingData::system(ks).precedence(), KeyBindingPrecedence::SystemActionsLevel);
    }

    #[test]
    fn parse_rejects_invalid_strings() {
        assert!(KeyBindingData::parse("ctrl G").is_ok());
        assert!(KeyBindingData::parse("ctrl").is_err());
    }

    #[test]
    fn update_follows_java_semantics() {
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        let trig = ActionTrigger::new(Some(ks), None).unwrap();
        assert_eq!(KeyBindingData::update(None, None), None);
        let added = KeyBindingData::update(None, Some(&trig)).unwrap();
        assert_eq!(added.key_binding(), Some(ks));
        assert_eq!(KeyBindingData::update(Some(&added), None), None);
        // same trigger: unchanged (Java returns the same instance)
        assert_eq!(KeyBindingData::update(Some(&added), Some(&trig)), Some(added.clone()));
    }

    #[test]
    fn mouse_only_binding_has_no_key_stroke() {
        let mb = crate::docking::MouseBinding::new(3, 0);
        let d = KeyBindingData::from_mouse(mb);
        assert_eq!(d.key_binding(), None);
        assert_eq!(d.mouse_binding(), Some(mb));
        assert_eq!(d.action_trigger().mouse_binding(), Some(mb));
    }
}
