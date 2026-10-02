//! Port of `gui.event.MouseBinding`: a mouse button plus modifier keys used as
//! an action trigger.

use crate::util::awt::key_stroke::{ALT_DOWN_MASK, CTRL_DOWN_MASK, META_DOWN_MASK, SHIFT_DOWN_MASK};

/// `InputEvent.BUTTON1_DOWN_MASK`
pub const BUTTON1_DOWN_MASK: i32 = 0x400;
/// `InputEvent.BUTTON2_DOWN_MASK`
pub const BUTTON2_DOWN_MASK: i32 = 0x800;
/// `InputEvent.BUTTON3_DOWN_MASK`
pub const BUTTON3_DOWN_MASK: i32 = 0x1000;

/// `InputEvent.getMaskForButton`: buttons 1-3 have fixed masks; extra buttons
/// start at bit 14.
pub fn mask_for_button(button: i32) -> i32 {
    match button {
        1 => BUTTON1_DOWN_MASK,
        2 => BUTTON2_DOWN_MASK,
        3 => BUTTON3_DOWN_MASK,
        b if (4..=20).contains(&b) => 1 << (14 + b - 4),
        _ => 0,
    }
}

/// A mouse button plus modifiers (`gui.event.MouseBinding`). As in Java the
/// modifiers include the button's own down mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MouseBinding {
    button: i32,
    modifiers: i32,
}

impl MouseBinding {
    /// `new MouseBinding(button, modifiers)`.
    pub fn new(button: i32, modifiers: i32) -> Self {
        let mut m = mask_for_button(button);
        if modifiers > 0 {
            m |= modifiers;
        }
        Self { button, modifiers: m }
    }

    /// The mouse button number (1-based).
    pub fn button(&self) -> i32 {
        self.button
    }

    /// Modifier bits, including the button mask.
    pub fn modifiers(&self) -> i32 {
        self.modifiers
    }

    /// `getDisplayText`, i.e. `InputEvent.getModifiersExText(modifiers)`:
    /// `Meta`, `Ctrl`, `Alt`, `Shift`, then `ButtonN`, joined by `+`.
    pub fn display_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (mask, name) in [
            (META_DOWN_MASK, "Meta"),
            (CTRL_DOWN_MASK, "Ctrl"),
            (ALT_DOWN_MASK, "Alt"),
            (SHIFT_DOWN_MASK, "Shift"),
        ] {
            if self.modifiers & mask != 0 {
                parts.push(name.to_owned());
            }
        }
        for b in 1..=20 {
            if self.modifiers & mask_for_button(b) != 0 {
                parts.push(format!("Button{b}"));
            }
        }
        if parts.is_empty() {
            format!("Button{}", self.button)
        } else {
            parts.join("+")
        }
    }

    /// `MouseBinding.getMouseBinding(String)`: needs a `buttonN` (N > 0) token;
    /// modifiers separated by `-`, `+` or space.
    pub fn parse(text: &str) -> Option<MouseBinding> {
        let lower = text.to_ascii_lowercase();
        let idx = lower.find("button")?;
        let digits: String = lower[idx + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
        let button: i32 = digits.parse().ok().filter(|b| *b > 0)?;
        let mut modifiers = 0;
        for token in lower.split(['-', '+', ' ']).filter(|t| !t.is_empty()) {
            if token.contains("shift") {
                modifiers |= SHIFT_DOWN_MASK;
            } else if token.contains("ctrl") {
                // Java uses the menu-shortcut mask (Ctrl off macOS).
                modifiers |= CTRL_DOWN_MASK;
            } else if token.contains("alt") {
                modifiers |= ALT_DOWN_MASK;
            } else if token.contains("meta") {
                modifiers |= META_DOWN_MASK;
            }
        }
        Some(MouseBinding::new(button, modifiers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::awt::key_stroke::{CTRL_DOWN_MASK, SHIFT_DOWN_MASK};

    #[test]
    fn modifiers_include_the_button_mask() {
        let mb = MouseBinding::new(3, CTRL_DOWN_MASK);
        assert_eq!(mb.button(), 3);
        assert_eq!(mb.modifiers(), CTRL_DOWN_MASK | BUTTON3_DOWN_MASK);
    }

    #[test]
    fn parses_like_java() {
        let mb = MouseBinding::parse("Ctrl-Button3").unwrap();
        assert_eq!(mb, MouseBinding::new(3, CTRL_DOWN_MASK));
        let mb = MouseBinding::parse("shift+ctrl+button4").unwrap();
        assert_eq!(mb.modifiers(), SHIFT_DOWN_MASK | CTRL_DOWN_MASK | (1 << 14));
        assert_eq!(MouseBinding::parse("Ctrl"), None);
        assert_eq!(MouseBinding::parse("Button0"), None);
    }

    #[test]
    fn display_text_uses_java_modifiers_ex_text() {
        assert_eq!(MouseBinding::new(3, CTRL_DOWN_MASK).display_text(), "Ctrl+Button3");
        assert_eq!(MouseBinding::new(1, 0).display_text(), "Button1");
    }
}
