//! Qt key events → Ghidra `KeyStroke`s. This is the UI-edge conversion (spec
//! §2): Qt key codes and modifier flags in, toolkit-neutral strokes out.

use ghidra_rs::util::awt::key_stroke::{vk, ALT_DOWN_MASK, CTRL_DOWN_MASK, META_DOWN_MASK, SHIFT_DOWN_MASK};
use ghidra_rs::util::awt::KeyStroke;

// Qt::KeyboardModifier flags.
const QT_SHIFT: u32 = 0x0200_0000;
const QT_CTRL: u32 = 0x0400_0000;
const QT_ALT: u32 = 0x0800_0000;
const QT_META: u32 = 0x1000_0000;

/// Maps a Qt key code to a Java `VK_*` code (`None` for modifier-only or
/// unmapped keys). Printable ASCII keys share their codes between Qt and Java.
fn qt_key_to_vk(qt_key: i32) -> Option<i32> {
    Some(match qt_key {
        0x41..=0x5a | 0x30..=0x39 => qt_key,
        0x20 => vk::SPACE,
        0x2c => vk::COMMA,
        0x2d => vk::MINUS,
        0x2e => vk::PERIOD,
        0x2f => vk::SLASH,
        0x3b => vk::SEMICOLON,
        0x3d => vk::EQUALS,
        0x5b => vk::OPEN_BRACKET,
        0x5c => vk::BACK_SLASH,
        0x5d => vk::CLOSE_BRACKET,
        0x60 => vk::BACK_QUOTE,
        0x27 => vk::QUOTE,
        0x0100_0000 => vk::ESCAPE,
        0x0100_0001 => vk::TAB,
        0x0100_0003 => vk::BACK_SPACE,
        0x0100_0004 | 0x0100_0005 => vk::ENTER,
        0x0100_0006 => vk::INSERT,
        0x0100_0007 => vk::DELETE,
        0x0100_0008 => vk::PAUSE,
        0x0100_0010 => vk::HOME,
        0x0100_0011 => vk::END,
        0x0100_0012 => vk::LEFT,
        0x0100_0013 => vk::UP,
        0x0100_0014 => vk::RIGHT,
        0x0100_0015 => vk::DOWN,
        0x0100_0016 => vk::PAGE_UP,
        0x0100_0017 => vk::PAGE_DOWN,
        0x0100_0024 => vk::CAPS_LOCK,
        0x0100_0055 => vk::CONTEXT_MENU,
        k @ 0x0100_0030..=0x0100_003b => vk::F1 + (k - 0x0100_0030),
        _ => return None,
    })
}

/// Converts a Qt key press (`QKeyEvent::key()`, `QKeyEvent::modifiers()`)
/// into a Ghidra key stroke.
pub fn qt_to_key_stroke(qt_key: i32, qt_modifiers: u32) -> Option<KeyStroke> {
    let code = qt_key_to_vk(qt_key)?;
    let mut m = 0;
    if qt_modifiers & QT_SHIFT != 0 {
        m |= SHIFT_DOWN_MASK;
    }
    if qt_modifiers & QT_CTRL != 0 {
        m |= CTRL_DOWN_MASK;
    }
    if qt_modifiers & QT_ALT != 0 {
        m |= ALT_DOWN_MASK;
    }
    if qt_modifiers & QT_META != 0 {
        m |= META_DOWN_MASK;
    }
    Some(KeyStroke::new(code, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIFT: u32 = 0x0200_0000;
    const CTRL: u32 = 0x0400_0000;
    const ALT: u32 = 0x0800_0000;
    const META: u32 = 0x1000_0000;

    #[test]
    fn letters_digits_and_modifiers() {
        let ks = qt_to_key_stroke(0x47 /*Key_G*/, CTRL | SHIFT).unwrap();
        assert_eq!(ks.to_ghidra_string(), "Ctrl-Shift-G");
        assert_eq!(qt_to_key_stroke(0x35 /*Key_5*/, ALT).unwrap().to_ghidra_string(), "Alt-5");
        assert_eq!(qt_to_key_stroke(0x51 /*Key_Q*/, META).unwrap().to_ghidra_string(), "Meta-Q");
    }

    #[test]
    fn special_keys() {
        assert_eq!(qt_to_key_stroke(0x0100_0030 /*Key_F1*/, 0).unwrap().to_ghidra_string(), "F1");
        assert_eq!(qt_to_key_stroke(0x0100_003b /*Key_F12*/, 0).unwrap().to_ghidra_string(), "F12");
        assert_eq!(qt_to_key_stroke(0x0100_0004 /*Key_Return*/, 0).unwrap().to_ghidra_string(), "ENTER");
        assert_eq!(qt_to_key_stroke(0x0100_0005 /*Key_Enter*/, 0).unwrap().to_ghidra_string(), "ENTER");
        assert_eq!(qt_to_key_stroke(0x0100_0000 /*Key_Escape*/, 0).unwrap().to_ghidra_string(), "ESCAPE");
        assert_eq!(qt_to_key_stroke(0x20 /*Key_Space*/, CTRL).unwrap().to_ghidra_string(), "Ctrl-SPACE");
        assert_eq!(qt_to_key_stroke(0x0100_0007 /*Key_Delete*/, 0).unwrap().to_ghidra_string(), "DELETE");
        assert_eq!(qt_to_key_stroke(0x0100_0013 /*Key_Up*/, 0).unwrap().to_ghidra_string(), "UP");
    }

    #[test]
    fn modifier_only_and_unknown_keys_are_none() {
        assert_eq!(qt_to_key_stroke(0x0100_0021 /*Key_Control*/, CTRL), None);
        assert_eq!(qt_to_key_stroke(0x0100_0020 /*Key_Shift*/, SHIFT), None);
        assert_eq!(qt_to_key_stroke(0x0100_ffff, 0), None);
    }
}
