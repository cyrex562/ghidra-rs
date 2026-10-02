//! Toolkit-neutral port of the `javax.swing.KeyStroke` value plus the
//! keystroke string forms Ghidra reads and writes (`KeyBindingUtils`).

/// `InputEvent.SHIFT_DOWN_MASK`
pub const SHIFT_DOWN_MASK: i32 = 0x40;
/// `InputEvent.CTRL_DOWN_MASK`
pub const CTRL_DOWN_MASK: i32 = 0x80;
/// `InputEvent.META_DOWN_MASK`
pub const META_DOWN_MASK: i32 = 0x100;
/// `InputEvent.ALT_DOWN_MASK`
pub const ALT_DOWN_MASK: i32 = 0x200;

// Legacy `InputEvent.*_MASK` values that `KeyStroke`s may still carry.
const SHIFT_MASK: i32 = 1;
const CTRL_MASK: i32 = 2;
const META_MASK: i32 = 4;
const ALT_MASK: i32 = 8;

/// Java `KeyEvent.VK_*` key codes and their names (the name is the `VK_`
/// constant without its prefix, as `AWTKeyStroke.toString` prints it).
pub mod vk {
    macro_rules! keys {
        ($($name:ident = $code:expr),* $(,)?) => {
            $(#[allow(missing_docs)] pub const $name: i32 = $code;)*
            const TABLE: &[(&str, i32)] = &[$((stringify!($name), $code)),*];
        };
    }
    keys! {
        ENTER = 0x0A, BACK_SPACE = 0x08, TAB = 0x09, CANCEL = 0x03, CLEAR = 0x0C, PAUSE = 0x13,
        CAPS_LOCK = 0x14, ESCAPE = 0x1B, SPACE = 0x20, PAGE_UP = 0x21, PAGE_DOWN = 0x22,
        END = 0x23, HOME = 0x24, LEFT = 0x25, UP = 0x26, RIGHT = 0x27, DOWN = 0x28,
        COMMA = 0x2C, MINUS = 0x2D, PERIOD = 0x2E, SLASH = 0x2F,
        D0 = 0x30, D1 = 0x31, D2 = 0x32, D3 = 0x33, D4 = 0x34, D5 = 0x35, D6 = 0x36, D7 = 0x37,
        D8 = 0x38, D9 = 0x39, SEMICOLON = 0x3B, EQUALS = 0x3D,
        A = 0x41, B = 0x42, C = 0x43, D = 0x44, E = 0x45, F = 0x46, G = 0x47, H = 0x48, I = 0x49,
        J = 0x4A, K = 0x4B, L = 0x4C, M = 0x4D, N = 0x4E, O = 0x4F, P = 0x50, Q = 0x51, R = 0x52,
        S = 0x53, T = 0x54, U = 0x55, V = 0x56, W = 0x57, X = 0x58, Y = 0x59, Z = 0x5A,
        OPEN_BRACKET = 0x5B, BACK_SLASH = 0x5C, CLOSE_BRACKET = 0x5D,
        NUMPAD0 = 0x60, NUMPAD1 = 0x61, NUMPAD2 = 0x62, NUMPAD3 = 0x63, NUMPAD4 = 0x64,
        NUMPAD5 = 0x65, NUMPAD6 = 0x66, NUMPAD7 = 0x67, NUMPAD8 = 0x68, NUMPAD9 = 0x69,
        MULTIPLY = 0x6A, ADD = 0x6B, SUBTRACT = 0x6D, DECIMAL = 0x6E, DIVIDE = 0x6F,
        F1 = 0x70, F2 = 0x71, F3 = 0x72, F4 = 0x73, F5 = 0x74, F6 = 0x75, F7 = 0x76, F8 = 0x77,
        F9 = 0x78, F10 = 0x79, F11 = 0x7A, F12 = 0x7B, DELETE = 0x7F, INSERT = 0x9B,
        BACK_QUOTE = 0xC0, QUOTE = 0xDE, CONTEXT_MENU = 0x20D,
    }

    /// Name of a key code (`"G"`, `"F5"`, `"DELETE"`), or `None` if unknown.
    /// Digits print as `"0"`..`"9"` like Java (`VK_0`).
    pub fn key_name(code: i32) -> Option<&'static str> {
        if (0x30..=0x39).contains(&code) {
            const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
            return Some(DIGITS[(code - 0x30) as usize]);
        }
        TABLE.iter().find(|(_, c)| *c == code).map(|(n, _)| *n)
    }

    /// Key code for an upper-case key name, or `None` if unknown.
    pub fn key_code(name: &str) -> Option<i32> {
        if name.len() == 1 && name.as_bytes()[0].is_ascii_digit() {
            return Some(name.as_bytes()[0] as i32);
        }
        TABLE.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
    }
}

/// A key press with modifiers (`javax.swing.KeyStroke`, `KEY_PRESSED` form).
/// Modifiers are always the `*_DOWN_MASK` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyStroke {
    key_code: i32,
    modifiers: i32,
    on_key_release: bool,
}

impl KeyStroke {
    /// `KeyStroke.getKeyStroke(keyCode, modifiers)`, with legacy masks
    /// normalised as `KeyBindingUtils.validateKeyStroke` does.
    pub fn new(key_code: i32, modifiers: i32) -> Self {
        Self { key_code, modifiers: normalise(modifiers), on_key_release: false }
    }

    /// The `KeyEvent.VK_*` code.
    pub fn key_code(self) -> i32 {
        self.key_code
    }

    /// The `*_DOWN_MASK` modifier bits.
    pub fn modifiers(self) -> i32 {
        self.modifiers
    }

    /// Whether this stroke fires on key release.
    pub fn is_on_key_release(self) -> bool {
        self.on_key_release
    }

    /// Ghidra's display/persistence form (`KeyBindingUtils.parseKeyStroke(KeyStroke)`).
    /// Java inserts each modifier at the front in the order Shift, Alt, Ctrl,
    /// Meta, so the printed order is `Meta-`, `Ctrl-`, `Alt-`, `Shift-`.
    pub fn to_ghidra_string(self) -> String {
        let mut out = String::new();
        if self.modifiers & META_DOWN_MASK != 0 {
            out.push_str("Meta-");
        }
        if self.modifiers & CTRL_DOWN_MASK != 0 {
            out.push_str("Ctrl-");
        }
        if self.modifiers & ALT_DOWN_MASK != 0 {
            out.push_str("Alt-");
        }
        if self.modifiers & SHIFT_DOWN_MASK != 0 {
            out.push_str("Shift-");
        }
        match vk::key_name(self.key_code) {
            Some(name) => out.push_str(name),
            None => out.push_str(&format!("Unknown keyCode: 0x{:x}", self.key_code)),
        }
        out
    }

    /// `KeyBindingUtils.parseKeyStroke(String)`: tokens separated by `-` or
    /// space, modifiers case-insensitive and de-duplicated, `pressed`/`typed`/
    /// `released` ignored; exactly one key name must remain.
    pub fn parse(text: &str) -> Option<KeyStroke> {
        let mut pieces: Vec<&str> = Vec::new();
        for token in text.split(['-', ' ']).filter(|t| !t.is_empty()) {
            if !pieces.contains(&token) {
                pieces.push(token);
            }
        }
        let mut modifiers = 0;
        let mut keys = Vec::new();
        for piece in pieces {
            let lower = piece.to_ascii_lowercase();
            if lower.contains("shift") {
                modifiers |= SHIFT_DOWN_MASK;
            } else if lower.contains("ctrl") || lower.contains("control") {
                modifiers |= CTRL_DOWN_MASK;
            } else if lower.contains("alt") {
                modifiers |= ALT_DOWN_MASK;
            } else if lower.contains("meta") {
                modifiers |= META_DOWN_MASK;
            } else if lower.contains("pressed") || lower.contains("typed") || lower.contains("released") {
                // event-type words carry no key information
            } else {
                keys.push(piece);
            }
        }
        if keys.len() != 1 {
            if !keys.is_empty() {
                tracing::warn!(
                    "Invalid keystroke string found. Expected format of '[modifier] ... key'. Found: '{text}'"
                );
            }
            return None;
        }
        let code = vk::key_code(&keys[0].to_ascii_uppercase())?;
        Some(KeyStroke::new(code, modifiers))
    }
}

fn normalise(mut m: i32) -> i32 {
    for (legacy, down) in [
        (SHIFT_MASK, SHIFT_DOWN_MASK),
        (CTRL_MASK, CTRL_DOWN_MASK),
        (META_MASK, META_DOWN_MASK),
        (ALT_MASK, ALT_DOWN_MASK),
    ] {
        if m & legacy != 0 {
            m = (m & !legacy) | down;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_space_and_dash_separated_forms_identically() {
        let a = KeyStroke::parse("ctrl shift G").unwrap();
        let b = KeyStroke::parse("Ctrl-Shift-G").unwrap();
        let c = KeyStroke::parse("shift-ctrl-g").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.key_code(), vk::G);
        assert_eq!(a.modifiers(), CTRL_DOWN_MASK | SHIFT_DOWN_MASK);
    }

    #[test]
    fn duplicate_modifiers_and_pressed_token_are_ignored() {
        assert_eq!(KeyStroke::parse("ctrl ctrl pressed G"), KeyStroke::parse("ctrl G"));
    }

    #[test]
    fn prints_in_ghidra_modifier_order() {
        // Java KeyBindingUtils.parseKeyStroke(KeyStroke): Meta, Ctrl, Alt, Shift; '-' separator.
        let ks = KeyStroke::new(vk::G, SHIFT_DOWN_MASK | CTRL_DOWN_MASK | ALT_DOWN_MASK);
        assert_eq!(ks.to_ghidra_string(), "Ctrl-Alt-Shift-G");
        assert_eq!(KeyStroke::new(vk::F5, 0).to_ghidra_string(), "F5");
        assert_eq!(KeyStroke::new(vk::DELETE, 0).to_ghidra_string(), "DELETE");
        let all = KeyStroke::new(vk::G, META_DOWN_MASK | SHIFT_DOWN_MASK | CTRL_DOWN_MASK | ALT_DOWN_MASK);
        assert_eq!(all.to_ghidra_string(), "Meta-Ctrl-Alt-Shift-G");
        assert_eq!(KeyStroke::new(vk::C, META_DOWN_MASK | CTRL_DOWN_MASK).to_ghidra_string(), "Meta-Ctrl-C");
    }

    #[test]
    fn plus_is_not_a_separator_like_java() {
        assert_eq!(KeyStroke::parse("CTRL+SHIFT+G"), None);
    }

    #[test]
    fn round_trips_through_string() {
        for s in ["Ctrl-Shift-G", "F5", "Alt-ENTER", "Ctrl-SPACE", "Meta-Q"] {
            let ks = KeyStroke::parse(s).unwrap_or_else(|| panic!("parse {s}"));
            assert_eq!(ks.to_ghidra_string(), s, "{s}");
        }
    }

    #[test]
    fn blank_or_modifier_only_is_none() {
        assert_eq!(KeyStroke::parse(""), None);
        assert_eq!(KeyStroke::parse("   "), None);
        assert_eq!(KeyStroke::parse("ctrl shift"), None);
        assert_eq!(KeyStroke::parse("ctrl NOT_A_KEY"), None);
    }

    #[test]
    fn legacy_masks_normalise_to_down_masks() {
        // Java validateKeyStroke: SHIFT_MASK(1)/CTRL_MASK(2)/META_MASK(4)/ALT_MASK(8) -> *_DOWN_MASK
        assert_eq!(KeyStroke::new(vk::A, 1 | 2).modifiers(), SHIFT_DOWN_MASK | CTRL_DOWN_MASK);
        assert_eq!(KeyStroke::new(vk::A, 4 | 8).modifiers(), META_DOWN_MASK | ALT_DOWN_MASK);
    }
}
