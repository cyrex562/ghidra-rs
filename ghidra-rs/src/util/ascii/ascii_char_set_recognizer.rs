use super::CharSetRecognizer;

/// Recognizes standard printable ASCII characters plus common whitespace control characters
/// (tab, newline, carriage return). Ports `ghidra.util.ascii.AsciiCharSetRecognizer`.
pub struct AsciiCharSetRecognizer;

impl CharSetRecognizer for AsciiCharSetRecognizer {
    fn contains(&self, c: i32) -> bool {
        (c >= 0x20 && c <= 0x7E) || c == 0x0D || c == 0x0A || c == 0x09
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recognizer() -> AsciiCharSetRecognizer {
        AsciiCharSetRecognizer
    }

    #[test]
    fn printable_ascii_range() {
        let r = recognizer();
        assert!(r.contains(0x20)); // space
        assert!(r.contains(0x7E)); // '~'
        assert!(r.contains(b'A' as i32));
        assert!(r.contains(b'z' as i32));
        assert!(r.contains(b'0' as i32));
    }

    #[test]
    fn accepted_control_chars() {
        let r = recognizer();
        assert!(r.contains(0x09)); // tab
        assert!(r.contains(0x0A)); // newline
        assert!(r.contains(0x0D)); // carriage return
    }

    #[test]
    fn rejected_control_chars() {
        let r = recognizer();
        assert!(!r.contains(0x00)); // NUL
        assert!(!r.contains(0x08)); // backspace
        assert!(!r.contains(0x0B)); // vertical tab
        assert!(!r.contains(0x0C)); // form feed
        assert!(!r.contains(0x0E));
        assert!(!r.contains(0x1F)); // unit separator (just below space)
    }

    #[test]
    fn rejected_above_tilde() {
        let r = recognizer();
        assert!(!r.contains(0x7F)); // DEL
        assert!(!r.contains(0x80)); // first extended byte
        assert!(!r.contains(0xFF));
    }

    #[test]
    fn rejected_negative() {
        let r = recognizer();
        assert!(!r.contains(-1));
        assert!(!r.contains(i32::MIN));
    }
}
