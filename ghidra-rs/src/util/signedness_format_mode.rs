/// Defines how the sign of integer-type numbers is to be interpreted for rendering.
///
/// Port of `ghidra.util.SignednessFormatMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignednessFormatMode {
    /// Values rendered in binary, octal, or hexadecimal are treated as unsigned;
    /// decimal values are treated as signed.
    Default,
    /// All values are rendered in their unsigned form.
    Unsigned,
    /// All values are rendered in their signed form.
    Signed,
}

impl SignednessFormatMode {
    /// Returns the variant whose ordinal equals `value`, or `None` if out of range.
    pub fn parse(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Default),
            1 => Some(Self::Unsigned),
            2 => Some(Self::Signed),
            _ => None,
        }
    }

    /// Returns the ordinal index of this variant (mirrors Java's `Enum.ordinal()`).
    pub fn ordinal(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_ordinals() {
        assert_eq!(SignednessFormatMode::parse(0), Some(SignednessFormatMode::Default));
        assert_eq!(SignednessFormatMode::parse(1), Some(SignednessFormatMode::Unsigned));
        assert_eq!(SignednessFormatMode::parse(2), Some(SignednessFormatMode::Signed));
    }

    #[test]
    fn parse_out_of_range() {
        assert_eq!(SignednessFormatMode::parse(3), None);
        assert_eq!(SignednessFormatMode::parse(-1), None);
        assert_eq!(SignednessFormatMode::parse(i32::MAX), None);
    }

    #[test]
    fn ordinal_roundtrip() {
        for (expected_ordinal, mode) in [
            (0, SignednessFormatMode::Default),
            (1, SignednessFormatMode::Unsigned),
            (2, SignednessFormatMode::Signed),
        ] {
            assert_eq!(mode.ordinal(), expected_ordinal);
            assert_eq!(SignednessFormatMode::parse(expected_ordinal), Some(mode));
        }
    }

    #[test]
    fn derives() {
        let a = SignednessFormatMode::Signed;
        let b = a;
        assert_eq!(a, b);
        let _ = format!("{:?}", a);
    }
}
