/// Character encoding width, mirroring `ghidra.util.ascii.CharWidth`.
///
/// Represents the byte-width of a single code unit for a given Unicode encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharWidth {
    /// UTF-8 encoding: 1-byte code units.
    Utf8,
    /// UTF-16 encoding: 2-byte code units.
    Utf16,
    /// UTF-32 encoding: 4-byte code units.
    Utf32,
}

impl CharWidth {
    /// Returns the number of bytes per code unit for this encoding.
    pub fn size(self) -> u8 {
        match self {
            CharWidth::Utf8 => 1,
            CharWidth::Utf16 => 2,
            CharWidth::Utf32 => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_size_is_one() {
        assert_eq!(CharWidth::Utf8.size(), 1);
    }

    #[test]
    fn utf16_size_is_two() {
        assert_eq!(CharWidth::Utf16.size(), 2);
    }

    #[test]
    fn utf32_size_is_four() {
        assert_eq!(CharWidth::Utf32.size(), 4);
    }

    #[test]
    fn all_variants_distinct() {
        assert_ne!(CharWidth::Utf8, CharWidth::Utf16);
        assert_ne!(CharWidth::Utf8, CharWidth::Utf32);
        assert_ne!(CharWidth::Utf16, CharWidth::Utf32);
    }

    #[test]
    fn copy_and_clone() {
        let w = CharWidth::Utf16;
        let w2 = w;
        assert_eq!(w, w2);
        let w3 = w.clone();
        assert_eq!(w, w3);
    }
}
