/// A legacy style charset
///
/// Finding the particulars for these online has not been fun, so these are implemented on an
/// as-needed basis. There's probably a simple translation to some unicode code pages, since those
/// seem to be ordered by some of these legacy character sets. The default implementation for each
/// charset will just be equivalent to US-ASCII. There's a lot of plumbing missing around these, two.
/// For example, I'm assuming that switching to "the alternate charset" means using G1 instead of G0.
/// I've not read carefully enough to know how G2 or G3 are used.
///
/// It'd be nice to just use UTF-8, but the application would have to agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtCharset {
    Uk,
    UsAscii,
    Finnish,
    Swedish,
    German,
    FrenchCanadian,
    French,
    Italian,
    Spanish,
    Dutch,
    Greek,
    Turkish,
    Portugese,
    Hebrew,
    Swiss,
    NorwegianDanish,
    DecSpecialLines,
    DecSupplemental,
    DecTechnical,
    DecHebrew,
    DecGreek,
    DecTurkish,
    DecSupplementalGraphics,
    DecCyrillic,
}

impl VtCharset {
    /// Map a character, as decoded using US-ASCII, into the actual character for the character set.
    pub fn map_char(&self, c: char) -> char {
        match self {
            VtCharset::DecSpecialLines => match c {
                'j' => '\u{2518}', // 1pt lower-right corner
                'k' => '\u{2510}', // 1pt upper-right corner
                'l' => '\u{250C}', // 1pt upper-left corner
                'm' => '\u{2514}', // 1pt lower-left corner
                'q' => '\u{2500}', // 1pt horizontal line
                'x' => '\u{2502}', // 1pt vertical line
                _ => c,
            },
            _ => c,
        }
    }
}

/// The designation for a charset slot
///
/// It seems the terminal allows for the selection of 4 alternative charsets, the first of which
/// G0 is the default or primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharsetSlot {
    G0,
    G1,
    G2,
    G3,
}

impl CharsetSlot {
    /// Returns the byte that identifies this slot in a control sequence
    pub fn as_byte(&self) -> u8 {
        match self {
            CharsetSlot::G0 => b'(',
            CharsetSlot::G1 => b')',
            CharsetSlot::G2 => b'*',
            CharsetSlot::G3 => b'-',
        }
    }

    /// Create a CharsetSlot from a byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'(' => Some(CharsetSlot::G0),
            b')' => Some(CharsetSlot::G1),
            b'*' => Some(CharsetSlot::G2),
            b'-' => Some(CharsetSlot::G3),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_map_char() {
        let charset = VtCharset::UsAscii;
        assert_eq!(charset.map_char('A'), 'A');
        assert_eq!(charset.map_char('0'), '0');
        assert_eq!(charset.map_char(' '), ' ');
    }

    #[test]
    fn test_dec_special_lines_map_char() {
        let charset = VtCharset::DecSpecialLines;
        assert_eq!(charset.map_char('j'), '\u{2518}'); // lower-right corner
        assert_eq!(charset.map_char('k'), '\u{2510}'); // upper-right corner
        assert_eq!(charset.map_char('l'), '\u{250C}'); // upper-left corner
        assert_eq!(charset.map_char('m'), '\u{2514}'); // lower-left corner
        assert_eq!(charset.map_char('q'), '\u{2500}'); // horizontal line
        assert_eq!(charset.map_char('x'), '\u{2502}'); // vertical line
    }

    #[test]
    fn test_dec_special_lines_unmapped_chars() {
        let charset = VtCharset::DecSpecialLines;
        // Characters not in the mapping should pass through unchanged
        assert_eq!(charset.map_char('a'), 'a');
        assert_eq!(charset.map_char('0'), '0');
        assert_eq!(charset.map_char(' '), ' ');
    }

    #[test]
    fn test_other_charsets_all_pass_through() {
        let charsets = [
            VtCharset::Uk,
            VtCharset::Finnish,
            VtCharset::Swedish,
            VtCharset::German,
            VtCharset::FrenchCanadian,
            VtCharset::French,
            VtCharset::Italian,
            VtCharset::Spanish,
            VtCharset::Dutch,
            VtCharset::Greek,
            VtCharset::Turkish,
            VtCharset::Portugese,
            VtCharset::Hebrew,
            VtCharset::Swiss,
            VtCharset::NorwegianDanish,
            VtCharset::DecSupplemental,
            VtCharset::DecTechnical,
            VtCharset::DecHebrew,
            VtCharset::DecGreek,
            VtCharset::DecTurkish,
            VtCharset::DecSupplementalGraphics,
            VtCharset::DecCyrillic,
        ];

        for charset in &charsets {
            assert_eq!(charset.map_char('A'), 'A');
            assert_eq!(charset.map_char('z'), 'z');
            assert_eq!(charset.map_char('5'), '5');
            assert_eq!(charset.map_char('@'), '@');
        }
    }

    #[test]
    fn test_charset_slot_as_byte() {
        assert_eq!(CharsetSlot::G0.as_byte(), b'(');
        assert_eq!(CharsetSlot::G1.as_byte(), b')');
        assert_eq!(CharsetSlot::G2.as_byte(), b'*');
        assert_eq!(CharsetSlot::G3.as_byte(), b'-');
    }

    #[test]
    fn test_charset_slot_from_byte() {
        assert_eq!(CharsetSlot::from_byte(b'('), Some(CharsetSlot::G0));
        assert_eq!(CharsetSlot::from_byte(b')'), Some(CharsetSlot::G1));
        assert_eq!(CharsetSlot::from_byte(b'*'), Some(CharsetSlot::G2));
        assert_eq!(CharsetSlot::from_byte(b'-'), Some(CharsetSlot::G3));
        assert_eq!(CharsetSlot::from_byte(b'x'), None);
        assert_eq!(CharsetSlot::from_byte(0), None);
    }

    #[test]
    fn test_charset_slot_roundtrip() {
        let slots = [CharsetSlot::G0, CharsetSlot::G1, CharsetSlot::G2, CharsetSlot::G3];
        for slot in &slots {
            assert_eq!(CharsetSlot::from_byte(slot.as_byte()), Some(*slot));
        }
    }

    #[test]
    fn test_vt_charset_clone_and_copy() {
        let charset = VtCharset::UsAscii;
        let charset_copy = charset;
        assert_eq!(charset, charset_copy);
    }
}
