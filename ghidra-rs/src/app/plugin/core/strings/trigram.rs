//! Rust port of `ghidra.app.plugin.core.strings.Trigram`.
//!
//! A tuple of 3 Unicode code points, used by the trigram string-validity model. Java's
//! `record Trigram(int[] codePoints)` becomes a plain struct; its `compareTo` (compare the three
//! code points in order) is exactly the derived lexicographic [`Ord`] on the array.

use std::fmt;
use std::io;

use super::string_trigram_iterator::StringTrigramIterator;

/// Symbol used in model files for the start-of-string position.
const START_OF_STRING: &str = "[^]";
/// Symbol used in model files for the end-of-string position.
const END_OF_STRING: &str = "[$]";

/// The `[xx]` descriptions used for control characters and space, mirroring Java's static
/// `mapCP(...)` table (`codePointToDescription` / `descriptionToCodePoint`).
const CODE_POINT_DESCRIPTIONS: &[(&str, i32)] = &[
    ("[NUL]", 0),
    ("[SOH]", 1),
    ("[STX]", 2),
    ("[ETX]", 3),
    ("[EOT]", 4),
    ("[ENQ]", 5),
    ("[ACK]", 6),
    ("[BEL]", 7),
    ("[BS]", 8),
    ("[HT]", 9),
    ("[LF]", 10),
    ("[VT]", 11),
    ("[FF]", 12),
    ("[CR]", 13),
    ("[SO]", 14),
    ("[SI]", 15),
    ("[DLE]", 16),
    ("[DC1]", 17),
    ("[DC2]", 18),
    ("[DC3]", 19),
    ("[DC4]", 20),
    ("[NAK]", 21),
    ("[SYN]", 22),
    ("[ETB]", 23),
    ("[CAN]", 24),
    ("[EM]", 25),
    ("[SUB]", 26),
    ("[ESC]", 27),
    ("[FS]", 28),
    ("[GS]", 29),
    ("[RS]", 30),
    ("[US]", 31),
    ("[SP]", 32),
    ("[DEL]", 127),
];

/// A tuple of 3 code points. The value `0` stands for the start/end of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Trigram {
    /// The three code points, in string order (Java record component `codePoints`).
    pub code_points: [i32; 3],
}

impl Trigram {
    /// Mirrors `Trigram.of(int, int, int)`.
    pub fn of(cp1: i32, cp2: i32, cp3: i32) -> Trigram {
        Trigram { code_points: [cp1, cp2, cp3] }
    }

    /// Parses a trigram from the three per-character symbols used in model files.
    ///
    /// Mirrors `Trigram.fromStringRep(String, String, String)`.
    ///
    /// # Errors
    /// An [`io::ErrorKind::InvalidData`] error for an empty or unknown symbol, or a bad
    /// `\uXXXX` / `\UXXXXXXXX` hex escape (Java's `NumberFormatException`).
    pub fn from_string_rep(s1: &str, s2: &str, s3: &str) -> io::Result<Trigram> {
        Ok(Trigram::of(decode_code_point(s1)?, decode_code_point(s2)?, decode_code_point(s3)?))
    }

    /// Iterates the trigrams of `s`. See [`StringTrigramIterator`].
    ///
    /// Mirrors `Trigram.iterate(String)`.
    pub fn iterate(s: &str) -> StringTrigramIterator<'_> {
        StringTrigramIterator::new(s)
    }

    /// The model-file representation of this trigram's three code points.
    ///
    /// Mirrors `toCharSeq()` (also `toString()`, see the [`fmt::Display`] impl).
    pub fn to_char_seq(&self) -> String {
        self.code_points.iter().map(|&cp| get_code_point_representation(cp)).collect()
    }
}

impl fmt::Display for Trigram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_char_seq())
    }
}

/// The model-file symbol for one code point: printable ASCII as itself, control characters and
/// space as `[xx]` descriptions, anything else as a `\uXXXX` / `\UXXXXXXXX` escape.
///
/// Mirrors the package-private static `getCodePointRepresentation(int)`.
pub fn get_code_point_representation(code_point: i32) -> String {
    if (33..=126).contains(&code_point) {
        return char::from(code_point as u8).to_string();
    }
    if let Some((desc, _)) = CODE_POINT_DESCRIPTIONS.iter().find(|(_, cp)| *cp == code_point) {
        return (*desc).to_string();
    }
    if code_point > 0 && code_point <= 0xFFFF {
        format!("\\u{:04X}", code_point)
    } else {
        format!("\\U{:08X}", code_point as u32)
    }
}

/// Mirrors the private static `decodeCodePoint(String)`.
fn decode_code_point(rep: &str) -> io::Result<i32> {
    let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
    let Some(first) = rep.chars().next() else {
        return Err(invalid("Invalid character symbol in model file".to_string()));
    };
    if rep.chars().count() == 1 {
        return Ok(first as i32);
    }
    let utf16_len = rep.encode_utf16().count();
    if utf16_len == 3 && (rep == START_OF_STRING || rep == END_OF_STRING) {
        // convert $, ^ (start-of-line, end-of-line) to null char
        return Ok(0);
    }
    let parse_hex = |digits: &str| {
        u32::from_str_radix(digits, 16)
            .ok()
            .map(|v| v as i32)
            .ok_or_else(|| invalid(format!("For input string: \"{digits}\" under radix 16")))
    };
    // "\\u" / "\\U" are ASCII, so the digits start at byte 2 and run to the end
    if utf16_len == 6 && rep.starts_with("\\u") {
        return parse_hex(&rep[2..]);
    }
    if utf16_len == 10 && rep.starts_with("\\U") {
        return parse_hex(&rep[2..]);
    }
    if rep.starts_with('[') {
        return CODE_POINT_DESCRIPTIONS
            .iter()
            .find(|(desc, _)| *desc == rep)
            .map(|(_, cp)| *cp)
            .ok_or_else(|| invalid(format!("Can not parse character {rep} in model file")));
    }
    Ok(first as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representation_of_printable_control_and_escaped() {
        assert_eq!(get_code_point_representation('a' as i32), "a");
        assert_eq!(get_code_point_representation('~' as i32), "~");
        assert_eq!(get_code_point_representation(0), "[NUL]");
        assert_eq!(get_code_point_representation(32), "[SP]");
        assert_eq!(get_code_point_representation(127), "[DEL]");
        assert_eq!(get_code_point_representation(0xE9), "\\u00E9");
        assert_eq!(get_code_point_representation(0x1F600), "\\U0001F600");
        assert_eq!(get_code_point_representation(-1), "\\UFFFFFFFF");
    }

    #[test]
    fn to_char_seq_concatenates() {
        let t = Trigram::of(0, 'h' as i32, 'i' as i32);
        assert_eq!(t.to_char_seq(), "[NUL]hi");
        assert_eq!(t.to_string(), "[NUL]hi");
    }

    #[test]
    fn from_string_rep_round_trips() {
        for t in [
            Trigram::of('a' as i32, ' ' as i32, 0xE9),
            Trigram::of(0x1F600, 10, 'Z' as i32),
            Trigram::of(127, 31, '[' as i32),
        ] {
            let reps: Vec<String> =
                t.code_points.iter().map(|&cp| get_code_point_representation(cp)).collect();
            assert_eq!(Trigram::from_string_rep(&reps[0], &reps[1], &reps[2]).unwrap(), t);
        }
    }

    #[test]
    fn from_string_rep_meta_chars_and_errors() {
        assert_eq!(Trigram::from_string_rep("[^]", "a", "[$]").unwrap(), Trigram::of(0, 97, 0));
        assert!(Trigram::from_string_rep("", "a", "b").is_err());
        assert!(Trigram::from_string_rep("[XX]", "a", "b").is_err());
        assert!(Trigram::from_string_rep("\\uZZZZ", "a", "b").is_err());
        // multi-char, non-special symbols decode to their first code point
        assert_eq!(Trigram::from_string_rep("ab", "c", "d").unwrap(), Trigram::of(97, 99, 100));
    }

    #[test]
    fn ordering_matches_compare_to() {
        assert!(Trigram::of(1, 2, 3) < Trigram::of(1, 2, 4));
        assert!(Trigram::of(1, 3, 0) > Trigram::of(1, 2, 9));
        assert!(Trigram::of(2, 0, 0) > Trigram::of(1, 9, 9));
        assert_eq!(Trigram::of(1, 2, 3).cmp(&Trigram::of(1, 2, 3)), std::cmp::Ordering::Equal);
    }
}
