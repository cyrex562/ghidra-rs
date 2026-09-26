use std::collections::HashSet;

use crate::util::string_utilities::UNICODE_REPLACEMENT;

use super::StringInfoFeature;

/// A curated subset of Unicode scripts, standing in for Java's `Character.UnicodeScript` enum
/// (backed by the full Unicode `Scripts.txt` character database, ~170 variants).
///
/// This crate has no dependency providing that database (see `Cargo.toml` -- no
/// `unicode-script`-style crate is pulled in), so rather than fabricate coverage this crate
/// doesn't actually have, [`UnicodeScript::of`] recognizes only a handful of major scripts by
/// well-known Unicode block ranges and falls back to [`UnicodeScript::Common`] for everything
/// else (including, unlike Java, scripts this list simply doesn't cover -- see
/// [`UnicodeScript::of`] for what that means for [`StringInfo::from_str`]'s `CODEC_ERROR`
/// detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeScript {
    Common,
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Hebrew,
    Arabic,
    Devanagari,
    Thai,
    Georgian,
    Hangul,
    Hiragana,
    Katakana,
    Han,
}

impl UnicodeScript {
    /// Classifies a Unicode code point into a script, mirroring `Character.UnicodeScript.of(int)`.
    ///
    /// Reduced-fidelity port: only the scripts listed on [`UnicodeScript`] are distinguished, each
    /// by a small set of contiguous code point ranges; anything else falls back to `Common`. Java's
    /// `UNKNOWN` variant (returned only for genuinely *unassigned* code points, which
    /// `Character.UnicodeScript.of` would otherwise throw `IllegalArgumentException` for if the
    /// code point weren't even a valid Unicode scalar value) has no analogue here, since
    /// distinguishing "valid but outside our covered ranges" from "genuinely unassigned" would
    /// require the same missing character database. Practically: `StringInfo::from_str`'s
    /// `CODEC_ERROR` feature (driven by `UNKNOWN` in Java) fires here only for the
    /// [`UNICODE_REPLACEMENT`] character, not for text in scripts this table doesn't cover.
    pub fn of(code_point: u32) -> Self {
        match code_point {
            0x0041..=0x005A | 0x0061..=0x007A | 0x00C0..=0x02AF => UnicodeScript::Latin,
            0x0370..=0x03FF | 0x1F00..=0x1FFF => UnicodeScript::Greek,
            0x0400..=0x04FF | 0x0500..=0x052F => UnicodeScript::Cyrillic,
            0x0530..=0x058F => UnicodeScript::Armenian,
            0x0590..=0x05FF => UnicodeScript::Hebrew,
            0x0600..=0x06FF | 0x0750..=0x077F => UnicodeScript::Arabic,
            0x0900..=0x097F => UnicodeScript::Devanagari,
            0x0E00..=0x0E7F => UnicodeScript::Thai,
            0x10A0..=0x10FF => UnicodeScript::Georgian,
            0xAC00..=0xD7A3 | 0x1100..=0x11FF => UnicodeScript::Hangul,
            0x3040..=0x309F => UnicodeScript::Hiragana,
            0x30A0..=0x30FF => UnicodeScript::Katakana,
            0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF => UnicodeScript::Han,
            _ => UnicodeScript::Common,
        }
    }
}

/// Information about a string: which scripts (alphabets) it's made of, and any notable
/// conditions found in it.
///
/// Port of `ghidra.app.plugin.core.strings.StringInfo`, a Java `record`.
///
/// Java records derive `hashCode()` from all components, including `Set`s (whose `hashCode()` is
/// well-defined -- the sum of element hashes). Rust's `HashSet` deliberately doesn't implement
/// `Hash` (its iteration/internal layout isn't a stable basis for one), so `StringInfo` doesn't
/// derive `Hash` either; `PartialEq`/`Eq` (also record-derived in Java, via `equals()`) are still
/// ported since `HashSet: PartialEq` is unconditionally available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringInfo {
    /// The string itself.
    pub string_value: String,
    /// The set of scripts (alphabets) the string is made of. See [`UnicodeScript::of`] for the
    /// reduced coverage compared to Java's `Character.UnicodeScript`.
    pub scripts: HashSet<UnicodeScript>,
    /// Informational flags about various conditions found in the string.
    pub string_features: HashSet<StringInfoFeature>,
}

impl StringInfo {
    const STD_CTRL_CHARS: [char; 3] = ['\n', '\t', '\r'];

    /// Creates a [`StringInfo`] instance for `s`.
    ///
    /// Port of `StringInfo.fromString(String)`. Java accepts a nullable `String`, substituting
    /// `""` for `null`; `&str` can't be null, so that substitution has no Rust equivalent to port
    /// -- callers that would have passed `null` in Java simply pass `""` directly.
    ///
    /// Java iterates `s.codePoints()`, catching `IllegalArgumentException` per-codepoint to skip
    /// malformed ones (an unpaired surrogate half, or a value outside the Unicode range). Rust's
    /// `&str` is guaranteed valid UTF-8 by the type system -- every `char` yielded by
    /// [`str::chars`] is already a well-formed Unicode scalar value -- so that defensive
    /// catch-and-skip has nothing to trigger on here and is dropped.
    ///
    /// Java's `!Character.isDefined(codePoint)` check (part of the `NON_STD_CTRL_CHARS` feature)
    /// flags genuinely *unassigned* code points; Rust has no equivalent query without the same
    /// missing character database noted on [`UnicodeScript::of`], so every `char` is treated as
    /// "defined" here -- this feature effectively narrows to just the standalone-control-character
    /// case below (which is also the common case in practice).
    pub fn from_str(s: &str) -> Self {
        let mut scripts = HashSet::new();
        let mut features = HashSet::new();

        for ch in s.chars() {
            let code_point = ch as u32;
            scripts.insert(UnicodeScript::of(code_point));

            if code_point == UNICODE_REPLACEMENT {
                features.insert(StringInfoFeature::CodecError);
            }

            let is_non_std_ctrl_char = code_point < 32 && !Self::STD_CTRL_CHARS.contains(&ch);
            if is_non_std_ctrl_char {
                features.insert(StringInfoFeature::NonStdCtrlChars);
            }
        }

        StringInfo {
            string_value: s.to_string(),
            scripts,
            string_features: features,
        }
    }

    /// Returns whether this string contains a Unicode replacement character, indicating a
    /// decoding error somewhere upstream.
    ///
    /// Port of `StringInfo.hasCodecError()`.
    pub fn has_codec_error(&self) -> bool {
        self.string_features.contains(&StringInfoFeature::CodecError)
    }

    /// Returns whether this string contains non-standard control characters.
    ///
    /// Port of `StringInfo.hasNonStdCtrlChars()`.
    pub fn has_non_std_ctrl_chars(&self) -> bool {
        self.string_features
            .contains(&StringInfoFeature::NonStdCtrlChars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_no_scripts_or_features() {
        let info = StringInfo::from_str("");
        assert_eq!(info.string_value, "");
        assert!(info.scripts.is_empty());
        assert!(info.string_features.is_empty());
        assert!(!info.has_codec_error());
        assert!(!info.has_non_std_ctrl_chars());
    }

    #[test]
    fn plain_ascii_string_is_latin_with_no_features() {
        let info = StringInfo::from_str("Hello");
        assert_eq!(info.scripts, HashSet::from([UnicodeScript::Latin]));
        assert!(info.string_features.is_empty());
    }

    #[test]
    fn digits_and_punctuation_are_common_script() {
        let info = StringInfo::from_str("123!?");
        assert_eq!(info.scripts, HashSet::from([UnicodeScript::Common]));
    }

    #[test]
    fn mixed_latin_and_common_reports_both_scripts() {
        let info = StringInfo::from_str("abc123");
        assert_eq!(
            info.scripts,
            HashSet::from([UnicodeScript::Latin, UnicodeScript::Common])
        );
    }

    #[test]
    fn greek_text_is_recognized() {
        let info = StringInfo::from_str("\u{03B1}\u{03B2}\u{03B3}"); // αβγ
        assert_eq!(info.scripts, HashSet::from([UnicodeScript::Greek]));
    }

    #[test]
    fn han_text_is_recognized() {
        let info = StringInfo::from_str("\u{4E2D}\u{6587}"); // 中文
        assert_eq!(info.scripts, HashSet::from([UnicodeScript::Han]));
    }

    #[test]
    fn standard_control_chars_do_not_set_non_std_ctrl_chars_feature() {
        let info = StringInfo::from_str("a\nb\tc\rd");
        assert!(!info.has_non_std_ctrl_chars());
    }

    #[test]
    fn other_control_chars_set_non_std_ctrl_chars_feature() {
        let info = StringInfo::from_str("a\u{0001}b"); // SOH, not one of \n\t\r
        assert!(info.has_non_std_ctrl_chars());
    }

    #[test]
    fn unicode_replacement_char_sets_codec_error_feature() {
        let info = StringInfo::from_str("a\u{FFFD}b");
        assert!(info.has_codec_error());
    }

    #[test]
    fn string_without_issues_has_no_codec_error() {
        let info = StringInfo::from_str("clean string");
        assert!(!info.has_codec_error());
    }

    #[test]
    fn equal_inputs_produce_equal_string_info() {
        assert_eq!(StringInfo::from_str("same"), StringInfo::from_str("same"));
        assert_ne!(StringInfo::from_str("same"), StringInfo::from_str("diff"));
    }

    #[test]
    fn unicode_script_of_unmapped_code_point_falls_back_to_common() {
        // U+1F600 (an emoji) is not covered by this port's reduced script table.
        assert_eq!(UnicodeScript::of(0x1F600), UnicodeScript::Common);
    }
}
