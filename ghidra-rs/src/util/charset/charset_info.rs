use std::collections::{BTreeSet, HashSet};

use serde::Serialize;

use crate::generic::json::Json;

/// Fields excluded from the JSON representation produced by [`CharsetInfo`]'s
/// `Display` impl.
const FIELDS_TO_EXCLUDE_FROM_JSON: &[&str] = &["standardCharset"];

/// Unicode script constants used to categorize the codepoints a charset can produce.
///
/// Mirrors the `java.lang.Character.UnicodeScript` values referenced by Ghidra's
/// `charset_info.json` dataset, plus [`UnicodeScript::Unknown`] mirroring
/// `UnicodeScript.UNKNOWN`. Rust has no built-in Unicode script registry, so this
/// enum stands in for the subset of the JDK's `UnicodeScript` enum that Ghidra's
/// charset metadata actually uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnicodeScript {
    Adlam,
    Ahom,
    AnatolianHieroglyphs,
    Arabic,
    Armenian,
    Avestan,
    Balinese,
    Bamum,
    BassaVah,
    Batak,
    Bengali,
    Bhaiksuki,
    Bopomofo,
    Brahmi,
    Braille,
    Buginese,
    Buhid,
    CanadianAboriginal,
    Carian,
    CaucasianAlbanian,
    Chakma,
    Cham,
    Cherokee,
    Chorasmian,
    Common,
    Coptic,
    Cuneiform,
    Cypriot,
    CyproMinoan,
    Cyrillic,
    Deseret,
    Devanagari,
    DivesAkuru,
    Dogra,
    Duployan,
    EgyptianHieroglyphs,
    Elbasan,
    Elymaic,
    Ethiopic,
    Georgian,
    Glagolitic,
    Gothic,
    Grantha,
    Greek,
    Gujarati,
    GunjalaGondi,
    Gurmukhi,
    Han,
    Hangul,
    HanifiRohingya,
    Hanunoo,
    Hatran,
    Hebrew,
    Hiragana,
    ImperialAramaic,
    Inherited,
    InscriptionalPahlavi,
    InscriptionalParthian,
    Javanese,
    Kaithi,
    Kannada,
    Katakana,
    Kawi,
    KayahLi,
    Kharoshthi,
    KhitanSmallScript,
    Khmer,
    Khojki,
    Khudawadi,
    Lao,
    Latin,
    Lepcha,
    Limbu,
    LinearA,
    LinearB,
    Lisu,
    Lycian,
    Lydian,
    Mahajani,
    Makasar,
    Malayalam,
    Mandaic,
    Manichaean,
    Marchen,
    MasaramGondi,
    Medefaidrin,
    MeeteiMayek,
    MendeKikakui,
    MeroiticCursive,
    MeroiticHieroglyphs,
    Miao,
    Modi,
    Mongolian,
    Mro,
    Multani,
    Myanmar,
    Nabataean,
    NagMundari,
    Nandinagari,
    Newa,
    NewTaiLue,
    Nko,
    Nushu,
    NyiakengPuachueHmong,
    Ogham,
    OldHungarian,
    OldItalic,
    OldNorthArabian,
    OldPermic,
    OldPersian,
    OldSogdian,
    OldSouthArabian,
    OldTurkic,
    OldUyghur,
    OlChiki,
    Oriya,
    Osage,
    Osmanya,
    PahawhHmong,
    Palmyrene,
    PauCinHau,
    PhagsPa,
    Phoenician,
    PsalterPahlavi,
    Rejang,
    Runic,
    Samaritan,
    Saurashtra,
    Sharada,
    Shavian,
    Siddham,
    Signwriting,
    Sinhala,
    Sogdian,
    SoraSompeng,
    Soyombo,
    Sundanese,
    SylotiNagri,
    Syriac,
    Tagalog,
    Tagbanwa,
    TaiLe,
    TaiTham,
    TaiViet,
    Takri,
    Tamil,
    Tangsa,
    Tangut,
    Telugu,
    Thaana,
    Thai,
    Tibetan,
    Tifinagh,
    Tirhuta,
    Toto,
    Ugaritic,
    Vai,
    Vithkuqi,
    Wancho,
    WarangCiti,
    Yezidi,
    Yi,
    ZanabazarSquare,
    /// Mirrors `UnicodeScript.UNKNOWN`: no known script.
    Unknown,
}

impl UnicodeScript {
    /// All script values, mirroring `EnumSet.allOf(UnicodeScript.class)`.
    pub const ALL: &'static [UnicodeScript] = &[
        UnicodeScript::Adlam,
        UnicodeScript::Ahom,
        UnicodeScript::AnatolianHieroglyphs,
        UnicodeScript::Arabic,
        UnicodeScript::Armenian,
        UnicodeScript::Avestan,
        UnicodeScript::Balinese,
        UnicodeScript::Bamum,
        UnicodeScript::BassaVah,
        UnicodeScript::Batak,
        UnicodeScript::Bengali,
        UnicodeScript::Bhaiksuki,
        UnicodeScript::Bopomofo,
        UnicodeScript::Brahmi,
        UnicodeScript::Braille,
        UnicodeScript::Buginese,
        UnicodeScript::Buhid,
        UnicodeScript::CanadianAboriginal,
        UnicodeScript::Carian,
        UnicodeScript::CaucasianAlbanian,
        UnicodeScript::Chakma,
        UnicodeScript::Cham,
        UnicodeScript::Cherokee,
        UnicodeScript::Chorasmian,
        UnicodeScript::Common,
        UnicodeScript::Coptic,
        UnicodeScript::Cuneiform,
        UnicodeScript::Cypriot,
        UnicodeScript::CyproMinoan,
        UnicodeScript::Cyrillic,
        UnicodeScript::Deseret,
        UnicodeScript::Devanagari,
        UnicodeScript::DivesAkuru,
        UnicodeScript::Dogra,
        UnicodeScript::Duployan,
        UnicodeScript::EgyptianHieroglyphs,
        UnicodeScript::Elbasan,
        UnicodeScript::Elymaic,
        UnicodeScript::Ethiopic,
        UnicodeScript::Georgian,
        UnicodeScript::Glagolitic,
        UnicodeScript::Gothic,
        UnicodeScript::Grantha,
        UnicodeScript::Greek,
        UnicodeScript::Gujarati,
        UnicodeScript::GunjalaGondi,
        UnicodeScript::Gurmukhi,
        UnicodeScript::Han,
        UnicodeScript::Hangul,
        UnicodeScript::HanifiRohingya,
        UnicodeScript::Hanunoo,
        UnicodeScript::Hatran,
        UnicodeScript::Hebrew,
        UnicodeScript::Hiragana,
        UnicodeScript::ImperialAramaic,
        UnicodeScript::Inherited,
        UnicodeScript::InscriptionalPahlavi,
        UnicodeScript::InscriptionalParthian,
        UnicodeScript::Javanese,
        UnicodeScript::Kaithi,
        UnicodeScript::Kannada,
        UnicodeScript::Katakana,
        UnicodeScript::Kawi,
        UnicodeScript::KayahLi,
        UnicodeScript::Kharoshthi,
        UnicodeScript::KhitanSmallScript,
        UnicodeScript::Khmer,
        UnicodeScript::Khojki,
        UnicodeScript::Khudawadi,
        UnicodeScript::Lao,
        UnicodeScript::Latin,
        UnicodeScript::Lepcha,
        UnicodeScript::Limbu,
        UnicodeScript::LinearA,
        UnicodeScript::LinearB,
        UnicodeScript::Lisu,
        UnicodeScript::Lycian,
        UnicodeScript::Lydian,
        UnicodeScript::Mahajani,
        UnicodeScript::Makasar,
        UnicodeScript::Malayalam,
        UnicodeScript::Mandaic,
        UnicodeScript::Manichaean,
        UnicodeScript::Marchen,
        UnicodeScript::MasaramGondi,
        UnicodeScript::Medefaidrin,
        UnicodeScript::MeeteiMayek,
        UnicodeScript::MendeKikakui,
        UnicodeScript::MeroiticCursive,
        UnicodeScript::MeroiticHieroglyphs,
        UnicodeScript::Miao,
        UnicodeScript::Modi,
        UnicodeScript::Mongolian,
        UnicodeScript::Mro,
        UnicodeScript::Multani,
        UnicodeScript::Myanmar,
        UnicodeScript::Nabataean,
        UnicodeScript::NagMundari,
        UnicodeScript::Nandinagari,
        UnicodeScript::Newa,
        UnicodeScript::NewTaiLue,
        UnicodeScript::Nko,
        UnicodeScript::Nushu,
        UnicodeScript::NyiakengPuachueHmong,
        UnicodeScript::Ogham,
        UnicodeScript::OldHungarian,
        UnicodeScript::OldItalic,
        UnicodeScript::OldNorthArabian,
        UnicodeScript::OldPermic,
        UnicodeScript::OldPersian,
        UnicodeScript::OldSogdian,
        UnicodeScript::OldSouthArabian,
        UnicodeScript::OldTurkic,
        UnicodeScript::OldUyghur,
        UnicodeScript::OlChiki,
        UnicodeScript::Oriya,
        UnicodeScript::Osage,
        UnicodeScript::Osmanya,
        UnicodeScript::PahawhHmong,
        UnicodeScript::Palmyrene,
        UnicodeScript::PauCinHau,
        UnicodeScript::PhagsPa,
        UnicodeScript::Phoenician,
        UnicodeScript::PsalterPahlavi,
        UnicodeScript::Rejang,
        UnicodeScript::Runic,
        UnicodeScript::Samaritan,
        UnicodeScript::Saurashtra,
        UnicodeScript::Sharada,
        UnicodeScript::Shavian,
        UnicodeScript::Siddham,
        UnicodeScript::Signwriting,
        UnicodeScript::Sinhala,
        UnicodeScript::Sogdian,
        UnicodeScript::SoraSompeng,
        UnicodeScript::Soyombo,
        UnicodeScript::Sundanese,
        UnicodeScript::SylotiNagri,
        UnicodeScript::Syriac,
        UnicodeScript::Tagalog,
        UnicodeScript::Tagbanwa,
        UnicodeScript::TaiLe,
        UnicodeScript::TaiTham,
        UnicodeScript::TaiViet,
        UnicodeScript::Takri,
        UnicodeScript::Tamil,
        UnicodeScript::Tangsa,
        UnicodeScript::Tangut,
        UnicodeScript::Telugu,
        UnicodeScript::Thaana,
        UnicodeScript::Thai,
        UnicodeScript::Tibetan,
        UnicodeScript::Tifinagh,
        UnicodeScript::Tirhuta,
        UnicodeScript::Toto,
        UnicodeScript::Ugaritic,
        UnicodeScript::Vai,
        UnicodeScript::Vithkuqi,
        UnicodeScript::Wancho,
        UnicodeScript::WarangCiti,
        UnicodeScript::Yezidi,
        UnicodeScript::Yi,
        UnicodeScript::ZanabazarSquare,
        UnicodeScript::Unknown,
    ];
}

/// Additional information about a [character encoding] that Ghidra needs to be
/// able to create Ghidra string datatype instances.
///
/// See `charset_info.json` to specify info about a custom charset.
///
/// Unlike the Java original, this type does not wrap a live charset codec object:
/// this crate has no charset/codec registry equivalent to `java.nio.charset.Charset`,
/// so `CharsetInfo` here only carries the charset's name and metadata.
///
/// [character encoding]: https://en.wikipedia.org/wiki/Character_encoding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CharsetInfo {
    name: String,
    comment: Option<String>,
    min_bytes_per_char: i32,
    max_bytes_per_char: i32,
    alignment: i32,
    code_point_count: i32,
    scripts: BTreeSet<UnicodeScript>,
    contains: HashSet<String>,
    can_produce_error: bool,
    /// Not serialized, see [`FIELDS_TO_EXCLUDE_FROM_JSON`].
    standard_charset: bool,
}

impl CharsetInfo {
    /// Creates a `CharsetInfo` wrapping an arbitrary charset name, with only
    /// minimal, conservative metadata: unknown byte-length bounds, no known
    /// scripts, and not one of Ghidra's curated "standard" charsets.
    pub fn from_charset_name(name: impl Into<String>) -> Self {
        Self::new(
            name.into(),
            None,
            1,
            -1,
            1,
            -1,
            false,
            true,
            BTreeSet::new(),
            HashSet::new(),
        )
    }

    /// Creates a new `CharsetInfo` with the given details.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        comment: Option<String>,
        min_bytes_per_char: i32,
        max_bytes_per_char: i32,
        alignment: i32,
        code_point_count: i32,
        standard_charset: bool,
        can_produce_error: bool,
        scripts: BTreeSet<UnicodeScript>,
        contains: HashSet<String>,
    ) -> Self {
        Self {
            name: name.into(),
            comment,
            min_bytes_per_char,
            max_bytes_per_char,
            alignment,
            code_point_count,
            standard_charset,
            can_produce_error,
            scripts,
            contains,
        }
    }

    /// Returns a copy of this instance, with a new comment value.
    pub fn with_comment(&self, new_comment: Option<String>) -> CharsetInfo {
        CharsetInfo::new(
            self.name.clone(),
            new_comment,
            self.min_bytes_per_char,
            self.max_bytes_per_char,
            self.alignment,
            self.code_point_count,
            self.standard_charset,
            self.can_produce_error,
            self.scripts.clone(),
            self.contains.clone(),
        )
    }

    /// Returns the name of the charset.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this is a standard charset that is guaranteed to be
    /// present in Ghidra's curated charset metadata, otherwise `false`.
    pub fn is_standard_charset(&self) -> bool {
        self.standard_charset
    }

    /// Returns `true` if this charset can produce Unicode REPLACEMENT codepoints
    /// for bad byte sequences, otherwise `false` if there are no byte sequences
    /// that result in REPLACEMENT codepoints. This is typically single-byte
    /// charsets that map all byte values to a codepoint.
    pub fn can_produce_error(&self) -> bool {
        self.can_produce_error
    }

    /// Returns `true` if this charset can produce Unicode codepoints that are in
    /// all scripts.
    pub fn supports_all_scripts(&self) -> bool {
        self.scripts.len() >= UnicodeScript::ALL.len() - 1 /* ignore unknown */
    }

    /// Returns the `UnicodeScript`s that this charset can produce.
    pub fn scripts(&self) -> &BTreeSet<UnicodeScript> {
        &self.scripts
    }

    /// Returns `true` if this charset only consumes a fixed number of bytes per
    /// output codepoint.
    pub fn has_fixed_length_chars(&self) -> bool {
        self.min_bytes_per_char > 0 && self.min_bytes_per_char == self.max_bytes_per_char
    }

    /// Returns the alignment value for this charset, typically 1 for most
    /// charsets, but for well-known fixed-width charsets, it will return those
    /// charsets' fixed width.
    pub fn alignment(&self) -> i32 {
        self.alignment
    }

    /// Returns the smallest number of bytes needed to produce a codepoint.
    pub fn min_bytes_per_char(&self) -> i32 {
        self.min_bytes_per_char
    }

    /// Returns the largest number of bytes needed to produce a codepoint.
    pub fn max_bytes_per_char(&self) -> i32 {
        self.max_bytes_per_char
    }

    /// Returns the number of codepoints that this charset can produce.
    pub fn code_point_count(&self) -> i32 {
        self.code_point_count
    }

    /// Returns the names of other charsets that this charset contains (in the
    /// sense of `Charset#contains(Charset)`).
    pub fn contains(&self) -> &HashSet<String> {
        &self.contains
    }

    /// Returns a string comment describing this charset, or `None`.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

impl PartialEq for CharsetInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for CharsetInfo {}

impl std::hash::Hash for CharsetInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl std::fmt::Display for CharsetInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Json::to_string_exclude(self, FIELDS_TO_EXCLUDE_FROM_JSON))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_scripts_count_includes_unknown() {
        assert_eq!(UnicodeScript::ALL.len(), 164);
        assert_eq!(UnicodeScript::ALL[UnicodeScript::ALL.len() - 1], UnicodeScript::Unknown);
    }

    #[test]
    fn from_charset_name_defaults() {
        let info = CharsetInfo::from_charset_name("UTF-8");
        assert_eq!(info.name(), "UTF-8");
        assert_eq!(info.comment(), None);
        assert_eq!(info.min_bytes_per_char(), 1);
        assert_eq!(info.max_bytes_per_char(), -1);
        assert_eq!(info.alignment(), 1);
        assert_eq!(info.code_point_count(), -1);
        assert!(!info.is_standard_charset());
        assert!(info.can_produce_error());
        assert!(info.scripts().is_empty());
        assert!(info.contains().is_empty());
    }

    #[test]
    fn new_and_getters() {
        let mut scripts = BTreeSet::new();
        scripts.insert(UnicodeScript::Latin);
        scripts.insert(UnicodeScript::Common);
        let mut contains = HashSet::new();
        contains.insert("US-ASCII".to_string());

        let info = CharsetInfo::new(
            "Big5",
            Some("Traditional Chinese".to_string()),
            1,
            2,
            1,
            13830,
            true,
            true,
            scripts.clone(),
            contains.clone(),
        );

        assert_eq!(info.name(), "Big5");
        assert_eq!(info.comment(), Some("Traditional Chinese"));
        assert_eq!(info.min_bytes_per_char(), 1);
        assert_eq!(info.max_bytes_per_char(), 2);
        assert_eq!(info.alignment(), 1);
        assert_eq!(info.code_point_count(), 13830);
        assert!(info.is_standard_charset());
        assert!(info.can_produce_error());
        assert_eq!(info.scripts(), &scripts);
        assert_eq!(info.contains(), &contains);
    }

    #[test]
    fn with_comment_returns_new_instance_with_other_fields_preserved() {
        let info = CharsetInfo::from_charset_name("US-ASCII");
        let commented = info.with_comment(Some("7-bit ASCII".to_string()));

        assert_eq!(info.comment(), None);
        assert_eq!(commented.comment(), Some("7-bit ASCII"));
        assert_eq!(commented.name(), info.name());
        assert_eq!(commented.min_bytes_per_char(), info.min_bytes_per_char());
    }

    #[test]
    fn equality_and_hash_are_based_on_name_only() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = CharsetInfo::new(
            "UTF-8",
            Some("a".to_string()),
            1,
            4,
            1,
            0,
            true,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        let b = CharsetInfo::new(
            "UTF-8",
            Some("b".to_string()),
            9,
            9,
            9,
            9,
            false,
            true,
            BTreeSet::new(),
            HashSet::new(),
        );
        let c = CharsetInfo::from_charset_name("UTF-16");

        assert_eq!(a, b);
        assert_ne!(a, c);

        let hash_of = |info: &CharsetInfo| {
            let mut hasher = DefaultHasher::new();
            info.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn has_fixed_length_chars() {
        let fixed = CharsetInfo::new(
            "UTF-32",
            None,
            4,
            4,
            4,
            0,
            true,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        assert!(fixed.has_fixed_length_chars());

        let variable = CharsetInfo::from_charset_name("UTF-8");
        assert!(!variable.has_fixed_length_chars());

        let unknown_min = CharsetInfo::new(
            "weird",
            None,
            -1,
            -1,
            1,
            0,
            true,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        assert!(!unknown_min.has_fixed_length_chars());
    }

    #[test]
    fn supports_all_scripts() {
        let all_but_unknown: BTreeSet<UnicodeScript> = UnicodeScript::ALL
            .iter()
            .copied()
            .filter(|s| *s != UnicodeScript::Unknown)
            .collect();
        let full = CharsetInfo::new(
            "everything",
            None,
            1,
            1,
            1,
            0,
            true,
            false,
            all_but_unknown,
            HashSet::new(),
        );
        assert!(full.supports_all_scripts());

        let partial = CharsetInfo::from_charset_name("US-ASCII");
        assert!(!partial.supports_all_scripts());
    }

    #[test]
    fn display_produces_json_excluding_standard_charset() {
        let info = CharsetInfo::from_charset_name("UTF-8");
        let s = info.to_string();
        assert!(s.contains("\"name\""));
        assert!(s.contains("UTF-8"));
        assert!(!s.contains("standardCharset"));
    }

    #[test]
    fn unicode_script_serializes_as_screaming_snake_case() {
        let json = serde_json::to_string(&UnicodeScript::CanadianAboriginal).unwrap();
        assert_eq!(json, "\"CANADIAN_ABORIGINAL\"");
        let json_unknown = serde_json::to_string(&UnicodeScript::Unknown).unwrap();
        assert_eq!(json_unknown, "\"UNKNOWN\"");
    }
}
