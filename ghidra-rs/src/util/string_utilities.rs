//! Mirrors `ghidra.util.StringUtilities`, a static-only Java utility class (private
//! constructor, all methods `static`) with no instance state.
//!
//! Ported as a trait rather than a plain struct-with-`impl` (as sibling utility classes like
//! `NamingUtilities`/`StringFormat`/`MathUtilities` are) because this type was selected as a
//! dependency-cycle cut-point: callers can depend on the [`StringUtilities`] trait instead of
//! importing a concrete implementation module directly.
//!
//! To keep the trait object-safe, it is blanket-implemented for `str` so every method that
//! naturally operates on "a string" takes `&self` (the subject string) plus whatever
//! additional arguments the Java static method took beyond its leading `String` parameter.
//! Java overloads without a leading `String`/`CharSequence` parameter (character-, byte-, and
//! code-point-level helpers, plus the varargs `isAllBlank`) have no natural receiver and are
//! ported as plain free functions in this module instead.
//!
//! `findWord`/`findWordLocation` return `ghidra.util.WordLocation`, an in-repo type not yet
//! ported; per the cut-point rules a minimal placeholder trait ([`WordLocationLike`] in
//! `seam_stubs.rs`) stands in for it, and [`find_word_location`](StringUtilities::find_word_location)
//! returns a boxed trait object backed by a small private implementor local to this module.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use super::seam_stubs::WordLocationLike;

/// This is Java's default rendered size of a tab (in spaces).
pub const DEFAULT_TAB_SIZE: usize = 8;

const ELLIPSES: &str = "...";

/// Unicode replacement character code point.
pub const UNICODE_REPLACEMENT: u32 = 0xFFFD;

/// Unicode Byte Order Mark (BOM) for big-endian text; works for both 16- and 32-bit chars.
pub const UNICODE_BE_BYTE_ORDER_MARK: u32 = 0xFEFF;

/// Little-endian Byte Order Mark for 16-bit characters.
pub const UNICODE_LE16_BYTE_ORDER_MARK: u32 = 0xFFFE;

/// Little-endian Byte Order Mark for 32-bit characters.
pub const UNICODE_LE32_BYTE_ORDER_MARK: u32 = 0xFFFE_0000;

/// The platform-specific string that is the line separator.
///
/// Mirrors `StringUtilities.LINE_SEPARATOR` (`System.getProperty("line.separator")`).
pub fn line_separator() -> &'static str {
    if cfg!(windows) {
        "\r\n"
    } else {
        "\n"
    }
}

fn control_to_escape_map() -> &'static HashMap<char, &'static str> {
    static MAP: OnceLock<HashMap<char, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ('\t', "\\t"),
            ('\u{8}', "\\b"),
            ('\r', "\\r"),
            ('\n', "\\n"),
            ('\u{c}', "\\f"),
            ('\\', "\\\\"),
            ('\u{b}', "\\v"),
            ('\u{7}', "\\a"),
        ])
    })
}

fn escape_to_control_map() -> &'static HashMap<&'static str, char> {
    static MAP: OnceLock<HashMap<&'static str, char>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ("\\t", '\t'),
            ("\\b", '\u{8}'),
            ("\\r", '\r'),
            ("\\n", '\n'),
            ("\\f", '\u{c}'),
            ("\\\\", '\\'),
            ("\\v", '\u{b}'),
            ("\\a", '\u{7}'),
            // Special-cased to allow users to enter nulls in search strings - no reverse entry.
            ("\\0", '\0'),
        ])
    })
}

fn double_quoted_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^"((?:[^\\"]|\\.)*)"$"#).unwrap())
}

// --- character/byte/code-point helpers with no natural `String` receiver ---

/// Returns true if the given character is a special character, e.g. `'\n'` or `'\\'`.
///
/// A value of 0 is not considered special for this purpose, as it is handled separately.
pub fn is_control_character_or_backslash(c: char) -> bool {
    control_to_escape_map().contains_key(&c)
}

/// Returns true if the given code point is a special character (see
/// [`is_control_character_or_backslash`]).
pub fn is_control_character_or_backslash_code_point(code_point: u32) -> bool {
    match char::from_u32(code_point) {
        Some(c) => code_point < 0x1_0000 && is_control_character_or_backslash(c),
        None => false,
    }
}

/// Returns true if the character is in displayable character range.
pub fn is_displayable(c: u32) -> bool {
    (0x20..0x7F).contains(&c)
}

/// Returns true if all the given sequences are either empty or only whitespace.
///
/// Rust strings cannot be null, so this only mirrors the blank-checking half of
/// `StringUtilities.isAllBlank`.
pub fn is_all_blank(sequences: &[&str]) -> bool {
    sequences.iter().all(|s| s.trim().is_empty())
}

/// Converts the character into a string, rendering special characters as their escape
/// sequence, e.g. `'\n'` becomes `"\\n"`.
pub fn character_to_string(c: char) -> String {
    match control_to_escape_map().get(&c) {
        Some(escaped) => (*escaped).to_string(),
        None => c.to_string(),
    }
}

fn append_char_converted_to_escape_sequence(c: u32, char_size: usize, out: &mut String) {
    if let Some(ch) = char::from_u32(c) {
        if let Some(escaped) = control_to_escape_map().get(&ch) {
            out.push_str(escaped);
            return;
        }
    }
    if (0x20..=0x7f).contains(&c) {
        out.push(c as u8 as char);
    } else if char_size <= 1 {
        out.push_str(&format!("\\x{:0>2x}", c));
    } else if char_size == 2 {
        out.push_str(&format!("\\u{:0>4x}", c));
    } else if char_size <= 4 {
        out.push_str(&format!("\\U{:0>8x}", c));
    }
    // else: unsupported, matches the Java `// TODO: unsupported` branch (no output).
}

/// Generate a quoted string from bytes assuming 1-byte characters.
///
/// Special/non-printable characters are escaped using C-style escapes (`\t`, `\n`, `\xHH`,
/// etc). Single-quoted if `bytes` is exactly one byte long, double-quoted otherwise.
pub fn to_quoted_string(bytes: &[u8]) -> String {
    let mut builder = String::new();
    for &b in bytes {
        append_char_converted_to_escape_sequence(b as u32, 1, &mut builder);
    }
    if bytes.len() == 1 {
        format!("'{}'", builder.replace('\'', "\\'"))
    } else {
        format!("\"{}\"", builder.replace('"', "\\\""))
    }
}

/// Generate a quoted string from bytes where each character is `char_size` bytes.
///
/// # Panics
/// Panics if `char_size` is greater than 4, mirroring the Java `IllegalArgumentException`.
pub fn to_quoted_string_sized(bytes: &[u8], char_size: usize) -> String {
    if char_size <= 1 {
        return to_quoted_string(bytes);
    }
    if char_size > 4 {
        panic!("unsupported charSize: {}", char_size);
    }

    let mut bytes = bytes.to_vec();
    let shortage = bytes.len() % char_size;
    if shortage != 0 {
        bytes.resize(bytes.len() + shortage, 0);
    }

    let mut builder = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut val: u32 = 0;
        for n in 0..char_size {
            val = (val << 8) + bytes[i + n] as u32;
        }
        append_char_converted_to_escape_sequence(val, char_size, &mut builder);
        i += char_size;
    }

    if bytes.len() <= char_size {
        format!("'{}'", builder.replace('\'', "\\'"))
    } else {
        format!("\"{}\"", builder.replace('"', "\\\""))
    }
}

/// Loosely defined as a character that would be expected as normal ASCII content meant for
/// consumption by a human; characters in `chars_to_allow` also pass.
pub fn is_word_char(c: char, chars_to_allow: &[char]) -> bool {
    if chars_to_allow.contains(&c) {
        return true;
    }
    is_valid_c_language_char(c)
}

/// Returns true if the character is OK to be contained inside a C-language string, i.e. the
/// string should not be tokenized on this char.
pub fn is_valid_c_language_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Returns true if the given character is within the ASCII range used by `StringUtilities`
/// (`0x20..=0x7f`).
pub fn is_ascii_char(c: char) -> bool {
    ('\u{20}'..='\u{7f}').contains(&c)
}

/// Returns true if the given code point is within the ASCII range used by `StringUtilities`
/// (`0x20..=0x7f`).
pub fn is_ascii_code_point(code_point: u32) -> bool {
    (0x20..=0x7f).contains(&code_point)
}

/// Converts an integer into a string by treating its 4 bytes as characters (big-endian). For
/// example, `0x41424344` becomes `"ABCD"`.
pub fn to_string_from_int(mut value: i32) -> String {
    let mut bytes = [0u8; 4];
    let mut byte_index: isize = 3;
    while value != 0 {
        if byte_index < 0 {
            break;
        }
        bytes[byte_index as usize] = value as u8;
        value >>= 8;
        byte_index -= 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Creates a JSON string for the given object using all of its fields.
///
/// This is here as a marker to point users to the real [`crate::generic::json::Json`]
/// utility, mirroring `StringUtilities.toStingJson(Object)`.
pub fn to_json_string<T: serde::Serialize>(o: &T) -> String {
    crate::generic::json::Json::to_string(o)
}

/// Renders `o` via its `Display` implementation and indents every line with a tab, or
/// returns `"null"` for `None`, mirroring `StringUtilities.toStringWithIndent(Object)`.
pub fn to_string_with_indent<T: std::fmt::Display>(o: Option<&T>) -> String {
    match o {
        None => "null".to_string(),
        Some(o) => o.to_string().as_str().indent_lines("\t"),
    }
}

/// Maps known control characters to their corresponding escape sequences, e.g. a line feed
/// becomes `"\\n"`. Falls back to the code point's own character if it isn't a mapped control
/// character.
pub fn convert_code_point_to_escape_sequence(code_point: u32) -> String {
    if let Some(c) = char::from_u32(code_point) {
        if let Some(escaped) = control_to_escape_map().get(&c) {
            return (*escaped).to_string();
        }
        return c.to_string();
    }
    char::REPLACEMENT_CHARACTER.to_string()
}

/// About the worst way to wrap lines ever.
///
/// Mirrors `StringUtilities.LineWrapper`.
pub struct LineWrapper {
    width: usize,
    result: String,
    len: usize,
}

#[derive(PartialEq, Eq)]
enum WrapMode {
    Init,
    Word,
    Space,
}

impl LineWrapper {
    /// Creates a new line wrapper that wraps at the given width.
    pub fn new(width: usize) -> Self {
        LineWrapper {
            width,
            result: String::new(),
            len: 0,
        }
    }

    /// Appends `cs` to the wrapped output, wrapping at whitespace as needed.
    pub fn append(&mut self, cs: &str) -> &mut Self {
        let chars: Vec<char> = cs.chars().collect();
        let mut mode = WrapMode::Init;
        let mut b = 0usize;
        for f in 0..chars.len() {
            let c = chars[f];
            if c == '\n' {
                match mode {
                    WrapMode::Space => self.append_space(&chars[b..f]),
                    WrapMode::Word => self.append_word(&chars[b..f]),
                    WrapMode::Init => {}
                }
                mode = WrapMode::Init;
                self.append_linesep();
                b = f + 1;
            } else if c.is_whitespace() {
                if mode == WrapMode::Word {
                    self.append_word(&chars[b..f]);
                    b = f;
                }
                mode = WrapMode::Space;
            } else {
                if mode == WrapMode::Space {
                    self.append_space(&chars[b..f]);
                    b = f;
                }
                mode = WrapMode::Word;
            }
        }
        match mode {
            WrapMode::Word => self.append_word(&chars[b..]),
            WrapMode::Space => self.append_space(&chars[b..]),
            WrapMode::Init => {}
        }
        self
    }

    fn append_word(&mut self, word: &[char]) {
        self.len += word.len();
        self.result.extend(word);
    }

    fn append_space(&mut self, space: &[char]) {
        if self.len > self.width {
            self.append_linesep();
            self.len += space.len().saturating_sub(1);
            self.result.extend(&space[1.min(space.len())..]);
        } else {
            self.len += space.len();
            self.result.extend(space);
        }
    }

    fn append_linesep(&mut self) {
        self.result.push('\n');
        self.len = 0;
    }

    /// Consumes the wrapper, returning the wrapped output.
    pub fn finish(self) -> String {
        self.result
    }
}

/// Minimal, private stand-in for `ghidra.util.WordLocation` construction: implements the
/// [`WordLocationLike`] placeholder so [`StringUtilities::find_word_location`] has a concrete
/// type to box. Replace with the real port once `WordLocation` lands.
struct SimpleWordLocation {
    word: String,
}

impl WordLocationLike for SimpleWordLocation {
    fn word(&self) -> &str {
        &self.word
    }
}

/// Static string-manipulation methods, ported from `ghidra.util.StringUtilities` as a trait
/// so callers can depend on this interface rather than a concrete implementation (this type
/// was selected as a dependency-cycle cut-point). Blanket-implemented for `str`; see the
/// module docs for how methods without a natural `String` receiver were handled.
pub trait StringUtilities {
    /// Determines if this string is enclosed in double quotes (ASCII 34, `0x22`).
    fn is_double_quoted(&self) -> bool;

    /// If this string is enclosed in double quotes, extracts the inner text; otherwise
    /// returns the string unmodified.
    fn extract_from_double_quotes(&self) -> String;

    /// Returns true if this string ends with whitespace.
    ///
    /// # Panics
    /// Panics if the string is empty, mirroring Java's `charAt` on an empty string.
    fn ends_with_white_space(&self) -> bool;

    /// Returns true if this string starts with `prefix`, ignoring case.
    fn starts_with_ignore_case(&self, prefix: &str) -> bool;

    /// Returns true if this string ends with `postfix`, ignoring case.
    fn ends_with_ignore_case(&self, postfix: &str) -> bool;

    /// Returns true if all the given `searches` are contained in this string.
    fn contains_all(&self, searches: &[&str]) -> bool;

    /// Returns true if all the given `searches` are contained in this string, ignoring case.
    fn contains_all_ignore_case(&self, searches: &[&str]) -> bool;

    /// Returns true if any of the given `searches` are contained in this string, ignoring
    /// case.
    fn contains_any_ignore_case(&self, searches: &[&str]) -> bool;

    /// Returns a count of how many times `occur` appears in this string.
    fn count_occurrences(&self, occur: char) -> usize;

    /// Compares this string to `other`, optionally case-sensitively.
    ///
    /// Rust strings cannot be null, so this only mirrors the non-null comparison half of
    /// `StringUtilities.equals(String, String, boolean)`.
    fn string_equals(&self, other: &str, case_sensitive: bool) -> bool;

    /// Returns the index of the first whole-word occurrence of `search_word` within this
    /// string, or `None` if not found. A whole word is one whose surrounding characters (if
    /// any) are not valid C-language identifier characters.
    fn index_of_word(&self, search_word: &str) -> Option<usize>;

    /// Returns true if the substring of this string starting at `start_index` with the given
    /// `length` is a whole word (see [`StringUtilities::index_of_word`]).
    fn is_whole_word(&self, start_index: usize, length: usize) -> bool;

    /// Converts tabs in this string to spaces using the given tab width.
    fn convert_tabs_to_spaces(&self, tab_size: usize) -> String;

    /// Converts tabs in this string to spaces using [`DEFAULT_TAB_SIZE`].
    fn convert_tabs_to_spaces_default(&self) -> String {
        self.convert_tabs_to_spaces(DEFAULT_TAB_SIZE)
    }

    /// Parses this string into lines delimited by `'\n'`.
    ///
    /// If `preserve_tokens` is true, consecutive/leading/trailing newlines produce empty-string
    /// entries; if false, they are treated as a single line break and no empty entries are
    /// produced. Returns an empty vector for an empty string.
    fn to_lines(&self, preserve_tokens: bool) -> Vec<String>;

    /// Parses this string into lines, preserving empty tokens (see
    /// [`StringUtilities::to_lines`]).
    fn to_lines_default(&self) -> Vec<String> {
        self.to_lines(true)
    }

    /// Enforces `size` upon this string by trimming (with ellipses) and then padding.
    fn to_fixed_size(&self, pad: char, size: usize) -> String;

    /// Pads this string to `length` using `filler`. Negative `length` left-justifies
    /// (appending filler); positive right-justifies (prepending filler). Zero is a no-op.
    fn pad(&self, filler: char, length: i32) -> String;

    /// Splits this string into lines using `'\n'` and prefixes each with `indent`.
    fn indent_lines(&self, indent: &str) -> String;

    /// Finds the word at `index` within this string, treating characters in
    /// `chars_to_allow` as part of the word even though they otherwise wouldn't be.
    fn find_word(&self, index: usize, chars_to_allow: &[char]) -> String;

    /// Finds the word at `index` within this string (see [`StringUtilities::find_word`]).
    fn find_word_default(&self, index: usize) -> String {
        self.find_word(index, &[])
    }

    /// Finds the word (and its position) at `index` within this string.
    fn find_word_location(&self, index: usize, chars_to_allow: &[char]) -> Box<dyn WordLocationLike>;

    /// Finds the starting position of the last word in this string, or `None` if this string
    /// is entirely letters/digits (mirroring the Java implementation's quirk of returning -1
    /// in that case too).
    fn find_last_word_position(&self) -> Option<usize>;

    /// Takes a path-like string and retrieves the last non-empty item split on `separator`.
    fn get_last_word(&self, separator: &str) -> String;

    /// Merges this string with `other`. If one contains the other, the largest is returned;
    /// if both are empty, the empty string is returned; otherwise this string and `other` are
    /// newline-joined.
    fn merge_strings(&self, other: &str) -> String;

    /// Limits this string to `max` characters (must be at least 4), trimming with ellipses.
    ///
    /// # Panics
    /// Panics if `max` is less than 4.
    fn trim_to_max(&self, max: usize) -> String;

    /// Trims trailing NUL (`'\0'`) characters from this string.
    fn trim_trailing_nulls(&self) -> String;

    /// Trims this string to `max` characters (must be at least 5), removing from the middle
    /// and inserting ellipses.
    ///
    /// # Panics
    /// Panics if `max` is less than 5.
    fn trim_middle(&self, max: usize) -> String;

    /// Replaces runs of two or more asterisks with a single asterisk.
    fn fix_multiple_asterisks(&self) -> String;

    /// Replaces escape sequences (e.g. `\n`, `\x41`) in this string with the corresponding
    /// control/literal characters.
    fn convert_escape_sequences(&self) -> String;

    /// Replaces control characters in this string with their corresponding escape sequences.
    fn convert_control_chars_to_escape_sequences(&self) -> String;

    /// Wraps this string at whitespace to best fit within `width` columns.
    fn wrap_to_width(&self, width: usize) -> String;

    /// Trims whitespace from both ends, then replaces any remaining non-printable character
    /// (`< 0x20`) or space (`0x20`) with an underscore.
    fn whitespace_to_underscores(&self) -> String;
}

impl StringUtilities for str {
    fn is_double_quoted(&self) -> bool {
        double_quoted_pattern().is_match(self)
    }

    fn extract_from_double_quotes(&self) -> String {
        match double_quoted_pattern().captures(self) {
            Some(caps) => caps.get(1).map_or("", |m| m.as_str()).to_string(),
            None => self.to_string(),
        }
    }

    fn ends_with_white_space(&self) -> bool {
        self.chars().next_back().unwrap().is_whitespace()
    }

    fn starts_with_ignore_case(&self, prefix: &str) -> bool {
        self.len() >= prefix.len() && self[..prefix.len()].eq_ignore_ascii_case(prefix)
    }

    fn ends_with_ignore_case(&self, postfix: &str) -> bool {
        self.len() >= postfix.len() && self[self.len() - postfix.len()..].eq_ignore_ascii_case(postfix)
    }

    fn contains_all(&self, searches: &[&str]) -> bool {
        if self.is_empty() || searches.is_empty() {
            return false;
        }
        searches.iter().all(|s| self.contains(s))
    }

    fn contains_all_ignore_case(&self, searches: &[&str]) -> bool {
        if self.is_empty() {
            return false;
        }
        let lower = self.to_lowercase();
        searches.iter().all(|s| lower.contains(&s.to_lowercase()))
    }

    fn contains_any_ignore_case(&self, searches: &[&str]) -> bool {
        if self.is_empty() {
            return false;
        }
        let lower = self.to_lowercase();
        searches.iter().any(|s| lower.contains(&s.to_lowercase()))
    }

    fn count_occurrences(&self, occur: char) -> usize {
        self.chars().filter(|&c| c == occur).count()
    }

    fn string_equals(&self, other: &str, case_sensitive: bool) -> bool {
        if case_sensitive {
            self == other
        } else {
            self.eq_ignore_ascii_case(other)
        }
    }

    fn index_of_word(&self, search_word: &str) -> Option<usize> {
        let chars: Vec<char> = self.chars().collect();
        let search_len = search_word.chars().count();
        let mut index = 0usize;
        while index < chars.len() {
            let rest: String = chars[index..].iter().collect();
            let found = rest.find(search_word)?;
            // `find` returns a byte offset into `rest`; since we only ever search ASCII-ish
            // word boundaries here, re-derive the char offset via char_indices.
            let char_offset = rest[..found].chars().count();
            index += char_offset;
            if self.is_whole_word(index, search_len) {
                return Some(index);
            }
            index += search_len;
        }
        None
    }

    fn is_whole_word(&self, start_index: usize, length: usize) -> bool {
        let chars: Vec<char> = self.chars().collect();
        if start_index > 0 {
            if let Some(&c) = chars.get(start_index - 1) {
                if is_valid_c_language_char(c) {
                    return false;
                }
            }
        }
        let end_index = start_index + length;
        if end_index < chars.len() {
            if is_valid_c_language_char(chars[end_index]) {
                return false;
            }
        }
        true
    }

    fn convert_tabs_to_spaces(&self, tab_size: usize) -> String {
        let mut buffer = String::new();
        let mut linepos = 0usize;
        for c in self.chars() {
            if c == '\t' {
                let n_spaces = tab_size - (linepos % tab_size);
                buffer.extend(std::iter::repeat(' ').take(n_spaces));
                linepos += n_spaces;
            } else {
                buffer.push(c);
                linepos += 1;
                if c == '\n' {
                    linepos = 0;
                }
            }
        }
        buffer
    }

    fn to_lines(&self, preserve_tokens: bool) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        if preserve_tokens {
            self.split('\n').map(|s| s.to_string()).collect()
        } else {
            self.split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        }
    }

    fn to_fixed_size(&self, pad_char: char, size: usize) -> String {
        let trimmed = self.trim_to_max(size + ELLIPSES.len());
        trimmed.pad(pad_char, -(size as i32))
    }

    fn pad(&self, filler: char, length: i32) -> String {
        if length == 0 {
            return self.to_string();
        }

        let right_justify = length > 0;
        let length = length.unsigned_abs() as usize;

        let source_len = self.chars().count();
        let n = length.saturating_sub(source_len);
        let filler_str: String = std::iter::repeat(filler).take(n).collect();

        if right_justify {
            format!("{}{}", filler_str, self)
        } else {
            format!("{}{}", self, filler_str)
        }
    }

    fn indent_lines(&self, indent: &str) -> String {
        let lines = self.to_lines(false);
        let mut buffy = String::new();
        for line in &lines {
            buffy.push_str(indent);
            buffy.push_str(line);
            buffy.push('\n');
        }
        if !buffy.is_empty() {
            buffy.pop();
        }
        buffy
    }

    fn find_word(&self, index: usize, chars_to_allow: &[char]) -> String {
        self.find_word_location(index, chars_to_allow).word().to_string()
    }

    fn find_word_location(&self, index: usize, chars_to_allow: &[char]) -> Box<dyn WordLocationLike> {
        let chars: Vec<char> = self.chars().collect();
        let len = chars.len();
        if index >= len {
            return Box::new(SimpleWordLocation { word: String::new() });
        }

        let curr_char = chars[index];
        if !is_word_char(curr_char, chars_to_allow) {
            let substring: String = chars[index..index + 1].iter().collect();
            return Box::new(SimpleWordLocation {
                word: substring.trim().to_string(),
            });
        }

        let mut start: isize = index as isize;
        while start >= 0 && is_word_char(chars[start as usize], chars_to_allow) {
            start -= 1;
        }

        let mut end = index;
        while end < len && is_word_char(chars[end], chars_to_allow) {
            end += 1;
        }

        let word_index = (start + 1) as usize;
        let substring: String = chars[word_index..end].iter().collect();
        Box::new(SimpleWordLocation {
            word: substring.trim().to_string(),
        })
    }

    fn find_last_word_position(&self) -> Option<usize> {
        let chars: Vec<char> = self.chars().collect();
        let len = chars.len();
        let mut pos: Option<usize> = None;
        for i in (0..len).rev() {
            if !chars[i].is_alphanumeric() {
                pos = Some(i + 1);
                break;
            }
        }
        match pos {
            Some(p) if p >= len => None,
            other => other,
        }
    }

    fn get_last_word(&self, separator: &str) -> String {
        let parts: Vec<&str> = self.split(separator).collect();
        parts.last().map(|s| s.to_string()).unwrap_or_default()
    }

    fn merge_strings(&self, other: &str) -> String {
        let has_string1 = !self.is_empty();
        let has_string2 = !other.is_empty();

        if has_string1 {
            if has_string2 {
                let string1_contains2 = other.len() <= self.len() && self.contains(other);
                if string1_contains2 {
                    return self.to_string();
                }
                let string2_contains1 = self.len() <= other.len() && other.contains(self);
                if string2_contains1 {
                    return other.to_string();
                }
                return format!("{}\n{}", self, other);
            }
            return self.to_string();
        }
        if has_string2 {
            return other.to_string();
        }
        String::new()
    }

    fn trim_to_max(&self, max: usize) -> String {
        let minimum = ELLIPSES.len() + 1;
        if max < minimum {
            panic!("Max cannot be less than {}", minimum);
        }

        let chars: Vec<char> = self.chars().collect();
        if chars.len() > max {
            let mut s: String = chars[..max - 3].iter().collect();
            s.push_str(ELLIPSES);
            s
        } else {
            self.to_string()
        }
    }

    fn trim_trailing_nulls(&self) -> String {
        let chars: Vec<char> = self.chars().collect();
        let mut i = chars.len();
        while i > 0 && chars[i - 1] == '\0' {
            i -= 1;
        }
        chars[..i].iter().collect()
    }

    fn trim_middle(&self, max: usize) -> String {
        let chars: Vec<char> = self.chars().collect();
        let len = chars.len();
        if len <= max {
            return self.to_string();
        }

        let minimum = ELLIPSES.len() + 2;
        if max < minimum {
            panic!("Max cannot be less than {}", minimum);
        }

        let to_remove = (len - max) + ELLIPSES.len();
        let to_keep = len - to_remove;
        let mut lhs_size = to_keep / 2;
        let mut rhs_size = lhs_size;
        if to_keep % 2 != 0 {
            rhs_size += 1;
        }
        // Guard against the (Java-unchecked) case where the split sizes overflow `len`.
        lhs_size = lhs_size.min(len);
        rhs_size = rhs_size.min(len - lhs_size);

        let mut buffy = String::new();
        buffy.extend(&chars[..lhs_size]);
        buffy.push_str(ELLIPSES);
        buffy.extend(&chars[len - rhs_size..]);
        buffy
    }

    fn fix_multiple_asterisks(&self) -> String {
        if !self.contains("**") {
            return self.to_string();
        }
        let mut result = String::with_capacity(self.len());
        let mut prev_star = false;
        for c in self.chars() {
            if c == '*' {
                if !prev_star {
                    result.push(c);
                }
                prev_star = true;
            } else {
                result.push(c);
                prev_star = false;
            }
        }
        result
    }

    fn convert_escape_sequences(&self) -> String {
        let chars: Vec<char> = self.chars().collect();
        let input_length = chars.len();
        let mut builder = String::new();
        let mut index = 0usize;
        while index < input_length {
            let sub_end = (index + 2).min(input_length);
            let sub_of_input: String = chars[index..sub_end].iter().collect();
            if let Some(&escape_char) = escape_to_control_map().get(sub_of_input.as_str()) {
                builder.push(escape_char);
                index += 2;
                continue;
            }
            if let Some(consumed) = handle_escape_sequence(&chars, "\\x", 2, index, &mut builder) {
                index += consumed;
                continue;
            }
            if let Some(consumed) = handle_escape_sequence(&chars, "\\u", 4, index, &mut builder) {
                index += consumed;
                continue;
            }
            if let Some(consumed) = handle_escape_sequence(&chars, "\\U", 8, index, &mut builder) {
                index += consumed;
                continue;
            }
            builder.push(chars[index]);
            index += 1;
        }
        builder
    }

    fn convert_control_chars_to_escape_sequences(&self) -> String {
        let mut builder = String::new();
        for c in self.chars() {
            match control_to_escape_map().get(&c) {
                Some(escaped) => builder.push_str(escaped),
                None => builder.push(c),
            }
        }
        builder
    }

    fn wrap_to_width(&self, width: usize) -> String {
        let mut wrapper = LineWrapper::new(width);
        wrapper.append(self);
        wrapper.finish()
    }

    fn whitespace_to_underscores(&self) -> String {
        self.trim()
            .chars()
            .map(|c| if c <= '\u{20}' { '_' } else { c })
            .collect()
    }
}

/// Attempts to handle a character escape sequence like `\xHH` / `\uHHHH` / `\UHHHHHHHH`.
///
/// Returns `Some(chars_consumed)` if an escape sequence was recognized and a character was
/// appended to `builder`, `None` otherwise.
fn handle_escape_sequence(
    chars: &[char],
    escape_sequence: &str,
    hex_length: usize,
    index: usize,
    builder: &mut String,
) -> Option<usize> {
    let escape_chars: Vec<char> = escape_sequence.chars().collect();
    let hex_start = index + escape_chars.len();
    let hex_end = hex_start + hex_length;
    if hex_end > chars.len() {
        return None;
    }
    if chars[index..hex_start] != escape_chars[..] {
        return None;
    }

    let hex_str: String = chars[hex_start..hex_end].iter().collect();
    let hex_mask: u32 = if hex_length >= 8 {
        u32::MAX
    } else {
        (1u32 << (hex_length * 4)) - 1
    };
    let val = u32::from_str_radix(&hex_str, 16).ok()? & hex_mask;
    if val <= 0xFFFF {
        if let Some(c) = char::from_u32(val) {
            builder.push(c);
            return Some(escape_chars.len() + hex_length);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock of a Java `WordLocation` implementor other than [`SimpleWordLocation`], proving
    /// [`WordLocationLike`] (and therefore the `Box<dyn WordLocationLike>` returned by
    /// [`StringUtilities::find_word_location`]) is usable as a trait object by third parties.
    struct MockWordLocation(&'static str);

    impl WordLocationLike for MockWordLocation {
        fn word(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn mock_word_location_is_object_safe() {
        let boxed: Box<dyn WordLocationLike> = Box::new(MockWordLocation("tree"));
        assert_eq!(boxed.word(), "tree");
    }

    #[test]
    fn is_double_quoted_basic() {
        assert!("\"hello\"".is_double_quoted());
        assert!(!"hello".is_double_quoted());
    }

    #[test]
    fn extract_from_double_quotes_basic() {
        assert_eq!("\"hello\"".extract_from_double_quotes(), "hello");
        assert_eq!("hello".extract_from_double_quotes(), "hello");
    }

    #[test]
    fn starts_and_ends_with_ignore_case() {
        assert!("HELLO world".starts_with_ignore_case("hello"));
        assert!("hello WORLD".ends_with_ignore_case("world"));
        assert!(!"hello".starts_with_ignore_case("world"));
    }

    #[test]
    fn contains_all_variants() {
        assert!("the quick brown fox".contains_all(&["quick", "fox"]));
        assert!(!"the quick brown fox".contains_all(&["quick", "slow"]));
        assert!("THE QUICK".contains_all_ignore_case(&["quick"]));
        assert!("THE QUICK".contains_any_ignore_case(&["slow", "quick"]));
    }

    #[test]
    fn count_occurrences_and_equals() {
        assert_eq!("mississippi".count_occurrences('s'), 4);
        assert!("Foo".string_equals("foo", false));
        assert!(!"Foo".string_equals("foo", true));
    }

    #[test]
    fn index_of_word_and_whole_word() {
        assert_eq!("the tree is green".index_of_word("tree"), Some(4));
        assert_eq!("the treehouse".index_of_word("tree"), None);
        assert!("the tree is green".is_whole_word(4, 4));
    }

    #[test]
    fn convert_tabs_to_spaces_default_width() {
        assert_eq!("a\tb".convert_tabs_to_spaces_default(), "a       b");
    }

    #[test]
    fn to_lines_preserve_vs_collapse() {
        assert_eq!("a\n\nb".to_lines(true), vec!["a", "", "b"]);
        assert_eq!("a\n\nb".to_lines(false), vec!["a", "b"]);
        assert_eq!("".to_lines(true), Vec::<String>::new());
    }

    #[test]
    fn pad_left_and_right_justify() {
        assert_eq!("ab".pad('0', 5), "000ab");
        assert_eq!("ab".pad('0', -5), "ab000");
        assert_eq!("abcdef".pad('0', 3), "abcdef");
    }

    #[test]
    fn find_word_basic() {
        assert_eq!("The tree is green".find_word_default(5), "tree");
        assert_eq!(
            "The tree* is green".find_word(5, &['*']),
            "tree*"
        );
    }

    #[test]
    fn find_last_word_position_variants() {
        assert_eq!("hello world".find_last_word_position(), Some(6));
        assert_eq!("helloworld".find_last_word_position(), None);
    }

    #[test]
    fn get_last_word_variants() {
        assert_eq!("/This/is/my/last/word/".get_last_word("/"), "");
        assert_eq!("This.is.my.last.word".get_last_word("."), "word");
    }

    #[test]
    fn merge_strings_variants() {
        assert_eq!("".merge_strings(""), "");
        assert_eq!("abc".merge_strings(""), "abc");
        assert_eq!("".merge_strings("abc"), "abc");
        assert_eq!("abc".merge_strings("abc"), "abc");
        assert_eq!("ab".merge_strings("abc"), "abc");
        assert_eq!("foo".merge_strings("bar"), "foo\nbar");
    }

    #[test]
    fn trim_to_max_and_middle() {
        assert_eq!("hello world".trim_to_max(8), "hello...");
        assert_eq!("hello".trim_to_max(8), "hello");
        // Java trimMiddle keeps toKeep/2 on the left and rounds the odd char onto the right.
        assert_eq!("abcdefghij".trim_middle(6), "a...ij");
    }

    #[test]
    fn fix_multiple_asterisks_collapses_runs() {
        assert_eq!("a**b***c".fix_multiple_asterisks(), "a*b*c");
        assert_eq!("a*b".fix_multiple_asterisks(), "a*b");
    }

    #[test]
    fn escape_sequence_roundtrip() {
        let escaped = "a\tb\nc".convert_control_chars_to_escape_sequences();
        assert_eq!(escaped, "a\\tb\\nc");
        assert_eq!(escaped.as_str().convert_escape_sequences(), "a\tb\nc");
    }

    #[test]
    fn wrap_to_width_breaks_on_whitespace() {
        let wrapped = "hello world foo".wrap_to_width(7);
        assert!(wrapped.contains('\n'));
    }

    #[test]
    fn whitespace_to_underscores_basic() {
        assert_eq!("  a\tb  ".whitespace_to_underscores(), "a_b");
    }

    #[test]
    fn free_functions_smoke() {
        assert!(is_control_character_or_backslash('\n'));
        assert!(!is_control_character_or_backslash('a'));
        assert_eq!(character_to_string('\n'), "\\n");
        assert!(is_valid_c_language_char('_'));
        assert!(!is_valid_c_language_char('*'));
        assert!(is_word_char('*', &['*']));
        assert_eq!(to_string_from_int(0x41424344), "ABCD");
        assert_eq!(to_quoted_string(b"a"), "'a'");
        assert_eq!(to_quoted_string(b"ab"), "\"ab\"");
        assert_eq!(convert_code_point_to_escape_sequence('\n' as u32), "\\n");
        assert!(is_all_blank(&["", "  ", "\t"]));
        assert!(!is_all_blank(&["", "x"]));
    }

    #[test]
    fn to_string_with_indent_handles_none_and_display() {
        assert_eq!(to_string_with_indent::<String>(None), "null");
        let value = 42i32;
        // Java toStringWithIndent indents each line with a tab (indentLines(_, "\t")).
        assert_eq!(to_string_with_indent(Some(&value)), "\t42");
    }

    #[test]
    fn line_wrapper_wraps_long_word_on_its_own_line() {
        let mut wrapper = LineWrapper::new(4);
        wrapper.append("supercalifragilistic word");
        let wrapped = wrapper.finish();
        assert!(wrapped.contains('\n'));
    }
}
