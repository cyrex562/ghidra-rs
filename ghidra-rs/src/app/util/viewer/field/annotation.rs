//! Parsed representation of an in-place `{@...}` annotation in comment text.

/// A single backslash character used to escape special annotation characters.
const BS: char = '\\';

/// Characters that must be escaped when they appear inside a quoted annotation part.
const ESCAPABLE_CHARS: &str = "{}\"\\";

/// A parsed `{@...}` annotation found within comment text.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.Annotation`.
///
/// Annotations are whitespace-separated words, optionally containing quoted
/// segments (which may themselves contain whitespace) and backslash-escaped
/// special characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    annotation_parts: Vec<String>,
    annotation_text: String,
}

impl Annotation {
    /// Creates a new `Annotation` by parsing the given annotation text.
    ///
    /// This assumes that `annotation_text` starts with `"{@"` and ends with `'}'`.
    pub fn new(annotation_text: impl Into<String>) -> Self {
        let annotation_text = annotation_text.into();
        let annotation_parts = Self::parse_annotation_text(&annotation_text);
        Self {
            annotation_parts,
            annotation_text,
        }
    }

    /// Creates a new `Annotation` from previously parsed annotation parts.
    pub fn from_parts(annotation_parts: Vec<String>) -> Self {
        let annotation_text = Self::build_annotation_text(&annotation_parts);
        Self {
            annotation_parts,
            annotation_text,
        }
    }

    /// Returns the parsed parts of this annotation.
    pub fn annotation_parts(&self) -> &[String] {
        &self.annotation_parts
    }

    /// Returns the complete annotation text.
    pub fn annotation_text(&self) -> &str {
        &self.annotation_text
    }

    fn parse_annotation_text(text: &str) -> Vec<String> {
        // remove "{@" and '}'
        let trimmed = &text[2..text.len() - 1];
        Self::parse_text(trimmed)
    }

    fn build_annotation_text(parts: &[String]) -> String {
        let joined = parts
            .iter()
            .map(|p| Self::maybe_quote(p))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{{@{}}}", joined)
    }

    fn parse_text(text: &str) -> Vec<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut escape = false;
        let mut quote = false;
        let mut buffy = String::new();

        for c in text.chars() {
            if escape {
                escape = false;
                buffy.push(BS);
                buffy.push(c);
                continue;
            }

            if c == BS {
                escape = true;
                continue;
            }

            if c == '"' {
                let s = std::mem::take(&mut buffy);
                if quote {
                    // end quote; keep the text as a single part
                    parts.push(s);
                }
                else {
                    // new quote start; split previous unquoted text into parts
                    parts.extend(s.split_whitespace().map(str::to_string));
                }
                quote = !quote;
            }
            else {
                buffy.push(c);
            }
        }

        parts.extend(buffy.split_whitespace().map(str::to_string));

        parts
            .into_iter()
            .filter(|t| !t.is_empty())
            .map(|t| Self::remove_escape_chars(&t))
            .collect()
    }

    /// Removes any backslashes that escape special annotation characters, like `'{'` and `'}'`.
    fn remove_escape_chars(text: &str) -> String {
        let mut escape = false;
        let mut buffy = String::new();
        for c in text.chars() {
            if escape {
                escape = false;
                if !ESCAPABLE_CHARS.contains(c) {
                    buffy.push(BS); // restore non-escaping backslash
                }
                buffy.push(c);
                continue;
            }

            if c == BS {
                escape = true;
                continue;
            }

            buffy.push(c);
        }

        buffy
    }

    fn maybe_quote(text: &str) -> String {
        if Self::needs_quotes(text) {
            format!("\"{}\"", Self::escape_annotation_chars(text))
        }
        else {
            text.to_string()
        }
    }

    fn needs_quotes(text: &str) -> bool {
        text.chars()
            .any(|c| ESCAPABLE_CHARS.contains(c) || c.is_whitespace())
    }

    fn escape_annotation_chars(text: &str) -> String {
        let mut buffy = String::new();
        for c in text.chars() {
            if ESCAPABLE_CHARS.contains(c) {
                buffy.push(BS);
            }
            buffy.push(c);
        }

        buffy
    }
}

impl std::fmt::Display for Annotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.annotation_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_annotation() {
        let a = Annotation::new("{@symbol addr}");
        assert_eq!(a.annotation_parts(), &["symbol", "addr"]);
        assert_eq!(a.annotation_text(), "{@symbol addr}");
    }

    #[test]
    fn test_quoted_part_with_whitespace() {
        let a = Annotation::new("{@symbol \"multi word\" addr}");
        assert_eq!(a.annotation_parts(), &["symbol", "multi word", "addr"]);
    }

    #[test]
    fn test_escaped_characters_are_unescaped() {
        let a = Annotation::new(r#"{@symbol \{escaped\}}"#);
        assert_eq!(a.annotation_parts(), &["symbol", "{escaped}"]);
    }

    #[test]
    fn test_from_parts_round_trip() {
        let parts = vec!["symbol".to_string(), "addr".to_string()];
        let a = Annotation::from_parts(parts.clone());
        assert_eq!(a.annotation_parts(), parts.as_slice());
        assert_eq!(a.annotation_text(), "{@symbol addr}");
    }

    #[test]
    fn test_from_parts_quotes_parts_with_whitespace() {
        let parts = vec!["symbol".to_string(), "multi word".to_string()];
        let a = Annotation::from_parts(parts);
        assert_eq!(a.annotation_text(), "{@symbol \"multi word\"}");
    }

    #[test]
    fn test_from_parts_quotes_and_escapes_special_chars() {
        let parts = vec!["a{b}c".to_string()];
        let a = Annotation::from_parts(parts);
        assert_eq!(a.annotation_text(), r#"{@"a\{b\}c"}"#);
    }

    #[test]
    fn test_display() {
        let a = Annotation::new("{@symbol addr}");
        assert_eq!(format!("{}", a), "{@symbol addr}");
    }

    #[test]
    fn test_non_escapable_backslash_is_preserved() {
        let a = Annotation::new(r#"{@sym\nbol}"#);
        assert_eq!(a.annotation_parts(), &["sym\\nbol"]);
    }

    #[test]
    fn test_round_trip_parse_then_rebuild() {
        let original = "{@symbol \"multi word\" addr}";
        let parsed = Annotation::new(original);
        let rebuilt = Annotation::from_parts(parsed.annotation_parts().to_vec());
        assert_eq!(rebuilt.annotation_text(), original);
    }
}
