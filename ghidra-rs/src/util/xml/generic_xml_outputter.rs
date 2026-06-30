/// XML output formatting configuration.
///
/// Mirrors `ghidra.util.xml.GenericXMLOutputter`, which is a factory for JDOM2
/// `XMLOutputter` pre-configured with compact formatting, a 4-space indent, and
/// text normalization (`TextMode.NORMALIZE`).
///
/// Since this crate does not depend on a JDOM2 equivalent, this struct carries
/// the same settings so callers can apply them to whatever XML writer they use.
pub(crate) struct GenericXmlOutputter {
    /// String inserted before each indent level.
    pub indent: String,
    /// When `true`, text content is normalized: leading/trailing whitespace is
    /// stripped and internal whitespace runs are collapsed to a single space,
    /// matching JDOM2's `TextMode.NORMALIZE` behaviour.
    pub normalize_text: bool,
    /// XML encoding declaration value (e.g. `"UTF-8"`).
    pub encoding: &'static str,
}

impl GenericXmlOutputter {
    /// Four-space indent used as the default for all Ghidra XML output.
    pub const DEFAULT_INDENT: &'static str = "    ";

    /// Returns a formatter with the same defaults produced by the Java
    /// `GenericXMLOutputter.getInstance()` factory:
    ///
    /// - `indent`: [`DEFAULT_INDENT`](Self::DEFAULT_INDENT) (four spaces)
    /// - `normalize_text`: `true`
    /// - `encoding`: `"UTF-8"`
    pub(crate) fn get_instance() -> Self {
        GenericXmlOutputter {
            indent: Self::DEFAULT_INDENT.to_string(),
            normalize_text: true,
            encoding: "UTF-8",
        }
    }

    /// Normalizes `text` when [`normalize_text`](Self::normalize_text) is `true`,
    /// otherwise returns it unchanged.
    ///
    /// Normalization splits on any Unicode whitespace, drops empty tokens, and
    /// rejoins with a single space — the same transformation JDOM2 applies in
    /// `TextMode.NORMALIZE`.
    pub(crate) fn normalize<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if !self.normalize_text {
            return std::borrow::Cow::Borrowed(text);
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.is_empty() {
            return std::borrow::Cow::Borrowed("");
        }
        // Fast-path: single unpadded token — borrow without allocation.
        if words.len() == 1 && text.trim() == text {
            return std::borrow::Cow::Borrowed(text);
        }
        std::borrow::Cow::Owned(words.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_instance_default_indent() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.indent, GenericXmlOutputter::DEFAULT_INDENT);
        assert_eq!(f.indent, "    ");
    }

    #[test]
    fn get_instance_normalize_text_is_true() {
        let f = GenericXmlOutputter::get_instance();
        assert!(f.normalize_text);
    }

    #[test]
    fn get_instance_encoding_is_utf8() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.encoding, "UTF-8");
    }

    #[test]
    fn normalize_strips_leading_and_trailing_whitespace() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.normalize("  hello  "), "hello");
    }

    #[test]
    fn normalize_collapses_internal_whitespace() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.normalize("foo   bar\tbaz"), "foo bar baz");
    }

    #[test]
    fn normalize_empty_string_returns_empty() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.normalize(""), "");
    }

    #[test]
    fn normalize_whitespace_only_returns_empty() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.normalize("   \t  "), "");
    }

    #[test]
    fn normalize_already_clean_borrows_without_allocation() {
        let f = GenericXmlOutputter::get_instance();
        let text = "clean";
        let result = f.normalize(text);
        // Should borrow, not allocate.
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result, "clean");
    }

    #[test]
    fn normalize_disabled_passes_through_unchanged() {
        let f = GenericXmlOutputter {
            indent: GenericXmlOutputter::DEFAULT_INDENT.to_string(),
            normalize_text: false,
            encoding: "UTF-8",
        };
        let text = "  not  normalized  ";
        let result = f.normalize(text);
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn default_indent_constant_is_four_spaces() {
        assert_eq!(GenericXmlOutputter::DEFAULT_INDENT, "    ");
        assert_eq!(GenericXmlOutputter::DEFAULT_INDENT.len(), 4);
    }

    #[test]
    fn normalize_newlines_and_tabs_collapsed() {
        let f = GenericXmlOutputter::get_instance();
        assert_eq!(f.normalize("line1\n  line2\r\nline3"), "line1 line2 line3");
    }
}
