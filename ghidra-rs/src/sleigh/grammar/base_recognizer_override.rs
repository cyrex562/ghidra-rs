use super::{AntlrUtil, LineArrayListWriter, SleighToken};

/// Platform-specific line separator, mirroring `System.getProperty("line.separator")`.
#[cfg(windows)]
pub const NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
pub const NEWLINE: &str = "\n";

/// Sentinel token type for end-of-file, mirroring `org.antlr.runtime.Token.EOF`.
pub const EOF: i32 = -1;

/// A minimal ANTLR-style token: a type and optional text.
///
/// Mirrors the slice of `org.antlr.runtime.Token` consulted by
/// [`BaseRecognizerOverride::get_token_error_display`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizerToken {
    pub token_type: i32,
    pub text: Option<String>,
}

impl RecognizerToken {
    /// Creates a token with no text, mirroring a token with a `null` text field.
    pub fn new(token_type: i32) -> Self {
        Self { token_type, text: None }
    }

    /// Creates a token carrying explicit text.
    pub fn with_text(token_type: i32, text: impl Into<String>) -> Self {
        Self { token_type, text: Some(text.into()) }
    }
}

impl From<&SleighToken> for RecognizerToken {
    fn from(token: &SleighToken) -> Self {
        Self {
            token_type: token.token_type(),
            text: token.text().map(|s| s.to_string()),
        }
    }
}

/// The subclass-specific data carried by a [`RecognitionException`].
///
/// Mirrors the ANTLR v3 `RecognitionException` subclasses inspected by
/// `BaseRecognizerOverride.getErrorMessage`: `UnwantedTokenException`,
/// `MissingTokenException`, `MismatchedTokenException`,
/// `MismatchedTreeNodeException`, `NoViableAltException`,
/// `EarlyExitException`, `MismatchedSetException`,
/// `MismatchedNotSetException`, and `FailedPredicateException`. `Generic`
/// stands in for a plain `RecognitionException` (or any subclass not
/// specifically handled), whose message passes through unchanged.
#[derive(Debug, Clone)]
pub enum RecognitionExceptionKind {
    Generic { message: Option<String> },
    UnwantedToken { expecting: i32, unexpected_token: RecognizerToken },
    MissingToken { expecting: i32 },
    MismatchedToken,
    MismatchedTreeNode { expecting: i32, node: String },
    NoViableAlt,
    EarlyExit,
    MismatchedSet { expecting: String },
    MismatchedNotSet { expecting: String },
    FailedPredicate { rule_name: String, predicate_text: String },
}

/// A parse-time recognition error.
///
/// Mirrors the fields of `org.antlr.runtime.RecognitionException` consulted
/// by `BaseRecognizerOverride`: the offending token, its line and column,
/// plus whichever subclass-specific data `kind` carries.
#[derive(Debug, Clone)]
pub struct RecognitionException {
    pub kind: RecognitionExceptionKind,
    pub token: RecognizerToken,
    pub line: i32,
    pub char_position_in_line: i32,
}

impl RecognitionException {
    pub fn generic(
        message: Option<String>,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self { kind: RecognitionExceptionKind::Generic { message }, token, line, char_position_in_line }
    }

    pub fn unwanted_token(
        expecting: i32,
        unexpected_token: RecognizerToken,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self {
            kind: RecognitionExceptionKind::UnwantedToken { expecting, unexpected_token },
            token,
            line,
            char_position_in_line,
        }
    }

    pub fn missing_token(
        expecting: i32,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self { kind: RecognitionExceptionKind::MissingToken { expecting }, token, line, char_position_in_line }
    }

    pub fn mismatched_token(token: RecognizerToken, line: i32, char_position_in_line: i32) -> Self {
        Self { kind: RecognitionExceptionKind::MismatchedToken, token, line, char_position_in_line }
    }

    pub fn mismatched_tree_node(
        expecting: i32,
        node: impl Into<String>,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self {
            kind: RecognitionExceptionKind::MismatchedTreeNode { expecting, node: node.into() },
            token,
            line,
            char_position_in_line,
        }
    }

    pub fn no_viable_alt(token: RecognizerToken, line: i32, char_position_in_line: i32) -> Self {
        Self { kind: RecognitionExceptionKind::NoViableAlt, token, line, char_position_in_line }
    }

    pub fn early_exit(token: RecognizerToken, line: i32, char_position_in_line: i32) -> Self {
        Self { kind: RecognitionExceptionKind::EarlyExit, token, line, char_position_in_line }
    }

    pub fn mismatched_set(
        expecting: impl Into<String>,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self {
            kind: RecognitionExceptionKind::MismatchedSet { expecting: expecting.into() },
            token,
            line,
            char_position_in_line,
        }
    }

    pub fn mismatched_not_set(
        expecting: impl Into<String>,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self {
            kind: RecognitionExceptionKind::MismatchedNotSet { expecting: expecting.into() },
            token,
            line,
            char_position_in_line,
        }
    }

    pub fn failed_predicate(
        rule_name: impl Into<String>,
        predicate_text: impl Into<String>,
        token: RecognizerToken,
        line: i32,
        char_position_in_line: i32,
    ) -> Self {
        Self {
            kind: RecognitionExceptionKind::FailedPredicate {
                rule_name: rule_name.into(),
                predicate_text: predicate_text.into(),
            },
            token,
            line,
            char_position_in_line,
        }
    }
}

/// Formats human-readable error messages for [`RecognitionException`]s.
///
/// Mirrors `ghidra.sleigh.grammar.BaseRecognizerOverride`, a base class that
/// generated ANTLR recognizers extend to override the default error
/// formatting.
pub struct BaseRecognizerOverride;

impl BaseRecognizerOverride {
    fn resolve_token_name(expecting: i32, token_names: Option<&[&str]>) -> String {
        if expecting == EOF {
            return "EOF".to_string();
        }
        match token_names {
            Some(names) => names
                .get(expecting as usize)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            None => "<unknown>".to_string(),
        }
    }

    /// Builds a multi-line error message: a description of `e`, followed by
    /// the offending source line (read from `writer`) and a `^` arrow
    /// pointing at the error column.
    ///
    /// Mirrors `getErrorMessage(RecognitionException, String[], LineArrayListWriter)`.
    pub fn get_error_message(
        e: &RecognitionException,
        token_names: Option<&[&str]>,
        writer: &LineArrayListWriter,
    ) -> String {
        let msg = match &e.kind {
            RecognitionExceptionKind::Generic { message } => message.clone().unwrap_or_default(),
            RecognitionExceptionKind::UnwantedToken { expecting, unexpected_token } => {
                let token_name = Self::resolve_token_name(*expecting, token_names);
                format!(
                    "extraneous input {} expecting {}",
                    Self::get_token_error_display(unexpected_token),
                    token_name
                )
            }
            RecognitionExceptionKind::MissingToken { expecting } => {
                // The Java source never actually looks `tokenName` up from
                // `tokenNames` in this branch; it stays "<unknown>".
                let token_name = "<unknown>";
                if *expecting == EOF {
                    format!("unexpected token: {}", Self::get_token_error_display(&e.token))
                } else {
                    format!("missing {} at {}", token_name, Self::get_token_error_display(&e.token))
                }
            }
            RecognitionExceptionKind::MismatchedToken => {
                format!("unexpected token: {}", Self::get_token_error_display(&e.token))
            }
            RecognitionExceptionKind::MismatchedTreeNode { expecting, node } => {
                let token_name = Self::resolve_token_name(*expecting, token_names);
                format!("mismatched tree node: {} expecting {}", node, token_name)
            }
            RecognitionExceptionKind::NoViableAlt => {
                format!("unexpected token: {}", Self::get_token_error_display(&e.token))
            }
            RecognitionExceptionKind::EarlyExit => {
                format!(
                    "required (...)+ loop did not match anything at input {}",
                    Self::get_token_error_display(&e.token)
                )
            }
            RecognitionExceptionKind::MismatchedSet { expecting } => {
                format!(
                    "mismatched input {} expecting set {}",
                    Self::get_token_error_display(&e.token),
                    expecting
                )
            }
            RecognitionExceptionKind::MismatchedNotSet { expecting } => {
                format!(
                    "mismatched input {} expecting set {}",
                    Self::get_token_error_display(&e.token),
                    expecting
                )
            }
            RecognitionExceptionKind::FailedPredicate { rule_name, predicate_text } => {
                format!("rule {} failed predicate: {{{}}}?", rule_name, predicate_text)
            }
        };

        let line = AntlrUtil::get_line_from_writer(writer, e.line);
        let position = AntlrUtil::tab_compensate(&line, e.char_position_in_line);
        format!(
            "{msg}:{nl}{nl}{line}{nl}{arrow}",
            msg = msg,
            nl = NEWLINE,
            line = line,
            arrow = AntlrUtil::generate_arrow(position)
        )
    }

    /// Formats a token for display in an error message: its quoted text, or
    /// `<EOF>` / `<type>` if it carries no text, with newlines, carriage
    /// returns, and tabs escaped.
    ///
    /// Mirrors `getTokenErrorDisplay(Token)`.
    pub fn get_token_error_display(t: &RecognizerToken) -> String {
        let mut s = match &t.text {
            Some(text) => text.clone(),
            None => {
                if t.token_type == EOF {
                    "<EOF>".to_string()
                } else {
                    format!("<{}>", t.token_type)
                }
            }
        };
        s = s.replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t");
        format!("'{}'", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer_with_lines(lines: &[&str]) -> LineArrayListWriter {
        let mut w = LineArrayListWriter::new();
        for (i, line) in lines.iter().enumerate() {
            if i != 0 {
                w.new_line();
            }
            w.write(line);
        }
        w
    }

    #[test]
    fn token_error_display_uses_text_when_present() {
        let t = RecognizerToken::with_text(5, "foo");
        assert_eq!(BaseRecognizerOverride::get_token_error_display(&t), "'foo'");
    }

    #[test]
    fn token_error_display_uses_eof_marker() {
        let t = RecognizerToken::new(EOF);
        assert_eq!(BaseRecognizerOverride::get_token_error_display(&t), "'<EOF>'");
    }

    #[test]
    fn token_error_display_uses_type_marker_when_no_text_and_not_eof() {
        let t = RecognizerToken::new(7);
        assert_eq!(BaseRecognizerOverride::get_token_error_display(&t), "'<7>'");
    }

    #[test]
    fn token_error_display_escapes_control_characters() {
        let t = RecognizerToken::with_text(1, "a\nb\rc\td");
        assert_eq!(BaseRecognizerOverride::get_token_error_display(&t), "'a\\nb\\rc\\td'");
    }

    #[test]
    fn recognizer_token_from_sleigh_token() {
        let sleigh = SleighToken::new_with_text(3, "hello");
        let t = RecognizerToken::from(&sleigh);
        assert_eq!(t.token_type, 3);
        assert_eq!(t.text.as_deref(), Some("hello"));
    }

    #[test]
    fn unwanted_token_message_looks_up_expected_name() {
        let e = RecognitionException::unwanted_token(
            2,
            RecognizerToken::with_text(9, "x"),
            RecognizerToken::new(0),
            1,
            0,
        );
        let names = ["<invalid>", "A", "B"];
        let writer = writer_with_lines(&["let x = 1"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, Some(&names), &writer);
        assert!(msg.starts_with("extraneous input 'x' expecting B:"));
    }

    #[test]
    fn unwanted_token_message_reports_eof_expecting() {
        let e = RecognitionException::unwanted_token(
            EOF,
            RecognizerToken::with_text(9, "x"),
            RecognizerToken::new(0),
            1,
            0,
        );
        let writer = writer_with_lines(&["let x = 1"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("extraneous input 'x' expecting EOF:"));
    }

    #[test]
    fn unwanted_token_message_falls_back_to_unknown_without_names() {
        let e = RecognitionException::unwanted_token(
            2,
            RecognizerToken::with_text(9, "x"),
            RecognizerToken::new(0),
            1,
            0,
        );
        let writer = writer_with_lines(&["let x = 1"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("extraneous input 'x' expecting <unknown>:"));
    }

    #[test]
    fn missing_token_message_never_resolves_token_name() {
        let e = RecognitionException::missing_token(3, RecognizerToken::with_text(1, "y"), 1, 0);
        let names = ["<invalid>", "A", "B", "C"];
        let writer = writer_with_lines(&["a b"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, Some(&names), &writer);
        assert!(msg.starts_with("missing <unknown> at 'y':"));
    }

    #[test]
    fn missing_token_message_reports_unexpected_for_eof() {
        let e = RecognitionException::missing_token(EOF, RecognizerToken::with_text(1, "y"), 1, 0);
        let writer = writer_with_lines(&["a b"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("unexpected token: 'y':"));
    }

    #[test]
    fn mismatched_token_message() {
        let e = RecognitionException::mismatched_token(RecognizerToken::with_text(1, "z"), 1, 0);
        let writer = writer_with_lines(&["a b"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("unexpected token: 'z':"));
    }

    #[test]
    fn mismatched_tree_node_message() {
        let e = RecognitionException::mismatched_tree_node(
            1,
            "SOME_NODE",
            RecognizerToken::new(0),
            1,
            0,
        );
        let names = ["<invalid>", "EXPECTED_NODE"];
        let writer = writer_with_lines(&["tree"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, Some(&names), &writer);
        assert!(msg.starts_with("mismatched tree node: SOME_NODE expecting EXPECTED_NODE:"));
    }

    #[test]
    fn no_viable_alt_message() {
        let e = RecognitionException::no_viable_alt(RecognizerToken::with_text(1, "q"), 1, 0);
        let writer = writer_with_lines(&["q"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("unexpected token: 'q':"));
    }

    #[test]
    fn early_exit_message() {
        let e = RecognitionException::early_exit(RecognizerToken::with_text(1, "r"), 1, 0);
        let writer = writer_with_lines(&["r"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("required (...)+ loop did not match anything at input 'r':"));
    }

    #[test]
    fn mismatched_set_message() {
        let e = RecognitionException::mismatched_set("{A, B}", RecognizerToken::with_text(1, "s"), 1, 0);
        let writer = writer_with_lines(&["s"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("mismatched input 's' expecting set {A, B}:"));
    }

    #[test]
    fn mismatched_not_set_message() {
        let e = RecognitionException::mismatched_not_set("{C}", RecognizerToken::with_text(1, "t"), 1, 0);
        let writer = writer_with_lines(&["t"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("mismatched input 't' expecting set {C}:"));
    }

    #[test]
    fn failed_predicate_message() {
        let e = RecognitionException::failed_predicate(
            "myRule",
            "x > 0",
            RecognizerToken::new(0),
            1,
            0,
        );
        let writer = writer_with_lines(&["u"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("rule myRule failed predicate: {x > 0}?:"));
    }

    #[test]
    fn generic_message_passes_through() {
        let e = RecognitionException::generic(
            Some("plain error".to_string()),
            RecognizerToken::new(0),
            1,
            0,
        );
        let writer = writer_with_lines(&["u"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.starts_with("plain error:"));
    }

    #[test]
    fn error_message_includes_source_line_and_arrow() {
        let e = RecognitionException::mismatched_token(RecognizerToken::with_text(1, "z"), 2, 4);
        let writer = writer_with_lines(&["first line", "second line"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        let expected = format!(
            "unexpected token: 'z':{nl}{nl}second line{nl}----^",
            nl = NEWLINE
        );
        assert_eq!(msg, expected);
    }

    #[test]
    fn error_message_clamps_line_past_end_of_writer() {
        let e = RecognitionException::mismatched_token(RecognizerToken::with_text(1, "z"), 99, 0);
        let writer = writer_with_lines(&["only line"]);
        let msg = BaseRecognizerOverride::get_error_message(&e, None, &writer);
        assert!(msg.contains("only line"));
    }
}
