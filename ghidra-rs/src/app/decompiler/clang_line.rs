//! Port of `ghidra.app.decompiler.ClangLine`.
//!
//! A line of C code. This is an independent grouping of C tokens from the statement, vardecl
//! retype groups.
//!
//! Tokens are held as `Box<dyn ClangToken>`: Java's `ArrayList<ClangToken>` is heterogeneous
//! across `ClangToken`'s subclasses, so the line owns trait objects rather than one concrete type.

use crate::app::decompiler::clang_token::ClangToken;
use crate::app::decompiler::pretty_printer::INDENT_STRING;

/// A line of C code. Port of `ghidra.app.decompiler.ClangLine`.
pub struct ClangLine {
    indent_level: i32,
    tokens: Vec<Box<dyn ClangToken>>,
    line_number: i32,
}

impl ClangLine {
    /// Port of `ClangLine(int, int)`.
    pub fn new(line_number: i32, indent: i32) -> Self {
        Self {
            indent_level: indent,
            tokens: Vec::new(),
            line_number,
        }
    }

    /// Port of `ClangLine.getIndentString()`.
    pub fn get_indent_string(&self) -> String {
        INDENT_STRING.repeat(self.indent_level.max(0) as usize)
    }

    /// Port of `ClangLine.getIndent()`.
    pub fn get_indent(&self) -> i32 {
        self.indent_level
    }

    /// Port of `ClangLine.addToken(ClangToken)`.
    pub fn add_token(&mut self, mut tok: Box<dyn ClangToken>) {
        tok.set_line_parent(self);
        self.tokens.push(tok);
    }

    /// Port of `ClangLine.getAllTokens()`.
    pub fn get_all_tokens(&self) -> &Vec<Box<dyn ClangToken>> {
        &self.tokens
    }

    /// Mutable counterpart of [`get_all_tokens`](Self::get_all_tokens), standing in for the
    /// aliasing Java gets for free by returning the live `tokens` list reference (used by
    /// `PrettyPrinter.padEmptyLines` to insert a spacer into an empty line in place).
    pub fn get_all_tokens_mut(&mut self) -> &mut Vec<Box<dyn ClangToken>> {
        &mut self.tokens
    }

    /// Port of `ClangLine.getNumTokens()`.
    pub fn get_num_tokens(&self) -> usize {
        self.tokens.len()
    }

    /// Port of `ClangLine.getLineNumber()`.
    pub fn get_line_number(&self) -> i32 {
        self.line_number
    }

    /// Port of `ClangLine.getToken(int)`.
    pub fn get_token(&self, i: usize) -> &dyn ClangToken {
        self.tokens[i].as_ref()
    }

    /// Port of `ClangLine.indexOfToken(ClangToken)`. `List.indexOf` relies on `ClangToken`'s
    /// (unoverridden) `Object.equals`, i.e. identity comparison, so this compares by reference
    /// identity rather than by value.
    pub fn index_of_token(&self, token: &dyn ClangToken) -> Option<usize> {
        self.tokens
            .iter()
            .position(|t| is_same_token(t.as_ref(), token))
    }

    /// Port of `ClangLine.toDebugString(List<ClangToken>)`.
    pub fn to_debug_string(&self, callout_tokens: Option<&[&dyn ClangToken]>) -> String {
        self.to_debug_string_delim(callout_tokens, "[", "]")
    }

    /// Port of `ClangLine.toDebugString(List<ClangToken>, String, String)`.
    pub fn to_debug_string_delim(
        &self,
        callout_tokens: Option<&[&dyn ClangToken]>,
        start: &str,
        end: &str,
    ) -> String {
        let callout_tokens = callout_tokens.unwrap_or(&[]);
        let mut buffy = format!("{}: ", self.get_line_number());
        for token in &self.tokens {
            let is_callout = callout_tokens
                .iter()
                .any(|t| is_same_token(*t, token.as_ref()));
            if is_callout {
                buffy.push_str(start);
            }
            buffy.push_str(token.get_text());
            if is_callout {
                buffy.push_str(end);
            }
        }
        buffy
    }
}

/// Identity comparison between two tokens, as Java's `List.indexOf` gets from `ClangToken`'s
/// (unoverridden) `Object.equals`. Trait-object references are compared by data pointer only --
/// two `&dyn ClangToken` to the same token can carry different vtable pointers when reached
/// through different traits.
fn is_same_token(a: &dyn ClangToken, b: &dyn ClangToken) -> bool {
    std::ptr::eq(a as *const dyn ClangToken as *const u8, b as *const dyn ClangToken as *const u8)
}

impl std::fmt::Display for ClangLine {
    /// Port of `ClangLine.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_debug_string(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_token::ClangTokenBase;

    fn token(text: &str) -> Box<dyn ClangToken> {
        Box::new(ClangTokenBase::with_text(None, text))
    }

    #[test]
    fn get_indent_string_repeats_per_level() {
        let line = ClangLine::new(0, 3);
        assert_eq!(line.get_indent_string(), format!("{INDENT_STRING}{INDENT_STRING}{INDENT_STRING}"));
    }

    #[test]
    fn add_token_marks_line_parent_and_appends() {
        let mut line = ClangLine::new(0, 0);
        line.add_token(token("a"));
        line.add_token(token("b"));

        assert_eq!(line.get_num_tokens(), 2);
        assert!(line.get_all_tokens().iter().all(|t| t.has_line_parent()));
        assert_eq!(line.get_token(0).get_text(), "a");
        assert_eq!(line.get_token(1).get_text(), "b");
    }

    #[test]
    fn get_line_number_returns_constructor_value() {
        let line = ClangLine::new(42, 0);
        assert_eq!(line.get_line_number(), 42);
    }

    #[test]
    fn index_of_token_uses_identity_not_value_equality() {
        let mut line = ClangLine::new(0, 0);
        line.add_token(token("x"));
        line.add_token(token("x"));

        let second_ref = line.get_all_tokens()[1].as_ref();
        assert_eq!(line.index_of_token(second_ref), Some(1));

        let outside = token("x");
        assert_eq!(line.index_of_token(outside.as_ref()), None);
    }

    #[test]
    fn to_debug_string_brackets_callout_tokens() {
        let mut line = ClangLine::new(7, 0);
        line.add_token(token("int"));
        line.add_token(token(" x;"));

        let callout_ref = line.get_all_tokens()[0].as_ref();
        let text = line.to_debug_string(Some(&[callout_ref]));
        assert_eq!(text, "7: [int] x;");
    }

    #[test]
    fn to_debug_string_defaults_to_no_callouts() {
        let mut line = ClangLine::new(1, 0);
        line.add_token(token("y;"));
        assert_eq!(line.to_debug_string(None), "1: y;");
    }

    #[test]
    fn display_matches_to_debug_string_with_no_callouts() {
        let mut line = ClangLine::new(3, 0);
        line.add_token(token("z;"));
        assert_eq!(line.to_string(), "3: z;");
    }
}
