//! Port of `ghidra.features.codecompare.decompile.TokenPair`.

use crate::app::decompiler::ClangToken;

/// A pair of matched decompiler tokens: one from each side of a dual decompiler code comparison.
///
/// Port of `ghidra.features.codecompare.decompile.TokenPair`, a Java `record`:
///
/// ```java
/// record TokenPair(ClangToken leftToken, ClangToken rightToken) {
/// }
/// ```
///
/// [`ClangToken`] is a trait, so following this crate's established convention for owning a
/// dynamically-typed decompiler token (e.g. `ClangLine::tokens`, one line's tokens are
/// `Vec<Box<dyn ClangToken>>`; `DecompilerActionContext::token_at_cursor` is a
/// `Box<dyn ClangToken>`), each field here is `Box<dyn ClangToken>` rather than attempting to
/// model Java's shared object reference directly.
///
/// Java records auto-generate `equals`/`hashCode`/`toString`, but every real caller of
/// `TokenPair` (`DualDecompilerActionContext` and the `*FromMatchedTokensAction` decompiler code
/// comparison actions) only ever reads the two accessors -- none compares, hashes, or prints a
/// `TokenPair` value directly -- so this port carries only the accessors. `Box<dyn ClangToken>`
/// can't derive `PartialEq`/`Hash` anyway, so synthesizing the unused record methods would be
/// both pointless and not straightforwardly possible.
pub struct TokenPair {
    left_token: Box<dyn ClangToken>,
    right_token: Box<dyn ClangToken>,
}

impl TokenPair {
    /// Port of the record's canonical constructor `TokenPair(ClangToken leftToken, ClangToken
    /// rightToken)`.
    pub fn new(left_token: Box<dyn ClangToken>, right_token: Box<dyn ClangToken>) -> Self {
        TokenPair { left_token, right_token }
    }

    /// Port of the record accessor `leftToken()`.
    pub fn left_token(&self) -> &dyn ClangToken {
        self.left_token.as_ref()
    }

    /// Port of the record accessor `rightToken()`.
    pub fn right_token(&self) -> &dyn ClangToken {
        self.right_token.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::ClangTokenBase;

    fn token(text: &str) -> Box<dyn ClangToken> {
        Box::new(ClangTokenBase::with_text(None, text))
    }

    #[test]
    fn new_stores_left_and_right_tokens() {
        let pair = TokenPair::new(token("foo"), token("bar"));
        assert_eq!(pair.left_token().get_text(), "foo");
        assert_eq!(pair.right_token().get_text(), "bar");
    }

    #[test]
    fn left_and_right_tokens_are_independent() {
        // Constructing with the same text on both sides shouldn't make them the same
        // object -- each accessor reflects only its own constructor argument.
        let pair = TokenPair::new(token("same"), token("same"));
        assert_eq!(pair.left_token().get_text(), "same");
        assert_eq!(pair.right_token().get_text(), "same");
    }

    #[test]
    fn accessors_match_record_component_order() {
        // leftToken is always the first constructor argument, rightToken the second -- verify
        // no accidental swap.
        let pair = TokenPair::new(token("left"), token("right"));
        assert_eq!(pair.left_token().get_text(), "left");
        assert_eq!(pair.right_token().get_text(), "right");
        assert_ne!(pair.left_token().get_text(), pair.right_token().get_text());
    }
}
