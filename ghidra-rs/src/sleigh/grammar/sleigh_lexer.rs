use crate::sleigh::grammar::frontend::{BaseLexer, DisplayLexer, SemanticLexer};
use crate::sleigh::grammar::{ParsingEnvironment, SleighToken};

/// A unified lexer for SLEIGH that wraps the base, display, and semantic lexer modes.
///
/// Mirrors `ghidra.sleigh.grammar.SleighLexer`. In the Java version, this extends
/// `LexerMultiplexer` and creates three separate lexer instances that all read from
/// the same ANTLR `CharStream`. In this Rust port, the frontend lexers (base, display,
/// semantic) are designed as views over a single `BaseLexer` that share the cursor,
/// matching the architecture used by the parser (see `display_lexer.rs` for details).
///
/// `SleighLexer` provides a convenient wrapper and the `set_env` method to configure
/// the lexing environment for all modes.
pub struct SleighLexer {
    input: String,
    base: BaseLexer,
}

impl SleighLexer {
    /// Creates a new SleighLexer from an input string.
    ///
    /// Mirrors `SleighLexer(CharStream input)`.
    pub fn new(input: &str) -> Self {
        Self {
            input: input.to_string(),
            base: BaseLexer::new(input),
        }
    }

    /// Creates a new SleighLexer with a parsing environment.
    ///
    /// Mirrors the constructor that takes both `CharStream` and a custom `TokenSource`,
    /// adapted for the Rust port where the environment is set directly on the base lexer.
    pub fn with_env(input: &str, env: ParsingEnvironment) -> Self {
        Self {
            input: input.to_string(),
            base: BaseLexer::with_env(input, env),
        }
    }

    /// Sets the parsing environment for all lexer modes.
    ///
    /// Mirrors `setEnv(ParsingEnvironment env)`. In the Java version, this iterates
    /// over the three `TokenSource`s in the multiplexer (BaseLexer, DisplayLexer,
    /// SemanticLexer) and calls `setEnv` on each. In this port, all modes read from
    /// the same `BaseLexer`, so we set the environment on it once.
    ///
    /// Note: this reinitializes the lexer to reset its position to the beginning.
    /// This is the intended behavior when configuring the lexer before starting to lex.
    pub fn set_env(&mut self, env: ParsingEnvironment) {
        self.base = BaseLexer::with_env(&self.input, env);
    }

    /// Returns a mutable reference to the underlying base lexer.
    ///
    /// Used by consumers to pull tokens or switch between lexer modes.
    pub fn base_lexer_mut(&mut self) -> &mut BaseLexer {
        &mut self.base
    }

    /// Returns a reference to the underlying base lexer.
    pub fn base_lexer(&self) -> &BaseLexer {
        &self.base
    }

    /// Creates a display-mode lexer view over the current base lexer.
    ///
    /// This is used by the parser when entering a constructor display section.
    /// The returned `DisplayLexer` borrows the base lexer's cursor and will advance it.
    pub fn display_lexer(&mut self) -> DisplayLexer<'_> {
        DisplayLexer::new(&mut self.base)
    }

    /// Creates a semantic-mode lexer view over the current base lexer.
    ///
    /// This is used by the parser when entering a p-code semantic body.
    /// The returned `SemanticLexer` borrows the base lexer's cursor and will advance it.
    pub fn semantic_lexer(&mut self) -> SemanticLexer<'_> {
        SemanticLexer::new(&mut self.base)
    }

    /// Pulls the next token in base mode.
    pub fn next_token(&mut self) -> SleighToken {
        self.base.next_token()
    }

    /// Returns any lexing errors encountered so far.
    pub fn errors(&self) -> &[String] {
        self.base.errors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_sleigh_lexer() {
        let lexer = SleighLexer::new("define endian=little;");
        assert_eq!(lexer.errors().len(), 0);
    }

    #[test]
    fn lexer_with_env() {
        let env = ParsingEnvironment::new(
            crate::sleigh::grammar::LineArrayListWriter::new(),
        );
        let lexer = SleighLexer::with_env("define endian=little;", env);
        assert_eq!(lexer.errors().len(), 0);
    }

    #[test]
    fn pull_basic_token() {
        let mut lexer = SleighLexer::new("define");
        let token = lexer.next_token();
        assert!(token.token_type() > 0);
    }

    #[test]
    fn set_env_after_construction() {
        let env = ParsingEnvironment::new(
            crate::sleigh::grammar::LineArrayListWriter::new(),
        );
        let mut lexer = SleighLexer::new("define endian=little;");
        lexer.set_env(env);
        assert_eq!(lexer.errors().len(), 0);
    }

    #[test]
    fn display_lexer_borrows_base() {
        let mut lexer = SleighLexer::new("define endian=little;");
        let _display = lexer.display_lexer();
    }

    #[test]
    fn semantic_lexer_borrows_base() {
        let mut lexer = SleighLexer::new("{ a = 1; }");
        let _semantic = lexer.semantic_lexer();
    }
}
