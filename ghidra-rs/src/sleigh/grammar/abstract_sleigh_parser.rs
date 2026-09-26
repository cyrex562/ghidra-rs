use crate::util::Msg;

use super::{BailoutException, ParsingEnvironment, SleighLexer};

/// Base helper for Sleigh parsers that need standard error handling.
///
/// Mirrors `ghidra.sleigh.grammar.AbstractSleighParser`. In Java, this is a base
/// class extending ANTLR's `Parser` and implementing `SleighRecognizerConstants`.
/// In this Rust port, ANTLR's base class infrastructure is not used, so this provides
/// a concrete struct that parsers can hold or embed to access the parsing environment
/// and lexer, along with standard error-handling methods (bail, emitErrorMessage).
///
/// The Java class also overrides error message formatting methods (getErrorHeader,
/// getErrorMessage, getTokenErrorDisplay) that depend on ANTLR's exception types.
/// Since the Rust port does not use ANTLR, those methods are not ported here.
pub struct AbstractSleighParser {
    env: Option<ParsingEnvironment>,
    lexer: Option<SleighLexer>,
}

impl AbstractSleighParser {
    /// Creates a new uninitialized parser.
    ///
    /// Mirrors the default constructor `AbstractSleighParser()`.
    pub fn new() -> Self {
        Self { env: None, lexer: None }
    }

    /// Creates a parser with a parsing environment.
    pub fn with_env(env: ParsingEnvironment) -> Self {
        Self { env: Some(env), lexer: None }
    }

    /// Aborts parsing by throwing a BailoutException.
    ///
    /// Mirrors `bail(String msg)`.
    pub fn bail(&self, msg: &str) -> ! {
        throw_bailout(msg);
    }

    /// Logs an error message using the standard error logger.
    ///
    /// Mirrors `emitErrorMessage(String msg)`, which in Java calls `Msg.error(this, msg)`.
    pub fn emit_error_message(&self, msg: &str) {
        Msg::error("AbstractSleighParser", &format!("{}", msg));
    }

    /// Returns the parsing environment, if set.
    ///
    /// Mirrors the implicit access to `env` in the Java version.
    pub fn env(&self) -> Option<&ParsingEnvironment> {
        self.env.as_ref()
    }

    /// Returns a mutable reference to the parsing environment, if set.
    pub fn env_mut(&mut self) -> Option<&mut ParsingEnvironment> {
        self.env.as_mut()
    }

    /// Returns the lexer, if set.
    ///
    /// Mirrors the implicit access to `lexer` in the Java version.
    pub fn lexer(&self) -> Option<&SleighLexer> {
        self.lexer.as_ref()
    }

    /// Returns a mutable reference to the lexer, if set.
    pub fn lexer_mut(&mut self) -> Option<&mut SleighLexer> {
        self.lexer.as_mut()
    }

    /// Sets the parsing environment.
    ///
    /// Mirrors `setEnv(ParsingEnvironment env)`.
    pub fn set_env(&mut self, env: ParsingEnvironment) {
        self.env = Some(env);
    }

    /// Sets the lexer.
    ///
    /// Mirrors `setLexer(SleighLexer lexer)`.
    pub fn set_lexer(&mut self, lexer: SleighLexer) {
        self.lexer = Some(lexer);
    }
}

impl Default for AbstractSleighParser {
    fn default() -> Self {
        Self::new()
    }
}

fn throw_bailout(msg: &str) -> ! {
    panic!("{}", BailoutException::with_message(msg));
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::LineArrayListWriter;

    #[test]
    fn new_parser_has_no_env_or_lexer() {
        let parser = AbstractSleighParser::new();
        assert!(parser.env().is_none());
        assert!(parser.lexer().is_none());
    }

    #[test]
    fn with_env_sets_environment() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let parser = AbstractSleighParser::with_env(env.clone());
        assert!(parser.env().is_some());
        assert_eq!(parser.env().unwrap(), &env);
    }

    #[test]
    fn set_env_updates_environment() {
        let mut parser = AbstractSleighParser::new();
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        parser.set_env(env.clone());
        assert!(parser.env().is_some());
        assert_eq!(parser.env().unwrap(), &env);
    }

    #[test]
    fn set_lexer_updates_lexer() {
        let mut parser = AbstractSleighParser::new();
        let lexer = SleighLexer::new("define endian=little;");
        parser.set_lexer(lexer);
        assert!(parser.lexer().is_some());
    }

    #[test]
    fn emit_error_message_does_not_panic() {
        let parser = AbstractSleighParser::new();
        parser.emit_error_message("test error");
    }

    #[test]
    #[should_panic(expected = "custom bail message")]
    fn bail_throws_bailout_exception() {
        let parser = AbstractSleighParser::new();
        let _ = parser.bail("custom bail message");
    }

    #[test]
    fn default_creates_new_parser() {
        let parser = AbstractSleighParser::default();
        assert!(parser.env().is_none());
        assert!(parser.lexer().is_none());
    }

    #[test]
    fn env_mut_allows_modification() {
        let mut parser = AbstractSleighParser::new();
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        parser.set_env(env);

        if let Some(env_ref) = parser.env_mut() {
            env_ref.lexing_error();
        }

        assert_eq!(parser.env().unwrap().get_lexing_errors(), 1);
    }

    #[test]
    fn lexer_mut_allows_modification() {
        let mut parser = AbstractSleighParser::new();
        let lexer = SleighLexer::new("test");
        parser.set_lexer(lexer);

        if let Some(lexer_ref) = parser.lexer_mut() {
            let _ = lexer_ref.base_lexer();
        }

        assert!(parser.lexer().is_some());
    }
}
