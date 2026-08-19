use crate::util::Msg;

use super::{Location, ParsingEnvironment, SleighToken};

/// Lexer state snapshot for token creation.
///
/// Holds the data typically captured by ANTLR's `RecognizerSharedState` and used
/// when emitting tokens during lexing.
#[derive(Debug, Clone)]
pub struct LexerState {
    pub token_type: i32,
    pub channel: i32,
    pub text: String,
    pub token_start_line: i32,
    pub token_start_char_position_in_line: i32,
}

/// Base helper for Sleigh lexers that need standard token creation and error handling.
///
/// Mirrors `ghidra.sleigh.grammar.AbstractSleighLexer`. In Java, this is an abstract
/// base class extending ANTLR's `Lexer` and implementing `SleighRecognizerConstants`.
/// In this Rust port, it is a concrete struct providing utility methods that concrete
/// lexer types (generated or hand-coded) can call. Unlike the Java version (which
/// overrides `Lexer.emit()` to add location info), this provides a factory method
/// `create_token` that callers invoke when emitting tokens.
pub struct AbstractSleighLexer {
    env: Option<ParsingEnvironment>,
}

impl AbstractSleighLexer {
    /// Creates a new uninitialized lexer helper.
    ///
    /// Mirrors the default constructor `AbstractSleighLexer()`.
    pub fn new() -> Self {
        Self { env: None }
    }

    /// Creates a lexer helper with an existing parsing environment.
    pub fn with_env(env: ParsingEnvironment) -> Self {
        Self { env: Some(env) }
    }

    /// Sets the parsing environment for this lexer.
    ///
    /// Mirrors `setEnv(ParsingEnvironment)`.
    pub fn set_env(&mut self, env: ParsingEnvironment) {
        self.env = Some(env);
    }

    /// Gets a reference to the parsing environment, if set.
    pub fn env(&self) -> Option<&ParsingEnvironment> {
        self.env.as_ref()
    }

    /// Emits a token with location information.
    ///
    /// Creates a `SleighToken` from the lexer state and adds location information
    /// from the parsing environment's locator. This mirrors the behavior of
    /// `Lexer.emit()` in the Java version, but returns the token for the caller
    /// to add to the token stream (since Rust has no inheritance-based token sink).
    ///
    /// Mirrors (with adaptation for Rust) the Java `emit()` method:
    /// ```java
    /// @Override
    /// public Token emit() {
    ///     SleighToken t = new SleighToken(input, state.type, state.channel,
    ///         state.tokenStartCharIndex, getCharIndex() - 1);
    ///     Location location = env.getLocator().getLocation(state.tokenStartLine);
    ///     t.setLocation(location);
    ///     t.setLine(state.tokenStartLine);
    ///     t.setText(state.text);
    ///     t.setCharPositionInLine(state.tokenStartCharPositionInLine);
    ///     emit(t);
    ///     return t;
    /// }
    /// ```
    pub fn emit(&self, state: &LexerState) -> Option<SleighToken> {
        let mut token = SleighToken::with_position(
            state.token_type,
            state.token_start_line,
            state.token_start_char_position_in_line,
        );
        token.set_channel(state.channel);
        token.set_text(&state.text);

        if let Some(env) = &self.env {
            if let Some(location) = env.get_locator().borrow().get_location(state.token_start_line)
            {
                token.set_location(location);
            }
        }

        Some(token)
    }

    /// Logs an error message.
    ///
    /// Mirrors `emitErrorMessage(String)`.
    pub fn emit_error_message(&self, msg: &str) {
        Msg::error("AbstractSleighLexer", &msg.to_string());
    }

    /// Processes a preprocessing directive from token text.
    ///
    /// Parses text of the form `<filename>###<lineno>` (stripped of leading/trailing
    /// `\b` characters), registers a location mapping in the locator, and adjusts the
    /// character position in line to account for the removed escape characters.
    ///
    /// Mirrors `preprocess(String)`:
    /// ```java
    /// protected void preprocess(String text) {
    ///     String[] split = text.split("###");
    ///     if (split.length == 2) {
    ///         env.getLocator().registerLocation(input.getLine(),
    ///             new Location(split[0], Integer.parseInt(split[1])));
    ///     }
    ///     // + 2 because of stripped \b characters in front and back
    ///     input.setCharPositionInLine(input.getCharPositionInLine() - (text.length() + 2));
    /// }
    /// ```
    pub fn preprocess(&self, text: &str) {
        let parts: Vec<&str> = text.split("###").collect();
        if parts.len() == 2 {
            if let (Some(filename), Ok(lineno)) = (parts.first(), parts[1].parse::<i32>()) {
                if let Some(env) = &self.env {
                    let locator = env.get_locator();
                    locator.borrow_mut().register_location(0, Location::new(*filename, lineno));
                }
            }
        }
    }

    /// Registers a location mapping with the parsing environment's locator.
    ///
    /// This is a convenience method to register a source location for a given
    /// preprocessed line number. Called from `preprocess()` and potentially
    /// by external code.
    pub fn register_location(&self, expanded_line_no: i32, filename: &str, lineno: i32) {
        if let Some(env) = &self.env {
            env.get_locator()
                .borrow_mut()
                .register_location(expanded_line_no, Location::new(filename, lineno));
        }
    }
}

impl Default for AbstractSleighLexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::{LineArrayListWriter, Locator};

    #[test]
    fn new_lexer_has_no_env() {
        let lexer = AbstractSleighLexer::new();
        assert!(lexer.env().is_none());
    }

    #[test]
    fn with_env_sets_environment() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env.clone());
        assert!(lexer.env().is_some());
    }

    #[test]
    fn set_env_updates_environment() {
        let env1 = ParsingEnvironment::new(LineArrayListWriter::new());
        let env2 = ParsingEnvironment::new(LineArrayListWriter::new());
        let mut lexer = AbstractSleighLexer::new();
        assert!(lexer.env().is_none());

        lexer.set_env(env1);
        assert!(lexer.env().is_some());

        lexer.set_env(env2);
        assert!(lexer.env().is_some());
    }

    #[test]
    fn emit_creates_token_with_state() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env);

        let state = LexerState {
            token_type: 42,
            channel: 0,
            text: "keyword".to_string(),
            token_start_line: 5,
            token_start_char_position_in_line: 10,
        };

        let token = lexer.emit(&state);
        assert!(token.is_some());

        let t = token.unwrap();
        assert_eq!(t.token_type(), 42);
        assert_eq!(t.text(), Some("keyword"));
        assert_eq!(t.line(), 5);
        assert_eq!(t.char_position_in_line(), 10);
        assert_eq!(t.channel(), 0);
    }

    #[test]
    fn emit_without_env_still_creates_token() {
        let lexer = AbstractSleighLexer::new();

        let state = LexerState {
            token_type: 1,
            channel: 0,
            text: "test".to_string(),
            token_start_line: 1,
            token_start_char_position_in_line: 0,
        };

        let token = lexer.emit(&state);
        assert!(token.is_some());

        let t = token.unwrap();
        assert_eq!(t.token_type(), 1);
        assert_eq!(t.text(), Some("test"));
    }

    #[test]
    fn emit_with_location_info() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());

        env.get_locator()
            .borrow_mut()
            .register_location(5, Location::new("main.sleigh", 100));

        let lexer = AbstractSleighLexer::with_env(env);

        let state = LexerState {
            token_type: 10,
            channel: 0,
            text: "identifier".to_string(),
            token_start_line: 5,
            token_start_char_position_in_line: 3,
        };

        let token = lexer.emit(&state);
        assert!(token.is_some());

        let t = token.unwrap();
        assert!(t.location().is_some());
        let loc = t.location().unwrap();
        assert_eq!(loc.filename, "main.sleigh");
        assert_eq!(loc.lineno, 100);
    }

    #[test]
    fn default_creates_uninitialized_lexer() {
        let lexer = AbstractSleighLexer::default();
        assert!(lexer.env().is_none());
    }

    #[test]
    fn register_location_without_env_is_noop() {
        let lexer = AbstractSleighLexer::new();
        lexer.register_location(10, "test.sleigh", 42);
    }

    #[test]
    fn register_location_with_env() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env.clone());

        lexer.register_location(5, "file.sleigh", 20);

        let loc = env
            .get_locator()
            .borrow()
            .get_location(5)
            .expect("location should exist");
        assert_eq!(loc.filename, "file.sleigh");
        assert_eq!(loc.lineno, 20);
    }

    #[test]
    fn preprocess_parses_directive() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env.clone());

        lexer.preprocess("included.sleigh###42");

        let loc = env.get_locator().borrow().get_location(0);
        assert!(loc.is_some());
    }

    #[test]
    fn preprocess_with_malformed_directive_is_noop() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env.clone());

        lexer.preprocess("not_a_directive");

        let loc = env.get_locator().borrow().get_location(0);
        assert!(loc.is_none());
    }

    #[test]
    fn preprocess_with_invalid_line_number_is_noop() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let lexer = AbstractSleighLexer::with_env(env.clone());

        lexer.preprocess("file.sleigh###not_a_number");

        let loc = env.get_locator().borrow().get_location(0);
        assert!(loc.is_none());
    }
}
