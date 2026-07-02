use super::{Location, Token, DEFAULT_CHANNEL};

/// A Sleigh grammar token with source location information.
///
/// Mirrors `ghidra.sleigh.grammar.SleighToken`, extending the minimal Token
/// interface with a `Location` that tracks the source file and line number.
#[derive(Debug, Clone)]
pub struct SleighToken {
    token_type: i32,
    channel: i32,
    text: Option<String>,
    line: i32,
    char_position_in_line: i32,
    location: Option<Location>,
}

impl SleighToken {
    /// Creates a new `SleighToken` from a CharStream-like context.
    ///
    /// Mirrors `SleighToken(CharStream, int, int, int, int)`.
    pub fn from_char_stream(
        token_type: i32,
        channel: i32,
        _start: i32,
        _stop: i32,
    ) -> Self {
        Self {
            token_type,
            channel,
            text: None,
            line: 1,
            char_position_in_line: 0,
            location: None,
        }
    }

    /// Creates a new `SleighToken` with type and text.
    ///
    /// Mirrors `SleighToken(int, String)`.
    pub fn new_with_text(token_type: i32, text: impl Into<String>) -> Self {
        Self {
            token_type,
            channel: DEFAULT_CHANNEL,
            text: Some(text.into()),
            line: 1,
            char_position_in_line: 0,
            location: None,
        }
    }

    /// Creates a new `SleighToken` with only a type.
    ///
    /// Mirrors `SleighToken(int)`.
    pub fn new(token_type: i32) -> Self {
        Self {
            token_type,
            channel: DEFAULT_CHANNEL,
            text: None,
            line: 1,
            char_position_in_line: 0,
            location: None,
        }
    }

    /// Creates a new `SleighToken` with type, line, and character position.
    ///
    /// Mirrors `SleighToken(int, int, int)`.
    pub fn with_position(token_type: i32, line: i32, char_position_in_line: i32) -> Self {
        Self {
            token_type,
            channel: DEFAULT_CHANNEL,
            text: None,
            line,
            char_position_in_line,
            location: None,
        }
    }

    /// Creates a new `SleighToken` by copying from another token.
    ///
    /// Mirrors `SleighToken(Token)`.
    pub fn from_token(other: &SleighToken) -> Self {
        Self {
            token_type: other.token_type,
            channel: other.channel,
            text: other.text.clone(),
            line: other.line,
            char_position_in_line: other.char_position_in_line,
            location: other.location.clone(),
        }
    }

    /// Gets the source location for this token.
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Sets the source location for this token.
    pub fn set_location(&mut self, location: Location) {
        self.location = Some(location);
    }

    /// Gets the token type.
    pub fn token_type(&self) -> i32 {
        self.token_type
    }

    /// Gets the token text.
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Sets the token text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = Some(text.into());
    }

    /// Gets the line number.
    pub fn line(&self) -> i32 {
        self.line
    }

    /// Sets the line number.
    pub fn set_line(&mut self, line: i32) {
        self.line = line;
    }

    /// Gets the character position in line.
    pub fn char_position_in_line(&self) -> i32 {
        self.char_position_in_line
    }

    /// Sets the character position in line.
    pub fn set_char_position_in_line(&mut self, char_position_in_line: i32) {
        self.char_position_in_line = char_position_in_line;
    }

    /// Gets the channel.
    pub fn channel(&self) -> i32 {
        self.channel
    }

    /// Sets the channel.
    pub fn set_channel(&mut self, channel: i32) {
        self.channel = channel;
    }
}

impl Token for SleighToken {
    fn channel(&self) -> i32 {
        self.channel
    }
}

impl std::fmt::Display for SleighToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.text {
            Some(text) => {
                write!(f, "{}", text)?;
            }
            None => {
                write!(f, "Token(type={})", self.token_type)?;
            }
        }
        if let Some(location) = &self.location {
            write!(f, "@{}", location)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_text() {
        let token = SleighToken::new_with_text(42, "hello");
        assert_eq!(token.token_type(), 42);
        assert_eq!(token.text(), Some("hello"));
        assert_eq!(token.channel(), DEFAULT_CHANNEL);
        assert_eq!(token.line(), 1);
        assert_eq!(token.char_position_in_line(), 0);
        assert!(token.location().is_none());
    }

    #[test]
    fn create_with_position() {
        let token = SleighToken::with_position(10, 25, 8);
        assert_eq!(token.token_type(), 10);
        assert_eq!(token.line(), 25);
        assert_eq!(token.char_position_in_line(), 8);
        assert_eq!(token.text(), None);
    }

    #[test]
    fn create_simple() {
        let token = SleighToken::new(5);
        assert_eq!(token.token_type(), 5);
        assert_eq!(token.text(), None);
        assert_eq!(token.line(), 1);
    }

    #[test]
    fn set_and_get_location() {
        let mut token = SleighToken::new(1);
        assert!(token.location().is_none());

        let loc = Location::new("test.sleigh", 42);
        token.set_location(loc.clone());

        let retrieved = token.location().unwrap();
        assert_eq!(retrieved.filename, "test.sleigh");
        assert_eq!(retrieved.lineno, 42);
    }

    #[test]
    fn clone_token() {
        let mut original = SleighToken::new_with_text(7, "test");
        original.set_location(Location::new("source.sl", 10));

        let cloned = SleighToken::from_token(&original);
        assert_eq!(cloned.token_type(), 7);
        assert_eq!(cloned.text(), Some("test"));
        assert_eq!(cloned.line(), 1);
        assert!(cloned.location().is_some());
    }

    #[test]
    fn display_without_location() {
        let token = SleighToken::new_with_text(1, "keyword");
        assert_eq!(token.to_string(), "keyword");
    }

    #[test]
    fn display_with_location() {
        let mut token = SleighToken::new_with_text(1, "identifier");
        token.set_location(Location::new("main.sleigh", 15));
        assert_eq!(token.to_string(), "identifier@main.sleigh:15");
    }

    #[test]
    fn display_token_without_text() {
        let token = SleighToken::new(99);
        assert_eq!(token.to_string(), "Token(type=99)");
    }

    #[test]
    fn display_token_without_text_with_location() {
        let mut token = SleighToken::new(99);
        token.set_location(Location::new("file.sl", 5));
        assert_eq!(token.to_string(), "Token(type=99)@file.sl:5");
    }

    #[test]
    fn set_text() {
        let mut token = SleighToken::new(1);
        assert_eq!(token.text(), None);

        token.set_text("new_text");
        assert_eq!(token.text(), Some("new_text"));
    }

    #[test]
    fn set_line() {
        let mut token = SleighToken::new(1);
        assert_eq!(token.line(), 1);

        token.set_line(100);
        assert_eq!(token.line(), 100);
    }

    #[test]
    fn set_char_position() {
        let mut token = SleighToken::new(1);
        assert_eq!(token.char_position_in_line(), 0);

        token.set_char_position_in_line(42);
        assert_eq!(token.char_position_in_line(), 42);
    }

    #[test]
    fn set_channel() {
        let mut token = SleighToken::new(1);
        assert_eq!(token.channel(), DEFAULT_CHANNEL);

        token.set_channel(5);
        assert_eq!(token.channel(), 5);
    }

    #[test]
    fn token_trait_implementation() {
        let mut token = SleighToken::new(1);
        token.set_channel(3);

        // Token trait should work
        let _t: &dyn Token = &token;
        assert_eq!(token.channel(), 3);
    }

    #[test]
    fn debug_format() {
        let token = SleighToken::new_with_text(42, "test");
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("SleighToken"));
    }
}
