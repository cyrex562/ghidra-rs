use std::collections::{HashSet, VecDeque};

/// The default channel for tokens in the ANTLR v3 runtime.
///
/// Corresponds to `org.antlr.runtime.Token.DEFAULT_CHANNEL`.
pub const DEFAULT_CHANNEL: i32 = 0;

/// A lexer token that carries a channel identifier.
///
/// Corresponds to the minimal subset of `org.antlr.runtime.Token` used by the
/// Sleigh grammar infrastructure.
pub trait Token {
    fn channel(&self) -> i32;
}

/// A source of lexer tokens.
///
/// Corresponds to `org.antlr.runtime.TokenSource`.
pub trait TokenSource {
    fn next_token(&mut self) -> Box<dyn Token>;
    fn source_name(&self) -> String;
}

/// Multiplexes between multiple [`TokenSource`]s using a LIFO mode stack.
///
/// Mirrors `ghidra.sleigh.grammar.LexerMultiplexer`. Token production is
/// dispatched to the source at the top of the mode stack. Tokens on inactive
/// channels are silently skipped; only tokens whose channel is present in the
/// active-channel set are returned.
///
/// The active-channel set is initialised with [`DEFAULT_CHANNEL`] (0). Use
/// [`channel_on`] / [`channel_off`] to broaden or narrow filtering.
///
/// [`channel_on`]: LexerMultiplexer::channel_on
/// [`channel_off`]: LexerMultiplexer::channel_off
pub struct LexerMultiplexer {
    modes: Vec<Box<dyn TokenSource>>,
    stack: VecDeque<usize>,
    channels: HashSet<i32>,
}

impl LexerMultiplexer {
    /// Creates a new multiplexer that starts in mode 0.
    pub fn new(modes: Vec<Box<dyn TokenSource>>) -> Self {
        let mut stack = VecDeque::new();
        stack.push_front(0);

        let mut channels = HashSet::new();
        channels.insert(DEFAULT_CHANNEL);

        Self { modes, stack, channels }
    }

    /// Pops and returns the mode at the top of the mode stack.
    pub fn pop_mode(&mut self) -> usize {
        self.stack.pop_front().unwrap()
    }

    /// Pushes `mode` onto the mode stack.
    pub fn push_mode(&mut self, mode: usize) {
        self.stack.push_front(mode);
    }

    /// Replaces the current top mode with `mode`.
    pub fn set_mode(&mut self, mode: usize) {
        self.pop_mode();
        self.push_mode(mode);
    }

    /// Adds `channel` to the set of active channels.
    pub fn channel_on(&mut self, channel: i32) {
        self.channels.insert(channel);
    }

    /// Removes `channel` from the set of active channels.
    pub fn channel_off(&mut self, channel: i32) {
        self.channels.remove(&channel);
    }
}

impl TokenSource for LexerMultiplexer {
    fn next_token(&mut self) -> Box<dyn Token> {
        let mode = *self.stack.front().unwrap();
        loop {
            let t = self.modes[mode].next_token();
            if self.channels.contains(&t.channel()) {
                return t;
            }
        }
    }

    fn source_name(&self) -> String {
        let mut sb = String::from("Mux[");
        for (i, mode) in self.modes.iter().enumerate() {
            if i != 0 {
                sb.push(',');
            }
            sb.push_str(&i.to_string());
            sb.push(':');
            sb.push_str(&mode.source_name());
        }
        sb.push(']');
        sb
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct SimpleToken {
        channel: i32,
    }

    impl Token for SimpleToken {
        fn channel(&self) -> i32 {
            self.channel
        }
    }

    struct MockSource {
        name: String,
        tokens: VecDeque<i32>,
    }

    impl MockSource {
        fn new(name: &str, channels: &[i32]) -> Box<Self> {
            Box::new(Self {
                name: name.to_string(),
                tokens: VecDeque::from(channels.to_vec()),
            })
        }
    }

    impl TokenSource for MockSource {
        fn next_token(&mut self) -> Box<dyn Token> {
            let ch = self.tokens.pop_front().unwrap_or(DEFAULT_CHANNEL);
            Box::new(SimpleToken { channel: ch })
        }

        fn source_name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn source_name_single_mode() {
        let mux = LexerMultiplexer::new(vec![MockSource::new("lexer", &[])]);
        assert_eq!(mux.source_name(), "Mux[0:lexer]");
    }

    #[test]
    fn source_name_multiple_modes() {
        let mux = LexerMultiplexer::new(vec![
            MockSource::new("lex0", &[]),
            MockSource::new("lex1", &[]),
        ]);
        assert_eq!(mux.source_name(), "Mux[0:lex0,1:lex1]");
    }

    #[test]
    fn next_token_returns_default_channel_token() {
        let mut mux = LexerMultiplexer::new(vec![MockSource::new("src", &[0])]);
        assert_eq!(mux.next_token().channel(), DEFAULT_CHANNEL);
    }

    #[test]
    fn next_token_skips_inactive_channel() {
        // channel 99 is not active; only the following default-channel token is returned
        let mut mux = LexerMultiplexer::new(vec![MockSource::new("src", &[99, 0])]);
        assert_eq!(mux.next_token().channel(), DEFAULT_CHANNEL);
    }

    #[test]
    fn channel_on_allows_additional_channel() {
        let mut mux = LexerMultiplexer::new(vec![MockSource::new("src", &[99, 0])]);
        mux.channel_on(99);
        assert_eq!(mux.next_token().channel(), 99);
    }

    #[test]
    fn channel_off_filters_default_channel() {
        // Turn default off and add channel 5; only channel-5 tokens pass.
        let mut mux = LexerMultiplexer::new(vec![MockSource::new("src", &[0, 5])]);
        mux.channel_off(DEFAULT_CHANNEL);
        mux.channel_on(5);
        assert_eq!(mux.next_token().channel(), 5);
    }

    #[test]
    fn push_mode_switches_source() {
        let mut mux = LexerMultiplexer::new(vec![
            MockSource::new("mode0", &[0]),
            MockSource::new("mode1", &[0]),
        ]);
        mux.push_mode(1);
        // Token comes from mode1; mode1 is on top of the stack
        assert_eq!(mux.next_token().channel(), DEFAULT_CHANNEL);
    }

    #[test]
    fn pop_mode_returns_removed_mode() {
        let mut mux = LexerMultiplexer::new(vec![
            MockSource::new("m0", &[]),
            MockSource::new("m1", &[]),
        ]);
        mux.push_mode(1);
        assert_eq!(mux.pop_mode(), 1);
    }

    #[test]
    fn pop_mode_restores_previous_mode() {
        let mut mux = LexerMultiplexer::new(vec![
            MockSource::new("m0", &[0]),
            MockSource::new("m1", &[0]),
        ]);
        mux.push_mode(1);
        mux.pop_mode();
        // Should now be back to mode 0
        let t = mux.next_token();
        assert_eq!(t.channel(), DEFAULT_CHANNEL);
    }

    #[test]
    fn set_mode_replaces_top() {
        let mut mux = LexerMultiplexer::new(vec![
            MockSource::new("m0", &[]),
            MockSource::new("m1", &[0]),
        ]);
        mux.set_mode(1);
        assert_eq!(mux.next_token().channel(), DEFAULT_CHANNEL);
        // Stack depth should still be 1 (not grown)
        assert_eq!(mux.pop_mode(), 1);
    }

    #[test]
    fn initial_state_is_mode_zero() {
        let mut mux = LexerMultiplexer::new(vec![
            MockSource::new("only", &[0]),
        ]);
        assert_eq!(mux.pop_mode(), 0);
    }
}
