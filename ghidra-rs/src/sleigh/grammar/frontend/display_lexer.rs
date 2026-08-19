//! Hand-written tokenizer for the SLEIGH DISPLAY lexer mode
//! (`DisplayLexer.g`), used for constructor display sections between the
//! constructor `:` and the terminating `is` keyword.
//!
//! `DisplayLexer.g` imports `BaseLexer.g` and changes four things:
//!
//! - `WS` moves to the DEFAULT channel: whitespace is significant in a
//!   display section and becomes a printpiece (in base mode it is HIDDEN);
//! - `LINECOMMENT` is overridden to match a single `#`, which prints
//!   verbatim as an assembly piece instead of starting a comment;
//! - `DISPCHAR` adds `@`, `$`, and `?` as displayable characters (`@` and
//!   `?` are lexing errors in base mode); per ANTLR longest-match, `$or`,
//!   `$and`, and `$xor` still win over a bare `$` DISPCHAR;
//! - `RES_IS` reserves the word `is` so the parser can tell where the
//!   display portion ends (`is` is an ordinary IDENTIFIER in base mode).
//!   Longest-match still applies: `island` or `disp` lex as IDENTIFIER.
//!
//! Everything else (identifiers, keywords, QSTRING, integer literals,
//! operators, grouping symbols, `\x08file###line\x08` position markers, and
//! the `//` CPPCOMMENT error) is inherited from the base rules by delegating
//! to [`BaseLexer::next_token`].
//!
//! Integration note: Ghidra switches lexer modes with a `LexerMultiplexer`
//! whose sub-lexers share one ANTLR `CharStream`. The ported Rust
//! [`LexerMultiplexer`] owns its `TokenSource`s outright, so two lexer
//! structs cannot share the single `BaseLexer` character cursor through it.
//! Instead -- mirroring `DisplayParser.g`, where it is the *parser* that
//! calls `lexer.pushMode(DISPLAY)` / `lexer.popMode()` around the display
//! rule -- the parser selects the mode per token pull: base-mode pulls go
//! straight to [`BaseLexer::next_token`], and display-mode pulls (between
//! the constructor `:` and `is`) go through [`DisplayLexer::next_token`],
//! which borrows the same cursor. See
//! `SleighParser::parse_display` in [`super::parser`].
//!
//! [`LexerMultiplexer`]: crate::sleigh::grammar::LexerMultiplexer

use crate::sleigh::grammar::{SleighToken, DEFAULT_CHANNEL};

use super::lexer::{BaseLexer, TokenType};

/// DISPLAY-mode view over a [`BaseLexer`]'s character cursor.
///
/// Construct one (cheaply, per pull) while the parser is inside a
/// constructor display section; tokens produced advance the underlying
/// base lexer's position, so dropping the `DisplayLexer` and resuming
/// base-mode lexing continues from the right spot.
pub struct DisplayLexer<'a> {
    base: &'a mut BaseLexer,
}

impl<'a> DisplayLexer<'a> {
    pub fn new(base: &'a mut BaseLexer) -> Self {
        Self { base }
    }

    /// Produces the next DISPLAY-mode token (including PREPROC-channel
    /// position markers); returns an EOF token at end of input.
    pub fn next_token(&mut self) -> SleighToken {
        let (line, col) = self.base.cursor();
        match self.base.peek() {
            // WS: overridden to the DEFAULT channel -- whitespace is a
            // printpiece in display sections.
            Some(' ' | '\t' | '\r' | '\n') => {
                let mut text = String::new();
                while let Some(w) = self.base.peek() {
                    if matches!(w, ' ' | '\t' | '\r' | '\n') {
                        text.push(w);
                        self.base.bump();
                    } else {
                        break;
                    }
                }
                self.base
                    .make_token(TokenType::Whitespace, DEFAULT_CHANNEL, text, line, col)
            }
            // LINECOMMENT override: a single '#', printed verbatim (it does
            // not swallow the rest of the line as in base mode).
            Some('#') => {
                self.base.bump();
                self.base.make_token(
                    TokenType::LineComment,
                    DEFAULT_CHANNEL,
                    "#".into(),
                    line,
                    col,
                )
            }
            // DISPCHAR: '@' | '?' (both are errors in base mode).
            Some(c @ ('@' | '?')) => {
                self.base.bump();
                self.base.make_token(
                    TokenType::DispChar,
                    DEFAULT_CHANNEL,
                    c.to_string(),
                    line,
                    col,
                )
            }
            // DISPCHAR '$' -- unless it starts '$or'/'$and'/'$xor', which
            // win by longest match and are inherited from the base rules.
            Some('$') => {
                let spec_word = ["$and", "$xor", "$or"].iter().any(|w| {
                    w.chars()
                        .enumerate()
                        .all(|(i, wc)| self.base.peek_at(i) == Some(wc))
                });
                if spec_word {
                    self.base.next_token()
                } else {
                    self.base.bump();
                    self.base.make_token(
                        TokenType::DispChar,
                        DEFAULT_CHANNEL,
                        "$".into(),
                        line,
                        col,
                    )
                }
            }
            // Everything else (EOF, position markers, identifiers/keywords,
            // strings, numbers, operators) is inherited from the base rules;
            // a standalone 'is' identifier is remapped to RES_IS.
            _ => {
                let t = self.base.next_token();
                if t.token_type() == TokenType::Identifier.as_i32() && t.text() == Some("is") {
                    let mut is_tok = SleighToken::with_position(
                        TokenType::ResIs.as_i32(),
                        t.line(),
                        t.char_position_in_line(),
                    );
                    is_tok.set_channel(t.channel());
                    is_tok.set_text("is");
                    if let Some(loc) = t.location() {
                        is_tok.set_location(loc.clone());
                    }
                    return is_tok;
                }
                t
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::PREPROC;

    fn display_tokens(input: &str) -> Vec<(TokenType, String, i32)> {
        let mut base = BaseLexer::new(input);
        let mut out = Vec::new();
        loop {
            let t = DisplayLexer::new(&mut base).next_token();
            let ty = TokenType::from_i32(t.token_type()).unwrap();
            let text = t.text().unwrap_or("").to_string();
            let channel = t.channel();
            let eof = ty == TokenType::Eof;
            out.push((ty, text, channel));
            if eof {
                return out;
            }
        }
    }

    #[test]
    fn whitespace_is_significant_and_default_channel() {
        let toks = display_tokens("a \t b");
        assert_eq!(toks[0], (TokenType::Identifier, "a".into(), 0));
        assert_eq!(toks[1], (TokenType::Whitespace, " \t ".into(), 0));
        assert_eq!(toks[2], (TokenType::Identifier, "b".into(), 0));
    }

    #[test]
    fn hash_is_a_single_char_token_not_a_comment() {
        let toks = display_tokens("#imm8");
        assert_eq!(toks[0], (TokenType::LineComment, "#".into(), 0));
        assert_eq!(toks[1], (TokenType::Identifier, "imm8".into(), 0));
    }

    #[test]
    fn dispchars_lex_without_error() {
        let mut base = BaseLexer::new("@?$");
        let mut toks = Vec::new();
        for _ in 0..3 {
            toks.push(DisplayLexer::new(&mut base).next_token());
        }
        for (t, expected) in toks.iter().zip(["@", "?", "$"]) {
            assert_eq!(t.token_type(), TokenType::DispChar.as_i32());
            assert_eq!(t.text(), Some(expected));
        }
        assert!(base.errors().is_empty());
    }

    #[test]
    fn dollar_words_win_over_dispchar() {
        let toks = display_tokens("$or$and$xor$x");
        assert_eq!(toks[0], (TokenType::SpecOr, "$or".into(), 0));
        assert_eq!(toks[1], (TokenType::SpecAnd, "$and".into(), 0));
        assert_eq!(toks[2], (TokenType::SpecXor, "$xor".into(), 0));
        assert_eq!(toks[3], (TokenType::DispChar, "$".into(), 0));
        assert_eq!(toks[4], (TokenType::Identifier, "x".into(), 0));
    }

    #[test]
    fn is_is_reserved_but_only_as_a_whole_word() {
        let toks = display_tokens("is");
        assert_eq!(toks[0], (TokenType::ResIs, "is".into(), 0));
        // Longest match: identifiers merely containing 'is' are unaffected.
        let toks = display_tokens("island disp");
        assert_eq!(toks[0].0, TokenType::Identifier);
        assert_eq!(toks[0].1, "island");
        assert_eq!(toks[2].0, TokenType::Identifier);
        assert_eq!(toks[2].1, "disp");
    }

    #[test]
    fn base_rules_are_inherited() {
        let toks = display_tokens("\"m\",(0x1f)^...");
        assert_eq!(toks[0], (TokenType::QString, "m".into(), 0));
        assert_eq!(toks[1], (TokenType::Comma, ",".into(), 0));
        assert_eq!(toks[2], (TokenType::LParen, "(".into(), 0));
        assert_eq!(toks[3], (TokenType::HexInt, "0x1f".into(), 0));
        assert_eq!(toks[4], (TokenType::RParen, ")".into(), 0));
        assert_eq!(toks[5], (TokenType::Caret, "^".into(), 0));
        assert_eq!(toks[6], (TokenType::Ellipsis, "...".into(), 0));
    }

    #[test]
    fn keywords_still_lex_as_keyword_tokens() {
        // The display parser treats them as identifiers (key_as_id).
        let toks = display_tokens("token");
        assert_eq!(toks[0], (TokenType::KeyToken, "token".into(), 0));
    }

    #[test]
    fn position_markers_stay_on_preproc_channel() {
        let toks = display_tokens("\u{8}f.slaspec###3\u{8}is");
        assert_eq!(toks[0].0, TokenType::PpPosition);
        assert_eq!(toks[0].2, PREPROC);
        assert_eq!(toks[1].0, TokenType::ResIs);
    }

    #[test]
    fn resumes_base_mode_at_shared_cursor() {
        // Lex 'MOV A' in display mode, then continue in base mode: the
        // shared cursor means base mode picks up exactly after the display
        // tokens (whitespace hidden again).
        let mut base = BaseLexer::new("MOV A is op");
        let mut display_seen = Vec::new();
        loop {
            let t = DisplayLexer::new(&mut base).next_token();
            if t.token_type() == TokenType::ResIs.as_i32() {
                break;
            }
            display_seen.push(t.text().unwrap_or("").to_string());
        }
        assert_eq!(display_seen, vec!["MOV", " ", "A", " "]);
        // Back to base mode: whitespace hidden, next default token is 'op'.
        let rest = base.tokenize_default_channel();
        assert_eq!(rest[0].text(), Some("op"));
        assert_eq!(rest[1].token_type(), TokenType::Eof.as_i32());
    }
}
