//! Hand-written tokenizer for the SLEIGH SEMANTIC lexer mode
//! (`SemanticLexer.g`), used for p-code semantic bodies between `{` and the
//! matching `}` (constructor bodies and `macro` bodies).
//!
//! `SemanticLexer.g` imports `BaseLexer.g` and adds:
//!
//! - the letter-prefixed operators, which only exist in this mode so that,
//!   e.g., `f=0` still lexes as `IDENTIFIER(f) ASSIGN DEF_INT(0)` in base
//!   mode: float comparisons `f==` `f!=` `f<` `f>` `f<=` `f>=`, float
//!   arithmetic `f+` `f-` `f*` `f/`, signed comparisons `s<` `s>` `s<=`
//!   `s>=`, and signed operations `s>>` `s/` `s%`;
//! - the reserved word `if` (`RES_IF`), so `if(a == b) ...` is not mistaken
//!   for a call to a function named `if`.
//!
//! Everything else (identifiers, keywords, QSTRING, integer literals, the
//! symbol operators, grouping, whitespace/comment channels, and
//! `\x08file###line\x08` position markers) is inherited from the base rules
//! by delegating to [`BaseLexer::next_token`].
//!
//! ANTLR longest-match semantics make the letter operators unambiguous
//! without backtracking: an `f`/`s` operator only fires when the very next
//! character(s) complete the operator, and operator characters are never
//! identifier characters, so `f<` can never be a prefix of a longer
//! identifier match. Conversely `foo<3` lexes `IDENTIFIER(foo) LESS ...`
//! because `f` is followed by `o`.
//!
//! # Number-context variants (`SemanticLexerHex.g` / `SemanticLexerIdHex.g`)
//!
//! Ghidra also generates two variants of the semantic lexer whose only
//! difference is how bare numbers and identifiers lex; they are used when
//! parsing standalone p-code fragments (`SleighUtils`), never for `.slaspec`
//! compilation. Both disable `BIN_INT` entirely, and because their
//! overriding `IDENTIFIER` rule is tried *before* the imported rules (ANTLR
//! composite-grammar delegator priority), keywords and `if` lex as plain
//! `IDENTIFIER`s on a length tie in these modes:
//!
//! - [`NumberMode::Hex`]: `DEF_INT : HEXDIGIT+` and
//!   `IDENTIFIER : ALPHAUP (ALPHAUP | DIGIT)*`, with `DEF_INT` winning ties
//!   (so `ff` is a number, `ffg` an identifier);
//! - [`NumberMode::IdHex`]: `DEF_INT : DIGIT HEXDIGIT*` (numbers must start
//!   with a decimal digit; `ff` stays an identifier).
//!
//! In these modes a `DEF_INT`'s digits are hexadecimal; the consumer decides
//! the radix (the token carries only its text).
//!
//! Integration note: as with the DISPLAY mode, mode selection is done by the
//! parser per token pull (see `display_lexer.rs`); the parser constructs a
//! `SemanticLexer` over the shared [`BaseLexer`] cursor for each pull inside
//! a `{ ... }` semantic body -- the Rust equivalent of `SemanticParser.g`'s
//! `lexer.pushMode(SEMANTIC) ... lexer.popMode()` actions.

use crate::sleigh::grammar::{SleighToken, DEFAULT_CHANNEL};

use super::lexer::{BaseLexer, TokenType};

/// Number-lexing context for the semantic mode, selecting between
/// `SemanticLexer.g` (Normal) and its `SemanticLexerHex.g` /
/// `SemanticLexerIdHex.g` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NumberMode {
    /// `SemanticLexer.g`: base-mode number rules (`0x…`, `0b…`, `0n…`,
    /// decimal `DEF_INT`), keywords and `if` reserved.
    #[default]
    Normal,
    /// `SemanticLexerHex.g`: `DEF_INT` is any run of hex digits (no prefix);
    /// `BIN_INT` disabled; keywords lex as identifiers.
    Hex,
    /// `SemanticLexerIdHex.g`: `DEF_INT` is a decimal digit followed by hex
    /// digits; `BIN_INT` disabled; keywords lex as identifiers.
    IdHex,
}

/// SEMANTIC-mode view over a [`BaseLexer`]'s character cursor.
///
/// Construct one (cheaply, per pull) while the parser is inside a semantic
/// body; tokens produced advance the underlying base lexer's position, so
/// dropping the `SemanticLexer` and resuming base-mode lexing continues from
/// the right spot.
pub struct SemanticLexer<'a> {
    base: &'a mut BaseLexer,
    mode: NumberMode,
}

/// The letter-prefixed operators, longest first per prefix so maximal munch
/// falls out of a linear scan (`s>>`/`s>=` before `s>`, `f<=` before `f<`).
const FS_OPERATORS: &[(&str, TokenType)] = &[
    ("f==", TokenType::FEqual),
    ("f!=", TokenType::FNotEqual),
    ("f<=", TokenType::FLessEqual),
    ("f>=", TokenType::FGreatEqual),
    ("f<", TokenType::FLess),
    ("f>", TokenType::FGreat),
    ("f+", TokenType::FPlus),
    ("f-", TokenType::FMinus),
    ("f*", TokenType::FMult),
    ("f/", TokenType::FDiv),
    ("s>>", TokenType::SRight),
    ("s<=", TokenType::SLessEqual),
    ("s>=", TokenType::SGreatEqual),
    ("s<", TokenType::SLess),
    ("s>", TokenType::SGreat),
    ("s/", TokenType::SDiv),
    ("s%", TokenType::SRem),
];

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '.'
}

fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

impl<'a> SemanticLexer<'a> {
    /// SEMANTIC mode as used for `.slaspec` compilation (`SemanticLexer.g`).
    pub fn new(base: &'a mut BaseLexer) -> Self {
        Self {
            base,
            mode: NumberMode::Normal,
        }
    }

    /// SEMANTIC mode with an explicit number-lexing context (the Hex/IdHex
    /// fragment-parsing variants).
    pub fn with_mode(base: &'a mut BaseLexer, mode: NumberMode) -> Self {
        Self { base, mode }
    }

    /// Produces the next SEMANTIC-mode token (including HIDDEN/COMMENT/
    /// PREPROC-channel tokens); returns an EOF token at end of input.
    pub fn next_token(&mut self) -> SleighToken {
        let (line, col) = self.base.cursor();
        let c = match self.base.peek() {
            None => return self.base.next_token(), // EOF via the base rules
            Some(c) => c,
        };

        // Letter-prefixed operators. These win by ANTLR longest match: when
        // the operator matches, the competing IDENTIFIER/DEF_INT match is
        // just the single 'f'/'s' character (operator characters are not
        // identifier or digit characters), so the operator is longer.
        if c == 'f' || c == 's' {
            for (text, ty) in FS_OPERATORS {
                if text
                    .chars()
                    .enumerate()
                    .all(|(i, wc)| self.base.peek_at(i) == Some(wc))
                {
                    for _ in 0..text.len() {
                        self.base.bump();
                    }
                    return self
                        .base
                        .make_token(*ty, DEFAULT_CHANNEL, (*text).into(), line, col);
                }
            }
        }

        match self.mode {
            NumberMode::Normal => {
                // Everything else is inherited from the base rules; a
                // standalone 'if' identifier is remapped to RES_IF
                // (SemanticLexer.g's reserved word).
                let t = self.base.next_token();
                if t.token_type() == TokenType::Identifier.as_i32() && t.text() == Some("if") {
                    return remap(&t, TokenType::ResIf);
                }
                t
            }
            NumberMode::Hex | NumberMode::IdHex => {
                if let Some(t) = self.next_number_mode_token(c, line, col) {
                    return t;
                }
                self.base.next_token()
            }
        }
    }

    /// Overriding DEF_INT/IDENTIFIER rules of the Hex/IdHex variants.
    /// Returns `None` when an inherited rule wins (longest match) or when
    /// the character does not start a number/identifier at all.
    fn next_number_mode_token(&mut self, c: char, line: i32, col: i32) -> Option<SleighToken> {
        if !is_ident_part(c) {
            return None;
        }

        // Candidate lengths, per rule.
        let run = |pred: fn(char) -> bool, from: usize| -> usize {
            let mut n = from;
            while self.base.peek_at(n).map(pred) == Some(true) {
                n += 1;
            }
            n - from
        };

        // Overriding DEF_INT.
        let def_len = match self.mode {
            NumberMode::Hex => run(|d| d.is_ascii_hexdigit(), 0),
            NumberMode::IdHex if c.is_ascii_digit() => 1 + run(|d| d.is_ascii_hexdigit(), 1),
            _ => 0,
        };
        // Overriding IDENTIFIER (same character set as the base rule).
        let ident_len = if is_ident_start(c) { run(is_ident_part, 0) } else { 0 };
        // Inherited HEX_INT ('0x' HEXDIGIT+) and DEC_INT ('0n' DIGIT+) can
        // still win by longest match (BIN_INT is disabled in these modes).
        let inherited_len = if c == '0' {
            match self.base.peek_at(1) {
                Some('x') => {
                    let n = run(|d| d.is_ascii_hexdigit(), 2);
                    if n > 0 { 2 + n } else { 0 }
                }
                Some('n') => {
                    let n = run(|d| d.is_ascii_digit(), 2);
                    if n > 0 { 2 + n } else { 0 }
                }
                _ => 0,
            }
        } else {
            0
        };

        // Longest match; ties go to the overriding rules in declaration
        // order (SemanticLexerHex.g declares DEF_INT before IDENTIFIER, and
        // both before every inherited rule -- which is why keywords and
        // 'if' lex as IDENTIFIER in these modes).
        let best = def_len.max(ident_len).max(inherited_len);
        if best == 0 {
            return None;
        }
        if inherited_len == best && def_len < best && ident_len < best {
            // '0x…'/'0n…' still lex through the base rules.
            return Some(self.base.next_token());
        }
        let ty = if def_len == best {
            TokenType::DefInt
        } else {
            TokenType::Identifier
        };
        let mut text = String::with_capacity(best);
        for _ in 0..best {
            text.push(self.base.bump().expect("length was just measured"));
        }
        Some(self.base.make_token(ty, DEFAULT_CHANNEL, text, line, col))
    }
}

/// Clones `t` with a different token type (used for reserved-word remaps).
fn remap(t: &SleighToken, ty: TokenType) -> SleighToken {
    let mut out = SleighToken::with_position(ty.as_i32(), t.line(), t.char_position_in_line());
    out.set_channel(t.channel());
    if let Some(text) = t.text() {
        out.set_text(text.to_string());
    }
    if let Some(loc) = t.location() {
        out.set_location(loc.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::frontend::lexer::HIDDEN_CHANNEL;

    fn semantic_tokens(input: &str, mode: NumberMode) -> Vec<(TokenType, String)> {
        let mut base = BaseLexer::new(input);
        let mut out = Vec::new();
        loop {
            let t = SemanticLexer::with_mode(&mut base, mode).next_token();
            let ty = TokenType::from_i32(t.token_type()).unwrap();
            let eof = ty == TokenType::Eof;
            if t.channel() == 0 || eof {
                out.push((ty, t.text().unwrap_or("").to_string()));
            }
            if eof {
                assert!(base.errors().is_empty(), "lexing errors: {:?}", base.errors());
                return out;
            }
        }
    }

    fn types(input: &str) -> Vec<TokenType> {
        semantic_tokens(input, NumberMode::Normal)
            .into_iter()
            .map(|(t, _)| t)
            .collect()
    }

    #[test]
    fn float_operators() {
        use TokenType::*;
        assert_eq!(
            types("f== f!= f< f> f<= f>= f+ f- f* f/"),
            vec![
                FEqual, FNotEqual, FLess, FGreat, FLessEqual, FGreatEqual, FPlus, FMinus, FMult,
                FDiv, Eof
            ]
        );
    }

    #[test]
    fn signed_operators() {
        use TokenType::*;
        assert_eq!(
            types("s< s> s<= s>= s>> s/ s%"),
            vec![SLess, SGreat, SLessEqual, SGreatEqual, SRight, SDiv, SRem, Eof]
        );
    }

    #[test]
    fn srightt_wins_over_sgreat_by_maximal_munch() {
        use TokenType::*;
        // 's>>' vs 's>' '>' -- longest match picks SRIGHT.
        assert_eq!(types("a s>> b"), vec![Identifier, SRight, Identifier, Eof]);
    }

    #[test]
    fn f_assign_zero_is_identifier_assign_number() {
        use TokenType::*;
        // The motivating case from SemanticLexer.g's comment: 'f=0'.
        assert_eq!(
            semantic_tokens("f=0", NumberMode::Normal),
            vec![
                (Identifier, "f".into()),
                (Assign, "=".into()),
                (DefInt, "0".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn identifiers_starting_with_f_or_s_are_untouched() {
        use TokenType::*;
        assert_eq!(
            semantic_tokens("flag < sp", NumberMode::Normal),
            vec![
                (Identifier, "flag".into()),
                (Less, "<".into()),
                (Identifier, "sp".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn lone_f_before_less_lexes_as_float_op() {
        use TokenType::*;
        // Faithful ANTLR longest match: even if 'f' were meant as a
        // variable, 'f<' lexes as FLESS in semantic mode.
        assert_eq!(types("f<b"), vec![FLess, Identifier, Eof]);
    }

    #[test]
    fn if_is_reserved_as_a_whole_word() {
        use TokenType::*;
        assert_eq!(types("if"), vec![ResIf, Eof]);
        // Longest match: identifiers merely containing 'if' are unaffected.
        assert_eq!(types("iff ifx"), vec![Identifier, Identifier, Eof]);
    }

    #[test]
    fn base_rules_are_inherited() {
        use TokenType::*;
        assert_eq!(
            types("local tmp:2 = *:2 SP; goto <done>;"),
            vec![
                KeyLocal, Identifier, Colon, DefInt, Assign, Asterisk, Colon, DefInt, Identifier,
                Semi, KeyGoto, Less, Identifier, Great, Semi, Eof
            ]
        );
    }

    #[test]
    fn whitespace_stays_hidden_and_comments_off_channel() {
        let mut base = BaseLexer::new("a # note\nb");
        let first = SemanticLexer::new(&mut base).next_token();
        assert_eq!(first.text(), Some("a"));
        let ws = SemanticLexer::new(&mut base).next_token();
        assert_eq!(ws.channel(), HIDDEN_CHANNEL);
    }

    #[test]
    fn resumes_base_mode_at_shared_cursor() {
        // Semantic tokens advance the shared cursor; base mode picks up
        // exactly after them.
        let mut base = BaseLexer::new("A f+ B } :next");
        let mut seen = Vec::new();
        loop {
            let t = SemanticLexer::new(&mut base).next_token();
            if t.token_type() == TokenType::RBrace.as_i32() {
                break;
            }
            if t.channel() == 0 {
                seen.push(t.text().unwrap_or("").to_string());
            }
        }
        assert_eq!(seen, vec!["A", "f+", "B"]);
        let rest = base.tokenize_default_channel();
        assert_eq!(rest[0].token_type(), TokenType::Colon.as_i32());
        assert_eq!(rest[1].text(), Some("next"));
    }

    // ----- Hex / IdHex number-context variants -------------------------------

    #[test]
    fn hex_mode_lexes_bare_hex_digits_as_def_int() {
        use TokenType::*;
        assert_eq!(
            semantic_tokens("ff 12ab", NumberMode::Hex),
            vec![
                (DefInt, "ff".into()),
                (DefInt, "12ab".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn hex_mode_longer_identifier_wins() {
        use TokenType::*;
        // 'ffg' extends past the hex digits, so IDENTIFIER is longer.
        assert_eq!(
            semantic_tokens("ffg", NumberMode::Hex),
            vec![(Identifier, "ffg".into()), (Eof, "<EOF>".into())]
        );
    }

    #[test]
    fn hex_mode_keywords_and_if_are_identifiers() {
        use TokenType::*;
        // The overriding IDENTIFIER rule is tried before the imported
        // keyword/RES_IF rules, so length ties go to IDENTIFIER.
        assert_eq!(
            types_of("goto if export", NumberMode::Hex),
            vec![Identifier, Identifier, Identifier, Eof]
        );
    }

    #[test]
    fn hex_mode_prefixed_literals_still_win_by_length() {
        use TokenType::*;
        assert_eq!(
            semantic_tokens("0x1f 0n42", NumberMode::Hex),
            vec![
                (HexInt, "0x1f".into()),
                (DecInt, "0n42".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn hex_mode_bin_int_is_disabled() {
        use TokenType::*;
        // '0b101' is all hex digits, so it is one DEF_INT (BIN_INT never
        // matches in this mode).
        assert_eq!(
            semantic_tokens("0b101", NumberMode::Hex),
            vec![(DefInt, "0b101".into()), (Eof, "<EOF>".into())]
        );
    }

    #[test]
    fn hex_mode_fs_operators_still_win() {
        use TokenType::*;
        // 'f' is a hex digit, but 'f+' is longer than the 1-char DEF_INT.
        assert_eq!(types_of("f+ s<", NumberMode::Hex), vec![FPlus, SLess, Eof]);
    }

    #[test]
    fn idhex_mode_numbers_need_a_leading_digit() {
        use TokenType::*;
        assert_eq!(
            semantic_tokens("ff 0ff 1a2b", NumberMode::IdHex),
            vec![
                (Identifier, "ff".into()),
                (DefInt, "0ff".into()),
                (DefInt, "1a2b".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn idhex_mode_prefixed_literals_and_keywords() {
        use TokenType::*;
        assert_eq!(
            types_of("0x1f goto", NumberMode::IdHex),
            vec![HexInt, Identifier, Eof]
        );
    }

    fn types_of(input: &str, mode: NumberMode) -> Vec<TokenType> {
        semantic_tokens(input, mode).into_iter().map(|(t, _)| t).collect()
    }
}
