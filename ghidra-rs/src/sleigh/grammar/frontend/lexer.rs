//! Hand-written tokenizer for the SLEIGH base lexer mode.
//!
//! Covers the `BaseLexer.g` token set: keywords, grouping symbols, operators,
//! identifiers, integer literals (hex/dec/bin/default), quoted strings, line
//! comments, whitespace, and the preprocessor-generated
//! `\x08file###line\x08` position markers (`PP_POSITION`).
//!
//! ANTLR-3 lexing semantics that are reproduced here:
//! - longest match wins; ties go to the earlier rule in the grammar, so a
//!   bare `_` is `UNDERSCORE` and a bare `...` is `ELLIPSIS`, while `_x` and
//!   `.foo` (and even `a...b` -- `.` is an identifier character) lex as
//!   `IDENTIFIER`;
//! - whitespace goes to the HIDDEN channel, line comments to the COMMENT
//!   channel, and position markers to the PREPROC channel;
//! - `//` (`CPPCOMMENT`) and unrecognized characters (`UNKNOWN`) are lexing
//!   errors.
//!
//! // TODO(sleigh-frontend): DisplayLexer.g and SemanticLexer.g sub-lexer
//! // MODES are not yet ported. Constructor display sections and semantic
//! // bodies are currently lexed with base-mode rules; the mode switch will
//! // hang off `LexerMultiplexer` (already ported) in a later increment.
//!
//! // TODO(sleigh-frontend): token type numbering is local to this port; it
//! // does not (yet) mirror the numbers in the generated SleighLexer.tokens
//! // vocabulary. Nothing downstream in the Rust port depends on the exact
//! // numbers.

use crate::sleigh::grammar::{Location, ParsingEnvironment, SleighToken, Token, TokenSource};
use crate::sleigh::grammar::{COMMENT, PREPROC};

/// ANTLR's `Token.HIDDEN_CHANNEL`.
pub const HIDDEN_CHANNEL: i32 = 99;

/// Base-mode token types (see `BaseLexer.g`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum TokenType {
    Eof = -1,

    PpPosition = 4,

    // Reserved words and keywords
    ResWith = 10,
    KeyAlignment = 11,
    KeyAttach = 12,
    KeyBig = 13,
    KeyBitrange = 14,
    KeyBuild = 15,
    KeyCall = 16,
    KeyContext = 17,
    KeyCrossbuild = 18,
    KeyDec = 19,
    KeyDefault = 20,
    KeyDefine = 21,
    KeyEndian = 22,
    KeyExport = 23,
    KeyGoto = 24,
    KeyHex = 25,
    KeyLittle = 26,
    KeyLocal = 27,
    KeyMacro = 28,
    KeyNames = 29,
    KeyNoflow = 30,
    KeyOffset = 31,
    KeyPcodeop = 32,
    KeyReturn = 33,
    KeySigned = 34,
    KeySize = 35,
    KeySpace = 36,
    KeyToken = 37,
    KeyType = 38,
    KeyUnimpl = 39,
    KeyValues = 40,
    KeyVariables = 41,
    KeyWordsize = 42,

    // Grouping, block, and sectioning symbols
    LBrace = 50,
    RBrace = 51,
    LBracket = 52,
    RBracket = 53,
    LParen = 54,
    RParen = 55,

    // Miscellaneous
    Ellipsis = 60,
    Underscore = 61,
    Colon = 62,
    Comma = 63,
    Exclaim = 64,
    Tilde = 65,
    Semi = 66,

    // Operators
    Assign = 70,
    Equal = 71,
    NotEqual = 72,
    Less = 73,
    Great = 74,
    LessEqual = 75,
    GreatEqual = 76,
    BoolOr = 77,
    BoolXor = 78,
    BoolAnd = 79,
    Pipe = 80,
    Caret = 81,
    Ampersand = 82,
    Left = 83,
    Right = 84,
    Plus = 85,
    Minus = 86,
    Asterisk = 87,
    Slash = 88,
    Percent = 89,
    SpecOr = 90,
    SpecAnd = 91,
    SpecXor = 92,

    // IDs and literals
    Identifier = 100,
    QString = 101,
    BinInt = 102,
    DecInt = 103,
    HexInt = 104,
    DefInt = 105,

    // Ignored things / errors
    LineComment = 110,
    CppComment = 111,
    Whitespace = 112,
    Unknown = 113,
}

impl TokenType {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Reverse of [`TokenType::as_i32`]; used when reading a
    /// [`SleighToken`]'s `token_type` back into the enum.
    pub fn from_i32(v: i32) -> Option<TokenType> {
        use TokenType::*;
        const ALL: &[TokenType] = &[
            Eof, PpPosition, ResWith, KeyAlignment, KeyAttach, KeyBig, KeyBitrange, KeyBuild,
            KeyCall, KeyContext, KeyCrossbuild, KeyDec, KeyDefault, KeyDefine, KeyEndian,
            KeyExport, KeyGoto, KeyHex, KeyLittle, KeyLocal, KeyMacro, KeyNames, KeyNoflow,
            KeyOffset, KeyPcodeop, KeyReturn, KeySigned, KeySize, KeySpace, KeyToken, KeyType,
            KeyUnimpl, KeyValues, KeyVariables, KeyWordsize, LBrace, RBrace, LBracket, RBracket,
            LParen, RParen, Ellipsis, Underscore, Colon, Comma, Exclaim, Tilde, Semi, Assign,
            Equal, NotEqual, Less, Great, LessEqual, GreatEqual, BoolOr, BoolXor, BoolAnd, Pipe,
            Caret, Ampersand, Left, Right, Plus, Minus, Asterisk, Slash, Percent, SpecOr, SpecAnd,
            SpecXor, Identifier, QString, BinInt, DecInt, HexInt, DefInt, LineComment, CppComment,
            Whitespace, Unknown,
        ];
        ALL.iter().copied().find(|t| t.as_i32() == v)
    }

    /// Keyword lookup, mirroring the `KEY_*` / `RES_WITH` literal rules.
    pub fn keyword(text: &str) -> Option<TokenType> {
        use TokenType::*;
        Some(match text {
            "with" => ResWith,
            "alignment" => KeyAlignment,
            "attach" => KeyAttach,
            "big" => KeyBig,
            "bitrange" => KeyBitrange,
            "build" => KeyBuild,
            "call" => KeyCall,
            "context" => KeyContext,
            "crossbuild" => KeyCrossbuild,
            "dec" => KeyDec,
            "default" => KeyDefault,
            "define" => KeyDefine,
            "endian" => KeyEndian,
            "export" => KeyExport,
            "goto" => KeyGoto,
            "hex" => KeyHex,
            "little" => KeyLittle,
            "local" => KeyLocal,
            "macro" => KeyMacro,
            "names" => KeyNames,
            "noflow" => KeyNoflow,
            "offset" => KeyOffset,
            "pcodeop" => KeyPcodeop,
            "return" => KeyReturn,
            "signed" => KeySigned,
            "size" => KeySize,
            "space" => KeySpace,
            "token" => KeyToken,
            "type" => KeyType,
            "unimpl" => KeyUnimpl,
            "values" => KeyValues,
            "variables" => KeyVariables,
            "wordsize" => KeyWordsize,
            _ => return None,
        })
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '.'
}

fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

/// Base-mode SLEIGH lexer over a preprocessed character stream.
///
/// Produces [`SleighToken`]s carrying line/column info; when a
/// [`ParsingEnvironment`] is attached, `PP_POSITION` markers register
/// original-source [`Location`]s with the environment's `Locator`, and each
/// token is stamped with the location registered for its line (mirroring
/// `AbstractSleighLexer.emit()`).
pub struct BaseLexer {
    chars: Vec<char>,
    pos: usize,
    line: i32,
    col: i32,
    env: Option<ParsingEnvironment>,
    errors: Vec<String>,
}

impl BaseLexer {
    pub fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            line: 1,
            col: 0,
            env: None,
            errors: Vec::new(),
        }
    }

    pub fn with_env(input: &str, env: ParsingEnvironment) -> Self {
        let mut lexer = Self::new(input);
        lexer.env = Some(env);
        lexer
    }

    /// Errors recorded so far (CPPCOMMENT, UNKNOWN, unterminated strings).
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 0;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn error(&mut self, msg: String) {
        if let Some(env) = &self.env {
            env.lexing_error();
        }
        self.errors.push(msg);
    }

    fn make_token(
        &self,
        ty: TokenType,
        channel: i32,
        text: String,
        line: i32,
        col: i32,
    ) -> SleighToken {
        let mut t = SleighToken::with_position(ty.as_i32(), line, col);
        t.set_channel(channel);
        t.set_text(text);
        if let Some(env) = &self.env {
            if let Some(location) = env.get_locator().borrow().get_location(line) {
                t.set_location(location);
            }
        }
        t
    }

    /// Produces the next token (including HIDDEN/COMMENT/PREPROC-channel
    /// tokens); returns an EOF token at end of input.
    pub fn next_token(&mut self) -> SleighToken {
        let start_line = self.line;
        let start_col = self.col;

        let c = match self.peek() {
            None => {
                return self.make_token(TokenType::Eof, 0, "<EOF>".into(), start_line, start_col)
            }
            Some(c) => c,
        };

        // PP_POSITION: '\b' ~('\n'|'\b')* '\b'
        if c == '\u{8}' {
            self.bump();
            let mut text = String::new();
            loop {
                match self.peek() {
                    None | Some('\n') => {
                        self.error(format!(
                            "{start_line}:{start_col}: unterminated preprocessor position marker"
                        ));
                        break;
                    }
                    Some('\u{8}') => {
                        self.bump();
                        break;
                    }
                    Some(other) => {
                        text.push(other);
                        self.bump();
                    }
                }
            }
            // Mirrors AbstractSleighLexer.preprocess(): register the original
            // source location for the current expanded line.
            let parts: Vec<&str> = text.split("###").collect();
            if parts.len() == 2 {
                if let Ok(lineno) = parts[1].parse::<i32>() {
                    if let Some(env) = &self.env {
                        env.get_locator()
                            .borrow_mut()
                            .register_location(self.line, Location::new(parts[0], lineno));
                    }
                }
            }
            return self.make_token(TokenType::PpPosition, PREPROC, text, start_line, start_col);
        }

        // WS
        if matches!(c, ' ' | '\t' | '\r' | '\n') {
            let mut text = String::new();
            while let Some(w) = self.peek() {
                if matches!(w, ' ' | '\t' | '\r' | '\n') {
                    text.push(w);
                    self.bump();
                } else {
                    break;
                }
            }
            return self.make_token(
                TokenType::Whitespace,
                HIDDEN_CHANNEL,
                text,
                start_line,
                start_col,
            );
        }

        // LINECOMMENT: '#' ~('\n'|'\r')* EOL
        if c == '#' {
            let mut text = String::new();
            while let Some(ch) = self.peek() {
                if ch == '\n' || ch == '\r' {
                    break;
                }
                text.push(ch);
                self.bump();
            }
            // The grammar includes the EOL in the comment token.
            if self.peek() == Some('\r') {
                text.push('\r');
                self.bump();
            }
            if self.peek() == Some('\n') {
                text.push('\n');
                self.bump();
            }
            return self.make_token(TokenType::LineComment, COMMENT, text, start_line, start_col);
        }

        // QSTRING (token text is the string body, quotes stripped, escapes verbatim)
        if c == '"' {
            self.bump();
            let mut text = String::new();
            loop {
                match self.peek() {
                    None => {
                        self.error(format!("{start_line}:{start_col}: unterminated string"));
                        break;
                    }
                    Some('"') => {
                        self.bump();
                        break;
                    }
                    Some('\\') => {
                        text.push('\\');
                        self.bump();
                        if let Some(esc) = self.peek() {
                            text.push(esc);
                            self.bump();
                        }
                    }
                    Some(other) => {
                        text.push(other);
                        self.bump();
                    }
                }
            }
            return self.make_token(TokenType::QString, 0, text, start_line, start_col);
        }

        // CPPCOMMENT: '//' is an error in SLEIGH
        if c == '/' && self.peek_at(1) == Some('/') {
            self.bump();
            self.bump();
            self.error(format!(
                "{start_line}:{start_col}: '//' is not a valid comment in SLEIGH; use '#'"
            ));
            return self.make_token(TokenType::CppComment, 0, "//".into(), start_line, start_col);
        }

        // Integer literals: 0b..., 0n..., 0x..., or plain decimal
        if c.is_ascii_digit() {
            if c == '0' {
                let radix = self.peek_at(1);
                let (ty, is_digit): (TokenType, fn(char) -> bool) = match radix {
                    Some('b') => (TokenType::BinInt, |d| d == '0' || d == '1'),
                    Some('n') => (TokenType::DecInt, |d| d.is_ascii_digit()),
                    Some('x') => (TokenType::HexInt, |d| d.is_ascii_hexdigit()),
                    _ => (TokenType::DefInt, |d| d.is_ascii_digit()),
                };
                if ty != TokenType::DefInt {
                    // Need at least one digit after the prefix; otherwise fall
                    // back to lexing the '0' as DEF_INT (the 'b'/'n'/'x' will
                    // then lex as an identifier), matching ANTLR fallback.
                    if self.peek_at(2).map(is_digit) == Some(true) {
                        let mut text = String::new();
                        text.push(self.bump().unwrap()); // 0
                        text.push(self.bump().unwrap()); // b/n/x
                        while let Some(d) = self.peek() {
                            if is_digit(d) {
                                text.push(d);
                                self.bump();
                            } else {
                                break;
                            }
                        }
                        return self.make_token(ty, 0, text, start_line, start_col);
                    }
                }
            }
            let mut text = String::new();
            while let Some(d) = self.peek() {
                if d.is_ascii_digit() {
                    text.push(d);
                    self.bump();
                } else {
                    break;
                }
            }
            return self.make_token(TokenType::DefInt, 0, text, start_line, start_col);
        }

        // Identifiers, keywords, UNDERSCORE, ELLIPSIS
        if is_ident_start(c) {
            let mut text = String::new();
            while let Some(ch) = self.peek() {
                if is_ident_part(ch) {
                    text.push(ch);
                    self.bump();
                } else {
                    break;
                }
            }
            let ty = if text == "_" {
                TokenType::Underscore
            } else if text == "..." {
                // Longest-match tie between ELLIPSIS and IDENTIFIER goes to
                // the earlier rule (ELLIPSIS).
                TokenType::Ellipsis
            } else if let Some(kw) = TokenType::keyword(&text) {
                kw
            } else {
                TokenType::Identifier
            };
            return self.make_token(ty, 0, text, start_line, start_col);
        }

        // '$or' | '$and' | '$xor'
        if c == '$' {
            for (word, ty) in [
                ("$and", TokenType::SpecAnd),
                ("$xor", TokenType::SpecXor),
                ("$or", TokenType::SpecOr),
            ] {
                let matches = word
                    .chars()
                    .enumerate()
                    .all(|(i, wc)| self.peek_at(i) == Some(wc));
                if matches {
                    for _ in 0..word.len() {
                        self.bump();
                    }
                    return self.make_token(ty, 0, word.into(), start_line, start_col);
                }
            }
            self.bump();
            self.error(format!("{start_line}:{start_col}: unexpected character '$'"));
            return self.make_token(TokenType::Unknown, 0, "$".into(), start_line, start_col);
        }

        // Operators and punctuation (maximal munch)
        let two: Option<(TokenType, &str)> = match (c, self.peek_at(1)) {
            ('=', Some('=')) => Some((TokenType::Equal, "==")),
            ('!', Some('=')) => Some((TokenType::NotEqual, "!=")),
            ('<', Some('=')) => Some((TokenType::LessEqual, "<=")),
            ('>', Some('=')) => Some((TokenType::GreatEqual, ">=")),
            ('<', Some('<')) => Some((TokenType::Left, "<<")),
            ('>', Some('>')) => Some((TokenType::Right, ">>")),
            ('|', Some('|')) => Some((TokenType::BoolOr, "||")),
            ('&', Some('&')) => Some((TokenType::BoolAnd, "&&")),
            ('^', Some('^')) => Some((TokenType::BoolXor, "^^")),
            _ => None,
        };
        if let Some((ty, text)) = two {
            self.bump();
            self.bump();
            return self.make_token(ty, 0, text.into(), start_line, start_col);
        }

        let one: Option<TokenType> = match c {
            '{' => Some(TokenType::LBrace),
            '}' => Some(TokenType::RBrace),
            '[' => Some(TokenType::LBracket),
            ']' => Some(TokenType::RBracket),
            '(' => Some(TokenType::LParen),
            ')' => Some(TokenType::RParen),
            ':' => Some(TokenType::Colon),
            ',' => Some(TokenType::Comma),
            '!' => Some(TokenType::Exclaim),
            '~' => Some(TokenType::Tilde),
            ';' => Some(TokenType::Semi),
            '=' => Some(TokenType::Assign),
            '<' => Some(TokenType::Less),
            '>' => Some(TokenType::Great),
            '|' => Some(TokenType::Pipe),
            '^' => Some(TokenType::Caret),
            '&' => Some(TokenType::Ampersand),
            '+' => Some(TokenType::Plus),
            '-' => Some(TokenType::Minus),
            '*' => Some(TokenType::Asterisk),
            '/' => Some(TokenType::Slash),
            '%' => Some(TokenType::Percent),
            _ => None,
        };
        if let Some(ty) = one {
            self.bump();
            return self.make_token(ty, 0, c.to_string(), start_line, start_col);
        }

        // UNKNOWN
        self.bump();
        self.error(format!("{start_line}:{start_col}: unexpected character '{c}'"));
        self.make_token(TokenType::Unknown, 0, c.to_string(), start_line, start_col)
    }

    /// Tokenizes the whole input, returning every token (all channels)
    /// followed by the terminating EOF token.
    pub fn tokenize(&mut self) -> Vec<SleighToken> {
        let mut out = Vec::new();
        loop {
            let t = self.next_token();
            let eof = t.token_type() == TokenType::Eof.as_i32();
            out.push(t);
            if eof {
                return out;
            }
        }
    }

    /// Tokenizes and keeps only default-channel tokens (drops whitespace,
    /// comments, and preprocessor position markers) plus the final EOF.
    pub fn tokenize_default_channel(&mut self) -> Vec<SleighToken> {
        self.tokenize()
            .into_iter()
            .filter(|t| {
                t.channel() == 0 || t.token_type() == TokenType::Eof.as_i32()
            })
            .collect()
    }
}

/// Lets the base lexer plug into the already-ported [`LexerMultiplexer`],
/// which will later host the display/semantic sub-lexer modes.
///
/// [`LexerMultiplexer`]: crate::sleigh::grammar::LexerMultiplexer
impl TokenSource for BaseLexer {
    fn next_token(&mut self) -> Box<dyn Token> {
        Box::new(BaseLexer::next_token(self))
    }

    fn source_name(&self) -> String {
        "SleighBaseLexer".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::LineArrayListWriter;

    fn types_and_texts(input: &str) -> Vec<(TokenType, String)> {
        BaseLexer::new(input)
            .tokenize_default_channel()
            .into_iter()
            .map(|t| {
                (
                    TokenType::from_i32(t.token_type()).unwrap(),
                    t.text().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn types(input: &str) -> Vec<TokenType> {
        types_and_texts(input).into_iter().map(|(t, _)| t).collect()
    }

    #[test]
    fn keywords_and_identifiers() {
        use TokenType::*;
        assert_eq!(
            types("define endian little definex"),
            vec![KeyDefine, KeyEndian, KeyLittle, Identifier, Eof]
        );
    }

    #[test]
    fn with_is_reserved() {
        assert_eq!(types("with"), vec![TokenType::ResWith, TokenType::Eof]);
    }

    #[test]
    fn simple_define_line() {
        use TokenType::*;
        assert_eq!(
            types("define endian=little;"),
            vec![KeyDefine, KeyEndian, Assign, KeyLittle, Semi, Eof]
        );
    }

    #[test]
    fn integer_literals() {
        use TokenType::*;
        let toks = types_and_texts("123 0x1f 0b1011 0n42 0");
        assert_eq!(
            toks,
            vec![
                (DefInt, "123".into()),
                (HexInt, "0x1f".into()),
                (BinInt, "0b1011".into()),
                (DecInt, "0n42".into()),
                (DefInt, "0".into()),
                (Eof, "<EOF>".into()),
            ]
        );
    }

    #[test]
    fn zero_prefix_without_digits_falls_back() {
        use TokenType::*;
        // "0x" with no hex digits: '0' is DEF_INT, 'x' becomes an identifier.
        assert_eq!(
            types_and_texts("0x"),
            vec![(DefInt, "0".into()), (Identifier, "x".into()), (Eof, "<EOF>".into())]
        );
    }

    #[test]
    fn qstring_strips_quotes_keeps_escapes() {
        let toks = types_and_texts(r#""hello \"there\"" x"#);
        assert_eq!(toks[0], (TokenType::QString, r#"hello \"there\""#.into()));
        assert_eq!(toks[1].0, TokenType::Identifier);
    }

    #[test]
    fn underscore_and_ellipsis_special_cases() {
        use TokenType::*;
        assert_eq!(types("_"), vec![Underscore, Eof]);
        assert_eq!(types("..."), vec![Ellipsis, Eof]);
        // '_' and '.' are identifier characters when not standing alone.
        assert_eq!(types("_x"), vec![Identifier, Eof]);
        assert_eq!(types(".foo"), vec![Identifier, Eof]);
        // Longest match: 'a...b' is a single IDENTIFIER, as in ANTLR.
        assert_eq!(
            types_and_texts("a...b"),
            vec![(Identifier, "a...b".into()), (Eof, "<EOF>".into())]
        );
    }

    #[test]
    fn operators_maximal_munch() {
        use TokenType::*;
        assert_eq!(
            types("== != <= >= << >> && || ^^ = < > & | ^"),
            vec![
                Equal, NotEqual, LessEqual, GreatEqual, Left, Right, BoolAnd, BoolOr, BoolXor,
                Assign, Less, Great, Ampersand, Pipe, Caret, Eof
            ]
        );
    }

    #[test]
    fn punctuation_and_arithmetic() {
        use TokenType::*;
        assert_eq!(
            types("{ } [ ] ( ) : , ! ~ ; + - * / %"),
            vec![
                LBrace, RBrace, LBracket, RBracket, LParen, RParen, Colon, Comma, Exclaim, Tilde,
                Semi, Plus, Minus, Asterisk, Slash, Percent, Eof
            ]
        );
    }

    #[test]
    fn spec_boolean_words() {
        use TokenType::*;
        assert_eq!(types("$or $and $xor"), vec![SpecOr, SpecAnd, SpecXor, Eof]);
    }

    #[test]
    fn line_comment_goes_to_comment_channel() {
        let mut lexer = BaseLexer::new("a # comment\nb");
        let all = lexer.tokenize();
        let comment = all
            .iter()
            .find(|t| t.token_type() == TokenType::LineComment.as_i32())
            .expect("comment token");
        assert_eq!(comment.channel(), COMMENT);
        assert_eq!(comment.text(), Some("# comment\n"));
        // Default-channel view sees only the identifiers.
        let def = types_and_texts("a # comment\nb");
        assert_eq!(def[0].1, "a");
        assert_eq!(def[1].1, "b");
    }

    #[test]
    fn whitespace_is_hidden() {
        let mut lexer = BaseLexer::new("a b");
        let all = lexer.tokenize();
        assert_eq!(all[1].channel(), HIDDEN_CHANNEL);
    }

    #[test]
    fn pp_position_marker_registers_location() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let input = "\u{8}orig.slaspec###7\u{8}define";
        let mut lexer = BaseLexer::with_env(input, env.clone());
        let all = lexer.tokenize();
        assert_eq!(all[0].token_type(), TokenType::PpPosition.as_i32());
        assert_eq!(all[0].channel(), PREPROC);
        assert_eq!(all[0].text(), Some("orig.slaspec###7"));
        // Location registered for the current (expanded) line 1.
        let loc = env.get_locator().borrow().get_location(1).unwrap();
        assert_eq!(loc.filename, "orig.slaspec");
        assert_eq!(loc.lineno, 7);
        // Subsequent tokens on that line are stamped with the location.
        assert_eq!(all[1].location().unwrap().lineno, 7);
    }

    #[test]
    fn cpp_comment_is_error() {
        let mut lexer = BaseLexer::new("// nope");
        let t = lexer.next_token();
        assert_eq!(t.token_type(), TokenType::CppComment.as_i32());
        assert_eq!(lexer.errors().len(), 1);
    }

    #[test]
    fn unknown_char_is_error() {
        let mut lexer = BaseLexer::new("@");
        let t = lexer.next_token();
        assert_eq!(t.token_type(), TokenType::Unknown.as_i32());
        assert_eq!(lexer.errors().len(), 1);
    }

    #[test]
    fn unknown_char_increments_env_lexing_errors() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let mut lexer = BaseLexer::with_env("@", env.clone());
        lexer.next_token();
        assert_eq!(env.get_lexing_errors(), 1);
    }

    #[test]
    fn line_and_column_tracking() {
        let mut lexer = BaseLexer::new("a\n  b");
        let all = lexer.tokenize_default_channel();
        assert_eq!(all[0].line(), 1);
        assert_eq!(all[0].char_position_in_line(), 0);
        assert_eq!(all[1].line(), 2);
        assert_eq!(all[1].char_position_in_line(), 2);
    }

    #[test]
    fn lexes_skeleton_varnode_line() {
        use TokenType::*;
        let toks = types_and_texts("define register offset=0x00 size=1 [ F A C B ];");
        let tys: Vec<TokenType> = toks.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            tys,
            vec![
                KeyDefine, Identifier, KeyOffset, Assign, HexInt, KeySize, Assign, DefInt,
                LBracket, Identifier, Identifier, Identifier, Identifier, RBracket, Semi, Eof
            ]
        );
    }

    #[test]
    fn token_type_roundtrip() {
        for v in [-1, 4, 10, 42, 50, 60, 70, 92, 100, 105, 110, 113] {
            let t = TokenType::from_i32(v).unwrap();
            assert_eq!(t.as_i32(), v);
        }
        assert_eq!(TokenType::from_i32(9999), None);
    }
}
