//! Port of `ghidra.program.model.data.StringRenderParser`.
//!
//! A parser to invert
//! [`StringRenderBuilder`](super::string_render_builder::StringRenderBuilder)'s output (and the
//! related `StringDataInstance.getStringRepresentation()`/`getCharRepresentation()` textual
//! renderings it backs): quoted/escaped text runs and comma-joined `XXh` byte sequences, with an
//! optional `u8`/`u`/`U` charset-size prefix before the opening quote.
//!
//! Ported the same way as [`StringRenderBuilder`] (a plain concrete struct with a direct `impl`,
//! not a `DataType`/cut-point trait -- this class isn't one in Java either): a small character-at-
//! -a-time state machine (`State` enum, `parseChar*` handlers) accumulating into an output byte
//! buffer.
//!
//! ## Differences from the Java original
//!
//! - **No `java.nio.charset.Charset`/`CharsetEncoder`, no `CharsetInfoManager`.** Matching
//!   [`StringRenderBuilder`]'s own established convention (see that module's docs), encoding is
//!   limited to the same handful of charset names this crate's standard library can handle
//!   without a full `Charset` registry: `US-ASCII`, `UTF-8`, `UTF-16BE`/`UTF-16LE`,
//!   `UTF-32BE`/`UTF-32LE`. [`charset_char_size`]/[`is_bom_charset`] are minimal free-function
//!   stand-ins for the two `CharsetInfoManager` queries `initCharset` needs (character size in
//!   bytes, and whether a charset needs an endian suffix appended before it can be resolved).
//! - **No `CharBuffer`/surrogate-pair reconstruction.** Java represents text internally as UTF-16
//!   `char`s, so a supplementary code point (`encodeCodePoint`) must first be split into a
//!   high/low surrogate pair and fed through a 2-`char` buffer before the encoder can consume it
//!   (`encodeBufferedCodePoint`). Rust's `char` already *is* a single Unicode scalar value, so
//!   `encodeCodePoint`/`encodeChar`/`encodeBufferedCodePoint` collapse into one helper,
//!   [`encode_scalar`](StringRenderParser::encode_scalar), which encodes a code point directly
//!   through whichever of the five supported charsets [`init_charset`](StringRenderParser::init_charset)
//!   resolved.
//! - **No `ByteBuffer` capacity/`BufferOverflowException` retry loop.** Java's public
//!   `parse(CharBuffer)` overload guesses an initial output capacity, retries with double the
//!   capacity (and a full [`reset`](StringRenderParser::reset) + re-parse from the start) on
//!   overflow. This port accumulates into a plain growable `Vec<u8>`, which never overflows, so
//!   that retry loop has nothing to do and is omitted; [`parse`](StringRenderParser::parse) is a
//!   single, direct pass.
//! - **`parse(ByteBuffer, CharBuffer)`'s position-rewind-on-error** (`in.position(in.position() -
//!   1)`, letting a caller resume feeding input from the exact character that failed) is
//!   reproduced via [`parse_into`](StringRenderParser::parse_into)'s `cursor: &mut usize` output
//!   parameter, which this port only ever advances *after* a character is fully, successfully
//!   consumed -- so on error, `*cursor` is already left pointing at the offending character,
//!   with no separate rewind step needed.
//! - **`finish(ByteBuffer)`'s `out` parameter is dropped.** Java's body (`state.checkFinal(pos);`)
//!   never reads it; [`finish`](StringRenderParser::finish) here takes no buffer argument.
//! - **One-line bug fix, verified by hand-tracing and covered by a regression test**: Java's
//!   `parseCharCodePoint` never resets `val` back to `0` after successfully emitting a `\x`/`\u`/
//!   `\U` code-point escape (unlike the structurally identical byte-sequence case,
//!   `parseCharByteSuffix`, which *does* reset `val = 0` after emitting a byte). Since `val`
//!   accumulates via left-shift-and-add across the 2/4/8 hex digits of *each* such escape, a
//!   second consecutive code-point escape in the same input silently starts from the *previous*
//!   escape's leftover value instead of zero, corrupting the decoded code point. This is a
//!   correctness bug on the exact "invert a rendered representation" path this class exists for
//!   (two adjacent non-displayable/control code points both needing `\x`/`\u` rendering is a
//!   realistic, not exotic, input), so this port adds the missing reset --
//!   see [`parse_char_code_point`](StringRenderParser::parse_char_code_point) -- rather than
//!   reproducing it. `consecutive_hex_escapes_do_not_corrupt_each_other` regression-tests this.
//! - **`StringParseException`** (the nested `extends UsrException` class) is ported as its own
//!   top-level struct with the same two constructors (by expected-character-set-and-actual, or by
//!   "unexpected end"), converts into [`UsrException`] via `From`, and is one variant of the
//!   umbrella [`StringRenderParseError`] this port's `Result`-returning methods use in place of
//!   Java's three separate checked `throws` clauses (`StringParseException`,
//!   `MalformedInputException`, `UnmappableCharacterException` -- the latter two have no port of
//!   their own in this crate, so they become [`StringRenderParseError::Malformed`]/
//!   [`StringRenderParseError::Unmappable`] instead). `State.checkAccepts`'s `Set<Character>` (a
//!   Java `HashSet`, so its `toString()` element order is unspecified) becomes a `BTreeSet<char>`
//!   here for a deterministic, sorted error message -- a minor, intentional improvement over an
//!   already-nondeterministic Java message, not a behavior change worth preserving.
//! - Java's `throw new AssertionError()` fallback branches (reached only when a character passes
//!   a state's `checkAccepts` gate -- which is deliberately looser than what the state's handler
//!   itself actually recognizes, e.g. `INIT`/`UNIT` accept *either* quote character regardless of
//!   this instance's configured `quoteChar`) are ported as `panic!`, matching this crate's
//!   established convention for unchecked Java exceptions that represent "should never happen"
//!   program errors (e.g. `BitFieldDataType`'s `AssertException` handling) rather than ordinary,
//!   recoverable parse failures. This is a faithful translation, not a weakening: Java's own
//!   `AssertionError` is *also* an unchecked `RuntimeException`-family throwable that isn't among
//!   `parseChar`'s declared checked exceptions, so it likewise propagates uncaught in Java.

use std::collections::BTreeSet;
use std::fmt;

use crate::program::model::lang::endian::Endian;
use crate::util::exception::UsrException;
use crate::util::string_utilities::UNICODE_BE_BYTE_ORDER_MARK;

const HEX_DIGITS: &str = "0123456789ABCDEFabcdef";

/// Stands in for `ghidra.util.charset.CharsetInfoManager.UTF8`/`UTF16`/`UTF32`/`USASCII`.
mod charset_names {
    pub const UTF8: &str = "UTF-8";
    pub const UTF16: &str = "UTF-16";
    pub const UTF32: &str = "UTF-32";
    pub const USASCII: &str = "US-ASCII";
}

/// Stands in for `CharsetInfoManager.getInstance().getCharsetCharSize(String)`, limited to the
/// handful of charset names this port supports -- see the module docs.
fn charset_char_size(name: &str) -> i32 {
    match name {
        "UTF-16" | "UTF-16BE" | "UTF-16LE" => 2,
        "UTF-32" | "UTF-32BE" | "UTF-32LE" => 4,
        _ => 1,
    }
}

/// Stands in for `CharsetInfoManager.isBOMCharset(String)`.
fn is_bom_charset(name: &str) -> bool {
    matches!(name, "UTF-16" | "UTF-32")
}

/// Encodes a single Unicode scalar value into `out` using one of the charsets this port supports
/// without a full `java.nio.charset.Charset` registry -- see the module docs. Mirrors (the
/// encoding inverse of) [`StringRenderBuilder`](super::string_render_builder)'s own
/// `decode_limited_charset`.
fn encode_limited_charset(
    charset_name: &str,
    code_point: u32,
    out: &mut Vec<u8>,
) -> Result<(), StringRenderParseError> {
    match charset_name {
        "US-ASCII" | "ASCII" => {
            if code_point > 0x7F {
                return Err(StringRenderParseError::Unmappable(format!(
                    "code point U+{code_point:04X} is not representable in US-ASCII"
                )));
            }
            out.push(code_point as u8);
            Ok(())
        }
        "UTF-8" => {
            let c = char::from_u32(code_point).ok_or_else(|| {
                StringRenderParseError::Malformed(format!(
                    "U+{code_point:04X} is not a valid Unicode scalar value"
                ))
            })?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            Ok(())
        }
        "UTF-16BE" | "UTF-16LE" => {
            let c = char::from_u32(code_point).ok_or_else(|| {
                StringRenderParseError::Malformed(format!(
                    "U+{code_point:04X} is not a valid Unicode scalar value"
                ))
            })?;
            let mut units = [0u16; 2];
            let encoded = c.encode_utf16(&mut units);
            let big_endian = charset_name.ends_with("BE");
            for unit in encoded.iter() {
                out.extend_from_slice(&if big_endian { unit.to_be_bytes() } else { unit.to_le_bytes() });
            }
            Ok(())
        }
        "UTF-32BE" | "UTF-32LE" => {
            let big_endian = charset_name.ends_with("BE");
            out.extend_from_slice(&if big_endian {
                code_point.to_be_bytes()
            } else {
                code_point.to_le_bytes()
            });
            Ok(())
        }
        other => Err(StringRenderParseError::Unmappable(format!("unsupported charset: {other}"))),
    }
}

/// Port of `StringRenderParser.StringParseException`.
///
/// An exception for when a string representation cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringParseException {
    message: String,
}

impl StringParseException {
    /// Port of `StringParseException(int, Set<Character>, char)`.
    pub fn unexpected_char(pos: i32, expected: &BTreeSet<char>, got: char) -> Self {
        let expected_str =
            format!("[{}]", expected.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "));
        StringParseException {
            message: format!(
                "Error parsing string representation at position {pos}. Expected one of {expected_str} but got {got}"
            ),
        }
    }

    /// Port of `StringParseException(int)`.
    pub fn unexpected_end(pos: i32) -> Self {
        StringParseException { message: format!("Unexpected end of string representation at position {pos}.") }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StringParseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StringParseException {}

impl From<StringParseException> for UsrException {
    fn from(value: StringParseException) -> Self {
        Self(value.message)
    }
}

/// Umbrella error type for [`StringRenderParser`]'s `Result`-returning methods, standing in for
/// the three separate checked exceptions (`StringParseException`, `MalformedInputException`,
/// `UnmappableCharacterException`) Java's `parse`/`finish` declare -- see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringRenderParseError {
    /// The representation's syntax could not be parsed (port of `StringParseException`).
    Parse(StringParseException),
    /// A character sequence in the representation was not valid for the charset in use (stands in
    /// for `java.nio.charset.MalformedInputException`).
    Malformed(String),
    /// A code point could not be encoded in the charset in use (stands in for
    /// `java.nio.charset.UnmappableCharacterException`).
    Unmappable(String),
}

impl fmt::Display for StringRenderParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringRenderParseError::Parse(e) => e.fmt(f),
            StringRenderParseError::Malformed(msg) => write!(f, "malformed input: {msg}"),
            StringRenderParseError::Unmappable(msg) => write!(f, "unmappable character: {msg}"),
        }
    }
}

impl std::error::Error for StringRenderParseError {}

impl From<StringParseException> for StringRenderParseError {
    fn from(value: StringParseException) -> Self {
        StringRenderParseError::Parse(value)
    }
}

/// Port of the private `StringRenderParser.State` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    Prefix,
    Unit,
    Str,
    Byte,
    ByteSuffix,
    Comma,
    Escape,
    CodePoint,
}

/// Port of `State.isFinal` (via `State.checkFinal`).
fn state_is_final(state: State) -> bool {
    matches!(state, State::Init | State::Unit | State::Comma)
}

/// Port of each `State` constant's `accepts` set. `None` matches Java's no-arg `State(boolean)`
/// constructor (`accepts == null`, meaning "accepts any character").
fn state_accepts(state: State) -> Option<&'static str> {
    match state {
        State::Init => Some("uU'\"0123456789ABCDEFabcdef"),
        State::Prefix => Some("8'\"0123456789ABCDEFabcdef"),
        State::Unit => Some("'\"0123456789ABCDEFabcdef"),
        State::Str => None,
        State::Byte => Some(HEX_DIGITS),
        State::ByteSuffix => Some("h"),
        State::Comma => Some(","),
        State::Escape => Some("0abtnvfr\\\"'xuU"),
        State::CodePoint => Some(HEX_DIGITS),
    }
}

/// Port of `State.checkAccepts(int, char)`.
fn check_accepts(state: State, pos: i32, c: char) -> Result<(), StringParseException> {
    let Some(accepts) = state_accepts(state) else {
        return Ok(());
    };
    if accepts.contains(c) {
        return Ok(());
    }
    let expected: BTreeSet<char> = accepts.chars().collect();
    Err(StringParseException::unexpected_char(pos, &expected, c))
}

/// Port of `State.checkFinal(int)`.
fn check_final(state: State, pos: i32) -> Result<(), StringParseException> {
    if state_is_final(state) {
        return Ok(());
    }
    Err(StringParseException::unexpected_end(pos))
}

/// Port of `ghidra.program.model.data.StringRenderParser`.
///
/// A parser to invert `StringDataInstance.getStringRepresentation()`,
/// `StringDataInstance.getCharRepresentation()`, and related -- in this crate, that means
/// [`StringRenderBuilder`](super::string_render_builder::StringRenderBuilder)'s output. See the
/// module docs for what differs from the Java original.
pub struct StringRenderParser {
    quote_char: char,
    endian: Endian,
    charset_name: Option<String>,
    include_bom: bool,

    /// Total characters consumed so far, for error messages (matches the Java field's own doc
    /// comment: "not just of the current buffer").
    pos: i32,
    state: State,
    /// The concrete charset resolved by [`init_charset`](Self::init_charset) (e.g. `"UTF-16BE"`),
    /// or `None` before the first character has been processed.
    charset: Option<String>,
    val: u32,
    code_digits: i32,
}

impl StringRenderParser {
    /// Construct a parser.
    ///
    /// `quote_char` is the character expected to enclose the representation: double quote (`"`)
    /// for strings, single quote (`'`) for characters. `endian` is the endianness for
    /// unicode strings. `charset_name` overrides the charset inferred from the representation's
    /// `u`/`u8`/`U` prefix, standing in for the constructor parameter of the same name (`None`
    /// matches passing Java's `null`). `include_bom` requests a byte-order-marker be prepended, if
    /// applicable to the resolved charset.
    ///
    /// Port of `StringRenderParser(char, Endian, String, boolean)`.
    pub fn new(quote_char: char, endian: Endian, charset_name: Option<&str>, include_bom: bool) -> Self {
        let mut parser = StringRenderParser {
            quote_char,
            endian,
            charset_name: charset_name.map(|s| s.to_string()),
            include_bom,
            pos: 0,
            state: State::Init,
            charset: None,
            val: 0,
            code_digits: 0,
        };
        parser.reset();
        parser
    }

    /// Reset the parser. Port of `StringRenderParser.reset()`.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.state = State::Init;
        self.val = 0;
        self.charset = None;
    }

    /// Port of `StringRenderParser.initCharset(ByteBuffer, String)`.
    fn init_charset(&mut self, out: &mut Vec<u8>, repr_charset_name: &str) {
        let mut charset_name = self.charset_name.clone().unwrap_or_else(|| repr_charset_name.to_string());
        let char_size = charset_char_size(&charset_name);
        if is_bom_charset(&charset_name) {
            // Take care of the BOM ourselves, because it must be first, before any initial bytes.
            charset_name.push_str(self.endian.to_short_string());
        }
        if self.include_bom {
            if char_size == 2 {
                let bom = UNICODE_BE_BYTE_ORDER_MARK as u16;
                out.extend_from_slice(&if self.endian.is_big_endian() { bom.to_be_bytes() } else { bom.to_le_bytes() });
            } else if char_size == 4 {
                out.extend_from_slice(&if self.endian.is_big_endian() {
                    UNICODE_BE_BYTE_ORDER_MARK.to_be_bytes()
                } else {
                    UNICODE_BE_BYTE_ORDER_MARK.to_le_bytes()
                });
            }
        }
        self.charset = Some(charset_name);
    }

    /// Port of `StringRenderParser.encodeCodePoint`/`encodeChar`/`encodeBufferedCodePoint`,
    /// collapsed into one helper since Rust's `char` needs no surrogate-pair reconstruction --
    /// see the module docs.
    fn encode_scalar(&mut self, out: &mut Vec<u8>, code_point: u32) -> Result<(), StringRenderParseError> {
        let charset = self
            .charset
            .as_deref()
            .expect("StringRenderParser: encode_scalar called before a charset was resolved");
        encode_limited_charset(charset, code_point, out)
    }

    /// Port of `StringRenderParser.parseCharInit(ByteBuffer, char)`.
    fn parse_char_init(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if c == 'u' {
            return Ok(State::Prefix);
        }
        if c == 'U' {
            self.init_charset(out, charset_names::UTF32);
            return Ok(State::Unit);
        }
        self.init_charset(out, charset_names::USASCII);
        self.parse_char_unit(out, c)
    }

    /// Port of `StringRenderParser.parseCharPrefix(ByteBuffer, char)`.
    fn parse_char_prefix(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if c == '8' {
            self.init_charset(out, charset_names::UTF8);
            return Ok(State::Unit);
        }
        self.init_charset(out, charset_names::UTF16);
        self.parse_char_unit(out, c)
    }

    /// Port of `StringRenderParser.parseCharUnit(ByteBuffer, char)`.
    fn parse_char_unit(&mut self, _out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if let Some(digit) = c.to_digit(16) {
            self.val = digit;
            return Ok(State::Byte);
        }
        if c == self.quote_char {
            return Ok(State::Str);
        }
        // Reachable if this parser's `quote_char` doesn't match the quote character actually used
        // by the representation being parsed (`INIT`/`UNIT` accept *either* quote character -- see
        // the module docs). A genuine "should never happen given a correctly-paired
        // builder/parser" assertion, matching Java's own uncaught `AssertionError` here.
        panic!("StringRenderParser: unexpected character {c:?} in UNIT state (quote_char mismatch?)");
    }

    /// Port of `StringRenderParser.parseCharStr(ByteBuffer, char)`.
    fn parse_char_str(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if c == self.quote_char {
            return Ok(State::Comma);
        }
        if c == '\\' {
            return Ok(State::Escape);
        }
        self.encode_scalar(out, c as u32)?;
        Ok(State::Str)
    }

    /// Port of `StringRenderParser.parseCharByte(ByteBuffer, char)`.
    fn parse_char_byte(&mut self, _out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        let digit = c.to_digit(16).expect("StringRenderParser: BYTE state must only see hex digits");
        self.val = (self.val << 4) + digit;
        Ok(State::ByteSuffix)
    }

    /// Port of `StringRenderParser.parseCharByteSuffix(ByteBuffer, char)`.
    fn parse_char_byte_suffix(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if c == 'h' {
            out.push(self.val as u8);
            self.val = 0;
            return Ok(State::Comma);
        }
        panic!("StringRenderParser: unreachable BYTE_SUFFIX character {c:?}");
    }

    /// Port of `StringRenderParser.parseCharComma(ByteBuffer, char)`.
    fn parse_char_comma(&mut self, _out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        if c == ',' {
            return Ok(State::Unit);
        }
        panic!("StringRenderParser: unreachable COMMA character {c:?}");
    }

    /// Port of `StringRenderParser.parseCharEscape(ByteBuffer, char)`.
    fn parse_char_escape(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        match c {
            '0' => {
                self.encode_scalar(out, 0)?;
                Ok(State::Str)
            }
            'a' => {
                self.encode_scalar(out, 7)?;
                Ok(State::Str)
            }
            'b' => {
                self.encode_scalar(out, 8)?;
                Ok(State::Str)
            }
            't' => {
                self.encode_scalar(out, 9)?;
                Ok(State::Str)
            }
            'n' => {
                self.encode_scalar(out, 10)?;
                Ok(State::Str)
            }
            'v' => {
                self.encode_scalar(out, 11)?;
                Ok(State::Str)
            }
            'f' => {
                self.encode_scalar(out, 12)?;
                Ok(State::Str)
            }
            'r' => {
                self.encode_scalar(out, 13)?;
                Ok(State::Str)
            }
            '\\' => {
                self.encode_scalar(out, '\\' as u32)?;
                Ok(State::Str)
            }
            '"' => {
                self.encode_scalar(out, '"' as u32)?;
                Ok(State::Str)
            }
            '\'' => {
                self.encode_scalar(out, '\'' as u32)?;
                Ok(State::Str)
            }
            'x' => {
                self.code_digits = 2;
                Ok(State::CodePoint)
            }
            'u' => {
                self.code_digits = 4;
                Ok(State::CodePoint)
            }
            'U' => {
                self.code_digits = 8;
                Ok(State::CodePoint)
            }
            _ => panic!("StringRenderParser: unreachable ESCAPE character {c:?}"),
        }
    }

    /// Port of `StringRenderParser.parseCharCodePoint(ByteBuffer, char)`. See the module docs for
    /// the one-line `val = 0` reset this port adds relative to Java (a verified bug fix, not a
    /// stub).
    fn parse_char_code_point(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        debug_assert!(self.code_digits > 0);
        let digit = c.to_digit(16).expect("StringRenderParser: CODE_POINT state must only see hex digits");
        self.val = (self.val << 4) + digit;
        self.code_digits -= 1;
        if self.code_digits == 0 {
            let code_point = self.val;
            self.val = 0; // bug fix relative to Java -- see the module docs.
            self.encode_scalar(out, code_point)?;
            return Ok(State::Str);
        }
        Ok(State::CodePoint)
    }

    /// Port of `StringRenderParser.parseChar(ByteBuffer, char)`.
    fn parse_char(&mut self, out: &mut Vec<u8>, c: char) -> Result<State, StringRenderParseError> {
        match self.state {
            State::Init => self.parse_char_init(out, c),
            State::Prefix => self.parse_char_prefix(out, c),
            State::Unit => self.parse_char_unit(out, c),
            State::Str => self.parse_char_str(out, c),
            State::Byte => self.parse_char_byte(out, c),
            State::ByteSuffix => self.parse_char_byte_suffix(out, c),
            State::Comma => self.parse_char_comma(out, c),
            State::Escape => self.parse_char_escape(out, c),
            State::CodePoint => self.parse_char_code_point(out, c),
        }
    }

    /// Parse and encode a complete string or character representation.
    ///
    /// Port of `StringRenderParser.parse(CharBuffer)`, minus the `ByteBuffer`-capacity-guessing
    /// retry loop -- see the module docs for why a growable `Vec<u8>` needs none of that.
    pub fn parse(&mut self, input: &str) -> Result<Vec<u8>, StringRenderParseError> {
        let chars: Vec<char> = input.chars().collect();
        let mut cursor = 0usize;
        let mut out = Vec::with_capacity(chars.len() * 2);
        self.parse_into(&mut out, &chars, &mut cursor)?;
        self.finish()?;
        Ok(out)
    }

    /// Parse and encode a portion of a string or character representation.
    ///
    /// `input`/`cursor` together stand in for Java's stateful `CharBuffer in` parameter: `cursor`
    /// is advanced past each successfully-consumed character, and is left unchanged (still
    /// pointing at the offending character) on error -- see the module docs for why this needs no
    /// separate rewind step the way Java's `in.position(in.position() - 1)` does.
    ///
    /// Port of `StringRenderParser.parse(ByteBuffer, CharBuffer)`.
    pub fn parse_into(
        &mut self,
        out: &mut Vec<u8>,
        input: &[char],
        cursor: &mut usize,
    ) -> Result<(), StringRenderParseError> {
        while *cursor < input.len() {
            let c = input[*cursor];
            check_accepts(self.state, self.pos, c)?;
            let next_state = self.parse_char(out, c)?;
            self.state = next_state;
            self.pos += 1;
            *cursor += 1;
        }
        Ok(())
    }

    /// Finish parsing an encoded string or character representation, verifying the parser ended
    /// in a valid stopping state.
    ///
    /// Port of `StringRenderParser.finish(ByteBuffer)`; the unused `out` parameter is dropped --
    /// see the module docs.
    pub fn finish(&self) -> Result<(), StringParseException> {
        check_final(self.state, self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
    use crate::program::model::data::string_render_builder::StringRenderBuilder;

    #[test]
    fn parses_plain_ascii_quoted_text() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"hi\"").unwrap();
        assert_eq!(bytes, b"hi");
    }

    #[test]
    fn parses_byte_sequence_with_no_charset_needed() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("01h,02h,FFh").unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0xFF]);
    }

    #[test]
    fn parses_mixed_text_and_byte_runs() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"Test\",01h,02h,\"more\"").unwrap();
        assert_eq!(bytes, b"Test\x01\x02more");
    }

    #[test]
    fn parses_named_escape_sequences() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"a\\tb\\n\\0c\"").unwrap();
        assert_eq!(bytes, b"a\tb\n\0c");
    }

    #[test]
    fn parses_escaped_quote_character() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"a\\\"b\"").unwrap();
        assert_eq!(bytes, b"a\"b");
    }

    #[test]
    fn parses_hex_escape_sequences_of_each_width() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        // \x41 == 'A', B == 'B'; both ASCII so no multi-byte encoding involved.
        let bytes = p.parse("\"\\x41\\u0042\"").unwrap();
        assert_eq!(bytes, b"AB");
    }

    #[test]
    fn consecutive_hex_escapes_do_not_corrupt_each_other() {
        // Regression test for the `val` reset bug fix described in the module docs: without the
        // fix, the second `\x` escape's `val` would start from the first escape's leftover value
        // (0x41) instead of 0, producing a wrong byte instead of 0x42.
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"\\x41\\x42\\x43\"").unwrap();
        assert_eq!(bytes, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn parses_u8_prefixed_utf8_text() {
        let mut p = StringRenderParser::new('"', Endian::Little, Some("UTF-8"), false);
        let bytes = p.parse("u8\"hi\"").unwrap();
        assert_eq!(bytes, b"hi");
    }

    #[test]
    fn parses_u_prefixed_utf16_text_using_configured_endian() {
        let mut p = StringRenderParser::new('"', Endian::Big, Some("UTF-16"), false);
        let bytes = p.parse("u\"hi\"").unwrap();
        // Big-endian UTF-16 code units for "hi".
        assert_eq!(bytes, vec![0x00, b'h', 0x00, b'i']);
    }

    #[test]
    fn parses_uppercase_u_prefixed_utf32_text() {
        let mut p = StringRenderParser::new('"', Endian::Little, Some("UTF-32"), false);
        let bytes = p.parse("U\"A\"").unwrap();
        assert_eq!(bytes, vec![b'A', 0, 0, 0]);
    }

    #[test]
    fn empty_quoted_string_decodes_to_empty_bytes() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let bytes = p.parse("\"\"").unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn include_bom_prepends_byte_order_marker_for_multi_byte_charsets() {
        let mut p = StringRenderParser::new('"', Endian::Big, Some("UTF-16"), true);
        let bytes = p.parse("u\"A\"").unwrap();
        assert_eq!(bytes, vec![0xFE, 0xFF, 0x00, b'A']);
    }

    #[test]
    fn unexpected_end_of_input_reports_position() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let err = p.parse("\"hi").unwrap_err();
        match err {
            StringRenderParseError::Parse(e) => {
                assert!(e.message().contains("Unexpected end"));
            }
            other => panic!("expected a Parse error, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_character_reports_position_and_expected_set() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        // 'z' is not a valid start character (not a quote, prefix letter, or hex digit).
        let err = p.parse("z").unwrap_err();
        match err {
            StringRenderParseError::Parse(e) => {
                assert!(e.message().contains("position 0"));
                assert!(e.message().contains("but got z"));
            }
            other => panic!("expected a Parse error, got {other:?}"),
        }
    }

    #[test]
    fn string_parse_exception_converts_to_usr_exception() {
        let e = StringParseException::unexpected_end(3);
        let usr: UsrException = e.into();
        assert!(usr.0.contains("Unexpected end"));
    }

    #[test]
    fn reset_clears_parser_state_between_uses() {
        let mut p = StringRenderParser::new('"', Endian::Little, None, false);
        let _ = p.parse("\"hi\"").unwrap();
        p.reset();
        // If state weren't reset, re-parsing from scratch would misinterpret the leading quote.
        let bytes = p.parse("\"bye\"").unwrap();
        assert_eq!(bytes, b"bye");
    }

    // --- Round-trip tests against StringRenderBuilder's output (its own module doc's inverse). ---

    #[test]
    fn round_trips_plain_ascii_through_builder() {
        let original = b"Hello, world!";
        let mut builder = StringRenderBuilder::new("US-ASCII", 1);
        builder.decode_bytes_using_charset(original, RenderEnum::All, false);
        let rendered = builder.build();

        let mut parser = StringRenderParser::new('"', Endian::Little, Some("US-ASCII"), false);
        let parsed = parser.parse(&rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trips_ascii_with_control_characters_through_builder() {
        let original = b"a\tb\nc\0d";
        let mut builder = StringRenderBuilder::new("US-ASCII", 1);
        builder.decode_bytes_using_charset(original, RenderEnum::All, false);
        let rendered = builder.build();

        let mut parser = StringRenderParser::new('"', Endian::Little, Some("US-ASCII"), false);
        let parsed = parser.parse(&rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trips_ascii_with_embedded_quote_through_builder() {
        let original = b"a\"b";
        let mut builder = StringRenderBuilder::new("US-ASCII", 1);
        builder.decode_bytes_using_charset(original, RenderEnum::All, false);
        let rendered = builder.build();

        let mut parser = StringRenderParser::new('"', Endian::Little, Some("US-ASCII"), false);
        let parsed = parser.parse(&rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trips_utf16be_text_through_builder() {
        // Big-endian UTF-16 code units for "hi".
        let original: &[u8] = &[0x00, b'h', 0x00, b'i'];
        let mut builder = StringRenderBuilder::new("UTF-16BE", 2);
        builder.decode_bytes_using_charset(original, RenderEnum::All, false);
        let rendered = builder.build();

        let mut parser = StringRenderParser::new('"', Endian::Big, Some("UTF-16BE"), false);
        let parsed = parser.parse(&rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trips_mixed_text_and_byte_runs_through_builder() {
        // A US-ASCII builder falls back to a literal byte run only for bytes that fail to decode
        // as US-ASCII (non-ASCII bytes), then back to quoted text for a subsequent all-ASCII
        // call -- the same "mixed mode" shape `StringRenderBuilder`'s own
        // `mixed_text_and_byte_mode_are_comma_joined` test exercises, built here through the
        // public API only (`add_byte` is private to that module). The representation only encodes
        // a flat byte stream with no run-boundary markers, so the parser reconstructs the
        // concatenation of both calls' original bytes.
        let mut builder = StringRenderBuilder::new("US-ASCII", 1);
        builder.decode_bytes_using_charset(&[0xFF, 0xFE], RenderEnum::All, false);
        builder.decode_bytes_using_charset(b"hi", RenderEnum::All, false);
        let rendered = builder.build();
        assert_eq!(rendered, "FFh,FEh,\"hi\"");

        let mut parser = StringRenderParser::new('"', Endian::Little, Some("US-ASCII"), false);
        let parsed = parser.parse(&rendered).unwrap();
        assert_eq!(parsed, vec![0xFF, 0xFE, b'h', b'i']);
    }
}
