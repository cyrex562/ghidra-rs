//! A non-validating, SAX-style XML reader backed by [`quick_xml`].
//!
//! Ghidra's pull parsers ([`NonThreadedXmlPullParserImpl`] and [`ThreadedXmlPullParserImpl`])
//! sit on top of the JDK's `javax.xml.parsers.SAXParser`, configured by
//! `XmlUtilities.createSecureSAXParserFactory` with namespace processing off and external
//! entities disabled. This module supplies the SAX layer those two ports need: it is not the
//! port of a Ghidra class, it stands in for the JDK.
//!
//! Tokenizing is done by `quick-xml`. On top of it this module keeps the parts of Xerces'
//! behavior that `quick-xml` deliberately leaves to its caller:
//!
//! * **decoding**: the input is decoded up front (UTF-8, `US-ASCII` or `ISO-8859-1` as named by
//!   the XML declaration, or UTF-8/UTF-16 by byte-order mark) and line ends are normalized
//!   (`\r\n` and lone `\r` become `\n`), so `quick-xml` always reads UTF-8. It can only
//!   tokenize ASCII-compatible input, so UTF-16 has to be decoded before it sees the bytes
//!   whether or not its `encoding` feature is on;
//! * **well-formedness checks** `quick-xml` does not make: legal characters, XML names,
//!   matching end tags and a single root element (reported with Xerces' messages), the XML
//!   declaration's pseudo-attributes, `]]>` in content, `<` in attribute values, and
//!   whitespace between attributes;
//! * **references**: the five predefined entities and decimal/hex character references, plus
//!   attribute-value normalization (literal tab/newline/return become a space);
//! * **`<!DOCTYPE>`** (only when [`SaxConfig::allow_doctype`] is set, mirroring Java's
//!   `disallow-doctype-decl` feature). `quick-xml` only delimits the declaration; the internal
//!   subset is scanned here for general entity declarations. The external subset is never
//!   loaded (Java's `load-external-dtd` is off), internal entities are expanded — including
//!   ones whose replacement text contains markup — and external entities are skipped rather
//!   than fetched (Java's `external-general-entities` is off). Other markup declarations
//!   (`ELEMENT`, `ATTLIST`, `NOTATION`, parameter entities) are skipped without being
//!   interpreted, so ATTLIST defaults are not applied.
//!
//! Names are taken verbatim (namespaces off, so `xmlns` and prefixed names are ordinary
//! attributes/names, as with Java's `namespaces` feature set to `false`).
//!
//! As with `FEATURE_SECURE_PROCESSING`, entity expansion is capped at
//! [`ENTITY_EXPANSION_LIMIT`] expansions per document, and recursive entities are rejected.
//!
//! DTD validation is not supported; the pull parsers reject `validate == true` up front.
//!
//! Locations follow Xerces' `Locator`: 1-based line, and a 1-based column pointing just past
//! the markup that produced the event (so `<a>` at the start of a line reports column 4).
//! Events produced from an entity's replacement text report the location just past the
//! entity reference.
//!
//! [`NonThreadedXmlPullParserImpl`]: super::non_threaded_xml_pull_parser_impl::NonThreadedXmlPullParserImpl
//! [`ThreadedXmlPullParserImpl`]: super::threaded_xml_pull_parser_impl::ThreadedXmlPullParserImpl

use std::collections::HashMap;
use std::fmt;

use quick_xml::errors::{Error as QuickXmlError, IllFormedError, SyntaxError};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::attributes::AttrError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::app::util::xml::xml_error_handler::{XmlError, XmlParseException};

/// Maximum number of entity expansions per document, matching the JDK's secure-processing
/// `jdk.xml.entityExpansionLimit` default.
pub(crate) const ENTITY_EXPANSION_LIMIT: usize = 64_000;

/// A position in the document, as reported by Xerces' `Locator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SaxLocation {
    /// 1-based line number.
    pub(crate) line: i32,
    /// 1-based column number, just past the markup that produced the event.
    pub(crate) column: i32,
}

/// Parser configuration: the SAX features Ghidra's pull parsers toggle.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SaxConfig {
    /// Whether a `<!DOCTYPE>` is accepted. `false` mirrors
    /// `XmlUtilities.createSecureSAXParserFactory(false)` (`disallow-doctype-decl` on).
    pub(crate) allow_doctype: bool,
}

/// Why a parse stopped.
#[derive(Debug, Clone)]
pub(crate) enum SaxError {
    /// The document is not well-formed (Java: a fatal `SAXParseException`).
    Fatal {
        /// Line of the error.
        line: i32,
        /// Column of the error.
        column: i32,
        /// Xerces-style description.
        message: String,
    },
    /// The content handler asked to stop (Java: a `SAXException` thrown by a handler).
    Handler(XmlError),
}

impl SaxError {
    /// The error as the `SAXParseException` a SAX error handler receives, if it is a parse error.
    pub(crate) fn as_parse_exception(&self) -> Option<XmlParseException> {
        match self {
            SaxError::Fatal { line, message, .. } => {
                Some(XmlParseException::new((*line).max(0) as u64, message.clone()))
            }
            SaxError::Handler(_) => None,
        }
    }
}

impl fmt::Display for SaxError {
    /// Formats like `SAXParseException.toString()` (less the class name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaxError::Fatal { line, column, message } => {
                write!(f, "lineNumber: {line}; columnNumber: {column}; {message}")
            }
            SaxError::Handler(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SaxError {}

impl From<SaxError> for XmlError {
    fn from(e: SaxError) -> Self {
        match e {
            SaxError::Handler(e) => e,
            fatal => XmlError::new(fatal.to_string()),
        }
    }
}

/// The subset of `org.xml.sax.ContentHandler` Ghidra's pull parsers override.
pub(crate) trait SaxContentHandler {
    /// An element start tag (or the start half of an empty-element tag). Attributes are in
    /// document order.
    fn start_element(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        location: SaxLocation,
    ) -> Result<(), SaxError>;

    /// An element end tag (or the end half of an empty-element tag).
    fn end_element(&mut self, name: &str, location: SaxLocation) -> Result<(), SaxError>;

    /// Character data; may be delivered in several pieces.
    fn characters(&mut self, text: &str) -> Result<(), SaxError>;

    /// A processing instruction other than the XML declaration.
    fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError>;
}

/// Parses `input` (raw bytes, encoding detected from the BOM / XML declaration) and reports
/// events to `handler`.
pub(crate) fn parse<H: SaxContentHandler>(
    input: &[u8],
    config: SaxConfig,
    handler: &mut H,
) -> Result<(), SaxError> {
    let text = decode(input)?;
    check_characters(&text)?;
    let mut parser = Parser {
        handler,
        config,
        entities: HashMap::new(),
        has_unread_declarations: false,
        expansions: 0,
        entity_stack: Vec::new(),
        text: String::new(),
    };
    parser.run(&text, Origin::Document(Tracker::default()))
}

fn fatal_at(line: i32, column: i32, message: impl Into<String>) -> SaxError {
    SaxError::Fatal { line, column, message: message.into() }
}

fn fatal_at_location(location: SaxLocation, message: impl Into<String>) -> SaxError {
    fatal_at(location.line, location.column, message)
}

// ---- decoding ---------------------------------------------------------------------------

/// Decodes `input` to a string, normalizing line ends.
fn decode(input: &[u8]) -> Result<String, SaxError> {
    let text: String = if let Some(rest) = input.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        decode_utf8(rest)?
    } else if let Some(rest) = input.strip_prefix(&[0xFE, 0xFF]) {
        decode_utf16(rest, u16::from_be_bytes)?
    } else if let Some(rest) = input.strip_prefix(&[0xFF, 0xFE]) {
        decode_utf16(rest, u16::from_le_bytes)?
    } else {
        match declared_encoding(input).map(|e| e.to_ascii_uppercase()) {
            None => decode_utf8(input)?,
            Some(enc) => match enc.as_str() {
                "UTF-8" | "UTF8" => decode_utf8(input)?,
                "US-ASCII" | "ASCII" => {
                    if let Some(pos) = input.iter().position(|b| *b >= 0x80) {
                        let (line, column) = byte_position(input, pos);
                        return Err(fatal_at(
                            line,
                            column,
                            format!("Invalid byte 1 of 1-byte ASCII sequence at offset {pos}."),
                        ));
                    }
                    input.iter().map(|b| *b as char).collect()
                }
                "ISO-8859-1" | "ISO8859-1" | "ISO8859_1" | "LATIN1" | "ISO-LATIN-1" => {
                    input.iter().map(|b| *b as char).collect()
                }
                _ => {
                    return Err(fatal_at(1, 1, format!("Invalid encoding name \"{enc}\".")));
                }
            },
        }
    };
    if !text.contains('\r') {
        return Ok(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\r' {
            if it.peek() == Some(&'\n') {
                it.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn byte_position(input: &[u8], pos: usize) -> (i32, i32) {
    let before = &input[..pos];
    let line = before.iter().filter(|b| **b == b'\n').count() as i32 + 1;
    let column = (pos - before.iter().rposition(|b| *b == b'\n').map_or(0, |p| p + 1)) as i32 + 1;
    (line, column)
}

fn decode_utf8(input: &[u8]) -> Result<String, SaxError> {
    match std::str::from_utf8(input) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => {
            let (line, column) = byte_position(input, e.valid_up_to());
            Err(fatal_at(line, column, "Invalid byte 1 of 1-byte UTF-8 sequence."))
        }
    }
}

fn decode_utf16(input: &[u8], to_u16: fn([u8; 2]) -> u16) -> Result<String, SaxError> {
    if input.len() % 2 != 0 {
        return Err(fatal_at(1, 1, "Premature end of file."));
    }
    let units = input.chunks_exact(2).map(|c| to_u16([c[0], c[1]]));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| fatal_at(1, 1, "Invalid UTF-16 surrogate sequence."))
}

/// Reads the `encoding` pseudo-attribute of an ASCII-compatible XML declaration, if present.
fn declared_encoding(input: &[u8]) -> Option<String> {
    if !input.starts_with(b"<?xml") {
        return None;
    }
    let end = input.windows(2).position(|w| w == b"?>")?;
    let decl = std::str::from_utf8(&input[..end]).ok()?;
    let idx = decl.find("encoding")?;
    let rest = decl[idx + "encoding".len()..].trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &rest[1..];
    Some(rest[..rest.find(quote)?].to_string())
}

/// Validates every character up front, reporting the first illegal one Xerces-style.
fn check_characters(text: &str) -> Result<(), SaxError> {
    match text.char_indices().find(|(_, c)| !is_xml_char(*c)) {
        None => Ok(()),
        Some((offset, c)) => Err(fatal_at_location(
            Tracker::default().location(text, offset),
            format!("An invalid XML character (Unicode: 0x{:x}) was found in the document.", c as u32),
        )),
    }
}

// ---- character classes ------------------------------------------------------------------

/// Whether `c` is a legal XML 1.0 character.
fn is_xml_char(c: char) -> bool {
    matches!(c as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// XML `NameStartChar`, approximated for non-ASCII as "alphabetic".
fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':' || (!c.is_ascii() && c.is_alphabetic())
}

/// XML `NameChar`, approximated for non-ASCII as "alphanumeric".
fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || c.is_ascii_digit()
        || c == '-'
        || c == '.'
        || c == '\u{B7}'
        || (!c.is_ascii() && c.is_alphanumeric())
}

/// Byte length of the longest XML name at the start of `s` (0 if `s` does not start with one).
fn name_len(s: &str) -> usize {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if is_name_start(c) => {}
        _ => return 0,
    }
    chars.find(|(_, c)| !is_name_char(*c)).map_or(s.len(), |(i, _)| i)
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && name_len(s) == s.len()
}

/// Views bytes `quick-xml` handed back as text. The reader runs over a `&str` and every event
/// boundary is an ASCII delimiter, so these slices are always valid UTF-8.
fn utf8(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("quick-xml slices of a &str split at ASCII delimiters")
}

// ---- locations --------------------------------------------------------------------------

/// Maps byte offsets in the decoded document to Xerces-style line/column pairs, scanning
/// forward incrementally.
#[derive(Clone, Copy)]
struct Tracker {
    offset: usize,
    line: i32,
    column: i32,
}

impl Default for Tracker {
    fn default() -> Self {
        Self { offset: 0, line: 1, column: 1 }
    }
}

impl Tracker {
    fn location(&mut self, src: &str, offset: usize) -> SaxLocation {
        if offset < self.offset {
            *self = Tracker::default();
        }
        for c in src[self.offset..offset].chars() {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        self.offset = offset;
        SaxLocation { line: self.line, column: self.column }
    }
}

/// Where the text being read came from.
enum Origin {
    /// The document itself: locations are tracked.
    Document(Tracker),
    /// The replacement text of an entity: every event reports the location just past the
    /// reference that expanded it.
    Entity(SaxLocation),
}

impl Origin {
    fn location(&mut self, src: &str, offset: usize) -> SaxLocation {
        match self {
            Origin::Document(tracker) => tracker.location(src, offset),
            Origin::Entity(location) => *location,
        }
    }

    fn fatal(&mut self, src: &str, offset: usize, message: impl Into<String>) -> SaxError {
        fatal_at_location(self.location(src, offset), message)
    }
}

// ---- references and entities ------------------------------------------------------------

/// A declared general entity.
enum EntityDecl {
    /// An internal entity with its replacement text (character references already expanded).
    Internal(String),
    /// An external entity; never fetched.
    External,
}

/// What a `&...;` reference resolves to.
enum Reference {
    Char(char),
    Predefined(&'static str),
    /// An internal entity: its name and replacement text.
    Internal(String, String),
    External(String),
    Undeclared(String),
}

/// Decodes the body of `&#...;` (the part after `#`).
fn character_reference_value(body: &str) -> Result<char, String> {
    let value = if let Some(hex) = body.strip_prefix('x') {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("A hexadecimal representation must immediately follow the \"&#x\" in a \
                        character reference."
                .to_string());
        }
        u32::from_str_radix(hex, 16).ok()
    } else {
        if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit()) {
            return Err("A decimal representation must immediately follow the \"&#\" in a \
                        character reference."
                .to_string());
        }
        body.parse::<u32>().ok()
    };
    value
        .and_then(char::from_u32)
        .filter(|c| is_xml_char(*c))
        .ok_or_else(|| format!("Character reference \"&#{body}\" is an invalid XML character."))
}

/// Checks the body of a general entity reference (between `&` and `;`) is a name.
fn check_entity_name(body: &str) -> Result<(), String> {
    match name_len(body) {
        0 => Err("The entity name must immediately follow the '&' in the entity reference."
            .to_string()),
        n if n < body.len() => Err(format!(
            "The reference to entity \"{}\" must end with the ';' delimiter.",
            &body[..n]
        )),
        _ => Ok(()),
    }
}

/// Expands character references in an entity value literal (they are expanded at
/// declaration time; general entity references are left for use time).
fn expand_character_references(literal: &str) -> Result<String, String> {
    let mut out = String::with_capacity(literal.len());
    let mut rest = literal;
    while let Some(i) = rest.find("&#") {
        out.push_str(&rest[..i]);
        let body_and_rest = &rest[i + 2..];
        let end = body_and_rest
            .find(';')
            .ok_or("The character reference must end with the ';' delimiter.")?;
        out.push(character_reference_value(&body_and_rest[..end])?);
        rest = &body_and_rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

// ---- the document type declaration ------------------------------------------------------

/// What the `<!DOCTYPE>` declaration declares, as far as this reader interprets it.
#[derive(Default)]
struct Doctype {
    /// General entity declarations in document order.
    entities: Vec<(String, EntityDecl)>,
    /// Processing instructions in the internal subset.
    processing_instructions: Vec<(String, String)>,
    /// Set when there is an external subset or a parameter-entity reference that was not
    /// read; undeclared entities are then skipped instead of being fatal (XML 1.0 WFC:
    /// Entity Declared).
    has_unread_declarations: bool,
}

/// A DTD scanning error: byte offset into the declaration content, and message.
type DtdError = (usize, String);

const DTD_MALFORMED: &str = "The markup declarations contained or pointed to by the document \
                             type declaration must be well-formed.";

/// A cursor over the content of a `<!DOCTYPE ...>` declaration.
struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    fn bump(&mut self, bytes: usize) {
        self.pos += bytes;
    }

    fn err(&self, message: impl Into<String>) -> DtdError {
        (self.pos, message.into())
    }

    fn skip_whitespace(&mut self) -> bool {
        let rest = self.rest();
        let skipped = rest.len() - rest.trim_start_matches(is_whitespace).len();
        self.pos += skipped;
        skipped > 0
    }

    fn require_whitespace(&mut self, context: &str) -> Result<(), DtdError> {
        if self.skip_whitespace() {
            Ok(())
        } else {
            Err(self.err(format!("White space is required {context}.")))
        }
    }

    fn name(&mut self, context: &str) -> Result<&'a str, DtdError> {
        let n = name_len(self.rest());
        if n == 0 {
            return Err(self.err(format!("{context} must be a valid XML name.")));
        }
        let name = &self.rest()[..n];
        self.pos += n;
        Ok(name)
    }

    /// Reads a quoted literal verbatim (no reference processing).
    fn quoted(&mut self) -> Result<&'a str, DtdError> {
        let quote = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err(self.err("A quoted string is required.")),
        };
        let body = &self.rest()[1..];
        let end = body.find(quote).ok_or_else(|| self.err(DTD_MALFORMED))?;
        self.pos += 1 + end + 1;
        Ok(&body[..end])
    }

    /// Skips to just past `terminator`.
    fn skip_past(&mut self, terminator: &str) -> Result<&'a str, DtdError> {
        let end = self.rest().find(terminator).ok_or_else(|| self.err(DTD_MALFORMED))?;
        let skipped = &self.rest()[..end];
        self.pos += end + terminator.len();
        Ok(skipped)
    }

    /// Skips a markup declaration up to its closing `>`, honoring quoted strings.
    fn skip_declaration(&mut self) -> Result<(), DtdError> {
        loop {
            match self.peek() {
                None => return Err(self.err(DTD_MALFORMED)),
                Some('>') => {
                    self.bump(1);
                    return Ok(());
                }
                Some('"' | '\'') => {
                    self.quoted()?;
                }
                Some(c) => self.bump(c.len_utf8()),
            }
        }
    }

    /// Parses `SYSTEM "sys"` or `PUBLIC "pub" "sys"`.
    fn external_id(&mut self) -> Result<(), DtdError> {
        if self.starts_with("SYSTEM") {
            self.bump(6);
            self.require_whitespace("before the system identifier")?;
            self.quoted()?;
        } else {
            self.bump(6);
            self.require_whitespace("before the public identifier")?;
            self.quoted()?;
            self.require_whitespace("between the public and system identifiers")?;
            self.quoted()?;
        }
        Ok(())
    }
}

/// Scans the content of a `<!DOCTYPE ...>` declaration (as `quick-xml` delimits it: after the
/// keyword and its whitespace, up to the closing `>`).
fn scan_doctype(content: &str) -> Result<Doctype, DtdError> {
    let mut c = Cursor { s: content, pos: 0 };
    let mut doctype = Doctype::default();
    let root = c.name("The root element type in the document type declaration")?;
    let had_space = c.skip_whitespace();
    if had_space && (c.starts_with("SYSTEM") || c.starts_with("PUBLIC")) {
        c.external_id()?;
        // Java's `load-external-dtd` is off: the external subset is never read.
        doctype.has_unread_declarations = true;
        c.skip_whitespace();
    }
    if c.peek() == Some('[') {
        c.bump(1);
        scan_internal_subset(&mut c, &mut doctype)?;
        c.skip_whitespace();
    }
    if c.peek().is_some() {
        return Err(c.err(format!(
            "The document type declaration for root element type \"{root}\" must end with '>'."
        )));
    }
    Ok(doctype)
}

fn scan_internal_subset(c: &mut Cursor<'_>, doctype: &mut Doctype) -> Result<(), DtdError> {
    loop {
        c.skip_whitespace();
        match c.peek() {
            None => return Err(c.err(DTD_MALFORMED)),
            Some(']') => {
                c.bump(1);
                return Ok(());
            }
            Some('%') => {
                // Parameter-entity reference: not expanded, so later declarations may be
                // missing.
                c.bump(1);
                c.name("The parameter entity reference")?;
                if !c.starts_with(";") {
                    return Err(c.err(
                        "The parameter entity reference must end with the ';' delimiter.",
                    ));
                }
                c.bump(1);
                doctype.has_unread_declarations = true;
            }
            Some('<') if c.starts_with("<!--") => {
                c.bump(4);
                if c.skip_past("-->")?.contains("--") {
                    return Err(c.err("The string \"--\" is not permitted within comments."));
                }
            }
            Some('<') if c.starts_with("<?") => {
                c.bump(2);
                let body = c.skip_past("?>")?;
                let (target, data) = split_processing_instruction(body).map_err(|m| c.err(m))?;
                doctype.processing_instructions.push((target.to_string(), data.to_string()));
            }
            Some('<') if c.starts_with("<!ENTITY") => {
                c.bump("<!ENTITY".len());
                if let Some(entity) = scan_entity_declaration(c)? {
                    doctype.entities.push(entity);
                }
            }
            Some('<') if c.starts_with("<!") => {
                c.bump(2);
                c.skip_declaration()?;
            }
            Some(_) => return Err(c.err(DTD_MALFORMED)),
        }
    }
}

/// Scans an entity declaration after `<!ENTITY`. Parameter-entity declarations are consumed
/// but not interpreted (`None`).
fn scan_entity_declaration(
    c: &mut Cursor<'_>,
) -> Result<Option<(String, EntityDecl)>, DtdError> {
    c.require_whitespace("after \"<!ENTITY\" in the entity declaration")?;
    if c.peek() == Some('%') {
        c.skip_declaration()?;
        return Ok(None);
    }
    let name = c.name("The entity name in the entity declaration")?;
    c.require_whitespace("after the entity name in the entity declaration")?;
    let decl = if c.starts_with("SYSTEM") || c.starts_with("PUBLIC") {
        c.external_id()?;
        if c.skip_whitespace() && c.starts_with("NDATA") {
            c.bump(5);
            c.require_whitespace("before the notation name")?;
            c.name("The notation name")?;
            c.skip_whitespace();
        }
        EntityDecl::External
    } else {
        let start = c.pos;
        let literal = c.quoted()?;
        c.skip_whitespace();
        EntityDecl::Internal(expand_character_references(literal).map_err(|m| (start, m))?)
    };
    if !c.starts_with(">") {
        return Err(c.err(format!("The declaration for the entity \"{name}\" must end with '>'.")));
    }
    c.bump(1);
    Ok(Some((name.to_string(), decl)))
}

/// Splits a processing instruction's content (between `<?` and `?>`) into target and data.
fn split_processing_instruction(content: &str) -> Result<(&str, &str), String> {
    let n = name_len(content);
    if n == 0 {
        return Err("The processing instruction must begin with the name of the target.".into());
    }
    let (target, rest) = content.split_at(n);
    if target.eq_ignore_ascii_case("xml") {
        return Err(
            "The processing instruction target matching \"[xX][mM][lL]\" is not allowed.".into()
        );
    }
    if !rest.is_empty() && !rest.starts_with(is_whitespace) {
        return Err(
            "White space is required between the processing instruction target and data.".into()
        );
    }
    Ok((target, rest.trim_start_matches(is_whitespace)))
}

/// Checks the pseudo-attributes of the XML declaration (content between `<?` and `?>`).
fn check_xml_declaration(content: &str) -> Result<(), String> {
    let start = BytesStart::from_content(content, 3);
    let mut saw_version = false;
    for attr in start.attributes() {
        let attr = attr.map_err(|e| format!("The XML declaration is not well-formed: {e}."))?;
        match utf8(attr.key.as_ref()) {
            "version" => saw_version = true,
            "encoding" | "standalone" => {}
            name => {
                return Err(format!(
                    "The pseudo attribute \"{name}\" is not allowed in the XML declaration."
                ));
            }
        }
    }
    if saw_version {
        Ok(())
    } else {
        Err("The version is required in the XML declaration.".to_string())
    }
}

// ---- the event loop -----------------------------------------------------------------------

/// Where in the document the reader is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Before the root element.
    Prolog,
    /// Inside the root element (always the case in entity replacement text).
    Content,
    /// After the root element.
    Epilog,
}

impl Phase {
    /// Xerces' message for markup that is not allowed here.
    fn bad_markup(self) -> &'static str {
        match self {
            Phase::Prolog => {
                "The markup in the document preceding the root element must be well-formed."
            }
            Phase::Content => {
                "The content of elements must consist of well-formed character data or markup."
            }
            Phase::Epilog => {
                "The markup in the document following the root element must be well-formed."
            }
        }
    }
}

const EOF_IN_DOCUMENT: &str = "XML document structures must start and end within the same entity.";
const EOF_IN_ENTITY: &str = "The entity replacement text must contain complete markup.";

struct Parser<'h, H> {
    handler: &'h mut H,
    config: SaxConfig,
    entities: HashMap<String, EntityDecl>,
    has_unread_declarations: bool,
    expansions: usize,
    /// Entities currently being expanded, innermost last.
    entity_stack: Vec<String>,
    /// Pending character data, flushed before the next non-character event.
    text: String,
}

impl<H: SaxContentHandler> Parser<'_, H> {
    /// Reads `src` — the document, or an entity's replacement text — reporting its events.
    fn run(&mut self, src: &str, mut origin: Origin) -> Result<(), SaxError> {
        let in_entity = matches!(origin, Origin::Entity(_));
        let mut reader = Reader::from_str(src);
        {
            let config = reader.config_mut();
            config.check_comments = true;
            // End tags are matched here, against this entity's own open elements.
            config.check_end_names = false;
            config.allow_unmatched_ends = true;
        }
        let mut phase = if in_entity { Phase::Content } else { Phase::Prolog };
        let mut open: Vec<String> = Vec::new();
        let mut seen_doctype = false;

        loop {
            let start = reader.buffer_position() as usize;
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(e) => {
                    let (offset, message) = describe_reader_error(&e, &reader, src, phase, in_entity);
                    return Err(origin.fatal(src, offset, message));
                }
            };
            let end = reader.buffer_position() as usize;
            match event {
                Event::Decl(decl) => {
                    if start != 0 || in_entity {
                        return Err(origin.fatal(
                            src,
                            start + 5,
                            "The processing instruction target matching \"[xX][mM][lL]\" is not \
                             allowed.",
                        ));
                    }
                    check_xml_declaration(utf8(&decl)).map_err(|m| origin.fatal(src, end, m))?;
                }
                Event::PI(pi) => {
                    let (target, data) = split_processing_instruction(utf8(&pi))
                        .map_err(|m| origin.fatal(src, end, m))?;
                    self.flush_text()?;
                    self.handler.processing_instruction(target, data)?;
                }
                Event::Comment(_) => {}
                Event::DocType(doctype) => {
                    if phase != Phase::Prolog || !src[start..].starts_with("<!DOCTYPE") {
                        return Err(origin.fatal(src, start, phase.bad_markup()));
                    }
                    if !self.config.allow_doctype {
                        return Err(origin.fatal(
                            src,
                            start + "<!DOCTYPE".len(),
                            "DOCTYPE is disallowed when the feature \
                             \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.",
                        ));
                    }
                    if seen_doctype {
                        return Err(origin.fatal(src, start, "Already seen doctype."));
                    }
                    seen_doctype = true;
                    if !src[start + "<!DOCTYPE".len()..].starts_with(is_whitespace) {
                        return Err(origin.fatal(
                            src,
                            start + "<!DOCTYPE".len(),
                            "White space is required after \"<!DOCTYPE\" in the document type \
                             declaration.",
                        ));
                    }
                    let content = utf8(&doctype);
                    let content_start = end - 1 - content.len();
                    let declared = scan_doctype(content)
                        .map_err(|(offset, m)| origin.fatal(src, content_start + offset, m))?;
                    self.declare(declared)?;
                }
                Event::Start(_) | Event::Empty(_) if phase == Phase::Epilog => {
                    return Err(origin.fatal(src, start, phase.bad_markup()));
                }
                Event::Start(tag) => {
                    let (name, attributes) =
                        self.read_tag(&tag, phase).map_err(|m| origin.fatal(src, end, m))?;
                    self.flush_text()?;
                    self.handler.start_element(&name, attributes, origin.location(src, end))?;
                    open.push(name);
                    phase = Phase::Content;
                }
                Event::Empty(tag) => {
                    let (name, attributes) =
                        self.read_tag(&tag, phase).map_err(|m| origin.fatal(src, end, m))?;
                    self.flush_text()?;
                    let location = origin.location(src, end);
                    self.handler.start_element(&name, attributes, location)?;
                    self.handler.end_element(&name, location)?;
                    if !in_entity && open.is_empty() {
                        phase = Phase::Epilog;
                    } else {
                        phase = Phase::Content;
                    }
                }
                Event::End(tag) => {
                    if phase != Phase::Content {
                        return Err(origin.fatal(src, start, phase.bad_markup()));
                    }
                    let name = utf8(&tag);
                    match open.last() {
                        None => return Err(origin.fatal(src, end, EOF_IN_ENTITY)),
                        Some(expected) if expected != name => {
                            return Err(origin.fatal(
                                src,
                                end - 1,
                                format!(
                                    "The element type \"{expected}\" must be terminated by the \
                                     matching end-tag \"</{expected}>\"."
                                ),
                            ));
                        }
                        Some(_) => {}
                    }
                    open.pop();
                    self.flush_text()?;
                    self.handler.end_element(name, origin.location(src, end))?;
                    if !in_entity && open.is_empty() {
                        phase = Phase::Epilog;
                    }
                }
                Event::Text(text) => {
                    let text = utf8(&text);
                    match phase {
                        Phase::Content => {
                            if let Some(i) = text.find("]]>") {
                                return Err(origin.fatal(
                                    src,
                                    start + i,
                                    "The character sequence \"]]>\" must not appear in content \
                                     unless used to mark the end of a CDATA section.",
                                ));
                            }
                            self.text.push_str(text);
                        }
                        Phase::Prolog | Phase::Epilog => {
                            if let Some(i) = text.find(|c| !is_whitespace(c)) {
                                let message = if phase == Phase::Prolog {
                                    "Content is not allowed in prolog."
                                } else {
                                    "Content is not allowed in trailing section."
                                };
                                return Err(origin.fatal(src, start + i, message));
                            }
                        }
                    }
                }
                Event::CData(cdata) => {
                    if phase != Phase::Content {
                        return Err(origin.fatal(src, start, phase.bad_markup()));
                    }
                    self.text.push_str(utf8(&cdata));
                }
                Event::GeneralRef(reference) => {
                    match phase {
                        Phase::Prolog => {
                            return Err(origin.fatal(src, start, "Content is not allowed in prolog."));
                        }
                        Phase::Epilog => {
                            return Err(origin.fatal(
                                src,
                                start,
                                "Content is not allowed in trailing section.",
                            ));
                        }
                        Phase::Content => {}
                    }
                    let resolved =
                        self.resolve(utf8(&reference)).map_err(|m| origin.fatal(src, end, m))?;
                    match resolved {
                        Reference::Char(c) => self.text.push(c),
                        Reference::Predefined(s) => self.text.push_str(s),
                        Reference::Internal(name, replacement) => {
                            let location = origin.location(src, end);
                            self.push_entity(name).map_err(|m| fatal_at_location(location, m))?;
                            let result = self.run(&replacement, Origin::Entity(location));
                            self.entity_stack.pop();
                            result?;
                        }
                        // External entities are not fetched (Java's external-general-entities
                        // feature is off): skipped.
                        Reference::External(_) => {}
                        Reference::Undeclared(name) => {
                            self.undeclared(&name).map_err(|m| origin.fatal(src, end, m))?;
                        }
                    }
                }
                Event::Eof => {
                    return match phase {
                        _ if in_entity => {
                            if open.is_empty() {
                                Ok(())
                            } else {
                                Err(origin.fatal(src, end, EOF_IN_ENTITY))
                            }
                        }
                        Phase::Prolog => Err(origin.fatal(src, end, "Premature end of file.")),
                        Phase::Content => Err(origin.fatal(src, end, EOF_IN_DOCUMENT)),
                        Phase::Epilog => Ok(()),
                    };
                }
            }
        }
    }

    fn flush_text(&mut self) -> Result<(), SaxError> {
        if self.text.is_empty() {
            return Ok(());
        }
        let text = std::mem::take(&mut self.text);
        self.handler.characters(&text)
    }

    /// Records the declarations of a `<!DOCTYPE>` and reports its processing instructions.
    fn declare(&mut self, doctype: Doctype) -> Result<(), SaxError> {
        self.has_unread_declarations |= doctype.has_unread_declarations;
        for (name, decl) in doctype.entities {
            // The first declaration is binding; predefined entities cannot be redefined usefully.
            if resolve_xml_entity(&name).is_none() {
                self.entities.entry(name).or_insert(decl);
            }
        }
        for (target, data) in doctype.processing_instructions {
            self.handler.processing_instruction(&target, &data)?;
        }
        Ok(())
    }

    /// Validates a start tag and reads its name and (expanded, normalized) attributes.
    fn read_tag(
        &mut self,
        tag: &BytesStart<'_>,
        phase: Phase,
    ) -> Result<(String, Vec<(String, String)>), String> {
        let content = utf8(tag);
        // quick-xml's tag name: everything up to the first whitespace.
        let raw_name = &content[..content.find(is_whitespace).unwrap_or(content.len())];
        let n = name_len(raw_name);
        if n == 0 {
            return Err(phase.bad_markup().to_string());
        }
        let name = &raw_name[..n];
        let bad_tag = || {
            format!(
                "Element type \"{name}\" must be followed by either attribute specifications, \
                 \">\" or \"/>\"."
            )
        };
        if n < raw_name.len() {
            return Err(bad_tag());
        }
        let mut attributes = Vec::new();
        for attr in tag.attributes() {
            let attr = attr.map_err(|e| attribute_error_message(&e, content, name))?;
            let key = utf8(attr.key.as_ref());
            let key_offset = key.as_ptr() as usize - content.as_ptr() as usize;
            if !is_name(key) || !content[..key_offset].ends_with(is_whitespace) {
                return Err(bad_tag());
            }
            let mut value = String::new();
            self.expand_attribute_value(name, key, utf8(&attr.value), &mut value)?;
            attributes.push((key.to_string(), value));
        }
        Ok((name.to_string(), attributes))
    }

    /// Appends an attribute value to `out`, resolving references and normalizing literal
    /// whitespace (XML 1.0 §3.3.3, for CDATA attributes).
    fn expand_attribute_value(
        &mut self,
        element: &str,
        attr: &str,
        raw: &str,
        out: &mut String,
    ) -> Result<(), String> {
        let mut rest = raw;
        while let Some(i) = rest.find(['&', '<', '\t', '\n', '\r']) {
            out.push_str(&rest[..i]);
            let special = rest.as_bytes()[i];
            rest = &rest[i + 1..];
            match special {
                b'<' => {
                    return Err(format!(
                        "The value of attribute \"{attr}\" associated with an element type \
                         \"{element}\" must not contain the '<' character."
                    ));
                }
                b'&' => {
                    let Some(end) = rest.find(';') else {
                        check_entity_name(rest)?;
                        return Err(format!(
                            "The reference to entity \"{rest}\" must end with the ';' delimiter."
                        ));
                    };
                    let body = &rest[..end];
                    rest = &rest[end + 1..];
                    match self.resolve(body)? {
                        Reference::Char(c) => out.push(c),
                        Reference::Predefined(s) => out.push_str(s),
                        Reference::Internal(name, replacement) => {
                            self.push_entity(name)?;
                            let result =
                                self.expand_attribute_value(element, attr, &replacement, out);
                            self.entity_stack.pop();
                            result?;
                        }
                        Reference::External(name) => {
                            return Err(format!(
                                "The external entity reference \"&{name};\" is not permitted in \
                                 an attribute value."
                            ));
                        }
                        Reference::Undeclared(name) => self.undeclared(&name)?,
                    }
                }
                _ => out.push(' '),
            }
        }
        out.push_str(rest);
        Ok(())
    }

    /// Resolves the body of a reference (between `&` and `;`).
    fn resolve(&self, body: &str) -> Result<Reference, String> {
        if let Some(number) = body.strip_prefix('#') {
            return character_reference_value(number).map(Reference::Char);
        }
        check_entity_name(body)?;
        if let Some(s) = resolve_xml_entity(body) {
            return Ok(Reference::Predefined(s));
        }
        Ok(match self.entities.get(body) {
            Some(EntityDecl::Internal(text)) => Reference::Internal(body.to_string(), text.clone()),
            Some(EntityDecl::External) => Reference::External(body.to_string()),
            None => Reference::Undeclared(body.to_string()),
        })
    }

    /// Enters an entity's replacement text, rejecting recursion and enforcing the expansion
    /// limit. The caller pops [`Self::entity_stack`] when done.
    fn push_entity(&mut self, name: String) -> Result<(), String> {
        if self.entity_stack.contains(&name) {
            return Err(format!("Recursive entity reference \"{name}\"."));
        }
        self.expansions += 1;
        if self.expansions > ENTITY_EXPANSION_LIMIT {
            return Err(format!(
                "JAXP00010001: The parser has encountered more than \"{ENTITY_EXPANSION_LIMIT}\" \
                 entity expansions in this document; this is the limit imposed by the JDK."
            ));
        }
        self.entity_stack.push(name);
        Ok(())
    }

    fn undeclared(&self, name: &str) -> Result<(), String> {
        if self.has_unread_declarations {
            // May have been declared in the unread external subset: skipped.
            Ok(())
        } else {
            Err(format!("The entity \"{name}\" was referenced, but not declared."))
        }
    }
}

/// Translates a `quick-xml` read error into the offset and Xerces message to report.
fn describe_reader_error(
    error: &QuickXmlError,
    reader: &Reader<&[u8]>,
    src: &str,
    phase: Phase,
    in_entity: bool,
) -> (usize, String) {
    let at = (reader.error_position() as usize).min(src.len());
    let eof = if in_entity { EOF_IN_ENTITY } else { EOF_IN_DOCUMENT };
    let message = match error {
        QuickXmlError::Syntax(syntax) => {
            // quick-xml reports an unknown `<!...>` under the error of the markup it guessed
            // at; it is only really unclosed if the markup opened properly.
            let opened = |opener: &str| {
                src.get(at..at + opener.len()).is_some_and(|s| s.eq_ignore_ascii_case(opener))
            };
            let unclosed = match syntax {
                SyntaxError::InvalidBangMarkup => false,
                SyntaxError::UnclosedCData => opened("<![CDATA["),
                SyntaxError::UnclosedComment => opened("<!--"),
                SyntaxError::UnclosedDoctype => opened("<!DOCTYPE"),
                _ => true,
            };
            if !unclosed {
                phase.bad_markup().to_string()
            } else if matches!(syntax, SyntaxError::UnclosedCData) {
                "The CDATA section must end with \"]]>\".".to_string()
            } else {
                return (src.len(), eof.to_string());
            }
        }
        QuickXmlError::IllFormed(IllFormedError::DoubleHyphenInComment) => {
            "The string \"--\" is not permitted within comments.".to_string()
        }
        QuickXmlError::IllFormed(IllFormedError::UnclosedReference) => {
            let after = &src[(at + 1).min(src.len())..];
            match name_len(after) {
                0 => "The entity name must immediately follow the '&' in the entity reference."
                    .to_string(),
                n => format!(
                    "The reference to entity \"{}\" must end with the ';' delimiter.",
                    &after[..n]
                ),
            }
        }
        QuickXmlError::IllFormed(IllFormedError::MissingDoctypeName) => {
            "The root element type must appear after \"<!DOCTYPE\" in the document type \
             declaration."
                .to_string()
        }
        other => other.to_string(),
    };
    (at, message)
}

/// Xerces' message for a malformed attribute list reported by `quick-xml`.
fn attribute_error_message(error: &AttrError, content: &str, element: &str) -> String {
    /// The last whitespace-separated token of `s`.
    fn last_token(s: &str) -> &str {
        s.trim_end_matches(is_whitespace).rsplit(is_whitespace).next().unwrap_or("")
    }
    let bad_tag = || {
        format!(
            "Element type \"{element}\" must be followed by either attribute specifications, \
             \">\" or \"/>\"."
        )
    };
    match *error {
        AttrError::ExpectedEq(pos) => {
            let key = last_token(&content[..pos.min(content.len())]);
            if is_name(key) {
                format!(
                    "Attribute name \"{key}\" associated with an element type \"{element}\" must \
                     be followed by the ' = ' character."
                )
            } else {
                bad_tag()
            }
        }
        AttrError::ExpectedValue(pos) | AttrError::UnquotedValue(pos) => {
            let before = &content[..pos.min(content.len())];
            let key = last_token(&before[..before.rfind('=').unwrap_or(0)]);
            format!(
                "Open quote is expected for attribute \"{key}\" associated with an  element type  \
                 \"{element}\"."
            )
        }
        AttrError::ExpectedQuote(..) => EOF_IN_DOCUMENT.to_string(),
        AttrError::Duplicated(pos, _) => {
            let rest = &content[pos.min(content.len())..];
            let key = &rest[..rest.find(|c: char| c == '=' || is_whitespace(c)).unwrap_or(rest.len())];
            format!("Attribute \"{key}\" was already specified for element \"{element}\".")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records events as compact strings.
    #[derive(Default)]
    struct Recorder {
        events: Vec<String>,
    }

    impl SaxContentHandler for Recorder {
        fn start_element(
            &mut self,
            name: &str,
            attributes: Vec<(String, String)>,
            location: SaxLocation,
        ) -> Result<(), SaxError> {
            let attrs: Vec<String> =
                attributes.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
            self.events.push(format!(
                "start {name} [{}] @{}:{}",
                attrs.join(" "),
                location.line,
                location.column
            ));
            Ok(())
        }

        fn end_element(&mut self, name: &str, location: SaxLocation) -> Result<(), SaxError> {
            self.events.push(format!("end {name} @{}:{}", location.line, location.column));
            Ok(())
        }

        fn characters(&mut self, text: &str) -> Result<(), SaxError> {
            self.events.push(format!("text {text:?}"));
            Ok(())
        }

        fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError> {
            self.events.push(format!("pi {target} {data:?}"));
            Ok(())
        }
    }

    fn events(xml: &str) -> Vec<String> {
        events_with(xml, SaxConfig::default())
    }

    fn events_with(xml: &str, config: SaxConfig) -> Vec<String> {
        let mut r = Recorder::default();
        parse(xml.as_bytes(), config, &mut r).unwrap_or_else(|e| panic!("{e}"));
        r.events
    }

    fn error(xml: &str) -> String {
        error_with(xml.as_bytes(), SaxConfig::default())
    }

    fn error_with(xml: &[u8], config: SaxConfig) -> String {
        let mut r = Recorder::default();
        match parse(xml, config, &mut r) {
            Ok(()) => panic!("expected an error, got {:?}", r.events),
            Err(e) => e.to_string(),
        }
    }

    const DTD: SaxConfig = SaxConfig { allow_doctype: true };

    #[test]
    fn elements_attributes_and_locations() {
        let ev = events("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a x=\"1\" y='two'>hi<b/></a>");
        assert_eq!(
            ev,
            vec![
                "start a [x=\"1\" y=\"two\"] @2:18",
                "text \"hi\"",
                "start b [] @2:24",
                "end b @2:24",
                "end a @2:28",
            ]
        );
    }

    #[test]
    fn entities_char_refs_and_cdata() {
        let ev = events("<a t=\"&lt;&#65;&#x42;&amp;\">&quot;&apos;&gt;<![CDATA[<x>&amp;]]></a>");
        assert_eq!(
            ev,
            vec!["start a [t=\"<AB&\"] @1:29", "text \"\\\"'><x>&amp;\"", "end a @1:69"]
        );
    }

    #[test]
    fn attribute_whitespace_is_normalized_but_char_refs_are_not() {
        let ev = events("<a v=\"x\ty\nz&#10;\"/>");
        assert_eq!(ev[0], "start a [v=\"x y z\\n\"] @2:10");
    }

    #[test]
    fn line_ends_are_normalized() {
        let ev = events("<a>1\r\n2\r3</a>");
        assert_eq!(ev[1], "text \"1\\n2\\n3\"");
        assert_eq!(ev[2], "end a @3:6");
    }

    #[test]
    fn comments_and_processing_instructions() {
        let ev = events(
            "<?program_dtd version=\"1\"?><!-- c --><a><?p  d e ?><!-- x - y --></a><!-- t -->",
        );
        assert_eq!(
            ev,
            vec![
                "pi program_dtd \"version=\\\"1\\\"\"",
                "start a [] @1:41",
                "pi p \"d e \"",
                "end a @1:70",
            ]
        );
    }

    #[test]
    fn namespaces_are_not_processed() {
        let ev = events("<n:a xmlns:n=\"urn:x\" n:b=\"1\"/>");
        assert_eq!(ev[0], "start n:a [xmlns:n=\"urn:x\" n:b=\"1\"] @1:31");
    }

    #[test]
    fn mismatched_end_tag_is_fatal() {
        assert!(error("<a><b></a>").contains(
            "The element type \"b\" must be terminated by the matching end-tag \"</b>\"."
        ));
    }

    #[test]
    fn well_formedness_errors() {
        assert!(error("").contains("Premature end of file."));
        assert!(error("x<a/>").contains("Content is not allowed in prolog."));
        assert!(error("<a/>x").contains("Content is not allowed in trailing section."));
        assert!(error("<a/><b/>").contains("following the root element must be well-formed"));
        assert!(error("<a x=\"1\" x=\"2\"/>").contains("Attribute \"x\" was already specified"));
        assert!(error("<a x=\"<\"/>").contains("must not contain the '<' character"));
        assert!(error("<a>&bogus;</a>").contains("The entity \"bogus\" was referenced, but not declared."));
        assert!(error("<a><!-- a -- b --></a>").contains("\"--\" is not permitted"));
        assert!(error("<a>]]></a>").contains("\"]]>\" must not appear in content"));
        assert!(error("<a>\u{1}</a>").contains("invalid XML character (Unicode: 0x1)"));
        assert!(error("<a>&#0;</a>").contains("is an invalid XML character"));
        assert!(error("<a><?xml version=\"1.0\"?></a>").contains("[xX][mM][lL]"));
        assert!(error("<a").contains("XML document structures must start and end"));
        assert!(error("<a x=1/>").contains("Open quote is expected"));
        assert!(error("<a/ >").contains("must be followed by either attribute specifications"));
    }

    #[test]
    fn error_location_is_reported() {
        let e = error("<a>\n  <b></c>\n</a>");
        assert!(e.starts_with("lineNumber: 2; columnNumber: 9;"), "{e}");
    }

    #[test]
    fn doctype_disallowed_unless_configured() {
        assert!(error("<!DOCTYPE a><a/>").contains("DOCTYPE is disallowed"));
        assert_eq!(events_with("<!DOCTYPE a><a/>", DTD).len(), 2);
    }

    #[test]
    fn internal_entities_expand_including_markup() {
        let xml = "<!DOCTYPE a [\n<!ENTITY e \"x&#38;amp;y\">\n<!ENTITY m '<b k=\"&e;\"/>'>\n\
                   <!ELEMENT a ANY>\n<!ATTLIST a z CDATA \"q\">\n]><a>[&e;]&m;</a>";
        let ev = events_with(xml, DTD);
        assert_eq!(ev[0], "start a [] @6:6");
        assert_eq!(ev[1], "text \"[x&y]\"");
        assert!(ev[2].starts_with("start b [k=\"x&y\"]"), "{:?}", ev);
        assert!(ev[3].starts_with("end b"));
        assert_eq!(ev[4], "end a @6:18");
    }

    #[test]
    fn external_entities_are_skipped_not_fetched() {
        let xml = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE foo [\n    \
                   <!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\
                   <foo>&xxe; fizzbizz</foo>";
        let ev = events_with(xml, DTD);
        assert_eq!(ev[1], "text \" fizzbizz\"");
    }

    #[test]
    fn external_entity_in_attribute_is_fatal() {
        let xml = "<!DOCTYPE a [<!ENTITY x SYSTEM \"f\">]><a v=\"&x;\"/>";
        assert!(error_with(xml.as_bytes(), DTD).contains("is not permitted in an attribute value"));
    }

    #[test]
    fn undeclared_entities_are_skipped_when_external_subset_unread() {
        let ev = events_with("<!DOCTYPE a SYSTEM \"a.dtd\"><a>&x;y</a>", DTD);
        assert_eq!(ev[1], "text \"y\"");
    }

    #[test]
    fn recursive_entities_are_fatal() {
        let xml = "<!DOCTYPE a [<!ENTITY x \"&y;\"><!ENTITY y \"&x;\">]><a>&x;</a>";
        assert!(error_with(xml.as_bytes(), DTD).contains("Recursive entity reference"));
    }

    #[test]
    fn entity_expansion_limit_is_enforced() {
        let xml = "<!DOCTYPE a [<!ENTITY a \"x\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\
                   <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\
                   <!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">\
                   <!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\">\
                   <!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\">]><a>&f;</a>";
        assert!(error_with(xml.as_bytes(), DTD).contains("JAXP00010001"));
    }

    #[test]
    fn encodings() {
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>\xe9</a>";
        let mut r = Recorder::default();
        parse(latin1, SaxConfig::default(), &mut r).unwrap();
        assert_eq!(r.events[1], "text \"\u{e9}\"");

        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice("<a>é</a>".as_bytes());
        let mut r = Recorder::default();
        parse(&bom, SaxConfig::default(), &mut r).unwrap();
        assert_eq!(r.events[1], "text \"é\"");

        let mut utf16 = vec![0xFF, 0xFE];
        for u in "<a>z</a>".encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        let mut r = Recorder::default();
        parse(&utf16, SaxConfig::default(), &mut r).unwrap();
        assert_eq!(r.events[1], "text \"z\"");

        assert!(error_with(b"<a>\xff</a>", SaxConfig::default()).contains("UTF-8"));
        assert!(error_with(
            b"<?xml version=\"1.0\" encoding=\"EBCDIC\"?><a/>",
            SaxConfig::default()
        )
        .contains("Invalid encoding name"));
    }

    #[test]
    fn utf16_big_endian_with_declaration() {
        let mut utf16 = vec![0xFE, 0xFF];
        for u in "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<a v='\u{e9}'>\u{263a}</a>".encode_utf16() {
            utf16.extend_from_slice(&u.to_be_bytes());
        }
        let mut r = Recorder::default();
        parse(&utf16, SaxConfig::default(), &mut r).unwrap();
        assert_eq!(r.events, vec!["start a [v=\"\u{e9}\"] @2:10", "text \"\u{263a}\"", "end a @2:15"]);
    }

    #[test]
    fn entity_events_report_the_reference_location() {
        let xml = "<!DOCTYPE a [<!ENTITY m \"<b/>\n<c/>\">]>\n<a>&m;</a>";
        let ev = events_with(xml, DTD);
        assert_eq!(
            ev,
            vec![
                "start a [] @3:4",
                "start b [] @3:7",
                "end b @3:7",
                "text \"\\n\"",
                "start c [] @3:7",
                "end c @3:7",
                "end a @3:11",
            ]
        );
    }

    #[test]
    fn entity_markup_must_be_complete() {
        let open = "<!DOCTYPE a [<!ENTITY m \"<b>\">]><a>&m;</b></a>";
        assert!(error_with(open.as_bytes(), DTD).contains("must contain complete markup"));
        let close = "<!DOCTYPE a [<!ENTITY m \"</a>\">]><a>&m;";
        assert!(error_with(close.as_bytes(), DTD).contains("must contain complete markup"));
    }

    #[test]
    fn entity_replacement_whitespace_is_normalized_in_attributes() {
        let xml = "<!DOCTYPE a [<!ENTITY t \"1\t2&#9;\">]><a v=\"&t;&lt;\"/>";
        assert_eq!(events_with(xml, DTD)[0], "start a [v=\"1 2 <\"] @1:53");
    }

    #[test]
    fn internal_subset_processing_instructions_are_reported() {
        let xml = "<!DOCTYPE a PUBLIC \"-//x//y\" 'a.dtd' [<?pi d?><!-- c --><!ENTITY % p \"x\">%p;]><a/>";
        let ev = events_with(xml, DTD);
        assert_eq!(ev[0], "pi pi \"d\"");
        assert_eq!(ev[1], "start a [] @1:83");
    }

    #[test]
    fn more_well_formedness_errors() {
        assert!(error("<a x=\"1\"y=\"2\"/>").contains("must be followed by either attribute"));
        assert!(error("<a x/>").contains("must be followed by the ' = ' character"));
        assert!(error("<a>&</a>").contains("entity name must immediately follow the '&'"));
        assert!(error("<a>&x </a>").contains("reference to entity \"x\" must end with the ';'"));
        assert!(error("<a><![CDATA[x</a>").contains("CDATA section must end with"));
        assert!(error("<a><!FOO></a>").contains("content of elements must consist"));
        assert!(error("<a>< b/></a>").contains("content of elements must consist"));
        assert!(error("&lt;<a/>").contains("Content is not allowed in prolog."));
        assert!(error(" <?xml version=\"1.0\"?><a/>").contains("[xX][mM][lL]"));
        assert!(error("<?xml version=\"1.0\" bogus=\"1\"?><a/>").contains("\"bogus\" is not allowed"));
        assert!(error("<a/></a>").contains("following the root element must be well-formed"));
        assert!(error("<a><!-- x").contains("XML document structures must start and end"));
        let twice = "<!DOCTYPE a><!DOCTYPE a><a/>";
        assert!(error_with(twice.as_bytes(), DTD).contains("Already seen doctype."));
    }

    #[test]
    fn xml_declaration_requires_version() {
        assert!(error("<?xml encoding=\"UTF-8\"?><a/>").contains("version is required"));
    }

    #[test]
    fn handler_errors_stop_the_parse() {
        struct Stop;
        impl SaxContentHandler for Stop {
            fn start_element(
                &mut self,
                _: &str,
                _: Vec<(String, String)>,
                _: SaxLocation,
            ) -> Result<(), SaxError> {
                Err(SaxError::Handler(XmlError::new("stop")))
            }
            fn end_element(&mut self, _: &str, _: SaxLocation) -> Result<(), SaxError> {
                panic!("not reached")
            }
            fn characters(&mut self, _: &str) -> Result<(), SaxError> {
                Ok(())
            }
            fn processing_instruction(&mut self, _: &str, _: &str) -> Result<(), SaxError> {
                Ok(())
            }
        }
        match parse(b"<a/>", SaxConfig::default(), &mut Stop) {
            Err(SaxError::Handler(e)) => assert_eq!(e.message(), "stop"),
            other => panic!("{other:?}"),
        }
    }
}
