//! A small, non-validating, SAX-style XML reader.
//!
//! Ghidra's pull parsers ([`NonThreadedXmlPullParserImpl`] and [`ThreadedXmlPullParserImpl`])
//! sit on top of the JDK's `javax.xml.parsers.SAXParser`, configured by
//! `XmlUtilities.createSecureSAXParserFactory` with namespace processing off and external
//! entities disabled. This crate has no XML dependency, so this module supplies the SAX layer
//! those two ports need: it is not the port of a Ghidra class, it stands in for the JDK.
//!
//! # Supported subset
//!
//! The reader handles what Ghidra's own XML (`.ldefs`, `.pspec`, `.cspec`, `.opinion`, pattern
//! files, program XML exports) uses, and reports a fatal error for anything malformed:
//!
//! * the XML declaration, with `UTF-8`, `US-ASCII` or `ISO-8859-1` encodings, plus a UTF-8 or
//!   UTF-16 byte-order mark;
//! * elements and attributes with names taken verbatim (namespaces off, so `xmlns` and prefixed
//!   names are ordinary attributes/names, as with Java's `namespaces` feature set to `false`);
//! * character data, CDATA sections, comments and processing instructions;
//! * the five predefined entities and decimal/hex character references;
//! * `<!DOCTYPE>` (only when [`SaxConfig::allow_doctype`] is set, mirroring Java's
//!   `disallow-doctype-decl` feature): the external subset is never loaded (Java's
//!   `load-external-dtd` is off), internal general entities declared in the internal subset are
//!   expanded, and external entities are skipped rather than fetched (Java's
//!   `external-general-entities` is off). Other markup declarations (`ELEMENT`, `ATTLIST`,
//!   `NOTATION`, parameter entities) are skipped without being interpreted, so ATTLIST defaults
//!   are not applied.
//! * line-end normalization (`\r\n` and lone `\r` become `\n`) and attribute-value
//!   normalization (literal tab/newline/return become a space).
//!
//! As with `FEATURE_SECURE_PROCESSING`, entity expansion is capped at
//! [`ENTITY_EXPANSION_LIMIT`] expansions per document.
//!
//! DTD validation is not supported; the pull parsers reject `validate == true` up front.
//!
//! Locations follow Xerces' `Locator`: 1-based line, and a 1-based column pointing just past
//! the markup that produced the event (so `<a>` at the start of a line reports column 4).
//!
//! [`NonThreadedXmlPullParserImpl`]: super::non_threaded_xml_pull_parser_impl::NonThreadedXmlPullParserImpl
//! [`ThreadedXmlPullParserImpl`]: super::threaded_xml_pull_parser_impl::ThreadedXmlPullParserImpl

use std::collections::HashMap;
use std::fmt;

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
    let chars = decode(input)?;
    let mut parser = Parser {
        frames: vec![Frame { chars, pos: 0, entity: None }],
        line: 1,
        column: 1,
        handler,
        config,
        entities: HashMap::new(),
        has_unread_declarations: false,
        expansions: 0,
        text: String::new(),
    };
    parser.check_characters()?;
    parser.parse_document()
}

fn fatal_at(line: i32, column: i32, message: impl Into<String>) -> SaxError {
    SaxError::Fatal { line, column, message: message.into() }
}

/// Decodes `input` to characters, normalizing line ends.
fn decode(input: &[u8]) -> Result<Vec<char>, SaxError> {
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
    let mut out = Vec::with_capacity(text.len());
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
            Err(fatal_at(
                line,
                column,
                "Invalid byte 1 of 1-byte UTF-8 sequence.".to_string(),
            ))
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

/// A declared general entity.
enum EntityDecl {
    /// An internal entity with its replacement text (character references already expanded).
    Internal(Vec<char>),
    /// An external entity; never fetched.
    External,
}

/// One level of input: the document itself, or the replacement text of an entity being
/// expanded.
struct Frame {
    chars: Vec<char>,
    pos: usize,
    entity: Option<String>,
}

struct Parser<'h, H> {
    frames: Vec<Frame>,
    line: i32,
    column: i32,
    handler: &'h mut H,
    config: SaxConfig,
    entities: HashMap<String, EntityDecl>,
    /// Set when the DTD has an external subset or parameter-entity references that were not
    /// read; undeclared entities are then skipped instead of being fatal (XML 1.0 WFC:
    /// Entity Declared).
    has_unread_declarations: bool,
    expansions: usize,
    /// Pending character data, flushed before the next non-character event.
    text: String,
}

impl<H: SaxContentHandler> Parser<'_, H> {
    // ---- input primitives -------------------------------------------------------------

    fn top(&self) -> &Frame {
        self.frames.last().expect("at least the document frame")
    }

    fn peek(&self) -> Option<char> {
        let f = self.top();
        f.chars.get(f.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        let f = self.top();
        f.chars.get(f.pos + offset).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        s.chars().enumerate().all(|(i, c)| self.peek_at(i) == Some(c))
    }

    fn advance(&mut self) -> Option<char> {
        let at_document = self.frames.len() == 1;
        let f = self.frames.last_mut().expect("at least the document frame");
        let c = f.chars.get(f.pos).copied()?;
        f.pos += 1;
        if at_document {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        Some(c)
    }

    fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.advance();
        }
    }

    fn location(&self) -> SaxLocation {
        SaxLocation { line: self.line, column: self.column }
    }

    fn fatal(&self, message: impl Into<String>) -> SaxError {
        fatal_at(self.line, self.column, message)
    }

    fn eof_error(&self) -> SaxError {
        if self.frames.len() > 1 {
            self.fatal("The entity replacement text must contain complete markup.")
        } else {
            self.fatal("XML document structures must start and end within the same entity.")
        }
    }

    /// Skips whitespace; returns whether any was skipped.
    fn skip_whitespace(&mut self) -> bool {
        let mut any = false;
        while self.peek().is_some_and(is_whitespace) {
            self.advance();
            any = true;
        }
        any
    }

    fn require_whitespace(&mut self, context: &str) -> Result<(), SaxError> {
        if self.skip_whitespace() {
            Ok(())
        } else {
            Err(self.fatal(format!("White space is required {context}.")))
        }
    }

    fn expect(&mut self, s: &str, context: &str) -> Result<(), SaxError> {
        if self.starts_with(s) {
            self.skip(s.chars().count());
            Ok(())
        } else if self.peek().is_none() {
            Err(self.eof_error())
        } else {
            Err(self.fatal(format!("{context} must end with the '{s}' delimiter.")))
        }
    }

    fn read_name(&mut self, context: &str) -> Result<String, SaxError> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            None => return Err(self.eof_error()),
            Some(_) => return Err(self.fatal(format!("{context} must be a valid XML name."))),
        }
        let mut name = String::new();
        while let Some(c) = self.peek().filter(|c| is_name_char(*c)) {
            name.push(c);
            self.advance();
        }
        Ok(name)
    }

    /// Reads a quoted literal verbatim (no reference processing).
    fn read_quoted_literal(&mut self) -> Result<String, SaxError> {
        let quote = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            None => return Err(self.eof_error()),
            Some(_) => return Err(self.fatal("A quoted string is required.")),
        };
        self.advance();
        let mut s = String::new();
        loop {
            match self.advance() {
                None => return Err(self.eof_error()),
                Some(c) if c == quote => return Ok(s),
                Some(c) => s.push(c),
            }
        }
    }

    /// Validates every character up front, reporting the first illegal one Xerces-style.
    fn check_characters(&self) -> Result<(), SaxError> {
        let mut line = 1;
        let mut column = 1;
        for &c in &self.top().chars {
            if !is_xml_char(c) {
                return Err(fatal_at(
                    line,
                    column,
                    format!(
                        "An invalid XML character (Unicode: 0x{:x}) was found in the document.",
                        c as u32
                    ),
                ));
            }
            if c == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        Ok(())
    }

    // ---- document structure -------------------------------------------------------------

    fn parse_document(&mut self) -> Result<(), SaxError> {
        if self.starts_with("<?xml") && self.peek_at(5).is_some_and(is_whitespace) {
            self.parse_xml_declaration()?;
        }

        // prolog
        let mut seen_doctype = false;
        loop {
            self.skip_whitespace();
            if self.peek().is_none() {
                return Err(self.fatal("Premature end of file."));
            } else if self.starts_with("<?") {
                self.parse_processing_instruction()?;
            } else if self.starts_with("<!--") {
                self.parse_comment()?;
            } else if self.starts_with("<!DOCTYPE") {
                if seen_doctype {
                    return Err(self.fatal("Already seen doctype."));
                }
                seen_doctype = true;
                self.parse_doctype()?;
            } else if self.starts_with("<") {
                break;
            } else {
                return Err(self.fatal("Content is not allowed in prolog."));
            }
        }

        self.parse_root_element()?;

        // epilog
        loop {
            self.skip_whitespace();
            if self.peek().is_none() {
                return Ok(());
            } else if self.starts_with("<?") {
                self.parse_processing_instruction()?;
            } else if self.starts_with("<!--") {
                self.parse_comment()?;
            } else if self.starts_with("<") && self.peek_at(1).is_some_and(is_name_start) {
                return Err(self.fatal(
                    "The markup in the document following the root element must be well-formed.",
                ));
            } else {
                return Err(self.fatal("Content is not allowed in trailing section."));
            }
        }
    }

    fn parse_xml_declaration(&mut self) -> Result<(), SaxError> {
        self.skip(5); // "<?xml"
        let mut saw_version = false;
        loop {
            let had_space = self.skip_whitespace();
            if self.starts_with("?>") {
                self.skip(2);
                break;
            }
            if self.peek().is_none() {
                return Err(self.eof_error());
            }
            if !had_space {
                return Err(self.fatal(
                    "White space is required before the pseudo attribute in the XML declaration.",
                ));
            }
            let name = self.read_name("The pseudo attribute in the XML declaration")?;
            self.skip_whitespace();
            self.expect("=", "The pseudo attribute in the XML declaration")?;
            self.skip_whitespace();
            let _value = self.read_quoted_literal()?;
            match name.as_str() {
                "version" => saw_version = true,
                "encoding" | "standalone" => {}
                _ => {
                    return Err(self.fatal(format!(
                        "The pseudo attribute \"{name}\" is not allowed in the XML declaration."
                    )));
                }
            }
        }
        if !saw_version {
            return Err(self.fatal("The version is required in the XML declaration."));
        }
        Ok(())
    }

    fn parse_processing_instruction(&mut self) -> Result<(), SaxError> {
        self.skip(2); // "<?"
        let target = self.read_name("The processing instruction target")?;
        if target.eq_ignore_ascii_case("xml") {
            return Err(self.fatal(
                "The processing instruction target matching \"[xX][mM][lL]\" is not allowed.",
            ));
        }
        let mut data = String::new();
        if !self.starts_with("?>") {
            self.require_whitespace("between the processing instruction target and data")?;
            while !self.starts_with("?>") {
                match self.advance() {
                    None => return Err(self.eof_error()),
                    Some(c) => data.push(c),
                }
            }
        }
        self.skip(2);
        self.flush_text()?;
        self.handler.processing_instruction(&target, &data)
    }

    fn parse_comment(&mut self) -> Result<(), SaxError> {
        self.skip(4); // "<!--"
        loop {
            if self.starts_with("--") {
                self.skip(2);
                if self.peek() == Some('>') {
                    self.advance();
                    return Ok(());
                }
                return Err(self.fatal("The string \"--\" is not permitted within comments."));
            }
            if self.advance().is_none() {
                return Err(self.eof_error());
            }
        }
    }

    fn parse_doctype(&mut self) -> Result<(), SaxError> {
        if !self.config.allow_doctype {
            return Err(self.fatal(
                "DOCTYPE is disallowed when the feature \
                 \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.",
            ));
        }
        self.skip("<!DOCTYPE".len());
        self.require_whitespace("after \"<!DOCTYPE\" in the document type declaration")?;
        self.read_name("The root element type in the document type declaration")?;
        self.skip_whitespace();
        if self.starts_with("SYSTEM") || self.starts_with("PUBLIC") {
            self.parse_external_id()?;
            // Java's `load-external-dtd` is off: the external subset is never read.
            self.has_unread_declarations = true;
            self.skip_whitespace();
        }
        if self.peek() == Some('[') {
            self.advance();
            self.parse_internal_subset()?;
            self.skip_whitespace();
        }
        self.expect(">", "The document type declaration")
    }

    /// Parses `SYSTEM "sys"` or `PUBLIC "pub" "sys"`.
    fn parse_external_id(&mut self) -> Result<(), SaxError> {
        if self.starts_with("SYSTEM") {
            self.skip(6);
            self.require_whitespace("before the system identifier")?;
            self.read_quoted_literal()?;
        } else {
            self.skip(6);
            self.require_whitespace("before the public identifier")?;
            self.read_quoted_literal()?;
            self.require_whitespace("between the public and system identifiers")?;
            self.read_quoted_literal()?;
        }
        Ok(())
    }

    fn parse_internal_subset(&mut self) -> Result<(), SaxError> {
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Err(self.eof_error()),
                Some(']') => {
                    self.advance();
                    return Ok(());
                }
                Some('%') => {
                    // Parameter-entity reference: not expanded, so later declarations may be
                    // missing.
                    self.advance();
                    self.read_name("The parameter entity reference")?;
                    self.expect(";", "The parameter entity reference")?;
                    self.has_unread_declarations = true;
                }
                Some('<') => {
                    if self.starts_with("<!--") {
                        self.parse_comment()?;
                    } else if self.starts_with("<?") {
                        self.parse_processing_instruction()?;
                    } else if self.starts_with("<!ENTITY") {
                        self.parse_entity_declaration()?;
                    } else if self.starts_with("<!") {
                        self.skip_markup_declaration()?;
                    } else {
                        return Err(self.fatal(
                            "The markup declarations contained or pointed to by the document \
                             type declaration must be well-formed.",
                        ));
                    }
                }
                Some(_) => {
                    return Err(self.fatal(
                        "The markup declarations contained or pointed to by the document type \
                         declaration must be well-formed.",
                    ));
                }
            }
        }
    }

    /// Skips an `ELEMENT`/`ATTLIST`/`NOTATION` declaration (or a parameter-entity
    /// declaration), honoring quoted strings.
    fn skip_markup_declaration(&mut self) -> Result<(), SaxError> {
        self.skip(2); // "<!"
        loop {
            match self.peek() {
                None => return Err(self.eof_error()),
                Some('>') => {
                    self.advance();
                    return Ok(());
                }
                Some('"' | '\'') => {
                    self.read_quoted_literal()?;
                }
                Some(_) => {
                    self.advance();
                }
            }
        }
    }

    fn parse_entity_declaration(&mut self) -> Result<(), SaxError> {
        self.skip("<!ENTITY".len());
        self.require_whitespace("after \"<!ENTITY\" in the entity declaration")?;
        if self.peek() == Some('%') {
            // Parameter entity: consumed but not interpreted.
            loop {
                match self.peek() {
                    None => return Err(self.eof_error()),
                    Some('>') => {
                        self.advance();
                        return Ok(());
                    }
                    Some('"' | '\'') => {
                        self.read_quoted_literal()?;
                    }
                    Some(_) => {
                        self.advance();
                    }
                }
            }
        }
        let name = self.read_name("The entity name in the entity declaration")?;
        self.require_whitespace("after the entity name in the entity declaration")?;
        let decl = if self.starts_with("SYSTEM") || self.starts_with("PUBLIC") {
            self.parse_external_id()?;
            let had_space = self.skip_whitespace();
            if had_space && self.starts_with("NDATA") {
                self.skip(5);
                self.require_whitespace("before the notation name")?;
                self.read_name("The notation name")?;
                self.skip_whitespace();
            }
            EntityDecl::External
        } else {
            let literal = self.read_quoted_literal()?;
            self.skip_whitespace();
            EntityDecl::Internal(self.expand_character_references(&literal)?)
        };
        self.expect(">", "The declaration for the entity")?;
        // The first declaration is binding; predefined entities cannot be redefined usefully.
        if predefined_entity(&name).is_none() {
            self.entities.entry(name).or_insert(decl);
        }
        Ok(())
    }

    /// Expands character references in an entity value literal (they are expanded at
    /// declaration time; general entity references are left for use time).
    fn expand_character_references(&self, literal: &str) -> Result<Vec<char>, SaxError> {
        let mut out = Vec::with_capacity(literal.len());
        let chars: Vec<char> = literal.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '&' && chars.get(i + 1) == Some(&'#') {
                let end = chars[i..]
                    .iter()
                    .position(|c| *c == ';')
                    .map(|p| p + i)
                    .ok_or_else(|| self.fatal("The character reference must end with the ';' delimiter."))?;
                let body: String = chars[i + 2..end].iter().collect();
                out.push(self.character_reference_value(&body)?);
                i = end + 1;
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        Ok(out)
    }

    /// Decodes the body of `&#...;` (the part after `#`).
    fn character_reference_value(&self, body: &str) -> Result<char, SaxError> {
        let value = if let Some(hex) = body.strip_prefix('x') {
            if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(self.fatal(
                    "A hexadecimal representation must immediately follow the \"&#x\" in a \
                     character reference.",
                ));
            }
            u32::from_str_radix(hex, 16).ok()
        } else {
            if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit()) {
                return Err(self.fatal(
                    "A decimal representation must immediately follow the \"&#\" in a character \
                     reference.",
                ));
            }
            body.parse::<u32>().ok()
        };
        match value.and_then(char::from_u32).filter(|c| is_xml_char(*c)) {
            Some(c) => Ok(c),
            None => Err(self.fatal(format!(
                "Character reference \"&#{body}\" is an invalid XML character."
            ))),
        }
    }

    // ---- elements -----------------------------------------------------------------------

    fn flush_text(&mut self) -> Result<(), SaxError> {
        if self.text.is_empty() {
            return Ok(());
        }
        let text = std::mem::take(&mut self.text);
        self.handler.characters(&text)
    }

    /// Parses a start tag (the `<` is next). Returns the element name and whether it was an
    /// empty-element tag.
    fn parse_start_tag(&mut self) -> Result<(String, bool), SaxError> {
        self.advance(); // '<'
        let name = self.read_name("The element type")?;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let empty = loop {
            let had_space = self.skip_whitespace();
            match self.peek() {
                None => return Err(self.eof_error()),
                Some('>') => {
                    self.advance();
                    break false;
                }
                Some('/') => {
                    self.advance();
                    if self.peek() != Some('>') {
                        return Err(self.fatal(format!(
                            "Element type \"{name}\" must be followed by either attribute \
                             specifications, \">\" or \"/>\"."
                        )));
                    }
                    self.advance();
                    break true;
                }
                Some(c) if had_space && is_name_start(c) => {
                    let attr = self.read_name("The attribute name")?;
                    self.skip_whitespace();
                    if self.peek() != Some('=') {
                        return Err(self.fatal(format!(
                            "Attribute name \"{attr}\" associated with an element type \
                             \"{name}\" must be followed by the ' = ' character."
                        )));
                    }
                    self.advance();
                    self.skip_whitespace();
                    let value = self.parse_attribute_value(&name, &attr)?;
                    if attributes.iter().any(|(k, _)| *k == attr) {
                        return Err(self.fatal(format!(
                            "Attribute \"{attr}\" was already specified for element \"{name}\"."
                        )));
                    }
                    attributes.push((attr, value));
                }
                Some(_) => {
                    return Err(self.fatal(format!(
                        "Element type \"{name}\" must be followed by either attribute \
                         specifications, \">\" or \"/>\"."
                    )));
                }
            }
        };
        self.flush_text()?;
        let location = self.location();
        self.handler.start_element(&name, attributes, location)?;
        if empty {
            self.handler.end_element(&name, location)?;
        }
        Ok((name, empty))
    }

    fn parse_attribute_value(&mut self, element: &str, attr: &str) -> Result<String, SaxError> {
        let quote = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            None => return Err(self.eof_error()),
            Some(_) => {
                return Err(self.fatal(format!(
                    "Open quote is expected for attribute \"{attr}\" associated with an element \
                     type \"{element}\"."
                )));
            }
        };
        self.advance();
        let base_depth = self.frames.len();
        let mut value = String::new();
        loop {
            if self.frames.len() > base_depth && self.peek().is_none() {
                self.frames.pop();
                continue;
            }
            let c = match self.advance() {
                None => return Err(self.eof_error()),
                Some(c) => c,
            };
            let in_base = self.frames.len() == base_depth;
            match c {
                c if c == quote && in_base => return Ok(value),
                '<' => {
                    return Err(self.fatal(format!(
                        "The value of attribute \"{attr}\" associated with an element type \
                         \"{element}\" must not contain the '<' character."
                    )));
                }
                '&' => {
                    if self.peek() == Some('#') {
                        value.push(self.parse_character_reference_body()?);
                    } else {
                        let name = self.read_name("The entity name")?;
                        self.expect(";", &format!("The reference to entity \"{name}\""))?;
                        if let Some(c) = predefined_entity(&name) {
                            value.push(c);
                        } else {
                            match self.entities.get(&name) {
                                Some(EntityDecl::Internal(text)) => {
                                    let text = text.clone();
                                    self.push_entity(name, text)?;
                                }
                                Some(EntityDecl::External) => {
                                    return Err(self.fatal(format!(
                                        "The external entity reference \"&{name};\" is not \
                                         permitted in an attribute value."
                                    )));
                                }
                                None => self.undeclared_entity(&name)?,
                            }
                        }
                    }
                }
                '\t' | '\n' | '\r' => value.push(' '),
                c => value.push(c),
            }
        }
    }

    /// Parses a character reference after its `&` (the `#` is next).
    fn parse_character_reference_body(&mut self) -> Result<char, SaxError> {
        self.advance(); // '#'
        let mut body = String::new();
        loop {
            match self.advance() {
                None => return Err(self.eof_error()),
                Some(';') => break,
                Some(c) if c.is_ascii_alphanumeric() => body.push(c),
                Some(_) => {
                    return Err(
                        self.fatal("The character reference must end with the ';' delimiter.")
                    );
                }
            }
        }
        self.character_reference_value(&body)
    }

    fn push_entity(&mut self, name: String, text: Vec<char>) -> Result<(), SaxError> {
        if self.frames.iter().any(|f| f.entity.as_deref() == Some(name.as_str())) {
            return Err(self.fatal(format!("Recursive entity reference \"{name}\".")));
        }
        self.expansions += 1;
        if self.expansions > ENTITY_EXPANSION_LIMIT {
            return Err(self.fatal(format!(
                "JAXP00010001: The parser has encountered more than \"{ENTITY_EXPANSION_LIMIT}\" \
                 entity expansions in this document; this is the limit imposed by the JDK."
            )));
        }
        self.frames.push(Frame { chars: text, pos: 0, entity: Some(name) });
        Ok(())
    }

    fn undeclared_entity(&self, name: &str) -> Result<(), SaxError> {
        if self.has_unread_declarations {
            // May have been declared in the unread external subset: skipped.
            Ok(())
        } else {
            Err(self.fatal(format!("The entity \"{name}\" was referenced, but not declared.")))
        }
    }

    fn parse_root_element(&mut self) -> Result<(), SaxError> {
        let (root, empty) = self.parse_start_tag()?;
        if empty {
            return Ok(());
        }
        let mut open: Vec<(String, usize)> = vec![(root, self.frames.len())];
        while !open.is_empty() {
            if self.peek().is_none() {
                if self.frames.len() > 1 {
                    let depth = self.frames.len();
                    if open.last().is_some_and(|(_, d)| *d == depth) {
                        return Err(self.fatal(
                            "The entity replacement text must contain complete markup.",
                        ));
                    }
                    self.frames.pop();
                    continue;
                }
                return Err(self.eof_error());
            }
            if self.starts_with("</") {
                self.skip(2);
                let name = self.read_name("The element type")?;
                self.skip_whitespace();
                let (expected, depth) = open.last().expect("non-empty").clone();
                if name != expected {
                    return Err(self.fatal(format!(
                        "The element type \"{expected}\" must be terminated by the matching \
                         end-tag \"</{expected}>\"."
                    )));
                }
                if depth != self.frames.len() {
                    return Err(
                        self.fatal("The entity replacement text must contain complete markup.")
                    );
                }
                self.expect(">", &format!("The end-tag for element type \"{name}\""))?;
                open.pop();
                self.flush_text()?;
                let location = self.location();
                self.handler.end_element(&name, location)?;
            } else if self.starts_with("<!--") {
                self.parse_comment()?;
            } else if self.starts_with("<![CDATA[") {
                self.skip("<![CDATA[".len());
                loop {
                    if self.starts_with("]]>") {
                        self.skip(3);
                        break;
                    }
                    match self.advance() {
                        None => {
                            return Err(self.fatal("The CDATA section must end with \"]]>\"."));
                        }
                        Some(c) => self.text.push(c),
                    }
                }
            } else if self.starts_with("<?") {
                self.parse_processing_instruction()?;
            } else if self.starts_with("<!") {
                return Err(self.fatal("The content of elements must consist of well-formed \
                                       character data or markup."));
            } else if self.peek() == Some('<') {
                let (name, empty) = self.parse_start_tag()?;
                if !empty {
                    open.push((name, self.frames.len()));
                }
            } else if self.peek() == Some('&') {
                self.advance();
                if self.peek() == Some('#') {
                    let c = self.parse_character_reference_body()?;
                    self.text.push(c);
                } else {
                    let name = self.read_name("The entity name")?;
                    self.expect(";", &format!("The reference to entity \"{name}\""))?;
                    if let Some(c) = predefined_entity(&name) {
                        self.text.push(c);
                    } else {
                        match self.entities.get(&name) {
                            Some(EntityDecl::Internal(text)) => {
                                let text = text.clone();
                                self.push_entity(name, text)?;
                            }
                            // External entities are not fetched (Java's
                            // external-general-entities feature is off): skipped.
                            Some(EntityDecl::External) => {}
                            None => self.undeclared_entity(&name)?,
                        }
                    }
                }
            } else if self.starts_with("]]>") {
                return Err(self.fatal(
                    "The character sequence \"]]>\" must not appear in content unless used to \
                     mark the end of a CDATA section.",
                ));
            } else if let Some(c) = self.advance() {
                self.text.push(c);
            }
        }
        Ok(())
    }
}

fn predefined_entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
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
