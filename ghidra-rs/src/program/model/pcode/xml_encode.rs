//! Port of `ghidra.program.model.pcode.XmlEncode`.
//!
//! An XML based [`Encoder`]/[`CachedEncoder`]: the human-readable, plain-text counterpart to
//! [`PackedEncode`](super::packed::PackedEncode) (a binary wire format). The encoder accumulates a
//! plain-text XML document in an in-memory buffer (Java's `StringBuilder`, here a `String`) as
//! calls are made on it.
//!
//! ## Tag-writing state machine
//!
//! Java tracks a small three-state machine (`TAG_START`/`TAG_CONTENT`/`TAG_STOP`) recording
//! whether an element's opening `<tag` has been written but not yet closed with `>` (`TAG_START`,
//! meaning attributes can still be appended), whether text content has just been written
//! (`TAG_CONTENT`), or whether no element tag is "in progress" (`TAG_STOP`). This determines,
//! e.g., whether `closeElement` emits a self-closing `/>` (no content or children were ever
//! written) or a full `</tag>`, and whether a leading `>` needs to be appended before the first
//! attribute/content write for an element. Ported here as the [`TagStatus`] enum rather than the
//! raw `int` constants, for clarity; the state transitions are otherwise a literal, line-by-line
//! port.
//!
//! ## Quirk: `writeSpace(AttributeId, int, String)` silently ignores its `index` parameter
//!
//! Java's `Encoder.writeSpace(AttributeId, int index, String name)` interface method exists to
//! write an address space "by name and unique index" (see `Encoder.java`'s doc comment). But
//! `XmlEncode`'s implementation of it never reads `index` at all -- the XML text only ever
//! contains `name`. This is faithfully reproduced in
//! [`write_space_indexed`](XmlEncode::write_space_indexed) (the `index` parameter is accepted,
//! per the trait signature, but never consulted), rather than "fixing" it to somehow encode the
//! index too.
//!
//! ## Quirk: `writeOpcode` on `OpCode.CPUI_MAX` writes the literal text `"null"`
//!
//! `ghidra.pcodeCPort.opcodes.OpCode.CPUI_MAX` is constructed with a `null` name (`CPUI_MAX(null)`
//! in the enum body), and `OpCode.getName()` returns that `null` verbatim. Java's
//! `StringBuilder.append(String)` treats a `null` argument specially: rather than throwing, it
//! appends the four literal characters `null`. So encoding `CPUI_MAX` via `writeOpcode` produces
//! the text `null` in the output XML, not an empty string or an error. Reproduced here via
//! `opcode.name().unwrap_or("null")`, matching this crate's established idiom for the same
//! Java-string-concatenation-with-null pattern elsewhere (see e.g. `address_xml.rs`).
//!
//! ## Quirk: `writeOpcode(AttributeId, int)` on an out-of-range ordinal panics like Java's IOOBE
//!
//! `ghidra.pcodeCPort.opcodes.OpCode.getOpcode(int)` does `opsByOrdinal.get(ordinal)` with no
//! bounds check, throwing `IndexOutOfBoundsException` for an invalid ordinal. This crate's
//! [`OpCode::from_ordinal`] returns `None` instead of panicking for the same input; this port
//! faithfully reproduces the Java crash by panicking (rather than silently swallowing the error)
//! when `from_ordinal` returns `None` -- see
//! [`write_opcode_ordinal_out_of_range_panics_like_java_ioobe`] below.

use super::ids::ATTRIB_CONTENT;
use super::{AttributeId, CachedEncoder, ElementId, Encoder};
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::util::xml::spec_xml_utils::xml_escape;
use std::io;

/// Port of the private `TAG_START`/`TAG_CONTENT`/`TAG_STOP` `int` constants. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagStatus {
    /// Tag has been opened; attributes can still be written. Port of `TAG_START`.
    Start,
    /// Opening tag and content have been written. Port of `TAG_CONTENT`.
    Content,
    /// No tag is currently being written. Port of `TAG_STOP`.
    Stop,
}

/// Port of the private `static final char[] spaces` table: a leading newline followed by 24
/// spaces, used by [`XmlEncode::new_line`] to indent by up to 24 characters (12 levels of 2-space
/// indentation) after a newline.
const SPACES: [char; 25] = [
    '\n', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ',
];

/// An XML based encoder. Port of `ghidra.program.model.pcode.XmlEncode`. See the module docs for
/// the tag-writing state machine and the real Java quirks reproduced here.
pub struct XmlEncode {
    /// Buffer accumulating the document characters. Port of the private `buffer` field
    /// (`StringBuilder` in Java).
    buffer: String,
    /// Stage of writing an element tag. Port of the private `tagStatus` field.
    tag_status: TagStatus,
    /// Depth of open elements. Port of the private `depth` field.
    depth: i32,
    /// `true` if the encoder should indent and emit newlines. Port of the private `doFormatting`
    /// field.
    do_formatting: bool,
}

impl XmlEncode {
    /// Port of `XmlEncode()`: formatting (indentation/newlines) on by default.
    pub fn new() -> Self {
        Self::with_formatting(true)
    }

    /// Port of `XmlEncode(boolean doFormat)`.
    pub fn with_formatting(do_format: bool) -> Self {
        Self {
            buffer: String::new(),
            tag_status: TagStatus::Stop,
            depth: 0,
            do_formatting: do_format,
        }
    }

    /// Port of the private `XmlEncode.newLine()`.
    fn new_line(&mut self) {
        if !self.do_formatting {
            return;
        }
        let mut num_spaces = (self.depth * 2 + 1).max(0) as usize;
        if num_spaces > SPACES.len() {
            num_spaces = SPACES.len();
        }
        self.buffer.push_str(&SPACES[0..num_spaces].iter().collect::<String>());
    }
}

impl Default for XmlEncode {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for XmlEncode {
    /// Port of `XmlEncode.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.buffer)
    }
}

impl Encoder for XmlEncode {
    /// Port of `XmlEncode.openElement(ElementId)`.
    fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        if self.tag_status == TagStatus::Start {
            self.buffer.push('>');
        } else {
            self.tag_status = TagStatus::Start;
        }
        self.new_line();
        self.buffer.push('<');
        self.buffer.push_str(elem_id.name);
        self.depth += 1;
        Ok(())
    }

    /// Port of `XmlEncode.closeElement(ElementId)`.
    fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        self.depth -= 1;
        if self.tag_status == TagStatus::Start {
            self.buffer.push_str("/>");
            self.tag_status = TagStatus::Stop;
            return Ok(());
        }
        if self.tag_status != TagStatus::Content {
            self.new_line();
        } else {
            self.tag_status = TagStatus::Stop;
        }
        self.buffer.push_str("</");
        self.buffer.push_str(elem_id.name);
        self.buffer.push('>');
        Ok(())
    }

    /// Port of `XmlEncode.writeBool(AttributeId, boolean)`.
    fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
        let text = if val { "true" } else { "false" };
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            self.buffer.push_str(text);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        self.buffer.push_str(text);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeSignedInteger(AttributeId, long)`.
    fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
        let text = val.to_string();
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            self.buffer.push_str(&text);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        self.buffer.push_str(&text);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeUnsignedInteger(AttributeId, long)`. Written as `0x`-prefixed hex,
    /// matching `Long.toHexString(val)` (an unsigned hex rendering of the 64-bit magnitude).
    fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
        let text = format!("0x{:x}", val);
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            self.buffer.push_str(&text);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        self.buffer.push_str(&text);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeString(AttributeId, String)`.
    fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            xml_escape(&mut self.buffer, val);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        xml_escape(&mut self.buffer, val);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeStringIndexed(AttributeId, int, String)`. Unlike the other
    /// `write*` methods, there is no `ATTRIB_CONTENT` special case here -- Java's implementation
    /// always writes this as an attribute, never as element content.
    fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str(&(index + 1).to_string());
        self.buffer.push_str("=\"");
        xml_escape(&mut self.buffer, val);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeSpace(AttributeId, AddressSpace)`.
    fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
        let spc_name: &str = if spc.space_type() == AddressSpaceType::Variable {
            "join"
        } else {
            spc.name()
        };
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            xml_escape(&mut self.buffer, spc_name);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        xml_escape(&mut self.buffer, spc_name);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeSpace(AttributeId, int, String)`. See the module docs: `index` is
    /// accepted per the trait signature but never consulted, faithfully matching Java.
    fn write_space_indexed(&mut self, attrib_id: AttributeId, _index: i32, name: &str) -> io::Result<()> {
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            xml_escape(&mut self.buffer, name);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        xml_escape(&mut self.buffer, name);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeOpcode(AttributeId, OpCode)`. See the module docs for the real
    /// `CPUI_MAX`-writes-the-literal-text-`"null"` quirk. Note (unlike every other `write*`
    /// method here) the opcode name is written verbatim, with no `xmlEscape` call, matching Java.
    fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()> {
        let name = opcode.name().unwrap_or("null");
        if attrib_id == ATTRIB_CONTENT {
            if self.tag_status == TagStatus::Start {
                self.buffer.push('>');
            }
            self.buffer.push_str(name);
            self.tag_status = TagStatus::Content;
            return Ok(());
        }
        self.buffer.push(' ');
        self.buffer.push_str(attrib_id.name);
        self.buffer.push_str("=\"");
        self.buffer.push_str(name);
        self.buffer.push('"');
        Ok(())
    }

    /// Port of `XmlEncode.writeOpcode(AttributeId, int)`.
    ///
    /// # Panics
    /// See the module docs: an out-of-range `opcode` ordinal panics, faithfully matching real
    /// Java's `IndexOutOfBoundsException` from `OpCode.getOpcode(int)`'s unchecked `List.get`.
    fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()> {
        let op = OpCode::from_ordinal(opcode as usize).unwrap_or_else(|| {
            panic!(
                "XmlEncode.writeOpcode: opcode ordinal {opcode} out of range (real Java throws \
                 IndexOutOfBoundsException from OpCode.getOpcode(int) here too)"
            )
        });
        self.write_opcode(attrib_id, op)
    }
}

impl CachedEncoder for XmlEncode {
    /// Port of `XmlEncode.clear()`.
    fn clear(&mut self) {
        self.buffer.clear();
        self.tag_status = TagStatus::Stop;
        self.depth = 0;
    }

    /// Port of `XmlEncode.isEmpty()`.
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Port of `XmlEncode.writeTo(OutputStream)`.
    fn write_to(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        writer.write_all(self.buffer.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::pcode::ids::{ATTRIB_NAME, ATTRIB_VAL, ELEM_ADDR, ELEM_DATA};
    use std::io::Cursor;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn join_space() -> AddressSpace {
        // A bare (unregistered) AddressSpace of TYPE_VARIABLE, matching how other tests in this
        // crate build a "join" space value directly (factories reject registering one; see
        // `packed.rs`'s test module comment).
        (*AddressSpace::new("join", 0, 1, AddressSpaceType::Variable, 0)).clone()
    }

    #[test]
    fn new_encoder_is_empty_and_formats_by_default() {
        let enc = XmlEncode::new();
        assert!(enc.is_empty());
        assert_eq!(enc.to_string(), "");
    }

    /// A self-closing element (no attributes, no content, no children) round-trips to `<tag/>`.
    #[test]
    fn self_closing_element_round_trip() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.close_element(ELEM_DATA).unwrap();

        assert_eq!(enc.to_string(), "\n<data/>");
        assert!(!enc.is_empty());
    }

    /// An element with one attribute and text content: exact text, including the leading
    /// newline/indent from `openElement`'s formatting and the `>`/`</tag>` sequence around
    /// content.
    #[test]
    fn element_with_attribute_and_content() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_string(ATTRIB_NAME, "foo").unwrap();
        enc.write_bool(ATTRIB_CONTENT, true).unwrap();
        enc.close_element(ELEM_DATA).unwrap();

        assert_eq!(enc.to_string(), "\n<data name=\"foo\">true</data>");
    }

    /// Nested elements: the parent's opening tag is closed with a bare `>` (not `/>`) once a
    /// child element is opened, and indentation grows by two spaces per depth level.
    #[test]
    fn nested_elements_indent_by_two_spaces_per_level() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.open_element(ELEM_ADDR).unwrap();
        enc.close_element(ELEM_ADDR).unwrap();
        enc.close_element(ELEM_DATA).unwrap();

        assert_eq!(enc.to_string(), "\n<data>\n  <addr/>\n</data>");
    }

    /// With formatting disabled (`XmlEncode(false)`), no newlines/indentation are emitted at all.
    #[test]
    fn formatting_disabled_omits_newlines_and_indentation() {
        let mut enc = XmlEncode::with_formatting(false);
        enc.open_element(ELEM_DATA).unwrap();
        enc.open_element(ELEM_ADDR).unwrap();
        enc.close_element(ELEM_ADDR).unwrap();
        enc.close_element(ELEM_DATA).unwrap();

        assert_eq!(enc.to_string(), "<data><addr/></data>");
    }

    #[test]
    fn write_signed_integer_attribute_and_content() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_signed_integer(ATTRIB_VAL, -1234).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data val=\"-1234\"/>");

        let mut enc2 = XmlEncode::new();
        enc2.open_element(ELEM_DATA).unwrap();
        enc2.write_signed_integer(ATTRIB_CONTENT, 99).unwrap();
        enc2.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc2.to_string(), "\n<data>99</data>");
    }

    /// Unsigned integers are written as `0x`-prefixed hex, matching `Long.toHexString`.
    #[test]
    fn write_unsigned_integer_uses_hex_with_0x_prefix() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_unsigned_integer(ATTRIB_VAL, 0xdead_beef).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data val=\"0xdeadbeef\"/>");
    }

    /// String attribute/content values are XML-escaped.
    #[test]
    fn write_string_escapes_special_characters() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_string(ATTRIB_CONTENT, "<a&b>\"'").unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data>&lt;a&amp;b&gt;&quot;&apos;</data>");
    }

    /// `writeStringIndexed` appends `index + 1` directly to the attribute name (no separator) and
    /// always writes an attribute, never content -- even when passed `ATTRIB_CONTENT`.
    #[test]
    fn write_string_indexed_appends_one_based_index_to_attribute_name() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_string_indexed(ATTRIB_VAL, 0, "first").unwrap();
        enc.write_string_indexed(ATTRIB_VAL, 2, "third").unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data val1=\"first\" val3=\"third\"/>");
    }

    #[test]
    fn write_space_uses_real_space_name() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_space(ATTRIB_SPACE_FOR_TEST, &ram_space()).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data space=\"ram\"/>");
    }

    /// A `TYPE_VARIABLE` space is always written as the literal name `"join"`, regardless of its
    /// actual registered name -- matching Java's `AddressSpace.TYPE_VARIABLE` special case.
    #[test]
    fn write_space_maps_variable_type_to_join() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_space(ATTRIB_SPACE_FOR_TEST, &join_space()).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data space=\"join\"/>");
    }

    /// `writeSpace(AttributeId, int, String)`'s `index` parameter is accepted but never actually
    /// written -- only `name` appears in the output, regardless of what `index` is.
    #[test]
    fn write_space_indexed_ignores_index_parameter() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_space_indexed(ATTRIB_SPACE_FOR_TEST, 7, "myspace").unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data space=\"myspace\"/>");
    }

    #[test]
    fn write_opcode_writes_mnemonic_name_unescaped() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_opcode(ATTRIB_CODE_FOR_TEST, OpCode::CpuiIntAdd).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data code=\"INT_ADD\"/>");
    }

    /// See the module docs: `OpCode.CPUI_MAX` has a `null` Java name, and `StringBuilder.append`
    /// on a `null` `String` appends the literal text `"null"` -- reproduced here.
    #[test]
    fn write_opcode_on_cpui_max_writes_literal_null_text() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.write_opcode(ATTRIB_CODE_FOR_TEST, OpCode::CpuiMax).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data code=\"null\"/>");
    }

    #[test]
    fn write_opcode_ordinal_resolves_the_same_as_write_opcode() {
        let mut by_ordinal = XmlEncode::new();
        by_ordinal.open_element(ELEM_DATA).unwrap();
        by_ordinal
            .write_opcode_ordinal(ATTRIB_CODE_FOR_TEST, OpCode::CpuiIntAdd.ordinal() as i32)
            .unwrap();
        by_ordinal.close_element(ELEM_DATA).unwrap();

        let mut by_opcode = XmlEncode::new();
        by_opcode.open_element(ELEM_DATA).unwrap();
        by_opcode.write_opcode(ATTRIB_CODE_FOR_TEST, OpCode::CpuiIntAdd).unwrap();
        by_opcode.close_element(ELEM_DATA).unwrap();

        assert_eq!(by_ordinal.to_string(), by_opcode.to_string());
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn write_opcode_ordinal_out_of_range_panics_like_java_ioobe() {
        let mut enc = XmlEncode::new();
        let _ = enc.write_opcode_ordinal(ATTRIB_CODE_FOR_TEST, 9999);
    }

    #[test]
    fn clear_resets_buffer_and_tag_state() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert!(!enc.is_empty());

        enc.clear();
        assert!(enc.is_empty());
        assert_eq!(enc.to_string(), "");

        // Depth was reset too: a fresh element after clear() produces the same text as if the
        // encoder had never been used, not extra-indented as if depth carried over.
        enc.open_element(ELEM_DATA).unwrap();
        enc.close_element(ELEM_DATA).unwrap();
        assert_eq!(enc.to_string(), "\n<data/>");
    }

    #[test]
    fn write_to_writes_exact_accumulated_bytes() {
        let mut enc = XmlEncode::new();
        enc.open_element(ELEM_DATA).unwrap();
        enc.close_element(ELEM_DATA).unwrap();

        let mut out = Cursor::new(Vec::new());
        enc.write_to(&mut out).unwrap();
        assert_eq!(out.into_inner(), b"\n<data/>");
    }

    #[test]
    fn write_to_empty_encoder_writes_nothing() {
        let enc = XmlEncode::new();
        let mut out = Cursor::new(Vec::new());
        enc.write_to(&mut out).unwrap();
        assert!(out.into_inner().is_empty());
    }

    // Local aliases so the tests above read naturally without depending on exactly which
    // AttributeId constants happen to exist; these are just real AttributeIds from `ids.rs`.
    use crate::program::model::pcode::ids::{ATTRIB_CODE, ATTRIB_SPACE};
    #[allow(non_upper_case_globals)]
    const ATTRIB_SPACE_FOR_TEST: AttributeId = ATTRIB_SPACE;
    #[allow(non_upper_case_globals)]
    const ATTRIB_CODE_FOR_TEST: AttributeId = ATTRIB_CODE;
}
