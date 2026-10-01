//! The crate's canonical DOM-style XML element: the subset of `org.jdom2.Element` (plus the
//! `SAXBuilder`/`XMLOutputter` entry points Ghidra's `XmlUtilities` wraps around it) that ported
//! code builds, reads and serializes.
//!
//! Not the port of a Ghidra class -- JDOM is a third-party library. This is the one owned element
//! tree type in the crate; it is distinct from [`XmlElement`](crate::util::xml::xml_element),
//! which mirrors Ghidra's unrelated `ghidra.xml.XmlElement` pull-parser event interface, and from
//! [`XmlTreeNode`](crate::util::xml::xml_tree_node), which pairs pull-parser start/end events.
//!
//! Parsing goes through the crate's SAX layer ([`sax_parser`](crate::util::xml::sax_parser)) with
//! `<!DOCTYPE>` disallowed, as `XmlUtilities.createSecureSAXBuilder(false, false)` does.
//! Serialization follows JDOM2's `XMLOutputter`: [`Element::output_string`] uses the format of
//! `GenericXMLOutputter.getInstance()` (compact, four-space indent, normalized text, `\r\n` line
//! separators), [`Element::output_string_raw`] the default raw format of `new XMLOutputter()`.

use std::fmt;

use crate::util::xml::sax_parser::{self, SaxConfig, SaxContentHandler, SaxError, SaxLocation};

/// JDOM2's default `Format` line separator.
const LINE_SEPARATOR: &str = "\r\n";

/// One piece of an element's content, in document order.
#[derive(Debug, Clone, PartialEq)]
enum Content {
    /// Character data (`org.jdom2.Text`).
    Text(String),
    /// The child element at this index of [`Element::children`].
    Child(usize),
}

/// A DOM-style XML element: a tag name, attributes in insertion order, and mixed text/element
/// content in document order. Mirrors `org.jdom2.Element` (namespaces are not modeled; Ghidra's
/// persisted XML uses none).
///
/// `Clone` is a deep copy, mirroring `Element.clone()`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
    content: Vec<Content>,
}

/// Why XML text could not be built into an [`Element`] (JDOM's `JDOMException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JdomParseError {
    message: String,
}

impl JdomParseError {
    /// The parser's description of the problem.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for JdomParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for JdomParseError {}

impl Element {
    /// `new Element(name)`: an element with no attributes and no content.
    pub fn new(name: impl Into<String>) -> Self {
        Element { name: name.into(), ..Default::default() }
    }

    /// `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// `setAttribute(name, value)`: replaces an existing attribute of that name in place (keeping
    /// its position), otherwise appends it.
    pub fn set_attribute(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let name = name.into();
        let value = value.into();
        match self.attributes.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = value,
            None => self.attributes.push((name, value)),
        }
        self
    }

    /// `getAttributeValue(name)`.
    pub fn get_attribute_value(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// `getAttribute(name) != null`.
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|(n, _)| n == name)
    }

    /// `getAttributes()`: `(name, value)` pairs in insertion order.
    pub fn get_attributes(&self) -> &[(String, String)] {
        &self.attributes
    }

    /// `addContent(Element)`: appends `child` as the last content of this element.
    pub fn add_content(&mut self, child: Element) -> &mut Self {
        self.content.push(Content::Child(self.children.len()));
        self.children.push(child);
        self
    }

    /// `addContent(String)`: appends a text node.
    pub fn add_text(&mut self, text: impl Into<String>) -> &mut Self {
        self.content.push(Content::Text(text.into()));
        self
    }

    /// `getChildren()`: the element children, in document order.
    pub fn get_children(&self) -> &[Element] {
        &self.children
    }

    /// `getChildren(name)`: the element children with the given tag name.
    pub fn get_children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// `getChild(name)`: the first element child with the given tag name.
    pub fn get_child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// `getText()`: the concatenated text content directly within this element.
    pub fn get_text(&self) -> String {
        let mut out = String::new();
        for c in &self.content {
            if let Content::Text(t) = c {
                out.push_str(t);
            }
        }
        out
    }

    /// `getValue()`: the concatenated text of this element and all its descendants.
    pub fn get_value(&self) -> String {
        let mut out = String::new();
        self.collect_value(&mut out);
        out
    }

    fn collect_value(&self, out: &mut String) {
        for c in &self.content {
            match c {
                Content::Text(t) => out.push_str(t),
                Content::Child(i) => self.children[*i].collect_value(out),
            }
        }
    }

    /// Builds the root element of the XML document in `bytes` (encoding detected from the BOM /
    /// XML declaration), as `XmlUtilities.createSecureSAXBuilder(false, false).build(..)
    /// .getRootElement()` does: `<!DOCTYPE>` is rejected. Whitespace text is kept, as JDOM's
    /// default builder does.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Element, JdomParseError> {
        let mut builder = TreeBuilder::default();
        sax_parser::parse(bytes, SaxConfig { allow_doctype: false }, &mut builder)
            .map_err(|e| JdomParseError { message: e.to_string() })?;
        builder.root.ok_or_else(|| JdomParseError { message: "no root element".into() })
    }

    /// `XmlUtilities.fromString(String)`.
    pub fn parse_str(xml: &str) -> Result<Element, JdomParseError> {
        Self::parse_bytes(xml.as_bytes())
    }

    /// `GenericXMLOutputter.getInstance().outputString(element)` (also `XmlUtilities.toString`):
    /// compact format with a four-space indent, normalized text and `\r\n` line separators. No
    /// XML declaration is written for a bare element.
    pub fn output_string(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    /// `XmlUtilities.xmlToByteArray(element)`: the element as a whole document (XML declaration,
    /// then the element, then a line separator) in [`output_string`](Self::output_string)'s
    /// format, UTF-8 encoded.
    pub fn to_document_bytes(&self) -> Vec<u8> {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        out.push_str(LINE_SEPARATOR);
        self.write_pretty(&mut out, 0);
        out.push_str(LINE_SEPARATOR);
        out.into_bytes()
    }

    /// `new XMLOutputter().outputString(element)`: JDOM's raw format -- no added whitespace, text
    /// written verbatim (escaped).
    pub fn output_string_raw(&self) -> String {
        let mut out = String::new();
        self.write_raw(&mut out);
        out
    }

    fn write_start_tag(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (n, v) in &self.attributes {
            out.push(' ');
            out.push_str(n);
            out.push_str("=\"");
            escape_attribute(v, out);
            out.push('"');
        }
    }

    fn write_raw(&self, out: &mut String) {
        self.write_start_tag(out);
        if self.content.is_empty() {
            out.push_str(" />");
            return;
        }
        out.push('>');
        for c in &self.content {
            match c {
                Content::Text(t) => escape_text(t, out),
                Content::Child(i) => self.children[*i].write_raw(out),
            }
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }

    /// JDOM2 `TextMode.NORMALIZE` with an indent: whitespace-only text is dropped, other text is
    /// collapsed; text-only content stays inline, otherwise each piece goes on its own indented
    /// line.
    fn write_pretty(&self, out: &mut String, depth: usize) {
        self.write_start_tag(out);
        let pieces: Vec<Piece<'_>> = self
            .content
            .iter()
            .filter_map(|c| match c {
                Content::Text(t) => {
                    let n = normalize(t);
                    (!n.is_empty()).then_some(Piece::Text(n))
                }
                Content::Child(i) => Some(Piece::Child(&self.children[*i])),
            })
            .collect();
        if self.content.is_empty() {
            out.push_str(" />");
            return;
        }
        out.push('>');
        if pieces.iter().all(|p| matches!(p, Piece::Text(_))) {
            let joined: Vec<&str> = pieces
                .iter()
                .map(|p| match p {
                    Piece::Text(t) => t.as_str(),
                    Piece::Child(_) => unreachable!(),
                })
                .collect();
            escape_text(&joined.join(" "), out);
        } else {
            for p in &pieces {
                out.push_str(LINE_SEPARATOR);
                push_indent(out, depth + 1);
                match p {
                    Piece::Text(t) => escape_text(t, out),
                    Piece::Child(c) => c.write_pretty(out, depth + 1),
                }
            }
            out.push_str(LINE_SEPARATOR);
            push_indent(out, depth);
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }
}

enum Piece<'a> {
    Text(String),
    Child(&'a Element),
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// JDOM2 `Format.trimFullWhite`/`compact`: collapse XML whitespace runs to one space and trim.
fn normalize(text: &str) -> String {
    text.split([' ', '\t', '\n', '\r']).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
}

/// JDOM2 `Format.escapeAttribute`.
fn escape_attribute(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '\r' => out.push_str("&#xD;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            c => out.push(c),
        }
    }
}

/// JDOM2 `Format.escapeText`.
fn escape_text(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// `org.jdom2.Verifier.isXMLCharacter`: whether `c` may appear in an XML 1.0 document.
pub fn is_xml_character(c: char) -> bool {
    matches!(c as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

/// `XmlUtilities.hasInvalidXMLCharacters(String)`.
pub fn has_invalid_xml_characters(s: &str) -> bool {
    !s.chars().all(is_xml_character)
}

/// Builds the [`Element`] tree from SAX events (JDOM's `SAXHandler`).
#[derive(Default)]
struct TreeBuilder {
    stack: Vec<Element>,
    root: Option<Element>,
}

impl SaxContentHandler for TreeBuilder {
    fn start_element(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        _location: SaxLocation,
    ) -> Result<(), SaxError> {
        self.stack.push(Element { name: name.to_string(), attributes, ..Default::default() });
        Ok(())
    }

    fn end_element(&mut self, _name: &str, _location: SaxLocation) -> Result<(), SaxError> {
        let element = self.stack.pop().expect("balanced elements");
        match self.stack.last_mut() {
            Some(parent) => {
                parent.add_content(element);
            }
            None => self.root = Some(element),
        }
        Ok(())
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        if let Some(e) = self.stack.last_mut() {
            // SAX may split one text node across several calls; JDOM's builder merges them.
            match e.content.last_mut() {
                Some(Content::Text(t)) => t.push_str(text),
                _ => e.content.push(Content::Text(text.to_string())),
            }
        }
        Ok(())
    }

    fn processing_instruction(&mut self, _target: &str, _data: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tree_with_attributes_children_and_value() {
        let root = Element::parse_str(
            "<?xml version=\"1.0\"?><a x=\"1\" y=\"two\">hi<b>there</b><c/><b k=\"v\"/></a>",
        )
        .unwrap();
        assert_eq!(root.get_name(), "a");
        assert_eq!(root.get_attribute_value("y"), Some("two"));
        assert!(root.has_attribute("x"));
        assert!(!root.has_attribute("z"));
        assert_eq!(root.get_children().len(), 3);
        assert_eq!(root.get_children_named("b").count(), 2);
        assert_eq!(root.get_child("b").unwrap().get_text(), "there");
        assert_eq!(root.get_text(), "hi");
        assert_eq!(root.get_value(), "hithere");
    }

    #[test]
    fn doctype_is_rejected_like_the_secure_builder() {
        assert!(Element::parse_str("<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>").is_err());
    }

    #[test]
    fn set_attribute_replaces_in_place() {
        let mut e = Element::new("E");
        e.set_attribute("A", "1").set_attribute("B", "2").set_attribute("A", "3");
        assert_eq!(e.output_string(), "<E A=\"3\" B=\"2\" />");
    }

    #[test]
    fn generic_outputter_format() {
        // JDOM2 compact format + 4-space indent + NORMALIZE, CRLF line separators.
        let mut root = Element::new("SAVE_STATE");
        let mut s = Element::new("STATE");
        s.set_attribute("NAME", "a<b").set_attribute("VALUE", "\"q\"\n&");
        root.add_content(s);
        let mut t = Element::new("T");
        t.add_text("  some   text\n here ");
        root.add_content(t);
        assert_eq!(
            root.output_string(),
            "<SAVE_STATE>\r\n    <STATE NAME=\"a&lt;b\" VALUE=\"&quot;q&quot;&#xA;&amp;\" />\r\n    \
             <T>some text here</T>\r\n</SAVE_STATE>"
        );
        let doc = String::from_utf8(root.to_document_bytes()).unwrap();
        assert!(doc.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<SAVE_STATE>"));
        assert!(doc.ends_with("</SAVE_STATE>\r\n"));
        assert_eq!(Element::parse_bytes(doc.as_bytes()).unwrap().get_children().len(), 2);
    }

    #[test]
    fn raw_outputter_keeps_text_verbatim() {
        let mut root = Element::new("r");
        root.add_text(" a  <b> ");
        root.add_content(Element::new("c"));
        assert_eq!(root.output_string_raw(), "<r> a  &lt;b&gt; <c /></r>");
        assert_eq!(Element::parse_str(&root.output_string_raw()).unwrap(), {
            let mut e = Element::new("r");
            e.add_text(" a  <b> ");
            e.add_content(Element::new("c"));
            e
        });
    }

    #[test]
    fn invalid_xml_characters() {
        assert!(!has_invalid_xml_characters("plain\ttext\n"));
        assert!(has_invalid_xml_characters("bell\u{7}"));
        assert!(has_invalid_xml_characters("\u{FFFF}"));
    }
}
