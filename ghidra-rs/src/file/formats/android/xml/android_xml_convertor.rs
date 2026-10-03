//! Port of `ghidra.file.formats.android.xml.AndroidXmlConvertor`.
//!
//! NOTE: most of this logic was copied from `AndroidXmlFileSystem`, which had the following
//! note: "most of this code was hijacked from AXMLPrinter.java class!"
//!
//! # The binary-XML parser is a seam, not a port
//!
//! Java's `convert` walks a `android.content.res.AXmlResourceParser` (implementing
//! `org.xmlpull.v1.XmlPullParser`). Neither type is part of Ghidra's own source tree -- both come
//! from a bundled third-party AXMLPrinter-derived library with no source under `orig_src` -- so
//! there is nothing to port for them. This port instead depends on the minimal
//! [`AXmlResourceParser`](crate::file::seam_stubs::AXmlResourceParser) trait (see that type's own
//! doc comment, which follows the same seam precedent as this crate's Z3 SDK seam), letting the
//! real conversion *algorithm* below -- indentation, tag/attribute rendering, `TypedValue`
//! decoding -- be fully ported and fully tested against a scripted test double.
//!
//! # `Float.toString`/`Float.intBitsToFloat` formatting is approximate
//!
//! The `TYPE_FLOAT` attribute-value branch mirrors Java's `String.valueOf(Float.intBitsToFloat(data))`
//! using Rust's own `f32::from_bits(..).to_string()`. The two agree for ordinary values, but
//! Java's `Float.toString` switches to scientific notation past certain magnitude thresholds
//! (and prints `Infinity`/`NaN` differently) in ways Rust's `Display` impl for `f32` does not
//! reproduce; no attempt is made to replicate the JDK's exact float-formatting algorithm here.

use std::io;

use crate::file::seam_stubs::{android_typed_value as tv, AndroidXmlEvent, AXmlResourceParser};
use crate::util::exception::CancelledException;
use crate::util::string_utilities::StringUtilities;
use crate::util::task::TaskMonitor;

/// Per-1024ths-of-a-unit radix multipliers used by [`complex_to_float`] to decode a `TypedValue`
/// complex (dimension/fraction) data word. Port of `AndroidXmlConvertor.RADIX_MULTS`.
const RADIX_MULTS: [f32; 4] = [0.00390625, 3.051758E-05, 1.192093E-07, 4.656613E-10];

/// Unit suffixes for `TYPE_DIMENSION` values, indexed by the data word's low
/// [`tv::COMPLEX_UNIT_MASK`] bits. Port of `AndroidXmlConvertor.DIMENSION_UNITS`.
const DIMENSION_UNITS: [&str; 8] = ["px", "dip", "sp", "pt", "in", "mm", "", ""];

/// Unit suffixes for `TYPE_FRACTION` values, indexed the same way as [`DIMENSION_UNITS`]. Port
/// of `AndroidXmlConvertor.FRACTION_UNITS`.
const FRACTION_UNITS: [&str; 8] = ["%", "%p", "", "", "", "", "", ""];

/// Magic bytes identifying a binary Android XML document. Port of
/// `AndroidXmlConvertor.ANDROID_BINARY_XML_MAGIC`.
pub const ANDROID_BINARY_XML_MAGIC: [u8; 4] = [0x03, 0x00, 0x08, 0x00];

/// Length, in bytes, of [`ANDROID_BINARY_XML_MAGIC`]. Port of
/// `AndroidXmlConvertor.ANDROID_BINARY_XML_MAGIC_LEN`.
pub const ANDROID_BINARY_XML_MAGIC_LEN: usize = 4;

/// Error produced by [`AndroidXmlConvertor::convert`], mirroring the `throws IOException,
/// CancelledException` on `AndroidXmlConvertor.convert`.
#[derive(thiserror::Error, Debug)]
pub enum AndroidXmlConvertError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Renders a binary Android XML document as text.
///
/// Port of `ghidra.file.formats.android.xml.AndroidXmlConvertor`.
pub struct AndroidXmlConvertor;

impl AndroidXmlConvertor {
    /// Converts the binary Android XML bytes in `input`, appending the rendered text to `out`.
    ///
    /// Port of `AndroidXmlConvertor.convert(InputStream, PrintWriter, TaskMonitor)`. Takes the
    /// whole payload directly rather than a stream, matching every in-crate caller (which already
    /// has the bytes in memory) and this crate's `AXmlResourceParser::open`.
    pub fn convert(
        input: &[u8],
        out: &mut String,
        parser: &mut dyn AXmlResourceParser,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), AndroidXmlConvertError> {
        monitor.set_message("Converting Android Binary XML to Text...");

        parser.open(input).map_err(|e| {
            AndroidXmlConvertError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to read AXML file: {e}")))
        })?;

        let result = Self::convert_events(out, parser, monitor);
        parser.close();
        result?;

        out.push('\n');
        Ok(())
    }

    /// The body of the Java `try` block: iterates parse events until `END_DOCUMENT`, appending
    /// each event's rendering to `out`. Split out from [`Self::convert`] so `parser.close()` can
    /// run (mirroring Java's `finally`) regardless of how this returns.
    fn convert_events(
        out: &mut String,
        parser: &mut dyn AXmlResourceParser,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), AndroidXmlConvertError> {
        let mut indent: i32 = -1;

        loop {
            let event = parser.next().map_err(|e| {
                AndroidXmlConvertError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read AXML file: {e}"),
                ))
            })?;
            if event == AndroidXmlEvent::EndDocument {
                break;
            }
            monitor.check_cancelled()?;

            let mut buffer = String::new();
            match event {
                AndroidXmlEvent::StartDocument => {
                    buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
                    buffer.push('\n');
                }
                AndroidXmlEvent::StartTag => {
                    indent += 1;

                    buffer.push_str(&"".pad('\t', indent));
                    buffer.push('<');
                    buffer.push_str(&namespace_prefix(parser.get_prefix().as_deref()));
                    buffer.push_str(&parser.get_name());
                    buffer.push('\n');

                    let namespace_count_before = parser.get_namespace_count(parser.get_depth() - 1);
                    let namespace_count = parser.get_namespace_count(parser.get_depth());

                    indent += 1;

                    for i in namespace_count_before..namespace_count {
                        buffer.push_str(&"".pad('\t', indent));
                        buffer.push_str("xmlns:");
                        buffer.push_str(&parser.get_namespace_prefix(i));
                        buffer.push('=');
                        buffer.push('"');
                        buffer.push_str(&parser.get_namespace_uri(i));
                        buffer.push('"');
                        buffer.push('\n');
                    }

                    for i in 0..parser.get_attribute_count() {
                        buffer.push_str(&"".pad('\t', indent));
                        buffer.push_str(&namespace_prefix(parser.get_attribute_prefix(i).as_deref()));
                        buffer.push_str(&parser.get_attribute_name(i));
                        buffer.push('=');
                        buffer.push('"');
                        buffer.push_str(&attribute_value(parser, i));
                        buffer.push('"');
                        buffer.push('\n');
                    }

                    buffer.push_str(&"".pad('\t', indent));
                    buffer.push('>');
                    buffer.push('\n');

                    indent -= 1;
                }
                AndroidXmlEvent::EndTag => {
                    buffer.push_str(&"".pad('\t', indent));
                    buffer.push('<');
                    buffer.push('/');
                    buffer.push_str(&namespace_prefix(parser.get_prefix().as_deref()));
                    buffer.push_str(&parser.get_name());
                    buffer.push('>');
                    buffer.push('\n');
                    indent -= 1;
                }
                AndroidXmlEvent::Text => {
                    buffer.push_str(&"".pad('\t', indent));
                    buffer.push_str(&parser.get_text());
                    buffer.push('\n');
                }
                AndroidXmlEvent::EndDocument | AndroidXmlEvent::Other => {}
            }

            out.push_str(&buffer);
        }

        Ok(())
    }
}

/// Port of the private static `getNamespacePrefix(String)`.
fn namespace_prefix(prefix: Option<&str>) -> String {
    match prefix {
        Some(p) if !p.is_empty() => format!("{p}:"),
        _ => String::new(),
    }
}

/// Port of the private static `getAttributeValue(AXmlResourceParser, int)`.
fn attribute_value(parser: &dyn AXmlResourceParser, index: i32) -> String {
    let value_type = parser.get_attribute_value_type(index);
    let data = parser.get_attribute_value_data(index);

    if value_type == tv::TYPE_STRING {
        return parser.get_attribute_value(index);
    }
    if value_type == tv::TYPE_ATTRIBUTE {
        return format!("?{}{:08X}", package_prefix(data), data);
    }
    if value_type == tv::TYPE_REFERENCE {
        return format!("@{}{:08X}", package_prefix(data), data);
    }
    if value_type == tv::TYPE_FLOAT {
        return f32::from_bits(data as u32).to_string();
    }
    if value_type == tv::TYPE_INT_HEX {
        return format!("0x{:08X}", data);
    }
    if value_type == tv::TYPE_INT_BOOLEAN {
        return if data == 0 { "false" } else { "true" }.to_string();
    }
    if value_type == tv::TYPE_DIMENSION {
        return format!("{}{}", complex_to_float(data), DIMENSION_UNITS[(data & tv::COMPLEX_UNIT_MASK) as usize]);
    }
    if value_type == tv::TYPE_FRACTION {
        return format!("{}{}", complex_to_float(data), FRACTION_UNITS[(data & tv::COMPLEX_UNIT_MASK) as usize]);
    }
    if (tv::TYPE_FIRST_COLOR_INT..=tv::TYPE_LAST_COLOR_INT).contains(&value_type) {
        return format!("#{:08X}", data);
    }
    if (tv::TYPE_FIRST_INT..=tv::TYPE_LAST_INT).contains(&value_type) {
        return data.to_string();
    }
    format!("<0x{:X}, type 0x{:02X}>", data, value_type)
}

/// Port of the private static `getPackage(int)`.
fn package_prefix(id: i32) -> &'static str {
    if ((id as u32) >> 24) == 1 { "android:" } else { "" }
}

/// Port of the private static `complexToFloat(int)`.
fn complex_to_float(complex: i32) -> f32 {
    ((complex & !0xffi32) as f32) * RADIX_MULTS[((complex >> 4) & 3) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::seam_stubs::AXmlParseError;
    use crate::util::task::DummyMonitor;

    /// One parse event, scripted ahead of time for [`ScriptedParser`].
    #[derive(Clone)]
    enum ScriptedEvent {
        StartDocument,
        StartTag {
            prefix: Option<&'static str>,
            name: &'static str,
            depth: i32,
            namespaces: Vec<(&'static str, &'static str)>,
            attributes: Vec<(Option<&'static str>, &'static str, i32, i32, Option<&'static str>)>,
        },
        EndTag {
            prefix: Option<&'static str>,
            name: &'static str,
        },
        Text(&'static str),
        EndDocument,
    }

    /// A scripted [`AXmlResourceParser`] test double: `next()` walks a pre-built list of
    /// [`ScriptedEvent`]s, and the various `get_*` accessors report whatever the *current* event
    /// carries -- mirroring how a real `AXmlResourceParser` reports state relative to its current
    /// position.
    struct ScriptedParser {
        events: Vec<ScriptedEvent>,
        /// `None` until the first `next()` call -- mirrors a real `XmlPullParser`, which is not
        /// positioned on any of *this* script's events until `next()` is called at least once
        /// (its very first call returns `events[0]`, not `events[1]`).
        index: Option<usize>,
        closed: bool,
    }

    impl ScriptedParser {
        fn new(events: Vec<ScriptedEvent>) -> Self {
            ScriptedParser { events, index: None, closed: false }
        }

        fn current(&self) -> &ScriptedEvent {
            &self.events[self.index.expect("current() called before the first next()")]
        }
    }

    impl AXmlResourceParser for ScriptedParser {
        fn open(&mut self, _input: &[u8]) -> Result<(), AXmlParseError> {
            Ok(())
        }

        fn next(&mut self) -> Result<AndroidXmlEvent, AXmlParseError> {
            self.index = Some(match self.index {
                None => 0,
                Some(i) if i + 1 < self.events.len() => i + 1,
                Some(i) => i,
            });
            Ok(match self.current() {
                ScriptedEvent::StartDocument => AndroidXmlEvent::StartDocument,
                ScriptedEvent::StartTag { .. } => AndroidXmlEvent::StartTag,
                ScriptedEvent::EndTag { .. } => AndroidXmlEvent::EndTag,
                ScriptedEvent::Text(_) => AndroidXmlEvent::Text,
                ScriptedEvent::EndDocument => AndroidXmlEvent::EndDocument,
            })
        }

        fn get_prefix(&self) -> Option<String> {
            match self.current() {
                ScriptedEvent::StartTag { prefix, .. } | ScriptedEvent::EndTag { prefix, .. } => {
                    prefix.map(|s| s.to_string())
                }
                _ => None,
            }
        }

        fn get_name(&self) -> String {
            match self.current() {
                ScriptedEvent::StartTag { name, .. } | ScriptedEvent::EndTag { name, .. } => name.to_string(),
                _ => String::new(),
            }
        }

        fn get_depth(&self) -> i32 {
            match self.current() {
                ScriptedEvent::StartTag { depth, .. } => *depth,
                _ => 0,
            }
        }

        fn get_namespace_count(&self, depth: i32) -> i32 {
            // Real `XmlPullParser.getNamespaceCount(depth)` reports namespaces in scope
            // *cumulatively up to and including* `depth`. This script only ever needs two
            // answers -- the count just before this tag's own declarations (`depth - 1`, assumed
            // 0: none of these tests nest namespace scopes) and the count including them
            // (`depth`, this tag's full `namespaces` list) -- so `depth >= this tag's own depth`
            // is enough to distinguish the two for every event this parser scripts.
            match self.current() {
                ScriptedEvent::StartTag { depth: event_depth, namespaces, .. } if depth >= *event_depth => {
                    namespaces.len() as i32
                }
                _ => 0,
            }
        }

        fn get_namespace_prefix(&self, index: i32) -> String {
            match self.current() {
                ScriptedEvent::StartTag { namespaces, .. } => namespaces[index as usize].0.to_string(),
                _ => String::new(),
            }
        }

        fn get_namespace_uri(&self, index: i32) -> String {
            match self.current() {
                ScriptedEvent::StartTag { namespaces, .. } => namespaces[index as usize].1.to_string(),
                _ => String::new(),
            }
        }

        fn get_attribute_count(&self) -> i32 {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => attributes.len() as i32,
                _ => 0,
            }
        }

        fn get_attribute_prefix(&self, index: i32) -> Option<String> {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => attributes[index as usize].0.map(|s| s.to_string()),
                _ => None,
            }
        }

        fn get_attribute_name(&self, index: i32) -> String {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => attributes[index as usize].1.to_string(),
                _ => String::new(),
            }
        }

        fn get_attribute_value(&self, index: i32) -> String {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => {
                    attributes[index as usize].4.expect("TYPE_STRING attribute must supply a value").to_string()
                }
                _ => String::new(),
            }
        }

        fn get_attribute_value_type(&self, index: i32) -> i32 {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => attributes[index as usize].2,
                _ => 0,
            }
        }

        fn get_attribute_value_data(&self, index: i32) -> i32 {
            match self.current() {
                ScriptedEvent::StartTag { attributes, .. } => attributes[index as usize].3,
                _ => 0,
            }
        }

        fn get_text(&self) -> String {
            match self.current() {
                ScriptedEvent::Text(text) => text.to_string(),
                _ => String::new(),
            }
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    #[test]
    fn convert_renders_a_simple_document_with_indentation() {
        let mut parser = ScriptedParser::new(vec![
            ScriptedEvent::StartDocument,
            ScriptedEvent::StartTag { prefix: None, name: "root", depth: 1, namespaces: vec![], attributes: vec![] },
            ScriptedEvent::StartTag { prefix: None, name: "child", depth: 2, namespaces: vec![], attributes: vec![] },
            ScriptedEvent::Text("hello"),
            ScriptedEvent::EndTag { prefix: None, name: "child" },
            ScriptedEvent::EndTag { prefix: None, name: "root" },
            ScriptedEvent::EndDocument,
        ]);

        let mut out = String::new();
        let monitor = DummyMonitor;
        AndroidXmlConvertor::convert(&ANDROID_BINARY_XML_MAGIC, &mut out, &mut parser, &monitor).unwrap();

        // Each tag's closing `>` is printed one indent level deeper than its opening `<name`
        // line (Java increments `indent` a second time before that line -- see
        // `AndroidXmlConvertor::convert_events`), so `<root` is unindented but its `>` gets one
        // tab, `<child` gets one tab but its `>` gets two, etc.
        let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                         <root\n\
                         \t>\n\
                         \t<child\n\
                         \t\t>\n\
                         \thello\n\
                         \t</child>\n\
                         </root>\n\
                         \n";
        assert_eq!(out, expected);
        assert!(parser.closed, "convert() must close the parser even on success");
    }

    #[test]
    fn convert_renders_namespace_declarations_and_attributes() {
        let mut parser = ScriptedParser::new(vec![
            ScriptedEvent::StartTag {
                prefix: Some("android"),
                name: "manifest",
                depth: 1,
                namespaces: vec![("android", "http://schemas.android.com/apk/res/android")],
                attributes: vec![(Some("android"), "versionCode", tv::TYPE_FIRST_INT, 7, None)],
            },
            ScriptedEvent::EndTag { prefix: Some("android"), name: "manifest" },
            ScriptedEvent::EndDocument,
        ]);

        let mut out = String::new();
        let monitor = DummyMonitor;
        AndroidXmlConvertor::convert(&ANDROID_BINARY_XML_MAGIC, &mut out, &mut parser, &monitor).unwrap();

        let expected = "<android:manifest\n\
                         \txmlns:android=\"http://schemas.android.com/apk/res/android\"\n\
                         \tandroid:versionCode=\"7\"\n\
                         \t>\n\
                         </android:manifest>\n\
                         \n";
        assert_eq!(out, expected);
    }

    #[test]
    fn attribute_value_covers_every_typed_value_branch() {
        let cases: Vec<(&str, i32, i32, &str)> = vec![
            ("attribute reference", tv::TYPE_ATTRIBUTE, 0x00abcdef, "?00ABCDEF"),
            ("attribute reference (android package)", tv::TYPE_ATTRIBUTE, 0x01abcdef, "?android:01ABCDEF"),
            ("resource reference", tv::TYPE_REFERENCE, 0x7f010001, "@7F010001"),
            ("int hex", tv::TYPE_INT_HEX, 0xff, "0x000000FF"),
            ("boolean true", tv::TYPE_INT_BOOLEAN, 1, "true"),
            ("boolean false", tv::TYPE_INT_BOOLEAN, 0, "false"),
            ("plain int", tv::TYPE_FIRST_INT, 42, "42"),
            ("color", tv::TYPE_FIRST_COLOR_INT, 0x00ff00ff_u32 as i32, "#00FF00FF"),
        ];

        for (label, value_type, data, expected) in cases {
            let mut parser = ScriptedParser::new(vec![ScriptedEvent::StartTag {
                prefix: None,
                name: "tag",
                depth: 1,
                namespaces: vec![],
                attributes: vec![(None, "attr", value_type, data, None)],
            }]);
            // Position the parser on the (only) StartTag event.
            let _ = parser.next();
            assert_eq!(attribute_value(&parser, 0), expected, "case: {label}");
        }
    }

    #[test]
    fn attribute_value_type_string_uses_the_pre_formatted_value() {
        let mut parser = ScriptedParser::new(vec![ScriptedEvent::StartTag {
            prefix: None,
            name: "tag",
            depth: 1,
            namespaces: vec![],
            attributes: vec![(None, "label", tv::TYPE_STRING, 0, Some("hello world"))],
        }]);
        let _ = parser.next();
        assert_eq!(attribute_value(&parser, 0), "hello world");
    }

    #[test]
    fn attribute_value_unknown_type_falls_back_to_the_generic_format() {
        // 0x00 is `TYPE_NULL` -- a real `TypedValue` constant, but not one any branch of
        // `attribute_value` special-cases (it falls between no other range), so it exercises the
        // final generic fallback.
        let mut parser = ScriptedParser::new(vec![ScriptedEvent::StartTag {
            prefix: None,
            name: "tag",
            depth: 1,
            namespaces: vec![],
            attributes: vec![(None, "attr", 0x00, 0x99, None)],
        }]);
        let _ = parser.next();
        assert_eq!(attribute_value(&parser, 0), "<0x99, type 0x00>");
    }

    #[test]
    fn namespace_prefix_formats_present_and_absent_prefixes() {
        assert_eq!(namespace_prefix(Some("android")), "android:");
        assert_eq!(namespace_prefix(None), "");
        assert_eq!(namespace_prefix(Some("")), "");
    }

    #[test]
    fn package_prefix_detects_the_android_package_byte() {
        assert_eq!(package_prefix(0x01000000), "android:");
        assert_eq!(package_prefix(0x7f000000), "");
    }

    #[test]
    fn complex_to_float_matches_a_known_dimension_encoding() {
        // 0x00000010 -> radix index 1 (bits 4-5 == 01), high byte 0x00 -> integer part 0, so the
        // decoded value is 0.0 -- exercises the shift/mask arithmetic without needing a golden
        // AXML fixture.
        assert_eq!(complex_to_float(0x00000010), 0.0);
        // 0x00010000: masked high bits = 0x00010000 -> as f32 = 65536.0; radix index = (0x0 >> 4)
        // & 3 = 0 -> RADIX_MULTS[0] = 0.00390625; product = 256.0.
        assert_eq!(complex_to_float(0x00010000), 256.0);
    }

    #[test]
    fn convert_propagates_cancellation() {
        struct CancellingMonitor;
        impl TaskMonitor for CancellingMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException("cancelled".to_string()))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                -1
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let mut parser = ScriptedParser::new(vec![
            ScriptedEvent::StartTag { prefix: None, name: "root", depth: 1, namespaces: vec![], attributes: vec![] },
            ScriptedEvent::EndDocument,
        ]);
        let mut out = String::new();
        let result = AndroidXmlConvertor::convert(&ANDROID_BINARY_XML_MAGIC, &mut out, &mut parser, &CancellingMonitor);
        assert!(matches!(result, Err(AndroidXmlConvertError::Cancelled(_))));
        assert!(parser.closed, "convert() must close the parser even when cancelled");
    }

    #[test]
    fn convert_wraps_a_parser_failure_as_failed_to_read_axml_file() {
        struct FailingParser;
        impl AXmlResourceParser for FailingParser {
            fn open(&mut self, _input: &[u8]) -> Result<(), AXmlParseError> {
                Ok(())
            }
            fn next(&mut self) -> Result<AndroidXmlEvent, AXmlParseError> {
                Err(AXmlParseError("bad token".to_string()))
            }
            fn get_prefix(&self) -> Option<String> {
                None
            }
            fn get_name(&self) -> String {
                String::new()
            }
            fn get_depth(&self) -> i32 {
                0
            }
            fn get_namespace_count(&self, _depth: i32) -> i32 {
                0
            }
            fn get_namespace_prefix(&self, _index: i32) -> String {
                String::new()
            }
            fn get_namespace_uri(&self, _index: i32) -> String {
                String::new()
            }
            fn get_attribute_count(&self) -> i32 {
                0
            }
            fn get_attribute_prefix(&self, _index: i32) -> Option<String> {
                None
            }
            fn get_attribute_name(&self, _index: i32) -> String {
                String::new()
            }
            fn get_attribute_value(&self, _index: i32) -> String {
                String::new()
            }
            fn get_attribute_value_type(&self, _index: i32) -> i32 {
                0
            }
            fn get_attribute_value_data(&self, _index: i32) -> i32 {
                0
            }
            fn get_text(&self) -> String {
                String::new()
            }
            fn close(&mut self) {}
        }

        let mut parser = FailingParser;
        let mut out = String::new();
        let result = AndroidXmlConvertor::convert(&ANDROID_BINARY_XML_MAGIC, &mut out, &mut parser, &DummyMonitor);
        match result {
            Err(AndroidXmlConvertError::Io(e)) => {
                assert!(e.to_string().contains("Failed to read AXML file"), "unexpected message: {e}");
            }
            other => panic!("expected an Io error, got {other:?}"),
        }
    }

    #[test]
    fn magic_constants_are_consistent() {
        assert_eq!(ANDROID_BINARY_XML_MAGIC_LEN, ANDROID_BINARY_XML_MAGIC.len());
    }
}
