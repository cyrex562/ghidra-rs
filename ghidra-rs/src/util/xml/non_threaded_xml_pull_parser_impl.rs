//! Port of `ghidra.xml.NonThreadedXmlPullParserImpl`.
//!
//! The Java class runs a JDK SAX parse to completion in its constructor, queueing every
//! start/end element, and then serves the queue through the `XmlPullParser` API. Here the SAX
//! layer is [`sax_parser`](super::sax_parser) (see its module docs for the supported XML
//! subset); everything the Java `DefaultContentHandlerWrapper` did -- level tracking, text
//! accumulation, processing-instruction bookkeeping -- is ported in [`ElementAssembler`] and the
//! processing-instruction helpers, which [`ThreadedXmlPullParserImpl`] shares (Java duplicated
//! the same inner class in both parsers).
//!
//! [`ThreadedXmlPullParserImpl`]: super::threaded_xml_pull_parser_impl::ThreadedXmlPullParserImpl

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::Path;

use crate::app::util::xml::xml_error_handler::{SaxErrorHandler, XmlError};

use super::sax_parser::{self, SaxConfig, SaxContentHandler, SaxError, SaxLocation};
use super::xml_element_impl::XmlElementImpl;
use super::xml_pull_parser::XmlPullParser;

/// Processing-instruction attributes, keyed by upper-cased target then upper-cased attribute.
pub(super) type ProcessingInstructions = HashMap<String, HashMap<String, String>>;

/// Records a processing instruction the way the Java content handlers'
/// `processingInstruction` does: the data is split on whitespace (`StringTokenizer`) into
/// `attr=value` pairs, surrounding double quotes are stripped from the value, and target,
/// attribute and value are all upper-cased.
pub(super) fn record_processing_instruction(
    map: &mut ProcessingInstructions,
    target: &str,
    data: &str,
) {
    let attrs = map.entry(target.to_uppercase()).or_default();
    for token in data.split([' ', '\t', '\n', '\r', '\u{c}']).filter(|t| !t.is_empty()) {
        parse_attribute_value(attrs, token);
    }
}

/// Port of the content handlers' private `parseAttributeValue`.
fn parse_attribute_value(map: &mut HashMap<String, String>, attr_value_pair: &str) {
    let chars: Vec<char> = attr_value_pair.chars().collect();
    let ix = match chars.iter().position(|c| *c == '=') {
        Some(ix) if ix >= 1 && ix != chars.len() - 1 => ix,
        _ => return,
    };
    let attr: String = chars[..ix].iter().collect();
    let mut value: String = chars[ix + 1..].iter().collect();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value = value[1..value.len() - 1].to_string();
    } else if value == "\"" {
        // Java: `"\"".startsWith("\"") && endsWith("\"")` holds, and `substring(1, 0)` throws
        // StringIndexOutOfBoundsException; a lone quote is never a valid value, so drop it.
        return;
    }
    map.insert(attr.to_uppercase(), value.to_uppercase());
}

/// Port of `getProcessingInstruction(String, String)`: case-insensitive on both names.
pub(super) fn lookup_processing_instruction(
    map: &ProcessingInstructions,
    pi_name: &str,
    attribute: &str,
) -> Option<String> {
    map.get(&pi_name.to_uppercase())?.get(&attribute.to_uppercase()).cloned()
}

/// Turns a failed parse into the error the Java constructor would throw: a fatal parse error
/// is first offered to the caller's `ErrorHandler`, whose own exception (if it throws one)
/// replaces the parse exception.
pub(super) fn report_failure(error: SaxError, err_handler: Option<&dyn SaxErrorHandler>) -> XmlError {
    if let (Some(handler), Some(parse_exception)) = (err_handler, error.as_parse_exception()) {
        if let Err(replacement) = handler.fatal_error(&parse_exception) {
            return replacement;
        }
    }
    XmlError::from(error)
}

/// The Java parsers take a `validate` flag that turns on DTD validation; that is not
/// supported (no in-tree Java caller passes `true`), so it is rejected rather than ignored.
pub(super) fn check_validate(validate: bool) -> Result<(), XmlError> {
    if validate {
        Err(XmlError::new("DTD validation is not supported by this XML parser"))
    } else {
        Ok(())
    }
}

/// Builds [`XmlElementImpl`]s from SAX events, as the Java `DefaultContentHandlerWrapper`'s
/// `startElement`/`endElement`/`characters` do.
pub(super) struct ElementAssembler {
    text: String,
    level: i32,
    upper_case_names: bool,
}

impl ElementAssembler {
    /// `upper_case_names` is the deprecated `reallyCreateNoncompliantDeprecated` mode.
    pub(super) fn new(upper_case_names: bool) -> Self {
        Self { text: String::new(), level: -1, upper_case_names }
    }

    fn element_name(&self, name: &str) -> String {
        if self.upper_case_names { name.to_uppercase() } else { name.to_string() }
    }

    /// Port of `startElement`: the level goes up and pending text is discarded (it is
    /// whitespace between nested start tags).
    pub(super) fn start(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        location: SaxLocation,
    ) -> XmlElementImpl {
        self.level += 1;
        self.text.clear();
        XmlElementImpl::new(
            true,
            false,
            self.element_name(name),
            self.level,
            attributes,
            None,
            location.column,
            location.line,
        )
        .expect("start element is not also an end element")
    }

    /// Port of `endElement`: the element carries the text accumulated since the last start or
    /// end element, then the level goes down.
    pub(super) fn end(&mut self, name: &str, location: SaxLocation) -> XmlElementImpl {
        let element = XmlElementImpl::new(
            false,
            true,
            self.element_name(name),
            self.level,
            Vec::new(),
            Some(std::mem::take(&mut self.text)),
            location.column,
            location.line,
        )
        .expect("end element is not also a start element");
        self.level -= 1;
        element
    }

    /// Port of `characters`.
    pub(super) fn characters(&mut self, text: &str) {
        self.text.push_str(text);
    }
}

/// Content handler that fills the queue.
struct QueueFiller<'a> {
    assembler: ElementAssembler,
    queue: &'a mut VecDeque<XmlElementImpl>,
    processing_instructions: &'a mut ProcessingInstructions,
}

impl SaxContentHandler for QueueFiller<'_> {
    fn start_element(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        location: SaxLocation,
    ) -> Result<(), SaxError> {
        self.queue.push_back(self.assembler.start(name, attributes, location));
        Ok(())
    }

    fn end_element(&mut self, name: &str, location: SaxLocation) -> Result<(), SaxError> {
        self.queue.push_back(self.assembler.end(name, location));
        Ok(())
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        self.assembler.characters(text);
        Ok(())
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError> {
        record_processing_instruction(self.processing_instructions, target, data);
        Ok(())
    }
}

/// An [`XmlPullParser`] that parses the whole document up front.
///
/// Port of `ghidra.xml.NonThreadedXmlPullParserImpl`. All parse errors therefore surface from
/// the constructor. As in Java, a `<!DOCTYPE>` is a fatal error for this parser
/// (`createSecureSAXParserFactory(false)` disallows it), except through
/// [`new_allowing_doctype`](Self::new_allowing_doctype), which the
/// [`xml_pull_parser_factory`](super::xml_pull_parser_factory) uses to reproduce the threaded
/// parser's configuration.
#[derive(Debug, Clone)]
pub(crate) struct NonThreadedXmlPullParserImpl {
    queue: VecDeque<XmlElementImpl>,
    processing_instructions: ProcessingInstructions,
    name: String,
}

impl NonThreadedXmlPullParserImpl {
    /// Port of `NonThreadedXmlPullParserImpl(File, ErrorHandler, boolean)`. The parser is named
    /// after the file's name.
    pub(crate) fn from_file(
        file: &Path,
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
    ) -> Result<Self, XmlError> {
        let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let bytes = std::fs::read(file).map_err(|e| XmlError::new(e.to_string()))?;
        Self::fill_queue(name, &bytes, err_handler, validate, false, false)
    }

    /// Port of `NonThreadedXmlPullParserImpl(String, String, ErrorHandler, boolean)`.
    pub(crate) fn from_str(
        input: &str,
        input_name: &str,
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
    ) -> Result<Self, XmlError> {
        Self::fill_queue(input_name.to_string(), input.as_bytes(), err_handler, validate, false, false)
    }

    /// Port of `NonThreadedXmlPullParserImpl(InputStream, String, ErrorHandler, boolean)`.
    pub(crate) fn from_reader<R: Read>(
        mut input: R,
        input_name: &str,
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
    ) -> Result<Self, XmlError> {
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).map_err(|e| XmlError::new(e.to_string()))?;
        Self::fill_queue(input_name.to_string(), &bytes, err_handler, validate, false, false)
    }

    /// Port of the deprecated package-private `NonThreadedXmlPullParserImpl(InputStream, String,
    /// ErrorHandler, boolean, boolean)`: with `really_create_noncompliant_deprecated`, element
    /// names are upper-cased (the old case-insensitive `XmlParser` behavior).
    pub(crate) fn from_reader_noncompliant_deprecated<R: Read>(
        mut input: R,
        input_name: &str,
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
        really_create_noncompliant_deprecated: bool,
    ) -> Result<Self, XmlError> {
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).map_err(|e| XmlError::new(e.to_string()))?;
        Self::fill_queue(
            input_name.to_string(),
            &bytes,
            err_handler,
            validate,
            really_create_noncompliant_deprecated,
            false,
        )
    }

    /// Parses `input` with a `<!DOCTYPE>` permitted (external subset and external entities
    /// still not loaded) -- the configuration Java's `ThreadedXmlPullParserImpl` uses
    /// (`createSecureSAXParserFactory(true)` with `load-external-dtd` off). Not a Java
    /// constructor: it lets [`xml_pull_parser_factory`](super::xml_pull_parser_factory) hand out
    /// an eagerly-parsed parser that accepts the same documents as the threaded one.
    pub(crate) fn new_allowing_doctype(
        input: &[u8],
        input_name: &str,
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
    ) -> Result<Self, XmlError> {
        Self::fill_queue(input_name.to_string(), input, err_handler, validate, false, true)
    }

    /// Port of the private `fillQueue`.
    fn fill_queue(
        name: String,
        input: &[u8],
        err_handler: Option<&dyn SaxErrorHandler>,
        validate: bool,
        really_create_noncompliant_deprecated: bool,
        allow_doctype: bool,
    ) -> Result<Self, XmlError> {
        check_validate(validate)?;
        let mut queue = VecDeque::new();
        let mut processing_instructions = ProcessingInstructions::new();
        let mut filler = QueueFiller {
            assembler: ElementAssembler::new(really_create_noncompliant_deprecated),
            queue: &mut queue,
            processing_instructions: &mut processing_instructions,
        };
        sax_parser::parse(input, SaxConfig { allow_doctype }, &mut filler)
            .map_err(|e| report_failure(e, err_handler))?;
        Ok(Self { queue, processing_instructions, name })
    }
}

impl XmlPullParser for NonThreadedXmlPullParserImpl {
    type Element = XmlElementImpl;

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_processing_instruction(&self, name: &str, attribute: &str) -> Option<String> {
        lookup_processing_instruction(&self.processing_instructions, name, attribute)
    }

    /// Always `false`: this implementation never produces content elements.
    fn is_pulling_content(&self) -> bool {
        false
    }

    /// Panics when asked to pull content, as Java throws
    /// `RuntimeException("this impl can't inject content")`.
    fn set_pulling_content(&mut self, pulling_content: bool) {
        if pulling_content {
            panic!("this impl can't inject content");
        }
    }

    fn has_next(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Panics at end of document, where Java returns `null`; check
    /// [`has_next`](XmlPullParser::has_next) first.
    fn peek(&self) -> XmlElementImpl {
        self.queue.front().cloned().expect("peek() called with no next XML element")
    }

    /// Panics at end of document, where Java returns `null`; check
    /// [`has_next`](XmlPullParser::has_next) first.
    fn next(&mut self) -> XmlElementImpl {
        self.queue.pop_front().expect("next() called with no next XML element")
    }

    /// Nothing to release: the document was fully read at construction.
    fn dispose(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::xml::xml_error_handler::{XmlErrorHandler, XmlParseException};
    use crate::util::xml::xml_element::XmlElement;
    use std::sync::Mutex;

    const PSPEC: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<?program_dtd version=\"1\"?>\n\
<processor_spec>\n\
  <programcounter register=\"PC\"/>\n\
  <context_data>\n\
    <context_set space=\"ram\">\n\
      <set name=\"TMode\" val=\"0\" description=\"0 for ARM 32-bit, 1 for THUMB 16-bit\"/>\n\
    </context_set>\n\
  </context_data>\n\
  <register_data>\n\
    <register name=\"cpsr\" group=\"Status\"/>\n\
  </register_data>\n\
</processor_spec>\n";

    fn parse(xml: &str) -> NonThreadedXmlPullParserImpl {
        NonThreadedXmlPullParserImpl::from_str(xml, "test", None, false).unwrap()
    }

    #[test]
    fn pspec_event_sequence() {
        let mut p = parse(PSPEC);
        assert_eq!(p.get_name(), "test");
        let root = p.start(&["processor_spec"]).unwrap();
        assert_eq!(root.get_level(), 0);
        assert_eq!((root.get_line_number(), root.get_column_number()), (3, 17));

        let pc = p.start(&["programcounter"]).unwrap();
        assert_eq!(pc.get_attribute("register").as_deref(), Some("PC"));
        assert_eq!(pc.get_level(), 1);
        let pc_end = p.end_matching(&pc).unwrap();
        assert_eq!(pc_end.get_level(), 1);
        assert_eq!(pc_end.get_text(), "");

        let ctx = p.start(&["context_data"]).unwrap();
        let set_space = p.start(&["context_set"]).unwrap();
        assert_eq!(set_space.get_attribute("space").as_deref(), Some("ram"));
        let set = p.start(&["set"]).unwrap();
        assert_eq!(set.get_level(), 3);
        let attrs: Vec<(String, String)> = set.get_attribute_iter().collect();
        assert_eq!(
            attrs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            vec!["name", "val", "description"]
        );
        assert_eq!(set.get_attribute("description").as_deref(), Some("0 for ARM 32-bit, 1 for THUMB 16-bit"));
        p.end_matching(&set).unwrap();
        p.end_matching(&set_space).unwrap();
        p.end_matching(&ctx).unwrap();

        // skip the register data subtree
        assert!(p.peek().is_start_with("register_data"));
        assert_eq!(p.discard_sub_tree(), 4);
        let end = p.end_matching(&root).unwrap();
        assert!(end.is_end());
        assert!(!p.has_next());
    }

    #[test]
    fn processing_instructions_are_case_insensitive() {
        let p = parse(PSPEC);
        assert_eq!(p.get_processing_instruction("program_dtd", "version").as_deref(), Some("1"));
        assert_eq!(p.get_processing_instruction("PROGRAM_DTD", "VERSION").as_deref(), Some("1"));
        assert_eq!(p.get_processing_instruction("program_dtd", "missing"), None);
        assert_eq!(p.get_processing_instruction("other", "version"), None);
    }

    #[test]
    fn processing_instruction_values_are_upper_cased_and_unquoted() {
        let p = parse("<?pi a=\"x y\" b=low c= =d e=\"\"?><r/>");
        // StringTokenizer splits `a="x y"` into `a="x` and `y"`: the first keeps its opening
        // quote only, so it is not stripped.
        assert_eq!(p.get_processing_instruction("pi", "a").as_deref(), Some("\"X"));
        assert_eq!(p.get_processing_instruction("pi", "b").as_deref(), Some("LOW"));
        assert_eq!(p.get_processing_instruction("pi", "c"), None);
        assert_eq!(p.get_processing_instruction("pi", "e").as_deref(), Some(""));
    }

    #[test]
    fn end_element_text_accumulates_since_last_event() {
        let mut p = parse("<a>\n  <b>hello &amp; <![CDATA[<bye>]]></b>\n  tail\n</a>");
        let a = p.start(&["a"]).unwrap();
        assert_eq!(a.get_text(), "");
        let b = p.start(&["b"]).unwrap();
        assert_eq!(p.end_matching(&b).unwrap().get_text(), "hello & <bye>");
        assert_eq!(p.end().unwrap().get_text(), "\n  tail\n");
    }

    #[test]
    fn cspec_pcode_injection_body_is_text() {
        let xml = "<compiler_spec><callotherfixup targetop=\"x\"><pcode><body><![CDATA[\n\
                   r0 = r1 + 1;\n]]></body></pcode></callotherfixup></compiler_spec>";
        let mut p = parse(xml);
        p.start(&["compiler_spec"]).unwrap();
        let fixup = p.start(&["callotherfixup"]).unwrap();
        assert_eq!(fixup.get_attribute("targetop").as_deref(), Some("x"));
        p.start(&["pcode"]).unwrap();
        p.start(&["body"]).unwrap();
        assert_eq!(p.end().unwrap().get_text(), "\nr0 = r1 + 1;\n");
    }

    #[test]
    fn start_errors_on_wrong_element() {
        let mut p = parse("<a><b/></a>");
        p.start(&["a"]).unwrap();
        let err = p.start(&["c", "d"]).unwrap_err();
        assert_eq!(err.message(), "got element b but expected start element [ c, d ]");
        assert!(p.soft_start(&["b"]).is_none()); // `b`'s start was consumed by the failed start
        assert!(p.end().is_ok());
    }

    #[test]
    fn empty_element_splits_into_start_and_end_at_same_position() {
        let mut p = parse("<a/>");
        let s = p.next();
        let e = p.next();
        assert!(s.is_start() && e.is_end());
        assert_eq!((s.get_line_number(), s.get_column_number()), (1, 5));
        assert_eq!((e.get_line_number(), e.get_column_number()), (1, 5));
        assert_eq!(e.get_level(), 0);
        assert!(!p.has_next());
    }

    #[test]
    fn doctype_is_rejected_but_allowed_via_factory_constructor() {
        let xml = "<!DOCTYPE a SYSTEM \"a.dtd\"><a/>";
        let err = NonThreadedXmlPullParserImpl::from_str(xml, "t", None, false).unwrap_err();
        assert!(err.message().contains("DOCTYPE is disallowed"), "{}", err.message());
        let p = NonThreadedXmlPullParserImpl::new_allowing_doctype(xml.as_bytes(), "t", None, false)
            .unwrap();
        assert!(p.peek().is_start_with("a"));
    }

    #[test]
    fn validate_is_rejected() {
        assert!(NonThreadedXmlPullParserImpl::from_str("<a/>", "t", None, true).is_err());
    }

    #[test]
    fn parse_errors_go_through_error_handler() {
        struct Recording(Mutex<Vec<(u64, String)>>);
        impl SaxErrorHandler for Recording {
            fn warning(&self, _: &XmlParseException) -> Result<(), XmlError> {
                Ok(())
            }
            fn error(&self, _: &XmlParseException) -> Result<(), XmlError> {
                Ok(())
            }
            fn fatal_error(&self, e: &XmlParseException) -> Result<(), XmlError> {
                self.0.lock().unwrap().push((e.line_number(), e.message().to_string()));
                Ok(())
            }
        }
        let handler = Recording(Mutex::new(Vec::new()));
        let err = NonThreadedXmlPullParserImpl::from_str("<a>\n<b></a>", "t", Some(&handler), false)
            .unwrap_err();
        let seen = handler.0.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, 2);
        assert!(err.message().starts_with("lineNumber: 2;"), "{}", err.message());

        // A throwing handler replaces the exception.
        let err = NonThreadedXmlPullParserImpl::from_str("<a>", "t", Some(&XmlErrorHandler::new()), false)
            .unwrap_err();
        assert!(err.message().starts_with("Fatal error on line 1:"), "{}", err.message());
    }

    #[test]
    fn noncompliant_mode_upper_cases_names() {
        let mut p = NonThreadedXmlPullParserImpl::from_reader_noncompliant_deprecated(
            "<Root><kid/></Root>".as_bytes(),
            "t",
            None,
            false,
            true,
        )
        .unwrap();
        assert_eq!(p.next().get_name(), "ROOT");
        assert_eq!(p.next().get_name(), "KID");
    }

    #[test]
    fn from_file_uses_file_name() {
        let dir = std::env::temp_dir().join(format!("ntxpp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spec.pspec");
        std::fs::write(&path, PSPEC).unwrap();
        let p = NonThreadedXmlPullParserImpl::from_file(&path, None, false).unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        assert_eq!(p.get_name(), "spec.pspec");
        assert!(p.peek().is_start_with("processor_spec"));
    }

    #[test]
    fn set_pulling_content_false_is_accepted() {
        let mut p = parse("<a/>");
        p.set_pulling_content(false);
        assert!(!p.is_pulling_content());
    }

    #[test]
    #[should_panic(expected = "this impl can't inject content")]
    fn set_pulling_content_true_panics() {
        parse("<a/>").set_pulling_content(true);
    }

    #[test]
    fn line_and_level_accessors() {
        let mut p = parse("<a>\n<b/>\n</a>");
        assert_eq!(p.get_current_level(), 0);
        p.next();
        assert_eq!(p.get_current_level(), 1);
        assert_eq!(p.get_line_number(), 2);
        assert_eq!(p.get_column_number(), 5);
        p.discard_sub_tree_named("b").unwrap();
        p.next();
        assert_eq!(p.get_line_number(), -1);
    }
}
