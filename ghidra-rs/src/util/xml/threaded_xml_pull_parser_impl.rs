//! Port of `ghidra.xml.ThreadedXmlPullParserImpl`.
//!
//! Java runs the SAX parse on a pooled thread (`GThreadPool "XMLParser"`) that pushes elements
//! into a bounded `LinkedBlockingQueue`, and the pulling side blocks on that queue. This port
//! keeps that shape with `std::thread` and a bounded [`sync_channel`]: the producer parses with
//! [`sax_parser`](super::sax_parser) and blocks once `capacity` events are waiting.
//!
//! Differences from Java, all consequences of using a channel instead of shared fields:
//!
//! * Processing instructions travel through the channel (in document order, ahead of the
//!   elements that follow them) instead of being written into a shared map, so they also count
//!   against `capacity`. `get_processing_instruction` still first waits for the first element,
//!   exactly as Java's does via `hasNext()`.
//! * A parse failure arrives after every element queued before it. Java's consumer may see the
//!   exception earlier, depending on thread timing; this is one of the orderings Java allows.
//! * The input is read into memory on the constructing thread (the parse itself still runs on
//!   the producer thread), because a `Box<dyn Read>` is not `Send`. A read error surfaces the way
//!   a Java read error inside the parse does: from the first `has_next`.
//! * `dispose` drops the receiving end, which wakes a producer blocked on a full channel; Java
//!   cancels the task and sets a `disposed` flag the producer polls.
//!
//! Like Java's `RuntimeException`s, a parse failure or use after dispose panics from
//! `has_next`/`peek`/`next`: the [`XmlPullParser`] contract has no error channel on those
//! methods. Callers that want failures as values should use the eager
//! [`NonThreadedXmlPullParserImpl`](super::non_threaded_xml_pull_parser_impl::NonThreadedXmlPullParserImpl),
//! which is what [`xml_pull_parser_factory`](super::xml_pull_parser_factory) returns.

use std::cell::RefCell;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use crate::app::util::xml::xml_error_handler::{SaxErrorHandler, XmlError};
use crate::generic::jar::resource_file::ResourceFile;

use super::non_threaded_xml_pull_parser_impl::{
    check_validate, lookup_processing_instruction, record_processing_instruction, report_failure,
    ElementAssembler, ProcessingInstructions,
};
use super::sax_parser::{self, SaxConfig, SaxContentHandler, SaxError, SaxLocation};
use super::xml_element_impl::XmlElementImpl;
use super::xml_pull_parser::XmlPullParser;

/// A caller-supplied error handler that can be invoked from the parsing thread.
pub(crate) type SharedErrorHandler = Arc<dyn SaxErrorHandler + Send + Sync>;

/// Message sent from the parsing thread to the pulling side.
enum ParserEvent {
    Element(XmlElementImpl),
    ProcessingInstruction(String, String),
    /// The parse failed (Java: the `exception` field being set).
    Failed(XmlError),
    /// The parse is over (Java: `XML_END_TOKEN`).
    Done,
}

/// The pulling side's view of the stream.
#[derive(Default)]
struct PullState {
    /// Java's `nextElement`.
    next: Option<XmlElementImpl>,
    /// Whether the end token has been received.
    done: bool,
    /// Java's `exception`.
    error: Option<XmlError>,
    processing_instructions: ProcessingInstructions,
}

/// Content handler running on the parsing thread.
struct ChannelFiller {
    assembler: ElementAssembler,
    sender: SyncSender<ParserEvent>,
}

impl ChannelFiller {
    /// Port of `addElement`: blocks while the channel is full; fails once the pulling side has
    /// been disposed (dropped its receiver), which stops the parse.
    fn send(&self, event: ParserEvent) -> Result<(), SaxError> {
        self.sender
            .send(event)
            .map_err(|_| SaxError::Handler(XmlError::new("Xml Parser was disposed!")))
    }
}

impl SaxContentHandler for ChannelFiller {
    fn start_element(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        location: SaxLocation,
    ) -> Result<(), SaxError> {
        let element = self.assembler.start(name, attributes, location);
        self.send(ParserEvent::Element(element))
    }

    fn end_element(&mut self, name: &str, location: SaxLocation) -> Result<(), SaxError> {
        let element = self.assembler.end(name, location);
        self.send(ParserEvent::Element(element))
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        self.assembler.characters(text);
        Ok(())
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError> {
        self.send(ParserEvent::ProcessingInstruction(target.to_string(), data.to_string()))
    }
}

/// An [`XmlPullParser`] whose parse runs concurrently on a producer thread, bounded by a
/// queue of `capacity` pending events.
///
/// Port of `ghidra.xml.ThreadedXmlPullParserImpl`. Accepts a `<!DOCTYPE>` but never loads the
/// external subset or external entities, as Java's configuration does.
pub(crate) struct ThreadedXmlPullParserImpl {
    name: String,
    /// `None` once disposed.
    receiver: Option<Receiver<ParserEvent>>,
    state: RefCell<PullState>,
    is_parsing: Arc<AtomicBool>,
    disposed: bool,
}

impl ThreadedXmlPullParserImpl {
    /// Port of `ThreadedXmlPullParserImpl(File, ErrorHandler, boolean, int)`.
    pub(crate) fn from_file(
        file: &Path,
        err_handler: Option<SharedErrorHandler>,
        validate: bool,
        capacity: usize,
    ) -> Result<Self, XmlError> {
        Self::from_resource_file(&ResourceFile::new(file.to_path_buf()), err_handler, validate, capacity)
    }

    /// Port of `ThreadedXmlPullParserImpl(ResourceFile, ErrorHandler, boolean, int)`. Java
    /// passes the file's parent directory to its entity resolver, but external DTDs and
    /// entities are never loaded, so only the file's name and contents matter.
    pub(crate) fn from_resource_file(
        file: &ResourceFile,
        err_handler: Option<SharedErrorHandler>,
        validate: bool,
        capacity: usize,
    ) -> Result<Self, XmlError> {
        let input = file.get_input_stream().map_err(|e| XmlError::new(e.to_string()))?;
        Self::from_reader(input, &file.name(), err_handler, validate, capacity)
    }

    /// Port of `ThreadedXmlPullParserImpl(InputStream, String, ErrorHandler, boolean, int)`.
    pub(crate) fn from_reader<R: Read>(
        mut input: R,
        input_name: &str,
        err_handler: Option<SharedErrorHandler>,
        validate: bool,
        capacity: usize,
    ) -> Result<Self, XmlError> {
        check_validate(validate)?;
        let mut bytes = Vec::new();
        let read = input.read_to_end(&mut bytes).map(|_| bytes);
        Ok(Self::spawn(input_name.to_string(), read, err_handler, capacity))
    }

    fn spawn(
        name: String,
        input: std::io::Result<Vec<u8>>,
        err_handler: Option<SharedErrorHandler>,
        capacity: usize,
    ) -> Self {
        let (sender, receiver) = sync_channel(capacity);
        // Java sets `isParsing` when the task starts running; setting it before the thread
        // exists means a consumer can never observe "not yet started" as "finished".
        let is_parsing = Arc::new(AtomicBool::new(true));
        let producer_is_parsing = Arc::clone(&is_parsing);
        let thread_name = format!("XMLParser - {name}");
        let spawned = thread::Builder::new().name(thread_name).spawn(move || {
            let outcome = match input {
                Err(e) => Err(XmlError::new(e.to_string())),
                Ok(bytes) => {
                    let mut filler = ChannelFiller {
                        assembler: ElementAssembler::new(false),
                        sender: sender.clone(),
                    };
                    sax_parser::parse(&bytes, SaxConfig { allow_doctype: true }, &mut filler)
                        .map_err(|e| report_failure(e, err_handler.as_deref().map(|h| h as &dyn SaxErrorHandler)))
                }
            };
            // Java: `finally { isParsing = false; closeQueue(); }`
            producer_is_parsing.store(false, Ordering::SeqCst);
            if let Err(e) = outcome {
                let _ = sender.send(ParserEvent::Failed(e));
            }
            let _ = sender.send(ParserEvent::Done);
        });
        let state = RefCell::new(PullState::default());
        if let Err(e) = spawned {
            is_parsing.store(false, Ordering::SeqCst);
            state.borrow_mut().error = Some(XmlError::new(format!("cannot start XML parser: {e}")));
        }
        Self { name, receiver: Some(receiver), state, is_parsing, disposed: false }
    }

    /// Whether the producer thread is still parsing. Java: package-private `isParsing()`, used
    /// by tests.
    pub(crate) fn is_parsing(&self) -> bool {
        self.is_parsing.load(Ordering::SeqCst)
    }

    /// Port of `checkForException`: panics (Java: throws `RuntimeException`) once the parse has
    /// failed or the parser has been disposed.
    fn check_for_exception(&self) {
        if let Some(e) = &self.state.borrow().error {
            panic!("{e}");
        }
        if self.disposed {
            panic!("Xml Parser was disposed!");
        }
    }

    /// Port of `waitForNextElement`: blocks until an element or the end of the stream is
    /// available.
    fn fill_next(&self) {
        self.check_for_exception();
        let receiver = self.receiver.as_ref().expect("receiver present until disposed");
        loop {
            {
                let state = self.state.borrow();
                if state.next.is_some() || state.done {
                    return;
                }
            }
            let event = receiver.recv();
            let mut state = self.state.borrow_mut();
            match event {
                Ok(ParserEvent::Element(e)) => state.next = Some(e),
                Ok(ParserEvent::ProcessingInstruction(target, data)) => {
                    record_processing_instruction(&mut state.processing_instructions, &target, &data);
                }
                Ok(ParserEvent::Failed(e)) => state.error = Some(e),
                Ok(ParserEvent::Done) => state.done = true,
                Err(_) => {
                    state.error = Some(XmlError::new("XML parser thread terminated unexpectedly"))
                }
            }
            drop(state);
            self.check_for_exception();
        }
    }
}

impl XmlPullParser for ThreadedXmlPullParserImpl {
    type Element = XmlElementImpl;

    fn get_name(&self) -> &str {
        &self.name
    }

    /// Waits for the first element (so every processing instruction before it has been seen),
    /// then looks the value up case-insensitively.
    fn get_processing_instruction(&self, name: &str, attribute: &str) -> Option<String> {
        self.has_next();
        lookup_processing_instruction(&self.state.borrow().processing_instructions, name, attribute)
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

    /// Blocks until the next element is available or the document has ended. Panics if the
    /// parse failed or the parser was disposed.
    fn has_next(&self) -> bool {
        self.fill_next();
        self.state.borrow().next.is_some()
    }

    /// Panics at end of document, where Java returns `null`.
    fn peek(&self) -> XmlElementImpl {
        if self.has_next() {
            return self.state.borrow().next.clone().expect("has_next");
        }
        panic!("peek() called with no next XML element");
    }

    /// Panics at end of document, where Java returns `null`.
    fn next(&mut self) -> XmlElementImpl {
        if self.has_next() {
            return self.state.get_mut().next.take().expect("has_next");
        }
        panic!("next() called with no next XML element");
    }

    /// Stops the parsing thread; no more elements may be read afterwards.
    fn dispose(&mut self) {
        self.disposed = true;
        self.receiver = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::xml::xml_error_handler::XmlParseException;
    use crate::util::xml::xml_element::XmlElement;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    // Fixtures from Java's ThreadedXmlParserTest.
    const GOOD_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc>\
<project name=\"foo\"/><project name=\"foo\"/><project name=\"foo\"/><project name=\"foo\"/>\
<project name=\"foo\"/><project name=\"foo\"/><project name=\"foo\"/></doc>";

    const BAD_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc>\
<project name=\"foo\"/><project name=\"foo\"/<project name=\"foo\"/><project name=\"foo\"/>\
<project name=\"foo\"/><project name=\"foo\"/><project name=\"foo\"/></doc>";

    const XXE_XML: &str = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n\
<!DOCTYPE foo [\n    <!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM \"file://@TEMP_FILE@\">]>\
<foo>&xxe; fizzbizz</foo>";

    #[derive(Default)]
    struct TestErrorHandler {
        my_exception: Mutex<Option<XmlParseException>>,
    }

    impl SaxErrorHandler for TestErrorHandler {
        fn warning(&self, _: &XmlParseException) -> Result<(), XmlError> {
            Ok(())
        }
        fn error(&self, e: &XmlParseException) -> Result<(), XmlError> {
            *self.my_exception.lock().unwrap() = Some(e.clone());
            Ok(())
        }
        fn fatal_error(&self, e: &XmlParseException) -> Result<(), XmlError> {
            *self.my_exception.lock().unwrap() = Some(e.clone());
            Ok(())
        }
    }

    fn parser(xml: &str, capacity: usize) -> ThreadedXmlPullParserImpl {
        ThreadedXmlPullParserImpl::from_reader(
            xml.as_bytes(),
            "test",
            Some(Arc::new(TestErrorHandler::default())),
            false,
            capacity,
        )
        .unwrap()
    }

    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        condition()
    }

    fn panic_message(result: thread::Result<()>) -> Option<String> {
        result.err().map(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        })
    }

    #[test]
    fn xxe_external_entity_is_not_resolved() {
        let dir = std::env::temp_dir().join(format!("txpp-xxe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.txt");
        std::fs::write(&file, "foobar").unwrap();
        let xml = XXE_XML.replace("@TEMP_FILE@", &file.to_string_lossy());

        let mut p = parser(&xml, 3);
        p.start(&["foo"]).unwrap();
        let x1 = p.next();
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&dir);
        assert!(!x1.get_text().contains("foobar"));
        assert_eq!(x1.get_text(), " fizzbizz");
    }

    #[test]
    fn good_xml() {
        let mut p = parser(GOOD_XML, 3);
        p.start(&["doc"]).unwrap();
        let project = p.start(&["project"]).unwrap();
        assert_eq!(project.get_attribute("name").as_deref(), Some("foo"));
        p.end_matching(&project).unwrap();
        assert!(p.is_parsing(), "parser should be running");
        let mut remaining = 0;
        while p.has_next() {
            p.next();
            remaining += 1;
        }
        assert_eq!(remaining, 6 * 2 + 1);
        assert!(!p.is_parsing(), "parser should be shutdown");
    }

    #[test]
    fn good_xml_early_exit() {
        let mut p = parser(GOOD_XML, 3);
        p.start(&["doc"]).unwrap();
        let project = p.start(&["project"]).unwrap();
        p.end_matching(&project).unwrap();
        assert!(p.is_parsing(), "parser should be running");
        p.dispose();
        assert!(wait_until(|| !p.is_parsing()), "parser should have shutdown");
    }

    #[test]
    fn bad_xml() {
        let handler = Arc::new(TestErrorHandler::default());
        let mut p = ThreadedXmlPullParserImpl::from_reader(
            BAD_XML.as_bytes(),
            "test",
            Some(handler.clone() as SharedErrorHandler),
            false,
            3,
        )
        .unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            p.start(&["doc"]).unwrap();
            while p.has_next() {
                p.next();
            }
        }));
        let message = panic_message(result).expect("expected a panic from has_next()");
        assert!(message.contains("lineNumber: 2;"), "{message}");
        assert!(handler.my_exception.lock().unwrap().is_some());
        assert!(!p.is_parsing(), "parser should be shutdown");
        // The failure is sticky, as Java's exception field is.
        assert!(panic_message(catch_unwind(AssertUnwindSafe(|| {
            p.has_next();
        })))
        .is_some());
    }

    #[test]
    fn has_next_after_dispose_panics() {
        let mut p = parser(GOOD_XML, 3);
        p.start(&["doc"]).unwrap();
        p.dispose();
        assert!(wait_until(|| !p.is_parsing()));
        let message = panic_message(catch_unwind(AssertUnwindSafe(|| {
            p.has_next();
        })));
        assert_eq!(message.as_deref(), Some("Xml Parser was disposed!"));
    }

    #[test]
    fn more_jobs_than_threads() {
        let mut parsers: Vec<ThreadedXmlPullParserImpl> =
            (0..25).map(|_| parser(GOOD_XML, 3)).collect();
        for p in &mut parsers {
            p.dispose();
        }
        for p in &parsers {
            assert!(wait_until(|| !p.is_parsing()));
        }
    }

    #[test]
    fn drains_from_another_thread_after_filling() {
        // Java's testInterruptingParserThreadDoesNotDeadlockClientThread: the client drains the
        // queue from a different thread without deadlocking.
        let mut p = parser(GOOD_XML, 3);
        p.start(&["doc"]).unwrap();
        let handle = thread::spawn(move || {
            let mut n = 0;
            while p.has_next() {
                p.next();
                n += 1;
            }
            n
        });
        assert_eq!(handle.join().unwrap(), 7 * 2 + 1);
    }

    #[test]
    fn processing_instructions_before_first_element() {
        let p = parser("<?program_dtd version=\"1\"?><a/>", 1);
        assert_eq!(p.get_processing_instruction("PROGRAM_DTD", "version").as_deref(), Some("1"));
        assert!(p.peek().is_start_with("a"));
    }

    #[test]
    fn resource_file_constructor_names_parser_after_file() {
        let dir = std::env::temp_dir().join(format!("txpp-rf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.cspec");
        std::fs::write(&path, "<compiler_spec><default_proto/></compiler_spec>").unwrap();
        let mut p = ThreadedXmlPullParserImpl::from_file(&path, None, false, 1000).unwrap();
        assert_eq!(p.get_name(), "x.cspec");
        assert_eq!(p.discard_sub_tree_named("compiler_spec").unwrap(), 4);
        assert!(!p.has_next());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn read_error_surfaces_from_has_next() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let p = ThreadedXmlPullParserImpl::from_reader(Failing, "t", None, false, 3).unwrap();
        let message = panic_message(catch_unwind(AssertUnwindSafe(|| {
            p.has_next();
        })));
        assert_eq!(message.as_deref(), Some("boom"));
    }

    #[test]
    fn validate_is_rejected() {
        assert!(ThreadedXmlPullParserImpl::from_reader("<a/>".as_bytes(), "t", None, true, 3).is_err());
    }
}
