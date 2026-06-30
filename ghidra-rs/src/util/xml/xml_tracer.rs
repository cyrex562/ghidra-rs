use std::error::Error;
use std::fmt;

/// Location information within an XML document.
///
/// Mirrors `org.xml.sax.Locator`. Line and column numbers are 1-based;
/// a value of -1 indicates the information is not available.
#[derive(Debug, Clone)]
pub(crate) struct XmlLocator {
    /// Public identifier, or `None` if unavailable.
    pub public_id: Option<String>,
    /// System identifier (URI), or `None` if unavailable.
    pub system_id: Option<String>,
    /// 1-based line number, or -1 if not available.
    pub line_number: i32,
    /// 1-based column number, or -1 if not available.
    pub column_number: i32,
}

impl XmlLocator {
    pub(crate) fn new(
        public_id: Option<String>,
        system_id: Option<String>,
        line_number: i32,
        column_number: i32,
    ) -> Self {
        Self { public_id, system_id, line_number, column_number }
    }
}

impl fmt::Display for XmlLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(sys) = &self.system_id {
            write!(f, "{}:", sys)?;
        }
        if self.line_number >= 0 {
            write!(f, "{}:{}", self.line_number, self.column_number)?;
        }
        Ok(())
    }
}

/// Callback interface for XML processing trace messages.
///
/// Port of `ghidra.xml.XmlTracer`. Implementations should complete quickly.
/// `locator` may be `None` when position information is unavailable, and
/// may be inaccurate even when present (matching the Java contract).
pub(crate) trait XmlTracer {
    fn trace(
        &self,
        locator: Option<&XmlLocator>,
        trace_message: &str,
        error: Option<&dyn Error>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for TestError {}

    struct CapturingTracer {
        messages: RefCell<Vec<String>>,
        error_count: RefCell<usize>,
    }

    impl CapturingTracer {
        fn new() -> Self {
            Self {
                messages: RefCell::new(Vec::new()),
                error_count: RefCell::new(0),
            }
        }
    }

    impl XmlTracer for CapturingTracer {
        fn trace(
            &self,
            _locator: Option<&XmlLocator>,
            trace_message: &str,
            error: Option<&dyn Error>,
        ) {
            self.messages.borrow_mut().push(trace_message.to_string());
            if error.is_some() {
                *self.error_count.borrow_mut() += 1;
            }
        }
    }

    #[test]
    fn trace_captures_message() {
        let tracer = CapturingTracer::new();
        tracer.trace(None, "hello xml", None);
        assert_eq!(tracer.messages.borrow()[0], "hello xml");
    }

    #[test]
    fn trace_without_locator_succeeds() {
        let tracer = CapturingTracer::new();
        tracer.trace(None, "no location", None);
        assert_eq!(tracer.messages.borrow().len(), 1);
    }

    #[test]
    fn trace_with_locator_passes_message() {
        let loc = XmlLocator::new(None, Some("file.xml".into()), 10, 5);
        let tracer = CapturingTracer::new();
        tracer.trace(Some(&loc), "at element", None);
        assert_eq!(tracer.messages.borrow()[0], "at element");
    }

    #[test]
    fn trace_with_error_increments_error_count() {
        let tracer = CapturingTracer::new();
        let err = TestError("boom".into());
        tracer.trace(None, "error trace", Some(&err));
        assert_eq!(*tracer.error_count.borrow(), 1);
    }

    #[test]
    fn trace_without_error_leaves_error_count_zero() {
        let tracer = CapturingTracer::new();
        tracer.trace(None, "clean trace", None);
        assert_eq!(*tracer.error_count.borrow(), 0);
    }

    #[test]
    fn xml_locator_display_with_system_id_and_line() {
        let loc = XmlLocator::new(None, Some("doc.xml".into()), 3, 7);
        assert_eq!(loc.to_string(), "doc.xml:3:7");
    }

    #[test]
    fn xml_locator_display_without_system_id() {
        let loc = XmlLocator::new(None, None, 5, 1);
        assert_eq!(loc.to_string(), "5:1");
    }

    #[test]
    fn xml_locator_display_unavailable_line() {
        let loc = XmlLocator::new(None, Some("x.xml".into()), -1, -1);
        assert_eq!(loc.to_string(), "x.xml:");
    }

    #[test]
    fn xml_locator_display_no_info() {
        let loc = XmlLocator::new(None, None, -1, -1);
        assert_eq!(loc.to_string(), "");
    }

    #[test]
    fn xml_locator_clone_preserves_fields() {
        let loc = XmlLocator::new(Some("pub".into()), Some("sys".into()), 2, 8);
        let loc2 = loc.clone();
        assert_eq!(loc2.public_id.as_deref(), Some("pub"));
        assert_eq!(loc2.system_id.as_deref(), Some("sys"));
        assert_eq!(loc2.line_number, 2);
        assert_eq!(loc2.column_number, 8);
    }

    #[test]
    fn multiple_traces_accumulate() {
        let tracer = CapturingTracer::new();
        tracer.trace(None, "first", None);
        tracer.trace(None, "second", None);
        tracer.trace(None, "third", None);
        assert_eq!(tracer.messages.borrow().len(), 3);
    }
}
