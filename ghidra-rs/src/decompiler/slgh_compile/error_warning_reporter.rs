use crate::sleigh::grammar::Location;

/// A callback interface for reporting errors and warnings during SLEIGH compilation.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.ErrorWarningReporter`.
pub trait ErrorWarningReporter {
    /// Reports a compilation error at the given location with the given message.
    fn report_error(&self, location: &Location, msg: &str);

    /// Reports a compilation warning at the given location with the given message.
    fn report_warning(&self, location: &Location, msg: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct MockReporter {
        errors: Rc<RefCell<Vec<(Location, String)>>>,
        warnings: Rc<RefCell<Vec<(Location, String)>>>,
    }

    impl ErrorWarningReporter for MockReporter {
        fn report_error(&self, location: &Location, msg: &str) {
            self.errors.borrow_mut().push((location.clone(), msg.to_string()));
        }

        fn report_warning(&self, location: &Location, msg: &str) {
            self.warnings.borrow_mut().push((location.clone(), msg.to_string()));
        }
    }

    #[test]
    fn trait_object_accepts_error() {
        let reporter: Box<dyn ErrorWarningReporter> = Box::new(MockReporter::default());
        let loc = Location::new("test.sleigh", 10);
        reporter.report_error(&loc, "test error");
    }

    #[test]
    fn trait_object_accepts_warning() {
        let reporter: Box<dyn ErrorWarningReporter> = Box::new(MockReporter::default());
        let loc = Location::new("test.sleigh", 20);
        reporter.report_warning(&loc, "test warning");
    }

    #[test]
    fn mock_captures_error() {
        let reporter = MockReporter::default();
        let loc = Location::new("file.sl", 5);
        reporter.report_error(&loc, "syntax error");

        let errors = reporter.errors.borrow();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, loc);
        assert_eq!(errors[0].1, "syntax error");
    }

    #[test]
    fn mock_captures_warning() {
        let reporter = MockReporter::default();
        let loc = Location::new("file.sl", 15);
        reporter.report_warning(&loc, "unused variable");

        let warnings = reporter.warnings.borrow();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].0, loc);
        assert_eq!(warnings[0].1, "unused variable");
    }

    #[test]
    fn mock_captures_multiple_errors() {
        let reporter = MockReporter::default();
        let loc1 = Location::new("file.sl", 1);
        let loc2 = Location::new("file.sl", 2);

        reporter.report_error(&loc1, "first error");
        reporter.report_error(&loc2, "second error");

        let errors = reporter.errors.borrow();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].1, "first error");
        assert_eq!(errors[1].1, "second error");
    }

    #[test]
    fn mock_captures_multiple_warnings() {
        let reporter = MockReporter::default();
        let loc1 = Location::new("file.sl", 1);
        let loc2 = Location::new("file.sl", 2);

        reporter.report_warning(&loc1, "first warning");
        reporter.report_warning(&loc2, "second warning");

        let warnings = reporter.warnings.borrow();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].1, "first warning");
        assert_eq!(warnings[1].1, "second warning");
    }

    #[test]
    fn mock_captures_errors_and_warnings_separately() {
        let reporter = MockReporter::default();
        let loc = Location::new("file.sl", 5);

        reporter.report_error(&loc, "an error");
        reporter.report_warning(&loc, "a warning");

        let errors = reporter.errors.borrow();
        let warnings = reporter.warnings.borrow();

        assert_eq!(errors.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(errors[0].1, "an error");
        assert_eq!(warnings[0].1, "a warning");
    }

    #[test]
    fn empty_message_is_valid() {
        let reporter = MockReporter::default();
        let loc = Location::new("file.sl", 1);

        reporter.report_error(&loc, "");
        reporter.report_warning(&loc, "");

        let errors = reporter.errors.borrow();
        let warnings = reporter.warnings.borrow();

        assert_eq!(errors[0].1, "");
        assert_eq!(warnings[0].1, "");
    }

    #[test]
    fn location_preserved_in_error() {
        let reporter = MockReporter::default();
        let loc = Location::new("important.sleigh", 999);
        reporter.report_error(&loc, "msg");

        let errors = reporter.errors.borrow();
        assert_eq!(errors[0].0.filename, "important.sleigh");
        assert_eq!(errors[0].0.lineno, 999);
    }
}
