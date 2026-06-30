use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct UsrException(pub String);

impl UsrException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Operation cancelled: {0}")]
pub struct CancelledException(pub String);

impl CancelledException {
    pub const DEFAULT_MESSAGE: &'static str = "Operation cancelled";

    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }

    pub fn is_default_message(&self) -> bool {
        self.0 == Self::DEFAULT_MESSAGE
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Address overflow: {0}")]
pub struct AddressOverflowException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Address out of bounds: {0}")]
pub struct AddressOutOfBoundsException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Assertion failed: {0}")]
pub struct AssertException(pub String);

impl AssertException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn from_error(err: &dyn std::error::Error) -> Self {
        Self(format!("Unexpected Error: {}", err))
    }
}

/// Exception thrown when a user requests an operation but does not have sufficient privileges.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct UserAccessException(pub String);

impl UserAccessException {
    pub const DEFAULT_MESSAGE: &'static str = "User has insufficient privilege for operation.";

    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl Default for UserAccessException {
    fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = UserAccessException::default();
        assert_eq!(e.0, UserAccessException::DEFAULT_MESSAGE);
        assert_eq!(e.to_string(), UserAccessException::DEFAULT_MESSAGE);
    }

    #[test]
    fn custom_message() {
        let e = UserAccessException::new("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn equality() {
        assert_eq!(
            UserAccessException::default(),
            UserAccessException::new(UserAccessException::DEFAULT_MESSAGE)
        );
        assert_ne!(
            UserAccessException::default(),
            UserAccessException::new("other")
        );
    }
}

/// Error indicating that the underlying resource has been closed and read/write operations
/// have failed.
///
/// Port of `ghidra.util.exception.ClosedException`.
#[derive(Debug, Clone, PartialEq)]
pub struct ClosedException {
    resource_name: Option<String>,
}

impl ClosedException {
    /// Creates a `ClosedException` with the default message "File is closed".
    pub fn new() -> Self {
        Self { resource_name: None }
    }

    /// Creates a `ClosedException` indicating the named resource is closed.
    ///
    /// The [`Display`](fmt::Display) message will be `"<resource_name> is closed"`.
    pub fn with_resource(resource_name: impl Into<String>) -> Self {
        Self { resource_name: Some(resource_name.into()) }
    }

    /// Returns the name of the closed resource, or `None` when using the default constructor.
    pub fn resource_name(&self) -> Option<&str> {
        self.resource_name.as_deref()
    }
}

impl Default for ClosedException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ClosedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.resource_name {
            None => write!(f, "File is closed"),
            Some(name) => write!(f, "{} is closed", name),
        }
    }
}

impl std::error::Error for ClosedException {}

/// Exception wrapping a cryptographic failure, analogous to Java's `IOException` subclass.
///
/// Port of `ghidra.util.exception.CryptoException`.
#[derive(Debug)]
pub struct CryptoException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl CryptoException {
    /// Creates a `CryptoException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), source: None }
    }

    /// Creates a `CryptoException` wrapping the given error as the cause.
    ///
    /// The display message is taken from the cause's `Display` output, mirroring
    /// Java's `super(cause)` which stores `cause.toString()` as the message.
    pub fn from_cause<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        Self { message: cause.to_string(), source: Some(Box::new(cause)) }
    }
}

impl fmt::Display for CryptoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CryptoException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod crypto_exception_tests {
    use super::*;

    #[test]
    fn message_constructor_stores_message() {
        let e = CryptoException::new("decryption failed");
        assert_eq!(e.to_string(), "decryption failed");
    }

    #[test]
    fn message_constructor_has_no_source() {
        let e = CryptoException::new("bad key");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_constructor_uses_cause_message() {
        let inner = CryptoException::new("inner error");
        let outer = CryptoException::from_cause(inner);
        assert_eq!(outer.to_string(), "inner error");
    }

    #[test]
    fn cause_constructor_exposes_source() {
        let inner = ClosedException::with_resource("keystore");
        let e = CryptoException::from_cause(inner);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "keystore is closed");
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &CryptoException::new("oops");
        assert_eq!(e.to_string(), "oops");
        assert!(e.source().is_none());
    }
}

/// Thrown when a file or folder cannot be created because one with that name already
/// exists at the same location.
///
/// Port of `ghidra.util.exception.DuplicateFileException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct DuplicateFileException(pub String);

impl DuplicateFileException {
    /// Creates a `DuplicateFileException` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod duplicate_file_exception_tests {
    use super::*;

    #[test]
    fn stores_message() {
        let e = DuplicateFileException::new("file already exists");
        assert_eq!(e.to_string(), "file already exists");
    }

    #[test]
    fn display_matches_message() {
        let e = DuplicateFileException::new("foo.txt");
        assert_eq!(format!("{}", e), "foo.txt");
    }

    #[test]
    fn equality() {
        assert_eq!(
            DuplicateFileException::new("a"),
            DuplicateFileException::new("a")
        );
        assert_ne!(
            DuplicateFileException::new("a"),
            DuplicateFileException::new("b")
        );
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &DuplicateFileException::new("dup");
        assert_eq!(e.to_string(), "dup");
        assert!(e.source().is_none());
    }
}

/// Indicates contention for a file that is currently in use (e.g. held by a file lock).
///
/// Port of `ghidra.util.exception.FileInUseException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct FileInUseException(pub String);

impl FileInUseException {
    /// Creates a `FileInUseException` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod file_in_use_exception_tests {
    use super::*;

    #[test]
    fn stores_message() {
        let e = FileInUseException::new("file is in use");
        assert_eq!(e.to_string(), "file is in use");
    }

    #[test]
    fn display_matches_message() {
        let e = FileInUseException::new("locked.db");
        assert_eq!(format!("{}", e), "locked.db");
    }

    #[test]
    fn equality() {
        assert_eq!(FileInUseException::new("a"), FileInUseException::new("a"));
        assert_ne!(FileInUseException::new("a"), FileInUseException::new("b"));
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &FileInUseException::new("resource");
        assert_eq!(e.to_string(), "resource");
        assert!(e.source().is_none());
    }
}

/// Wrapper allowing multiple causes to be recorded in place of a single cause.
///
/// Use an instance as the [`source`](std::error::Error::source) of a parent error when multiple
/// independent attempts all failed and each failure should be reported. The causes stored here
/// apply to the "parent" error that chains to this `MultipleCauses` as its source.
///
/// Port of `ghidra.util.exception.MultipleCauses`.
pub struct MultipleCauses {
    causes: Vec<std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl MultipleCauses {
    /// Creates a new `MultipleCauses` with no causes recorded.
    pub fn new() -> Self {
        Self { causes: Vec::new() }
    }

    /// Creates a new `MultipleCauses` pre-populated with the given causes.
    pub fn with_causes(
        causes: Vec<std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self { causes }
    }

    /// Returns a slice of all recorded causes.
    pub fn causes(&self) -> &[std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>] {
        &self.causes
    }

    /// Adds `cause` to the collection.
    pub fn add_cause(
        &mut self,
        cause: std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>,
    ) {
        self.causes.push(cause);
    }

    /// If `e`'s source is a [`MultipleCauses`], flattens its causes into `self`;
    /// otherwise adds `e` directly as a single cause.
    pub fn add_flattened_if_multiple(
        &mut self,
        e: std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>,
    ) {
        if Self::has_multiple(&*e) {
            if let Some(source) = e.source() {
                if let Some(mc) = source.downcast_ref::<MultipleCauses>() {
                    for c in &mc.causes {
                        self.causes.push(std::sync::Arc::clone(c));
                    }
                }
            }
        } else {
            self.causes.push(e);
        }
    }

    /// Copies all causes from the [`MultipleCauses`] source of `e` into `self`.
    ///
    /// If `e`'s source is not a `MultipleCauses` this is a no-op.
    pub fn add_all_causes_from_error(&mut self, e: &dyn std::error::Error) {
        if let Some(source) = e.source() {
            if let Some(mc) = source.downcast_ref::<MultipleCauses>() {
                for c in &mc.causes {
                    self.causes.push(std::sync::Arc::clone(c));
                }
            }
        }
    }

    /// Copies all causes from `that` into `self`.
    pub fn add_all_causes(&mut self, that: &MultipleCauses) {
        for c in &that.causes {
            self.causes.push(std::sync::Arc::clone(c));
        }
    }

    /// Returns `true` if no causes have been recorded.
    pub fn is_empty(&self) -> bool {
        self.causes.is_empty()
    }

    /// Returns `true` if `e`'s [`source`](std::error::Error::source) is a [`MultipleCauses`].
    pub fn has_multiple(e: &dyn std::error::Error) -> bool {
        e.source()
            .and_then(|s| s.downcast_ref::<MultipleCauses>())
            .is_some()
    }

    /// Prints `e` and recursively prints each sub-cause with an increasing `>` prefix.
    pub fn print_tree(out: &mut dyn std::io::Write, e: &dyn std::error::Error) {
        Self::print_tree_with_prefix(out, "", e);
    }

    /// Prints `e` with `prefix`, then recursively prints each cause prefixed with `>`.
    pub fn print_tree_with_prefix(
        out: &mut dyn std::io::Write,
        prefix: &str,
        e: &dyn std::error::Error,
    ) {
        let _ = writeln!(out, "{}{}", prefix, e);
        if Self::has_multiple(e) {
            if let Some(source) = e.source() {
                if let Some(report) = source.downcast_ref::<MultipleCauses>() {
                    let next_prefix = format!("{}>", prefix);
                    for t in &report.causes {
                        Self::print_tree_with_prefix(out, &next_prefix, &**t);
                    }
                }
            }
        }
    }

    /// Returns the causes from `exc`'s [`MultipleCauses`] source.
    ///
    /// If `exc`'s source is not a `MultipleCauses`, returns an empty `Vec`.
    ///
    /// Port of `MultipleCauses.Util.iterCauses`.
    pub fn iter_causes(
        exc: &dyn std::error::Error,
    ) -> Vec<std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>> {
        if let Some(source) = exc.source() {
            if let Some(mc) = source.downcast_ref::<MultipleCauses>() {
                return mc.causes.iter().map(std::sync::Arc::clone).collect();
            }
        }
        vec![]
    }
}

impl Default for MultipleCauses {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MultipleCauses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Multiple Causes")
    }
}

impl fmt::Debug for MultipleCauses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipleCauses")
            .field("causes_count", &self.causes.len())
            .finish()
    }
}

impl std::error::Error for MultipleCauses {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod multiple_causes_tests {
    use super::*;
    use std::sync::Arc;

    fn arc_err(msg: &'static str) -> Arc<dyn std::error::Error + Send + Sync + 'static> {
        Arc::new(UsrException::new(msg))
    }

    #[test]
    fn new_is_empty() {
        let mc = MultipleCauses::new();
        assert!(mc.is_empty());
        assert_eq!(mc.causes().len(), 0);
    }

    #[test]
    fn with_causes_stores_them() {
        let mc = MultipleCauses::with_causes(vec![arc_err("a"), arc_err("b")]);
        assert!(!mc.is_empty());
        assert_eq!(mc.causes().len(), 2);
    }

    #[test]
    fn add_cause_appends() {
        let mut mc = MultipleCauses::new();
        mc.add_cause(arc_err("first"));
        mc.add_cause(arc_err("second"));
        assert_eq!(mc.causes().len(), 2);
        assert_eq!(mc.causes()[0].to_string(), "first");
        assert_eq!(mc.causes()[1].to_string(), "second");
    }

    #[test]
    fn display_is_multiple_causes() {
        assert_eq!(MultipleCauses::new().to_string(), "Multiple Causes");
    }

    #[test]
    fn source_is_none() {
        let mc = MultipleCauses::new();
        let e: &dyn std::error::Error = &mc;
        assert!(e.source().is_none());
    }

    #[test]
    fn default_is_empty() {
        assert!(MultipleCauses::default().is_empty());
    }

    // Helper error that chains to a MultipleCauses as its source.
    #[derive(Debug)]
    struct ParentError(Arc<MultipleCauses>);
    impl fmt::Display for ParentError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "parent")
        }
    }
    impl std::error::Error for ParentError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.0)
        }
    }

    fn parent_with_causes(causes: Vec<Arc<dyn std::error::Error + Send + Sync + 'static>>) -> ParentError {
        let mc = Arc::new(MultipleCauses::with_causes(causes));
        ParentError(mc)
    }

    #[test]
    fn has_multiple_true_when_source_is_multiple_causes() {
        let parent = parent_with_causes(vec![arc_err("x")]);
        assert!(MultipleCauses::has_multiple(&parent));
    }

    #[test]
    fn has_multiple_false_when_no_source() {
        let err = UsrException::new("plain");
        assert!(!MultipleCauses::has_multiple(&err));
    }

    #[test]
    fn has_multiple_false_when_source_is_not_multiple_causes() {
        let inner = CryptoException::new("crypto");
        // Create an error whose source is a plain error, not MultipleCauses
        #[derive(Debug)]
        struct Wrapper(CryptoException);
        impl fmt::Display for Wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "wrap") }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
        }
        let w = Wrapper(inner);
        assert!(!MultipleCauses::has_multiple(&w));
    }

    #[test]
    fn add_all_causes_copies_from_other() {
        let mut dest = MultipleCauses::new();
        let src = MultipleCauses::with_causes(vec![arc_err("p"), arc_err("q")]);
        dest.add_all_causes(&src);
        assert_eq!(dest.causes().len(), 2);
    }

    #[test]
    fn add_all_causes_from_error_flattens_via_source() {
        let parent = parent_with_causes(vec![arc_err("c1"), arc_err("c2")]);
        let mut dest = MultipleCauses::new();
        dest.add_all_causes_from_error(&parent);
        assert_eq!(dest.causes().len(), 2);
    }

    #[test]
    fn add_flattened_if_multiple_flattens_when_has_multiple() {
        let inner_mc = Arc::new(MultipleCauses::with_causes(vec![arc_err("a"), arc_err("b")]));
        let parent: Arc<dyn std::error::Error + Send + Sync + 'static> =
            Arc::new(ParentError(inner_mc));

        let mut dest = MultipleCauses::new();
        dest.add_flattened_if_multiple(parent);
        assert_eq!(dest.causes().len(), 2);
    }

    #[test]
    fn add_flattened_if_multiple_adds_directly_when_no_multiple() {
        let plain: Arc<dyn std::error::Error + Send + Sync + 'static> = arc_err("solo");
        let mut dest = MultipleCauses::new();
        dest.add_flattened_if_multiple(plain);
        assert_eq!(dest.causes().len(), 1);
        assert_eq!(dest.causes()[0].to_string(), "solo");
    }

    #[test]
    fn iter_causes_returns_causes_when_source_is_multiple_causes() {
        let parent = parent_with_causes(vec![arc_err("x"), arc_err("y")]);
        let causes = MultipleCauses::iter_causes(&parent);
        assert_eq!(causes.len(), 2);
        assert_eq!(causes[0].to_string(), "x");
        assert_eq!(causes[1].to_string(), "y");
    }

    #[test]
    fn iter_causes_returns_empty_when_no_multiple_causes() {
        let err = UsrException::new("plain");
        let causes = MultipleCauses::iter_causes(&err);
        assert!(causes.is_empty());
    }

    #[test]
    fn print_tree_writes_error_message() {
        let parent = parent_with_causes(vec![arc_err("cause1"), arc_err("cause2")]);
        let mut buf = Vec::<u8>::new();
        MultipleCauses::print_tree(&mut buf, &parent);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("parent"));
        assert!(output.contains("cause1"));
        assert!(output.contains("cause2"));
        assert!(output.contains('>'));
    }
}

/// Occurs when a link-file's expected linked content type does not match the actual content
/// type of the linked file.
///
/// Port of `ghidra.util.exception.BadLinkException`.
#[derive(Debug)]
pub struct BadLinkException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl BadLinkException {
    /// Creates a `BadLinkException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), source: None }
    }

    /// Creates a `BadLinkException` with the given message and a chained cause.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self { message: message.into(), source: Some(Box::new(cause)) }
    }
}

impl fmt::Display for BadLinkException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BadLinkException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod bad_link_exception_tests {
    use super::*;

    #[test]
    fn message_constructor_stores_message() {
        let e = BadLinkException::new("expected folder, got file");
        assert_eq!(e.to_string(), "expected folder, got file");
    }

    #[test]
    fn message_constructor_has_no_source() {
        let e = BadLinkException::new("link type mismatch");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = ClosedException::with_resource("target");
        let e = BadLinkException::with_cause("bad link", cause);
        assert_eq!(e.to_string(), "bad link");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = ClosedException::with_resource("linked-file");
        let e = BadLinkException::with_cause("bad link", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "linked-file is closed");
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &BadLinkException::new("mismatch");
        assert_eq!(e.to_string(), "mismatch");
        assert!(e.source().is_none());
    }
}

/// Thrown when a property value does not match the expected type.
///
/// Port of `ghidra.util.exception.PropertyTypeMismatchException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct PropertyTypeMismatchException(pub String);

impl PropertyTypeMismatchException {
    /// Creates a `PropertyTypeMismatchException` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod property_type_mismatch_exception_tests {
    use super::*;

    #[test]
    fn stores_message() {
        let e = PropertyTypeMismatchException::new("expected int, got string");
        assert_eq!(e.to_string(), "expected int, got string");
    }

    #[test]
    fn display_matches_message() {
        let e = PropertyTypeMismatchException::new("type mismatch");
        assert_eq!(format!("{}", e), "type mismatch");
    }

    #[test]
    fn equality() {
        assert_eq!(
            PropertyTypeMismatchException::new("a"),
            PropertyTypeMismatchException::new("a")
        );
        assert_ne!(
            PropertyTypeMismatchException::new("a"),
            PropertyTypeMismatchException::new("b")
        );
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &PropertyTypeMismatchException::new("mismatch");
        assert_eq!(e.to_string(), "mismatch");
        assert!(e.source().is_none());
    }
}

/// Thrown during development when a feature or method is not yet implemented.
///
/// This is a development-time exception and should not appear in released code.
///
/// Port of `ghidra.util.exception.NotYetImplementedException`.
#[derive(Debug, Clone, PartialEq)]
pub struct NotYetImplementedException {
    message: Option<String>,
}

impl NotYetImplementedException {
    /// Creates a `NotYetImplementedException` with no detail message.
    pub fn new() -> Self {
        Self { message: None }
    }

    /// Creates a `NotYetImplementedException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self { message: Some(message.into()) }
    }

    /// Returns the detail message, or `None` if none was set.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for NotYetImplementedException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NotYetImplementedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            None => write!(f, "Not yet implemented"),
            Some(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for NotYetImplementedException {}

#[cfg(test)]
mod not_yet_implemented_exception_tests {
    use super::*;

    #[test]
    fn no_arg_constructor_has_no_message() {
        let e = NotYetImplementedException::new();
        assert_eq!(e.message(), None);
    }

    #[test]
    fn no_arg_display_is_not_yet_implemented() {
        let e = NotYetImplementedException::new();
        assert_eq!(e.to_string(), "Not yet implemented");
    }

    #[test]
    fn with_message_stores_message() {
        let e = NotYetImplementedException::with_message("feature X");
        assert_eq!(e.message(), Some("feature X"));
    }

    #[test]
    fn with_message_display_matches_message() {
        let e = NotYetImplementedException::with_message("todo: parse PE headers");
        assert_eq!(format!("{}", e), "todo: parse PE headers");
    }

    #[test]
    fn default_is_same_as_new() {
        assert_eq!(NotYetImplementedException::default(), NotYetImplementedException::new());
    }

    #[test]
    fn equality() {
        assert_eq!(NotYetImplementedException::new(), NotYetImplementedException::new());
        assert_eq!(
            NotYetImplementedException::with_message("a"),
            NotYetImplementedException::with_message("a"),
        );
        assert_ne!(
            NotYetImplementedException::new(),
            NotYetImplementedException::with_message("a"),
        );
        assert_ne!(
            NotYetImplementedException::with_message("a"),
            NotYetImplementedException::with_message("b"),
        );
    }

    #[test]
    fn clone_is_equal() {
        let e = NotYetImplementedException::with_message("clone me");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &NotYetImplementedException::with_message("oops");
        assert_eq!(e.to_string(), "oops");
        assert!(e.source().is_none());
    }
}

#[cfg(test)]
mod closed_exception_tests {
    use super::*;

    #[test]
    fn default_message_is_file_is_closed() {
        assert_eq!(ClosedException::new().to_string(), "File is closed");
        assert_eq!(ClosedException::default().to_string(), "File is closed");
    }

    #[test]
    fn named_resource_message() {
        let e = ClosedException::with_resource("Database");
        assert_eq!(e.to_string(), "Database is closed");
    }

    #[test]
    fn resource_name_accessor_none_for_default() {
        assert_eq!(ClosedException::new().resource_name(), None);
    }

    #[test]
    fn resource_name_accessor_returns_name() {
        let e = ClosedException::with_resource("MyFile");
        assert_eq!(e.resource_name(), Some("MyFile"));
    }

    #[test]
    fn equality() {
        assert_eq!(ClosedException::new(), ClosedException::default());
        assert_ne!(
            ClosedException::new(),
            ClosedException::with_resource("x")
        );
        assert_eq!(
            ClosedException::with_resource("A"),
            ClosedException::with_resource("A")
        );
        assert_ne!(
            ClosedException::with_resource("A"),
            ClosedException::with_resource("B")
        );
    }

    #[test]
    fn clone_is_equal() {
        let e = ClosedException::with_resource("res");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &ClosedException::with_resource("disk");
        assert_eq!(e.to_string(), "disk is closed");
        assert!(e.source().is_none());
    }
}
