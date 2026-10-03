//! Port of `ghidra.app.script.GhidraScriptUnsupportedClassVersionError`.

use std::fmt;

use crate::generic::jar::resource_file::ResourceFile;

/// Signals that a compiled script class file was built by a newer JDK than the one currently
/// running Ghidra.
///
/// Port of `ghidra.app.script.GhidraScriptUnsupportedClassVersionError`, a package-private class
/// (`class GhidraScriptUnsupportedClassVersionError extends RuntimeException`) -- hence
/// `pub(crate)` here rather than `pub`, matching that visibility. Java's constructor is
/// `GhidraScriptUnsupportedClassVersionError(UnsupportedClassVersionError cause, ResourceFile
/// classFile)`, calling `super(cause)`; there is no Rust equivalent of the JDK's
/// `UnsupportedClassVersionError` type (it is thrown by the classloader, not by any Ghidra code),
/// so the cause is accepted generically as any [`std::error::Error`].
///
/// Divergence: Java's `Throwable(Throwable cause)` super-constructor derives this exception's
/// message from `cause.toString()`, which for a typical `Throwable` renders as
/// `"java.lang.UnsupportedClassVersionError: <message>"` (class name prefix included). Since the
/// cause here is a generic Rust error rather than a real `UnsupportedClassVersionError` object,
/// [`Display`](fmt::Display) renders just the cause's own message (via its `Display` impl)
/// without a synthesized class-name prefix.
pub(crate) struct GhidraScriptUnsupportedClassVersionError {
    class_file: ResourceFile,
    cause: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl fmt::Debug for GhidraScriptUnsupportedClassVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GhidraScriptUnsupportedClassVersionError")
            .field("class_file", &self.class_file.absolute_path())
            .field("cause", &self.cause.to_string())
            .finish()
    }
}

impl GhidraScriptUnsupportedClassVersionError {
    /// Mirrors `GhidraScriptUnsupportedClassVersionError(UnsupportedClassVersionError cause,
    /// ResourceFile classFile)`.
    pub(crate) fn new<E>(cause: E, class_file: ResourceFile) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self { class_file, cause: Box::new(cause) }
    }

    /// Mirrors the package-private `getClassFile()`.
    pub(crate) fn get_class_file(&self) -> &ResourceFile {
        &self.class_file
    }
}

impl fmt::Display for GhidraScriptUnsupportedClassVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cause)
    }
}

impl std::error::Error for GhidraScriptUnsupportedClassVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct FakeClassVersionError(String);

    impl fmt::Display for FakeClassVersionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for FakeClassVersionError {}

    #[test]
    fn get_class_file_returns_constructor_argument() {
        let class_file = ResourceFile::new(PathBuf::from("/scripts/MyScript.class"));
        let err = GhidraScriptUnsupportedClassVersionError::new(
            FakeClassVersionError("class file has wrong version 61.0, should be 55.0".into()),
            class_file,
        );
        assert_eq!(err.get_class_file().absolute_path(), "/scripts/MyScript.class");
    }

    #[test]
    fn display_shows_cause_message() {
        let class_file = ResourceFile::new(PathBuf::from("/scripts/MyScript.class"));
        let err = GhidraScriptUnsupportedClassVersionError::new(
            FakeClassVersionError("class file has wrong version 61.0, should be 55.0".into()),
            class_file,
        );
        assert_eq!(err.to_string(), "class file has wrong version 61.0, should be 55.0");
    }

    #[test]
    fn source_returns_the_cause() {
        let class_file = ResourceFile::new(PathBuf::from("/scripts/MyScript.class"));
        let err = GhidraScriptUnsupportedClassVersionError::new(
            FakeClassVersionError("bad version".into()),
            class_file,
        );
        let src = std::error::Error::source(&err).expect("source must be Some");
        assert_eq!(src.to_string(), "bad version");
    }
}
