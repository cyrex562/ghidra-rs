use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use crate::demangler::demangler_options::DemanglerOptions;

/// The "incomplete prefix" character used in label names.
pub const INCOMPLETE_PREFIX: &str = "$";

/// The "unsupported prefix" character used in label names.
pub const UNSUPPORTED_PREFIX: &str = "$$";

/// Swift demangler options.
///
/// Mirrors `ghidra.app.util.demangler.swift.SwiftDemanglerOptions`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SwiftDemanglerOptions {
    options: DemanglerOptions,
    swift_dir: Option<PathBuf>,
    use_incomplete_prefix: bool,
    use_unsupported_prefix: bool,
}

impl SwiftDemanglerOptions {
    /// Creates a `SwiftDemanglerOptions` with default values.
    ///
    /// Mirrors `SwiftDemanglerOptions()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets the Swift directory.
    ///
    /// If the Swift directory is on the PATH environment variable, this may return `None`.
    ///
    /// Mirrors `getSwiftDir()`.
    pub fn swift_dir(&self) -> Option<&PathBuf> {
        self.swift_dir.as_ref()
    }

    /// Sets the Swift directory.
    ///
    /// If the Swift directory is on the PATH environment variable, it is fine to set this to
    /// `None`.
    ///
    /// Mirrors `setSwiftDir(File)`.
    pub fn set_swift_dir(&mut self, swift_dir: Option<PathBuf>) {
        self.swift_dir = swift_dir;
    }

    /// Gets the "incomplete prefix" character to use in label names.
    ///
    /// Mirrors `getIncompletePrefix()`.
    pub fn incomplete_prefix(&self) -> &'static str {
        if self.use_incomplete_prefix {
            INCOMPLETE_PREFIX
        } else {
            ""
        }
    }

    /// Sets whether or not to use an "incomplete prefix" character in label names.
    ///
    /// Mirrors `setIncompletePrefix(boolean)`.
    pub fn set_incomplete_prefix(&mut self, incomplete_prefix: bool) {
        self.use_incomplete_prefix = incomplete_prefix;
    }

    /// Gets the "unsupported prefix" character to use in label names.
    ///
    /// Mirrors `getUnsupportedPrefix()`.
    pub fn unsupported_prefix(&self) -> &'static str {
        if self.use_unsupported_prefix {
            UNSUPPORTED_PREFIX
        } else {
            ""
        }
    }

    /// Sets whether or not to use an "unsupported prefix" character in label names.
    ///
    /// Mirrors `setUnsupportedPrefix(boolean)`.
    pub fn set_unsupported_prefix(&mut self, unsupported_prefix: bool) {
        self.use_unsupported_prefix = unsupported_prefix;
    }
}

impl Deref for SwiftDemanglerOptions {
    type Target = DemanglerOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for SwiftDemanglerOptions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let opts = SwiftDemanglerOptions::new();
        assert_eq!(opts.swift_dir(), None);
        assert_eq!(opts.incomplete_prefix(), "");
        assert_eq!(opts.unsupported_prefix(), "");
    }

    #[test]
    fn test_swift_dir() {
        let mut opts = SwiftDemanglerOptions::new();
        let dir = PathBuf::from("/usr/local/swift");
        opts.set_swift_dir(Some(dir.clone()));
        assert_eq!(opts.swift_dir(), Some(&dir));

        opts.set_swift_dir(None);
        assert_eq!(opts.swift_dir(), None);
    }

    #[test]
    fn test_incomplete_prefix() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_incomplete_prefix(true);
        assert_eq!(opts.incomplete_prefix(), INCOMPLETE_PREFIX);

        opts.set_incomplete_prefix(false);
        assert_eq!(opts.incomplete_prefix(), "");
    }

    #[test]
    fn test_unsupported_prefix() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_unsupported_prefix(true);
        assert_eq!(opts.unsupported_prefix(), UNSUPPORTED_PREFIX);

        opts.set_unsupported_prefix(false);
        assert_eq!(opts.unsupported_prefix(), "");
    }

    #[test]
    fn test_deref_exposes_demangler_options() {
        let mut opts = SwiftDemanglerOptions::new();
        assert!(opts.apply_signature());

        opts.set_apply_signature(false);
        assert!(!opts.apply_signature());
    }
}
