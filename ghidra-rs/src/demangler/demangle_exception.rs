use std::fmt;

/// Error type representing a failure during symbol demangling.
///
/// Mirrors the three constructors of `ghidra.app.util.demangler.DemangledException`:
///
/// | Java constructor | Rust variant |
/// |---|---|
/// | `DemangledException(Exception cause)` | [`DemangledException::Cause`] |
/// | `DemangledException(String message)` | [`DemangledException::Message`] |
/// | `DemangledException(boolean invalidMangledName)` | [`DemangledException::Flag`] |
#[derive(Debug)]
pub enum DemangledException {
    /// Demangling failed because an underlying error was raised.
    Cause(Box<dyn std::error::Error + Send + Sync>),
    /// Demangling failed with a descriptive message (e.g. unrecognised datatype).
    Message(String),
    /// Constructed with an explicit `invalidMangledName` boolean flag.
    ///
    /// When `true`, the input does not appear to be a valid mangled name at all.
    Flag { invalid_mangled_name: bool },
}

impl DemangledException {
    /// Creates a [`DemangledException::Cause`] wrapping `cause`.
    ///
    /// Mirrors `new DemangledException(Exception cause)`.
    pub fn from_cause<E>(cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Cause(Box::new(cause))
    }

    /// Creates a [`DemangledException::Message`] with `message`.
    ///
    /// Mirrors `new DemangledException(String message)`.
    pub fn from_message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    /// Creates a [`DemangledException::Flag`] indicating whether `invalid_mangled_name`.
    ///
    /// Mirrors `new DemangledException(boolean invalidMangledName)`.
    pub fn from_invalid_mangled_name(invalid_mangled_name: bool) -> Self {
        Self::Flag { invalid_mangled_name }
    }

    /// Returns `true` if the input string does not appear to be a valid mangled name.
    ///
    /// Mirrors `DemangledException.isInvalidMangledName()`.
    pub fn is_invalid_mangled_name(&self) -> bool {
        match self {
            Self::Flag { invalid_mangled_name } => *invalid_mangled_name,
            _ => false,
        }
    }
}

impl fmt::Display for DemangledException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cause(cause) => write!(f, "{cause}"),
            Self::Message(msg) => write!(f, "{msg}"),
            Self::Flag { invalid_mangled_name } => {
                if *invalid_mangled_name {
                    write!(f, "invalid mangled name")
                } else {
                    write!(f, "demangling failed")
                }
            }
        }
    }
}

impl std::error::Error for DemangledException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Cause(cause) = self {
            Some(cause.as_ref())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    #[test]
    fn from_cause_wraps_error() {
        let inner = io::Error::new(io::ErrorKind::Other, "inner error");
        let ex = DemangledException::from_cause(inner);
        assert!(!ex.is_invalid_mangled_name());
        assert!(ex.source().is_some());
        assert_eq!(ex.to_string(), "inner error");
    }

    #[test]
    fn from_message_stores_message() {
        let ex = DemangledException::from_message("unrecognized datatype");
        assert!(!ex.is_invalid_mangled_name());
        assert!(ex.source().is_none());
        assert_eq!(ex.to_string(), "unrecognized datatype");
    }

    #[test]
    fn from_invalid_mangled_name_true() {
        let ex = DemangledException::from_invalid_mangled_name(true);
        assert!(ex.is_invalid_mangled_name());
        assert!(ex.source().is_none());
        assert_eq!(ex.to_string(), "invalid mangled name");
    }

    #[test]
    fn from_invalid_mangled_name_false() {
        let ex = DemangledException::from_invalid_mangled_name(false);
        assert!(!ex.is_invalid_mangled_name());
        assert!(ex.source().is_none());
        assert_eq!(ex.to_string(), "demangling failed");
    }

    #[test]
    fn cause_source_chain_is_accessible() {
        let inner = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let ex = DemangledException::from_cause(inner);
        let src = ex.source().expect("source should be set");
        assert!(src.to_string().contains("file missing"));
    }

    #[test]
    fn message_and_flag_have_no_source() {
        let msg_ex = DemangledException::from_message("bad symbol");
        let flag_ex = DemangledException::from_invalid_mangled_name(true);
        assert!(msg_ex.source().is_none());
        assert!(flag_ex.source().is_none());
    }

    #[test]
    fn implements_std_error() {
        fn takes_error(_: &dyn std::error::Error) {}
        let ex = DemangledException::from_message("test");
        takes_error(&ex);
    }
}
