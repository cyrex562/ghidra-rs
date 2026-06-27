/// Error type for encountering invalid NT Headers.
///
/// See `NTHeader` for context on when this error is raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidNtHeaderException;

impl std::fmt::Display for InvalidNtHeaderException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid NT header")
    }
}

impl std::error::Error for InvalidNtHeaderException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_display() {
        let e = InvalidNtHeaderException;
        assert_eq!(format!("{e}"), "invalid NT header");
        assert_eq!(format!("{e:?}"), "InvalidNtHeaderException");
    }

    #[test]
    fn test_is_error() {
        let e: &dyn std::error::Error = &InvalidNtHeaderException;
        assert_eq!(e.to_string(), "invalid NT header");
    }

    #[test]
    fn test_clone_eq() {
        let a = InvalidNtHeaderException;
        let b = a.clone();
        assert_eq!(a, b);
    }
}
