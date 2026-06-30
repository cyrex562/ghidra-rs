use std::fmt;

/// Occurs when a graph cannot be sorted.
#[derive(Debug, Clone)]
pub struct SorterException {
    message: String,
}

impl SorterException {
    /// Creates a new `SorterException` with a description and two values.
    ///
    /// Formats the message as `"{desc}: {v1} ?? {v2}"`.
    pub fn new(desc: &str, v1: impl fmt::Display, v2: impl fmt::Display) -> Self {
        SorterException {
            message: format!("{}: {} ?? {}", desc, v1, v2),
        }
    }

    /// Creates a new `SorterException` with a description and a collection of values.
    ///
    /// Formats the message as `"{desc}: [{v0}, {v1}, ...]"`.
    pub fn from_items<S: fmt::Display>(desc: &str, vs: impl IntoIterator<Item = S>) -> Self {
        let parts: Vec<String> = vs.into_iter().map(|v| v.to_string()).collect();
        SorterException {
            message: format!("{}: [{}]", desc, parts.join(", ")),
        }
    }
}

impl fmt::Display for SorterException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SorterException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_formats_two_objects() {
        let e = SorterException::new("cycle detected", "A", "B");
        assert_eq!(e.to_string(), "cycle detected: A ?? B");
    }

    #[test]
    fn test_new_with_integer_values() {
        let e = SorterException::new("bad nodes", 1, 2);
        assert_eq!(e.to_string(), "bad nodes: 1 ?? 2");
    }

    #[test]
    fn test_from_items_empty() {
        let e = SorterException::from_items("no items", Vec::<&str>::new());
        assert_eq!(e.to_string(), "no items: []");
    }

    #[test]
    fn test_from_items_single() {
        let e = SorterException::from_items("one item", vec!["X"]);
        assert_eq!(e.to_string(), "one item: [X]");
    }

    #[test]
    fn test_from_items_multiple() {
        let e = SorterException::from_items("cycle", vec!["A", "B", "C"]);
        assert_eq!(e.to_string(), "cycle: [A, B, C]");
    }

    #[test]
    fn test_implements_error() {
        let e = SorterException::new("desc", "v1", "v2");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_debug_impl() {
        let e = SorterException::new("desc", "v1", "v2");
        let s = format!("{:?}", e);
        assert!(s.contains("SorterException"));
    }

    #[test]
    fn test_clone() {
        let e = SorterException::new("desc", "v1", "v2");
        let e2 = e.clone();
        assert_eq!(e.to_string(), e2.to_string());
    }
}
