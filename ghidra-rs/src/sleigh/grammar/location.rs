use once_cell::sync::Lazy;

/// A source location: filename and line number.
///
/// Mirrors `ghidra.sleigh.grammar.Location`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Location {
    pub filename: String,
    pub lineno: i32,
}

/// Sentinel for locations that are internally synthesized rather than read from a file.
///
/// Mirrors `Location.INTERNALLY_DEFINED`.
pub static INTERNALLY_DEFINED: Lazy<Location> =
    Lazy::new(|| Location::new("<internally defined>", 1));

impl Location {
    pub fn new(filename: impl Into<String>, lineno: i32) -> Self {
        Self {
            filename: filename.into(),
            lineno,
        }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.filename, self.lineno)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_filename_and_line() {
        let loc = Location::new("foo.sleigh", 42);
        assert_eq!(loc.to_string(), "foo.sleigh:42");
    }

    #[test]
    fn internally_defined_sentinel() {
        assert_eq!(INTERNALLY_DEFINED.filename, "<internally defined>");
        assert_eq!(INTERNALLY_DEFINED.lineno, 1);
        assert_eq!(INTERNALLY_DEFINED.to_string(), "<internally defined>:1");
    }

    #[test]
    fn clone_and_eq() {
        let a = Location::new("a.sl", 10);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Location::new("x.sl", 1));
        set.insert(Location::new("x.sl", 1));
        assert_eq!(set.len(), 1);
    }
}
