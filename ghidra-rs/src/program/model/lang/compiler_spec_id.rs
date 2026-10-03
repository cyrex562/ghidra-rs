use std::fmt;

/// Represents an opinion's compiler (gcc, borlandcpp, etc).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompilerSpecID(String);

impl CompilerSpecID {
    /// The default compiler spec ID, used when no ID is given.
    pub const DEFAULT_ID: &'static str = "default";

    /// Creates a new compiler spec ID.
    ///
    /// `id` is the compiler ID (gcc, borlandcpp, etc) as defined in the appropriate
    /// `LanguageDescription`. If `None`, the value of [`Self::DEFAULT_ID`] is assumed.
    pub fn new(id: Option<&str>) -> Self {
        CompilerSpecID(id.unwrap_or(Self::DEFAULT_ID).to_string())
    }

    /// Gets the compiler spec ID as a string.
    pub fn get_id_as_string(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompilerSpecID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_id() {
        let id = CompilerSpecID::new(Some("gcc"));
        assert_eq!(id.get_id_as_string(), "gcc");
    }

    #[test]
    fn new_with_none_defaults() {
        let id = CompilerSpecID::new(None);
        assert_eq!(id.get_id_as_string(), CompilerSpecID::DEFAULT_ID);
    }

    #[test]
    fn display() {
        let id = CompilerSpecID::new(Some("borlandcpp"));
        assert_eq!(id.to_string(), "borlandcpp");
    }

    #[test]
    fn equality() {
        let a = CompilerSpecID::new(Some("gcc"));
        let b = CompilerSpecID::new(Some("gcc"));
        assert_eq!(a, b);
    }

    #[test]
    fn inequality() {
        let a = CompilerSpecID::new(Some("gcc"));
        let b = CompilerSpecID::new(Some("borlandcpp"));
        assert_ne!(a, b);
    }

    #[test]
    fn ordering() {
        let a = CompilerSpecID::new(Some("borlandcpp"));
        let b = CompilerSpecID::new(Some("gcc"));
        assert!(a < b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CompilerSpecID::new(Some("gcc")));
        assert!(set.contains(&CompilerSpecID::new(Some("gcc"))));
        assert!(!set.contains(&CompilerSpecID::new(Some("borlandcpp"))));
    }

    #[test]
    fn clone_preserves_id() {
        let id = CompilerSpecID::new(Some("gcc"));
        assert_eq!(id.clone(), id);
    }
}
