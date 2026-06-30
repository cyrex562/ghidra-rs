use std::fmt;

/// Represents an opinion's processor language (x86:LE:32:default, 8051:BE:16:default, etc).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LanguageID(String);

impl LanguageID {
    /// Creates a new language ID.
    ///
    /// Returns `Err` if `id` is empty.
    pub fn new(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.is_empty() {
            return Err("empty id not allowed");
        }
        Ok(Self(id))
    }

    /// Returns the language ID as a string.
    pub fn get_id_as_string(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_valid() {
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert_eq!(id.get_id_as_string(), "x86:LE:32:default");
    }

    #[test]
    fn new_empty_returns_err() {
        assert!(LanguageID::new("").is_err());
    }

    #[test]
    fn display() {
        let id = LanguageID::new("8051:BE:16:default").unwrap();
        assert_eq!(id.to_string(), "8051:BE:16:default");
    }

    #[test]
    fn equality() {
        let a = LanguageID::new("x86:LE:32:default").unwrap();
        let b = LanguageID::new("x86:LE:32:default").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality() {
        let a = LanguageID::new("x86:LE:32:default").unwrap();
        let b = LanguageID::new("8051:BE:16:default").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ordering() {
        let a = LanguageID::new("8051:BE:16:default").unwrap();
        let b = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(a < b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LanguageID::new("x86:LE:32:default").unwrap());
        assert!(set.contains(&LanguageID::new("x86:LE:32:default").unwrap()));
        assert!(!set.contains(&LanguageID::new("arm:LE:32:default").unwrap()));
    }

    #[test]
    fn clone_preserves_id() {
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert_eq!(id.clone(), id);
    }
}
