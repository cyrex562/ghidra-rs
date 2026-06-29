/// A key identifying a column in a SARIF table view, with a visibility flag.
/// Mirrors `sarif.model.SarifColumnKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SarifColumnKey {
    name: String,
    is_hidden: bool,
}

impl SarifColumnKey {
    pub fn new(name: impl Into<String>, is_hidden: bool) -> Self {
        Self {
            name: name.into(),
            is_hidden,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_hidden(&self) -> bool {
        self.is_hidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_visible_column() {
        let key = SarifColumnKey::new("Location", false);
        assert_eq!(key.name(), "Location");
        assert!(!key.is_hidden());
    }

    #[test]
    fn test_new_hidden_column() {
        let key = SarifColumnKey::new("InternalId", true);
        assert_eq!(key.name(), "InternalId");
        assert!(key.is_hidden());
    }

    #[test]
    fn test_empty_name() {
        let key = SarifColumnKey::new("", false);
        assert_eq!(key.name(), "");
    }

    #[test]
    fn test_clone() {
        let key = SarifColumnKey::new("Rule", false);
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn test_equality() {
        let a = SarifColumnKey::new("Message", true);
        let b = SarifColumnKey::new("Message", true);
        let c = SarifColumnKey::new("Message", false);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
