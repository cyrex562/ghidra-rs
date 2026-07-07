/// Specifies a Ghidra user as a principal for use with server login/authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GhidraPrincipal {
    username: String,
}

impl GhidraPrincipal {
    /// Create a new [`GhidraPrincipal`] with the given username.
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
        }
    }

    /// Returns the username associated with this principal.
    pub fn name(&self) -> &str {
        &self.username
    }

    /// Returns the first [`GhidraPrincipal`] from the given collection, or `None` if the
    /// collection is absent or empty.
    ///
    /// This mirrors `GhidraPrincipal.getGhidraPrincipal(Subject)` from the Java source: the
    /// caller is responsible for supplying the already-typed slice (equivalent to
    /// `Subject.getPrincipals(GhidraPrincipal.class)`).
    pub fn get_ghidra_principal<'a>(
        principals: Option<&'a [GhidraPrincipal]>,
    ) -> Option<&'a GhidraPrincipal> {
        principals?.first()
    }
}

impl std::fmt::Display for GhidraPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_name() {
        let p = GhidraPrincipal::new("alice");
        assert_eq!(p.name(), "alice");
    }

    #[test]
    fn test_display() {
        let p = GhidraPrincipal::new("bob");
        assert_eq!(p.to_string(), "bob");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = GhidraPrincipal::new("carol");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_users() {
        let a = GhidraPrincipal::new("dave");
        let b = GhidraPrincipal::new("eve");
        assert_ne!(a, b);
    }

    #[test]
    fn test_get_ghidra_principal_none_subject() {
        assert!(GhidraPrincipal::get_ghidra_principal(None).is_none());
    }

    #[test]
    fn test_get_ghidra_principal_empty_slice() {
        assert!(GhidraPrincipal::get_ghidra_principal(Some(&[])).is_none());
    }

    #[test]
    fn test_get_ghidra_principal_returns_first() {
        let principals = vec![
            GhidraPrincipal::new("first"),
            GhidraPrincipal::new("second"),
        ];
        let result = GhidraPrincipal::get_ghidra_principal(Some(&principals));
        assert_eq!(result.map(|p| p.name()), Some("first"));
    }

    #[test]
    fn test_get_ghidra_principal_single() {
        let principals = vec![GhidraPrincipal::new("only")];
        let result = GhidraPrincipal::get_ghidra_principal(Some(&principals));
        assert_eq!(result.map(|p| p.name()), Some("only"));
    }

    #[test]
    fn test_debug() {
        let p = GhidraPrincipal::new("frank");
        assert!(format!("{:?}", p).contains("GhidraPrincipal"));
        assert!(format!("{:?}", p).contains("frank"));
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GhidraPrincipal::new("grace"));
        set.insert(GhidraPrincipal::new("grace"));
        assert_eq!(set.len(), 1);
    }
}
