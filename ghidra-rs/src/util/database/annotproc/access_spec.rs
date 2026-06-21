use std::collections::HashSet;

use super::Modifier;

/// Represents different levels of access specifiers (private, package-private, protected, public)
/// with corresponding access levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessSpec {
    Private = 0,
    Package = 1,
    Protected = 2,
    Public = 3,
}

impl AccessSpec {
    /// Check if the second permits the same or more access than the first.
    pub fn is_same_or_more_permissive(first: AccessSpec, second: AccessSpec) -> bool {
        first <= second
    }

    /// Get the access specifier derived from the given modifiers.
    pub fn get(modifiers: &HashSet<Modifier>) -> AccessSpec {
        if modifiers.contains(&Modifier::Private) {
            return AccessSpec::Private;
        }
        if modifiers.contains(&Modifier::Protected) {
            return AccessSpec::Protected;
        }
        if modifiers.contains(&Modifier::Public) {
            return AccessSpec::Public;
        }
        AccessSpec::Package
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        assert!(AccessSpec::Private < AccessSpec::Package);
        assert!(AccessSpec::Package < AccessSpec::Protected);
        assert!(AccessSpec::Protected < AccessSpec::Public);
    }

    #[test]
    fn test_is_same_or_more_permissive() {
        assert!(AccessSpec::is_same_or_more_permissive(
            AccessSpec::Private,
            AccessSpec::Private
        ));
        assert!(AccessSpec::is_same_or_more_permissive(
            AccessSpec::Private,
            AccessSpec::Public
        ));
        assert!(!AccessSpec::is_same_or_more_permissive(
            AccessSpec::Public,
            AccessSpec::Private
        ));
        assert!(!AccessSpec::is_same_or_more_permissive(
            AccessSpec::Protected,
            AccessSpec::Package
        ));
        assert!(AccessSpec::is_same_or_more_permissive(
            AccessSpec::Package,
            AccessSpec::Protected
        ));
    }

    #[test]
    fn test_get_private() {
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Private);
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Private);
    }

    #[test]
    fn test_get_protected() {
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Protected);
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Protected);
    }

    #[test]
    fn test_get_public() {
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Public);
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Public);
    }

    #[test]
    fn test_get_package_private() {
        let modifiers = HashSet::new();
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Package);
    }

    #[test]
    fn test_get_private_takes_precedence() {
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Private);
        modifiers.insert(Modifier::Static);
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Private);
    }

    #[test]
    fn test_get_other_modifiers_yield_package() {
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Static);
        modifiers.insert(Modifier::Final);
        assert_eq!(AccessSpec::get(&modifiers), AccessSpec::Package);
    }
}
