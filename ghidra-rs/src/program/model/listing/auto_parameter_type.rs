use std::fmt;

/// Defines the various types of auto-parameters (hidden parameters injected by a calling convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoParameterType {
    /// Object pointer passed as a hidden parameter for the `__thiscall` calling convention.
    This,
    /// Caller-allocated return storage pointer passed as a hidden parameter.
    ReturnStoragePtr,
}

impl AutoParameterType {
    /// Returns the display name used to identify this auto-parameter type.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::This => "this",
            Self::ReturnStoragePtr => "__return_storage_ptr__",
        }
    }
}

impl fmt::Display for AutoParameterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_this() {
        assert_eq!(AutoParameterType::This.display_name(), "this");
    }

    #[test]
    fn display_name_return_storage_ptr() {
        assert_eq!(
            AutoParameterType::ReturnStoragePtr.display_name(),
            "__return_storage_ptr__"
        );
    }

    #[test]
    fn display_matches_display_name() {
        for v in [AutoParameterType::This, AutoParameterType::ReturnStoragePtr] {
            assert_eq!(v.to_string(), v.display_name());
        }
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(AutoParameterType::This, AutoParameterType::ReturnStoragePtr);
    }

    #[test]
    fn clone_preserves_variant() {
        for v in [AutoParameterType::This, AutoParameterType::ReturnStoragePtr] {
            assert_eq!(v, v);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", AutoParameterType::This).contains("This"));
        assert!(
            format!("{:?}", AutoParameterType::ReturnStoragePtr).contains("ReturnStoragePtr")
        );
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AutoParameterType::This);
        assert!(set.contains(&AutoParameterType::This));
        assert!(!set.contains(&AutoParameterType::ReturnStoragePtr));
    }
}
