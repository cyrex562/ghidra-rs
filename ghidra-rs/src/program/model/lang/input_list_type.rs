use std::fmt;

/// Cspec prototype model input list type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputListType {
    /// Standard input list.
    Standard,
    /// Register-based input list.
    Register,
}

impl fmt::Display for InputListType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Standard => "standard",
            Self::Register => "register",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_standard() {
        assert_eq!(InputListType::Standard.to_string(), "standard");
    }

    #[test]
    fn display_register() {
        assert_eq!(InputListType::Register.to_string(), "register");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(InputListType::Standard, InputListType::Register);
    }

    #[test]
    fn clone_preserves_variant() {
        for v in [InputListType::Standard, InputListType::Register] {
            assert_eq!(v.clone(), v);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", InputListType::Standard).contains("Standard"));
        assert!(format!("{:?}", InputListType::Register).contains("Register"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(InputListType::Standard);
        assert!(set.contains(&InputListType::Standard));
        assert!(!set.contains(&InputListType::Register));
    }
}
