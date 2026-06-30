use std::fmt;

/// Languages that can be output by the decompiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerLanguage {
    /// Output decompiled code as C.
    CLanguage,
    /// Output decompiled code as Java.
    JavaLanguage,
}

impl fmt::Display for DecompilerLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CLanguage => "c-language",
            Self::JavaLanguage => "java-language",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_c_language() {
        assert_eq!(DecompilerLanguage::CLanguage.to_string(), "c-language");
    }

    #[test]
    fn display_java_language() {
        assert_eq!(DecompilerLanguage::JavaLanguage.to_string(), "java-language");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(DecompilerLanguage::CLanguage, DecompilerLanguage::JavaLanguage);
    }

    #[test]
    fn clone_preserves_variant() {
        for v in [DecompilerLanguage::CLanguage, DecompilerLanguage::JavaLanguage] {
            assert_eq!(v.clone(), v);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", DecompilerLanguage::CLanguage).contains("CLanguage"));
        assert!(format!("{:?}", DecompilerLanguage::JavaLanguage).contains("JavaLanguage"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DecompilerLanguage::CLanguage);
        assert!(set.contains(&DecompilerLanguage::CLanguage));
        assert!(!set.contains(&DecompilerLanguage::JavaLanguage));
    }
}
