use crate::program::model::lang::compiler_spec::{
    CALLING_CONVENTION_CDECL, CALLING_CONVENTION_FASTCALL, CALLING_CONVENTION_STDCALL,
    CALLING_CONVENTION_THISCALL, CALLING_CONVENTION_VECTORCALL,
};

/// Identifies the generic calling convention associated with a specific function definition.
/// This can be used to help identify the appropriate compiler-specific function prototype
/// (i.e., calling convention).
///
/// # Deprecation
/// Calling convention name strings should be used instead of this enum.
/// [`CompilerSpec`](crate::program::model::lang::compiler_spec::CompilerSpec)
/// provides constants for those included in this enumeration and other setter/getter methods
/// exist for using the string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericCallingConvention {
    /// The calling convention has not been identified.
    Unknown,
    /// A MS Windows specific calling convention applies in which the called-function
    /// is responsible for purging the stack.
    Stdcall,
    /// The standard/default calling convention applies in which the stack is used
    /// to pass parameters.
    Cdecl,
    /// A standard/default calling convention applies in which only registers are used
    /// to pass parameters.
    Fastcall,
    /// A C++ instance method calling convention applies.
    Thiscall,
    /// Similar to fastcall but extended vector registers are used.
    Vectorcall,
}

impl GenericCallingConvention {
    /// Returns the declaration name (string representation) for this calling convention.
    /// For `Unknown`, this returns an empty string.
    pub fn declaration_name(self) -> &'static str {
        match self {
            GenericCallingConvention::Unknown => "",
            GenericCallingConvention::Stdcall => CALLING_CONVENTION_STDCALL,
            GenericCallingConvention::Cdecl => CALLING_CONVENTION_CDECL,
            GenericCallingConvention::Fastcall => CALLING_CONVENTION_FASTCALL,
            GenericCallingConvention::Thiscall => CALLING_CONVENTION_THISCALL,
            GenericCallingConvention::Vectorcall => CALLING_CONVENTION_VECTORCALL,
        }
    }

    /// Returns the GenericCallingConvention corresponding to the specified type string,
    /// or `Unknown` if the name is not defined.
    ///
    /// First tries to match against the declaration names (e.g., "__stdcall").
    /// If no match is found, tries to match against the enum variant names (for backward compatibility).
    /// If still no match, returns `Unknown`.
    pub fn from_declaration_name(calling_convention: &str) -> Self {
        for variant in &[
            GenericCallingConvention::Unknown,
            GenericCallingConvention::Stdcall,
            GenericCallingConvention::Cdecl,
            GenericCallingConvention::Fastcall,
            GenericCallingConvention::Thiscall,
            GenericCallingConvention::Vectorcall,
        ] {
            if variant.declaration_name().eq_ignore_ascii_case(calling_convention) {
                return *variant;
            }
        }

        for variant in &[
            GenericCallingConvention::Unknown,
            GenericCallingConvention::Stdcall,
            GenericCallingConvention::Cdecl,
            GenericCallingConvention::Fastcall,
            GenericCallingConvention::Thiscall,
            GenericCallingConvention::Vectorcall,
        ] {
            if variant.name().eq_ignore_ascii_case(calling_convention) {
                return *variant;
            }
        }

        GenericCallingConvention::Unknown
    }

    /// Returns the enum variant name (e.g., "Unknown", "Stdcall", etc.).
    fn name(self) -> &'static str {
        match self {
            GenericCallingConvention::Unknown => "Unknown",
            GenericCallingConvention::Stdcall => "Stdcall",
            GenericCallingConvention::Cdecl => "Cdecl",
            GenericCallingConvention::Fastcall => "Fastcall",
            GenericCallingConvention::Thiscall => "Thiscall",
            GenericCallingConvention::Vectorcall => "Vectorcall",
        }
    }

    /// Returns the GenericCallingConvention corresponding to the specified ordinal.
    /// The ordinal represents the position in the enumeration.
    /// If the ordinal is out of range, returns `Unknown`.
    pub fn from_ordinal(ordinal: usize) -> Self {
        match ordinal {
            0 => GenericCallingConvention::Unknown,
            1 => GenericCallingConvention::Stdcall,
            2 => GenericCallingConvention::Cdecl,
            3 => GenericCallingConvention::Fastcall,
            4 => GenericCallingConvention::Thiscall,
            5 => GenericCallingConvention::Vectorcall,
            _ => GenericCallingConvention::Unknown,
        }
    }

    /// Returns the ordinal value for this calling convention.
    pub fn ordinal(self) -> usize {
        match self {
            GenericCallingConvention::Unknown => 0,
            GenericCallingConvention::Stdcall => 1,
            GenericCallingConvention::Cdecl => 2,
            GenericCallingConvention::Fastcall => 3,
            GenericCallingConvention::Thiscall => 4,
            GenericCallingConvention::Vectorcall => 5,
        }
    }
}

impl std::fmt::Display for GenericCallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.declaration_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_declaration_names() {
        assert_eq!(GenericCallingConvention::Unknown.declaration_name(), "");
        assert_eq!(
            GenericCallingConvention::Stdcall.declaration_name(),
            "__stdcall"
        );
        assert_eq!(
            GenericCallingConvention::Cdecl.declaration_name(),
            "__cdecl"
        );
        assert_eq!(
            GenericCallingConvention::Fastcall.declaration_name(),
            "__fastcall"
        );
        assert_eq!(
            GenericCallingConvention::Thiscall.declaration_name(),
            "__thiscall"
        );
        assert_eq!(
            GenericCallingConvention::Vectorcall.declaration_name(),
            "__vectorcall"
        );
    }

    #[test]
    fn test_from_declaration_name_case_insensitive() {
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__stdcall"),
            GenericCallingConvention::Stdcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__STDCALL"),
            GenericCallingConvention::Stdcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__StdCall"),
            GenericCallingConvention::Stdcall
        );

        assert_eq!(
            GenericCallingConvention::from_declaration_name("__cdecl"),
            GenericCallingConvention::Cdecl
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__fastcall"),
            GenericCallingConvention::Fastcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__thiscall"),
            GenericCallingConvention::Thiscall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__vectorcall"),
            GenericCallingConvention::Vectorcall
        );
    }

    #[test]
    fn test_from_declaration_name_unknown_returns_unknown() {
        assert_eq!(
            GenericCallingConvention::from_declaration_name(""),
            GenericCallingConvention::Unknown
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("invalid"),
            GenericCallingConvention::Unknown
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__unknown_convention"),
            GenericCallingConvention::Unknown
        );
    }

    #[test]
    fn test_from_declaration_name_backward_compatibility_with_enum_names() {
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Unknown"),
            GenericCallingConvention::Unknown
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Stdcall"),
            GenericCallingConvention::Stdcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Cdecl"),
            GenericCallingConvention::Cdecl
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Fastcall"),
            GenericCallingConvention::Fastcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Thiscall"),
            GenericCallingConvention::Thiscall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("Vectorcall"),
            GenericCallingConvention::Vectorcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("unknown"),
            GenericCallingConvention::Unknown
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("stdcall"),
            GenericCallingConvention::Stdcall
        );
    }

    #[test]
    fn test_from_ordinal() {
        assert_eq!(GenericCallingConvention::from_ordinal(0), GenericCallingConvention::Unknown);
        assert_eq!(GenericCallingConvention::from_ordinal(1), GenericCallingConvention::Stdcall);
        assert_eq!(GenericCallingConvention::from_ordinal(2), GenericCallingConvention::Cdecl);
        assert_eq!(GenericCallingConvention::from_ordinal(3), GenericCallingConvention::Fastcall);
        assert_eq!(GenericCallingConvention::from_ordinal(4), GenericCallingConvention::Thiscall);
        assert_eq!(GenericCallingConvention::from_ordinal(5), GenericCallingConvention::Vectorcall);
    }

    #[test]
    fn test_from_ordinal_out_of_range() {
        assert_eq!(GenericCallingConvention::from_ordinal(6), GenericCallingConvention::Unknown);
        assert_eq!(GenericCallingConvention::from_ordinal(100), GenericCallingConvention::Unknown);
    }

    #[test]
    fn test_ordinal() {
        assert_eq!(GenericCallingConvention::Unknown.ordinal(), 0);
        assert_eq!(GenericCallingConvention::Stdcall.ordinal(), 1);
        assert_eq!(GenericCallingConvention::Cdecl.ordinal(), 2);
        assert_eq!(GenericCallingConvention::Fastcall.ordinal(), 3);
        assert_eq!(GenericCallingConvention::Thiscall.ordinal(), 4);
        assert_eq!(GenericCallingConvention::Vectorcall.ordinal(), 5);
    }

    #[test]
    fn test_roundtrip_ordinal() {
        for ordinal in 0..=5 {
            let convention = GenericCallingConvention::from_ordinal(ordinal);
            assert_eq!(convention.ordinal(), ordinal);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(GenericCallingConvention::Unknown.to_string(), "");
        assert_eq!(GenericCallingConvention::Stdcall.to_string(), "__stdcall");
        assert_eq!(GenericCallingConvention::Cdecl.to_string(), "__cdecl");
        assert_eq!(GenericCallingConvention::Fastcall.to_string(), "__fastcall");
        assert_eq!(GenericCallingConvention::Thiscall.to_string(), "__thiscall");
        assert_eq!(GenericCallingConvention::Vectorcall.to_string(), "__vectorcall");
    }

    #[test]
    fn test_variants_are_distinct() {
        let all = [
            GenericCallingConvention::Unknown,
            GenericCallingConvention::Stdcall,
            GenericCallingConvention::Cdecl,
            GenericCallingConvention::Fastcall,
            GenericCallingConvention::Thiscall,
            GenericCallingConvention::Vectorcall,
        ];

        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }

    #[test]
    fn test_clone_preserves_variant() {
        for variant in [
            GenericCallingConvention::Unknown,
            GenericCallingConvention::Stdcall,
            GenericCallingConvention::Cdecl,
            GenericCallingConvention::Fastcall,
            GenericCallingConvention::Thiscall,
            GenericCallingConvention::Vectorcall,
        ] {
            assert_eq!(variant.clone(), variant);
        }
    }

    #[test]
    fn test_hash_consistent_with_equality() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(GenericCallingConvention::Unknown);
        assert!(set.contains(&GenericCallingConvention::Unknown));
        assert!(!set.contains(&GenericCallingConvention::Stdcall));

        set.insert(GenericCallingConvention::Stdcall);
        assert!(set.contains(&GenericCallingConvention::Stdcall));
        assert_eq!(set.len(), 2);
    }
}
