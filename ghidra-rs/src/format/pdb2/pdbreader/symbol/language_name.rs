//! Language name used by certain PDB symbols.
//!
//! Corresponds to the Java enum
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.LanguageName`.
//!
//! Ported as a trait (rather than a plain Rust enum) because this type was selected as a
//! dependency-cycle cut-point: callers such as `AbstractCompile2MsSymbol`, `Compile3MsSymbol`,
//! and `CompileFlagsMsSymbol` (not yet ported) can depend on `dyn LanguageName` instead of a
//! single concrete enum, so their crates don't need to see the full fixed variant list.

/// A language name used by certain PDB symbols.
///
/// See `AbstractCompile2MsSymbol`, `Compile3MsSymbol`, and `CompileFlagsMsSymbol` in the Java
/// source.
pub trait LanguageName: std::fmt::Debug {
    /// Returns the display label (e.g. `"C++"`), matching Java's `toString()`.
    fn label(&self) -> &str;

    /// Returns the raw wire value of this language name.
    fn value(&self) -> i32;
}

/// The standard, fixed set of language names recognized by the PDB reader.
///
/// Corresponds to the enum constants of the Java `LanguageName` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardLanguageName {
    Invalid,
    C,
    Cpp,
    Fortran,
    Masm,
    Pascal,
    Basic,
    Cobol,
    Link,
    Cvtres,
    Cvtpgd,
    Csharp,
    VisualBasic,
    Ilasm,
    Java,
    JScript,
    Msil,
    Hlsl,
}

impl StandardLanguageName {
    fn data(self) -> (&'static str, i32) {
        match self {
            Self::Invalid => ("???", -1),
            Self::C => ("C", 0),
            Self::Cpp => ("C++", 1),
            Self::Fortran => ("FORTRAN", 2),
            Self::Masm => ("MASM", 3),
            Self::Pascal => ("Pascal", 4),
            Self::Basic => ("Basic", 5),
            Self::Cobol => ("COBOL", 6),
            Self::Link => ("LINK", 7),
            Self::Cvtres => ("CVTRES", 8),
            Self::Cvtpgd => ("CVTPGD", 9),
            Self::Csharp => ("C#", 10),
            Self::VisualBasic => ("VisualBasic", 11),
            Self::Ilasm => ("ILASM", 12),
            Self::Java => ("Java", 13),
            Self::JScript => ("JScript", 14),
            Self::Msil => ("MSIL", 15),
            Self::Hlsl => ("HLSL", 16),
        }
    }

    /// Looks up a language name by its raw wire value, matching Java's `fromValue(int)`.
    /// Unrecognized values map to [`StandardLanguageName::Invalid`].
    pub fn from_value(val: i32) -> Self {
        match val {
            0 => Self::C,
            1 => Self::Cpp,
            2 => Self::Fortran,
            3 => Self::Masm,
            4 => Self::Pascal,
            5 => Self::Basic,
            6 => Self::Cobol,
            7 => Self::Link,
            8 => Self::Cvtres,
            9 => Self::Cvtpgd,
            10 => Self::Csharp,
            11 => Self::VisualBasic,
            12 => Self::Ilasm,
            13 => Self::Java,
            14 => Self::JScript,
            15 => Self::Msil,
            16 => Self::Hlsl,
            -1 => Self::Invalid,
            _ => Self::Invalid,
        }
    }
}

impl LanguageName for StandardLanguageName {
    fn label(&self) -> &str {
        self.data().0
    }

    fn value(&self) -> i32 {
        self.data().1
    }
}

impl std::fmt::Display for StandardLanguageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_matches_java_constants() {
        assert_eq!(StandardLanguageName::from_value(0), StandardLanguageName::C);
        assert_eq!(StandardLanguageName::from_value(1), StandardLanguageName::Cpp);
        assert_eq!(StandardLanguageName::from_value(16), StandardLanguageName::Hlsl);
        assert_eq!(StandardLanguageName::from_value(-1), StandardLanguageName::Invalid);
        assert_eq!(StandardLanguageName::from_value(9999), StandardLanguageName::Invalid);
    }

    #[test]
    fn accessors_match_java_fields() {
        let cpp = StandardLanguageName::Cpp;
        assert_eq!(cpp.label(), "C++");
        assert_eq!(cpp.value(), 1);
        assert_eq!(cpp.to_string(), "C++");
    }

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn LanguageName`, matching how a cycle-breaking cut-point trait is consumed.
    #[derive(Debug)]
    struct MockLanguageName;

    impl LanguageName for MockLanguageName {
        fn label(&self) -> &str {
            "MockLang"
        }

        fn value(&self) -> i32 {
            100
        }
    }

    #[test]
    fn is_object_safe() {
        let languages: Vec<Box<dyn LanguageName>> = vec![
            Box::new(StandardLanguageName::Csharp),
            Box::new(MockLanguageName),
        ];
        assert_eq!(languages[0].label(), "C#");
        assert_eq!(languages[0].value(), 10);
        assert_eq!(languages[1].label(), "MockLang");
        assert_eq!(languages[1].value(), 100);
    }
}
