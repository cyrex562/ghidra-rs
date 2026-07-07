use std::fmt;

/// Numeric radix used by the JAD decompiler output formatter.
///
/// Mirrors `ghidra.file.jad.Radix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Radix {
    /// Octal (base 8).
    Eight,
    /// Decimal (base 10).
    Ten,
    /// Hexadecimal (base 16).
    Sixteen,
}

impl fmt::Display for Radix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Radix::Eight => write!(f, "8"),
            Radix::Ten => write!(f, "10"),
            Radix::Sixteen => write!(f, "16"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_eight() {
        assert_eq!(Radix::Eight.to_string(), "8");
    }

    #[test]
    fn display_ten() {
        assert_eq!(Radix::Ten.to_string(), "10");
    }

    #[test]
    fn display_sixteen() {
        assert_eq!(Radix::Sixteen.to_string(), "16");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(Radix::Eight, Radix::Ten);
        assert_ne!(Radix::Ten, Radix::Sixteen);
        assert_ne!(Radix::Eight, Radix::Sixteen);
    }

    #[test]
    fn variants_are_copy() {
        let a = Radix::Ten;
        let _b = a;
        let _c = a;
    }
}
