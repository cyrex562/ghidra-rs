use std::fmt;

/// C++ class-key keywords, as defined in the PDB format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassKey {
    Unknown,
    Blank,
    Class,
    Struct,
    Union,
}

impl ClassKey {
    /// Integer value assigned to each variant.
    pub fn value(self) -> i32 {
        match self {
            ClassKey::Unknown => -1,
            ClassKey::Blank => 1,
            ClassKey::Class => 2,
            ClassKey::Struct => 3,
            ClassKey::Union => 4,
        }
    }

    /// Human-readable label, matching the Java `getString()` output.
    pub fn label(self) -> &'static str {
        match self {
            ClassKey::Unknown => "UNKNOWN_TYPE",
            ClassKey::Blank => "",
            ClassKey::Class => "class",
            ClassKey::Struct => "struct",
            ClassKey::Union => "union",
        }
    }

    /// Returns the variant whose integer value is `val`, or `Unknown` if unrecognised.
    pub fn from_value(val: i32) -> Self {
        match val {
            -1 => ClassKey::Unknown,
            1 => ClassKey::Blank,
            2 => ClassKey::Class,
            3 => ClassKey::Struct,
            4 => ClassKey::Union,
            _ => ClassKey::Unknown,
        }
    }
}

impl fmt::Display for ClassKey {
    /// Matches Java `toString()`: appends a trailing space for non-empty labels.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbl = self.label();
        if lbl.is_empty() {
            write!(f, "")
        } else {
            write!(f, "{} ", lbl)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_values() {
        assert_eq!(ClassKey::Unknown.value(), -1);
        assert_eq!(ClassKey::Blank.value(), 1);
        assert_eq!(ClassKey::Class.value(), 2);
        assert_eq!(ClassKey::Struct.value(), 3);
        assert_eq!(ClassKey::Union.value(), 4);
    }

    #[test]
    fn test_labels() {
        assert_eq!(ClassKey::Unknown.label(), "UNKNOWN_TYPE");
        assert_eq!(ClassKey::Blank.label(), "");
        assert_eq!(ClassKey::Class.label(), "class");
        assert_eq!(ClassKey::Struct.label(), "struct");
        assert_eq!(ClassKey::Union.label(), "union");
    }

    #[test]
    fn test_display_appends_space_for_non_empty() {
        assert_eq!(format!("{}", ClassKey::Class), "class ");
        assert_eq!(format!("{}", ClassKey::Struct), "struct ");
        assert_eq!(format!("{}", ClassKey::Union), "union ");
        assert_eq!(format!("{}", ClassKey::Unknown), "UNKNOWN_TYPE ");
    }

    #[test]
    fn test_display_blank_is_empty() {
        assert_eq!(format!("{}", ClassKey::Blank), "");
    }

    #[test]
    fn test_from_value_known() {
        assert_eq!(ClassKey::from_value(-1), ClassKey::Unknown);
        assert_eq!(ClassKey::from_value(1), ClassKey::Blank);
        assert_eq!(ClassKey::from_value(2), ClassKey::Class);
        assert_eq!(ClassKey::from_value(3), ClassKey::Struct);
        assert_eq!(ClassKey::from_value(4), ClassKey::Union);
    }

    #[test]
    fn test_from_value_unknown_fallback() {
        assert_eq!(ClassKey::from_value(0), ClassKey::Unknown);
        assert_eq!(ClassKey::from_value(99), ClassKey::Unknown);
        assert_eq!(ClassKey::from_value(-99), ClassKey::Unknown);
    }

    #[test]
    fn test_roundtrip_value() {
        for key in [
            ClassKey::Unknown,
            ClassKey::Blank,
            ClassKey::Class,
            ClassKey::Struct,
            ClassKey::Union,
        ] {
            assert_eq!(ClassKey::from_value(key.value()), key);
        }
    }
}
