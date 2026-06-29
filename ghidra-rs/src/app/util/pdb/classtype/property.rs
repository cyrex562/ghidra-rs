use std::fmt;

/// Class properties for C++ PDB symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Property {
    Unknown,
    Blank,
    Virtual,
    Static,
    Friend,
}

impl Property {
    /// Integer value assigned to each variant.
    pub fn value(self) -> i32 {
        match self {
            Property::Unknown => -1,
            Property::Blank => 0,
            Property::Virtual => 1,
            Property::Static => 2,
            Property::Friend => 3,
        }
    }

    /// Human-readable label, matching the Java `getString()` / `toString()` output.
    pub fn label(self) -> &'static str {
        match self {
            Property::Unknown => "INVALID_PROPERTY",
            Property::Blank => "",
            Property::Virtual => "virtual",
            Property::Static => "static",
            Property::Friend => "friend",
        }
    }

    /// Returns the variant whose integer value is `val`, or `Unknown` if unrecognised.
    pub fn from_value(val: i32) -> Self {
        match val {
            -1 => Property::Unknown,
            0 => Property::Blank,
            1 => Property::Virtual,
            2 => Property::Static,
            3 => Property::Friend,
            _ => Property::Unknown,
        }
    }
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_values() {
        assert_eq!(Property::Unknown.value(), -1);
        assert_eq!(Property::Blank.value(), 0);
        assert_eq!(Property::Virtual.value(), 1);
        assert_eq!(Property::Static.value(), 2);
        assert_eq!(Property::Friend.value(), 3);
    }

    #[test]
    fn test_labels() {
        assert_eq!(Property::Unknown.label(), "INVALID_PROPERTY");
        assert_eq!(Property::Blank.label(), "");
        assert_eq!(Property::Virtual.label(), "virtual");
        assert_eq!(Property::Static.label(), "static");
        assert_eq!(Property::Friend.label(), "friend");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Property::Virtual), "virtual");
        assert_eq!(format!("{}", Property::Unknown), "INVALID_PROPERTY");
        assert_eq!(format!("{}", Property::Blank), "");
    }

    #[test]
    fn test_from_value_known() {
        assert_eq!(Property::from_value(-1), Property::Unknown);
        assert_eq!(Property::from_value(0), Property::Blank);
        assert_eq!(Property::from_value(1), Property::Virtual);
        assert_eq!(Property::from_value(2), Property::Static);
        assert_eq!(Property::from_value(3), Property::Friend);
    }

    #[test]
    fn test_from_value_unknown_fallback() {
        assert_eq!(Property::from_value(99), Property::Unknown);
        assert_eq!(Property::from_value(-99), Property::Unknown);
    }

    #[test]
    fn test_roundtrip_value() {
        for prop in [
            Property::Unknown,
            Property::Blank,
            Property::Virtual,
            Property::Static,
            Property::Friend,
        ] {
            assert_eq!(Property::from_value(prop.value()), prop);
        }
    }
}
