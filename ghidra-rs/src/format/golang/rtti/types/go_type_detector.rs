use super::go_kind::GoKind;

/// Lightweight stub for detecting the kind field of a Go runtime type structure.
///
/// Mirrors Ghidra's `GoTypeDetector` Java class. Used to fetch the `kind` field
/// from either `runtime._type` or `internal/abi.Type` and determine which actual
/// type detector to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoTypeDetector {
    kind: u8,
}

impl GoTypeDetector {
    /// Creates a new type detector with the given kind byte.
    pub fn new(kind: u8) -> Self {
        Self { kind }
    }

    /// Returns the parsed `GoKind` from this detector's kind byte.
    pub fn get_kind(&self) -> GoKind {
        GoKind::parse_byte(self.kind)
    }

    /// Returns the raw kind byte.
    pub fn kind_byte(&self) -> u8 {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::{GoTypeDetector, GoKind};

    #[test]
    fn new_stores_kind_byte() {
        let detector = GoTypeDetector::new(1);
        assert_eq!(detector.kind_byte(), 1);
    }

    #[test]
    fn get_kind_parses_byte_to_go_kind() {
        let detector = GoTypeDetector::new(1);
        assert_eq!(detector.get_kind(), GoKind::Bool);

        let detector = GoTypeDetector::new(25);
        assert_eq!(detector.get_kind(), GoKind::Struct);
    }

    #[test]
    fn get_kind_strips_flag_bits() {
        // ordinal 1 (Bool) with GC_PROG and DIRECT_IFACE bits set
        let detector = GoTypeDetector::new(1 | 64 | 32);
        assert_eq!(detector.get_kind(), GoKind::Bool);
    }

    #[test]
    fn clone_and_equality() {
        let detector = GoTypeDetector::new(5);
        let cloned = detector.clone();
        assert_eq!(detector, cloned);
    }

    #[test]
    fn zero_kind_returns_invalid() {
        let detector = GoTypeDetector::new(0);
        assert_eq!(detector.get_kind(), GoKind::Invalid);
    }

    #[test]
    fn out_of_range_kind_returns_invalid() {
        let detector = GoTypeDetector::new(27);
        assert_eq!(detector.get_kind(), GoKind::Invalid);
    }

    #[test]
    fn all_valid_kinds() {
        let cases = [
            (1, GoKind::Bool),
            (2, GoKind::Int),
            (3, GoKind::Int8),
            (4, GoKind::Int16),
            (5, GoKind::Int32),
            (6, GoKind::Int64),
            (7, GoKind::Uint),
            (8, GoKind::Uint8),
            (9, GoKind::Uint16),
            (10, GoKind::Uint32),
            (11, GoKind::Uint64),
            (12, GoKind::Uintptr),
            (13, GoKind::Float32),
            (14, GoKind::Float64),
            (15, GoKind::Complex64),
            (16, GoKind::Complex128),
            (17, GoKind::Array),
            (18, GoKind::Chan),
            (19, GoKind::Func),
            (20, GoKind::Interface),
            (21, GoKind::Map),
            (22, GoKind::Pointer),
            (23, GoKind::Slice),
            (24, GoKind::String),
            (25, GoKind::Struct),
            (26, GoKind::UnsafePointer),
        ];
        for (byte_val, expected_kind) in cases {
            let detector = GoTypeDetector::new(byte_val);
            assert_eq!(
                detector.get_kind(),
                expected_kind,
                "byte {} should map to {:?}",
                byte_val,
                expected_kind
            );
        }
    }

    #[test]
    fn debug_format() {
        let detector = GoTypeDetector::new(42);
        let debug_str = format!("{:?}", detector);
        assert!(debug_str.contains("GoTypeDetector"));
        assert!(debug_str.contains("42"));
    }
}
