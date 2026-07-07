/// Go primitive kind discriminant, mirroring Go's `reflect.Kind` and
/// Ghidra's `GoKind` Java enum.
///
/// The numeric ordinals (1 = `Bool` … 26 = `UnsafePointer`) match those
/// encoded in the `kind` byte of a Go runtime `_type` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoKind {
    Invalid,
    Bool,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uintptr,
    Float32,
    Float64,
    Complex64,
    Complex128,
    Array,
    Chan,
    Func,
    Interface,
    Map,
    Pointer,
    Slice,
    String,
    Struct,
    UnsafePointer,
}

/// Mask isolating the kind bits from the `_type.kind` byte (bits 0–4).
pub const KIND_MASK: u8 = (1 << 5) - 1;

/// Bit flag: type uses a GC program rather than a bitmap (bit 6).
pub const GC_PROG: u8 = 1 << 6;

/// Bit flag: pointer is stored directly in the interface value (bit 5).
pub const DIRECT_IFACE: u8 = 1 << 5;

impl GoKind {
    /// Parses the byte value read from a Go runtime `_type.kind` field.
    ///
    /// Strips flag bits with [`KIND_MASK`] and maps the resulting ordinal
    /// (1–26) to the corresponding variant.  Returns [`GoKind::Invalid`]
    /// for any value outside that range.
    pub fn parse_byte(b: u8) -> Self {
        match b & KIND_MASK {
            1 => Self::Bool,
            2 => Self::Int,
            3 => Self::Int8,
            4 => Self::Int16,
            5 => Self::Int32,
            6 => Self::Int64,
            7 => Self::Uint,
            8 => Self::Uint8,
            9 => Self::Uint16,
            10 => Self::Uint32,
            11 => Self::Uint64,
            12 => Self::Uintptr,
            13 => Self::Float32,
            14 => Self::Float64,
            15 => Self::Complex64,
            16 => Self::Complex128,
            17 => Self::Array,
            18 => Self::Chan,
            19 => Self::Func,
            20 => Self::Interface,
            21 => Self::Map,
            22 => Self::Pointer,
            23 => Self::Slice,
            24 => Self::String,
            25 => Self::Struct,
            26 => Self::UnsafePointer,
            _ => Self::Invalid,
        }
    }

    /// Looks up a [`GoKind`] by its Go type-name string (case-insensitive).
    ///
    /// Returns [`GoKind::Invalid`] when no variant matches.
    pub fn parse_typename(type_name: &str) -> Self {
        let lower = type_name.to_ascii_lowercase();
        match lower.as_str() {
            "bool" => Self::Bool,
            "int" => Self::Int,
            "int8" => Self::Int8,
            "int16" => Self::Int16,
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "uint" => Self::Uint,
            "uint8" => Self::Uint8,
            "uint16" => Self::Uint16,
            "uint32" => Self::Uint32,
            "uint64" => Self::Uint64,
            "uintptr" => Self::Uintptr,
            "float32" => Self::Float32,
            "float64" => Self::Float64,
            "complex64" => Self::Complex64,
            "complex128" => Self::Complex128,
            "array" => Self::Array,
            "chan" => Self::Chan,
            "func()" => Self::Func,
            "interface" => Self::Interface,
            "map" => Self::Map,
            "pointer" => Self::Pointer,
            "slice" => Self::Slice,
            "string" => Self::String,
            "struct" => Self::Struct,
            "unsafe.pointer" => Self::UnsafePointer,
            "invalid" => Self::Invalid,
            _ => Self::Invalid,
        }
    }

    /// Returns the Go source-language type name for this kind.
    pub fn type_name(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Int8 => "int8",
            Self::Int16 => "int16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Uint => "uint",
            Self::Uint8 => "uint8",
            Self::Uint16 => "uint16",
            Self::Uint32 => "uint32",
            Self::Uint64 => "uint64",
            Self::Uintptr => "uintptr",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Complex64 => "complex64",
            Self::Complex128 => "complex128",
            Self::Array => "array",
            Self::Chan => "chan",
            Self::Func => "func()",
            Self::Interface => "interface",
            Self::Map => "map",
            Self::Pointer => "pointer",
            Self::Slice => "slice",
            Self::String => "string",
            Self::Struct => "struct",
            Self::UnsafePointer => "unsafe.Pointer",
        }
    }

    /// Returns `true` for kinds that are represented as a single, non-composite
    /// value in Go (scalars, pointer-sized types, and `string`).
    pub fn is_primitive(self) -> bool {
        matches!(
            self,
            Self::Bool
                | Self::Int
                | Self::Int8
                | Self::Int16
                | Self::Int32
                | Self::Int64
                | Self::Uint
                | Self::Uint8
                | Self::Uint16
                | Self::Uint32
                | Self::Uint64
                | Self::Uintptr
                | Self::Float32
                | Self::Float64
                | Self::Complex64
                | Self::Complex128
                | Self::Pointer
                | Self::String
                | Self::UnsafePointer
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{GoKind, DIRECT_IFACE, GC_PROG, KIND_MASK};

    #[test]
    fn constants_match_java() {
        assert_eq!(KIND_MASK, 31);
        assert_eq!(GC_PROG, 64);
        assert_eq!(DIRECT_IFACE, 32);
    }

    #[test]
    fn parse_byte_all_valid_ordinals() {
        let cases: &[(u8, GoKind)] = &[
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
        for &(b, expected) in cases {
            assert_eq!(GoKind::parse_byte(b), expected, "ordinal {b}");
        }
    }

    #[test]
    fn parse_byte_zero_returns_invalid() {
        assert_eq!(GoKind::parse_byte(0), GoKind::Invalid);
    }

    #[test]
    fn parse_byte_out_of_range_returns_invalid() {
        assert_eq!(GoKind::parse_byte(27), GoKind::Invalid);
        assert_eq!(GoKind::parse_byte(31), GoKind::Invalid);
    }

    #[test]
    fn parse_byte_strips_flag_bits() {
        // ordinal 1 (Bool) with GC_PROG and DIRECT_IFACE bits set
        let b = 1u8 | GC_PROG | DIRECT_IFACE;
        assert_eq!(GoKind::parse_byte(b), GoKind::Bool);
    }

    #[test]
    fn parse_typename_exact_match() {
        assert_eq!(GoKind::parse_typename("bool"), GoKind::Bool);
        assert_eq!(GoKind::parse_typename("func()"), GoKind::Func);
        assert_eq!(GoKind::parse_typename("unsafe.Pointer"), GoKind::UnsafePointer);
    }

    #[test]
    fn parse_typename_case_insensitive() {
        assert_eq!(GoKind::parse_typename("BOOL"), GoKind::Bool);
        assert_eq!(GoKind::parse_typename("Int64"), GoKind::Int64);
        assert_eq!(GoKind::parse_typename("UNSAFE.POINTER"), GoKind::UnsafePointer);
    }

    #[test]
    fn parse_typename_unknown_returns_invalid() {
        assert_eq!(GoKind::parse_typename("notakind"), GoKind::Invalid);
        assert_eq!(GoKind::parse_typename(""), GoKind::Invalid);
    }

    #[test]
    fn type_name_round_trips_via_parse() {
        let all = [
            GoKind::Bool, GoKind::Int, GoKind::Int8, GoKind::Int16,
            GoKind::Int32, GoKind::Int64, GoKind::Uint, GoKind::Uint8,
            GoKind::Uint16, GoKind::Uint32, GoKind::Uint64, GoKind::Uintptr,
            GoKind::Float32, GoKind::Float64, GoKind::Complex64, GoKind::Complex128,
            GoKind::Array, GoKind::Chan, GoKind::Func, GoKind::Interface,
            GoKind::Map, GoKind::Pointer, GoKind::Slice, GoKind::String,
            GoKind::Struct, GoKind::UnsafePointer,
        ];
        for kind in all {
            assert_eq!(GoKind::parse_typename(kind.type_name()), kind,
                "round-trip failed for {kind:?}");
        }
    }

    #[test]
    fn is_primitive_true_for_primitive_kinds() {
        let primitives = [
            GoKind::Bool, GoKind::Int, GoKind::Int8, GoKind::Int16,
            GoKind::Int32, GoKind::Int64, GoKind::Uint, GoKind::Uint8,
            GoKind::Uint16, GoKind::Uint32, GoKind::Uint64, GoKind::Uintptr,
            GoKind::Float32, GoKind::Float64, GoKind::Complex64, GoKind::Complex128,
            GoKind::Pointer, GoKind::String, GoKind::UnsafePointer,
        ];
        for kind in primitives {
            assert!(kind.is_primitive(), "{kind:?} should be primitive");
        }
    }

    #[test]
    fn is_primitive_false_for_composite_kinds() {
        let composites = [
            GoKind::Array, GoKind::Chan, GoKind::Func, GoKind::Interface,
            GoKind::Map, GoKind::Slice, GoKind::Struct, GoKind::Invalid,
        ];
        for kind in composites {
            assert!(!kind.is_primitive(), "{kind:?} should not be primitive");
        }
    }
}
