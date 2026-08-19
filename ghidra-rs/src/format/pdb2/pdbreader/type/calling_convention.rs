//! Calling convention used by certain data types.
//!
//! Corresponds to the Java enum
//! `ghidra.app.util.bin.format.pdb2.pdbreader.type.CallingConvention`.
//!
//! Ported as a trait (rather than a plain Rust enum) because this type was selected as a
//! dependency-cycle cut-point: callers such as `AbstractMemberFunctionMsType` and
//! `AbstractProcedureMsType` (not yet ported) can depend on `dyn CallingConvention` instead of
//! a single concrete enum, so their crates don't need to see the full fixed variant list.

/// A calling convention used by certain data types.
///
/// See `AbstractMemberFunctionMsType` and `AbstractProcedureMsType` in the Java source.
pub trait CallingConvention: std::fmt::Debug {
    /// Returns the display label (e.g. `"__cdecl"`), matching Java's `toString()`.
    fn label(&self) -> &str;

    /// Returns the raw wire value of this calling convention.
    fn value(&self) -> i32;

    /// Returns the human-readable description of this calling convention.
    fn info(&self) -> &str;
}

/// The standard, fixed set of calling conventions recognized by the PDB reader.
///
/// Corresponds to the enum constants of the Java `CallingConvention` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardCallingConvention {
    Unknown,
    NearC,
    FarC,
    NearPascal,
    FarPascal,
    NearFast,
    FarFast,
    Skipped,
    NearStd,
    FarStd,
    NearSys,
    FarSys,
    ThisCall,
    MipsCall,
    Generic,
    AlphaCall,
    PpcCall,
    ShCall,
    ArmCall,
    Am33Call,
    TriCall,
    Sh5Call,
    M32RCall,
    ClrCall,
    Inline,
    NearVector,
    Reserved,
}

impl StandardCallingConvention {
    fn data(self) -> (&'static str, i32, &'static str) {
        match self {
            Self::Unknown => ("INVALID", -1, "INVALID"),
            Self::NearC => ("__cdecl", 0x00, "near right to left push, caller pops stack"),
            Self::FarC => ("__cdecl", 0x01, "far right to left push, caller pops stack"),
            Self::NearPascal => {
                ("__pascal", 0x02, "near left to right push, callee pops stack")
            }
            Self::FarPascal => {
                ("__pascal", 0x03, "far left to right push, callee pops stack")
            }
            Self::NearFast => (
                "__fastcall",
                0x04,
                "near left to right push with regs, callee pops stack",
            ),
            Self::FarFast => (
                "__fastcall",
                0x05,
                "far left to right push with regs, callee pops stack",
            ),
            Self::Skipped => ("", 0x06, "skipped (unused) call index"),
            Self::NearStd => ("__stdcall", 0x07, "near standard call"),
            Self::FarStd => ("__stdcall", 0x08, "far standard call"),
            Self::NearSys => ("__syscall", 0x09, "near sys call"),
            Self::FarSys => ("__syscall", 0x0a, "far sys call"),
            Self::ThisCall => ("__thiscall", 0x0b, "this call (this passed in register)"),
            Self::MipsCall => ("", 0x0c, "Mips call"),
            Self::Generic => ("", 0x0d, "Generic call sequence"),
            Self::AlphaCall => ("", 0x0e, "Alpha call"),
            Self::PpcCall => ("", 0x0f, "PPC call"),
            Self::ShCall => ("", 0x10, "Hitachi SuperH call"),
            Self::ArmCall => ("", 0x11, "ARM call"),
            Self::Am33Call => ("", 0x12, "AM33 call"),
            Self::TriCall => ("", 0x13, "TriCore Call"),
            Self::Sh5Call => ("", 0x14, "Hitachi SuperH-5 call"),
            Self::M32RCall => ("", 0x15, "M32R Call"),
            Self::ClrCall => ("", 0x16, "clr call"),
            Self::Inline => (
                "",
                0x17,
                "Marker for routines always inlined and thus lacking a convention",
            ),
            Self::NearVector => (
                "__vectorcall",
                0x18,
                "near left to right push with regs, callee pops stack",
            ),
            Self::Reserved => ("", 0x19, "first unused call enumeration"),
        }
    }

    /// Looks up a calling convention by its raw wire value, matching Java's `fromValue(int)`.
    /// Unrecognized values map to [`StandardCallingConvention::Unknown`].
    pub fn from_value(val: i32) -> Self {
        match val {
            0x00 => Self::NearC,
            0x01 => Self::FarC,
            0x02 => Self::NearPascal,
            0x03 => Self::FarPascal,
            0x04 => Self::NearFast,
            0x05 => Self::FarFast,
            0x06 => Self::Skipped,
            0x07 => Self::NearStd,
            0x08 => Self::FarStd,
            0x09 => Self::NearSys,
            0x0a => Self::FarSys,
            0x0b => Self::ThisCall,
            0x0c => Self::MipsCall,
            0x0d => Self::Generic,
            0x0e => Self::AlphaCall,
            0x0f => Self::PpcCall,
            0x10 => Self::ShCall,
            0x11 => Self::ArmCall,
            0x12 => Self::Am33Call,
            0x13 => Self::TriCall,
            0x14 => Self::Sh5Call,
            0x15 => Self::M32RCall,
            0x16 => Self::ClrCall,
            0x17 => Self::Inline,
            0x18 => Self::NearVector,
            0x19 => Self::Reserved,
            _ => Self::Unknown,
        }
    }
}

impl CallingConvention for StandardCallingConvention {
    fn label(&self) -> &str {
        self.data().0
    }

    fn value(&self) -> i32 {
        self.data().1
    }

    fn info(&self) -> &str {
        self.data().2
    }
}

impl std::fmt::Display for StandardCallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_matches_java_constants() {
        assert_eq!(StandardCallingConvention::from_value(0x00), StandardCallingConvention::NearC);
        assert_eq!(
            StandardCallingConvention::from_value(0x18),
            StandardCallingConvention::NearVector
        );
        assert_eq!(StandardCallingConvention::from_value(0x19), StandardCallingConvention::Reserved);
        assert_eq!(StandardCallingConvention::from_value(-1), StandardCallingConvention::Unknown);
        assert_eq!(
            StandardCallingConvention::from_value(9999),
            StandardCallingConvention::Unknown
        );
    }

    #[test]
    fn accessors_match_java_fields() {
        let thiscall = StandardCallingConvention::ThisCall;
        assert_eq!(thiscall.label(), "__thiscall");
        assert_eq!(thiscall.value(), 0x0b);
        assert_eq!(thiscall.info(), "this call (this passed in register)");
        assert_eq!(thiscall.to_string(), "__thiscall");
    }

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn CallingConvention`, matching how a cycle-breaking cut-point trait is consumed.
    #[derive(Debug)]
    struct MockCallingConvention;

    impl CallingConvention for MockCallingConvention {
        fn label(&self) -> &str {
            "__mockcall"
        }

        fn value(&self) -> i32 {
            0x7f
        }

        fn info(&self) -> &str {
            "mock calling convention for testing"
        }
    }

    #[test]
    fn is_object_safe() {
        let conventions: Vec<Box<dyn CallingConvention>> = vec![
            Box::new(StandardCallingConvention::NearC),
            Box::new(MockCallingConvention),
        ];
        assert_eq!(conventions[0].label(), "__cdecl");
        assert_eq!(conventions[0].value(), 0x00);
        assert_eq!(conventions[1].label(), "__mockcall");
        assert_eq!(conventions[1].value(), 0x7f);
        assert_eq!(conventions[1].info(), "mock calling convention for testing");
    }
}
