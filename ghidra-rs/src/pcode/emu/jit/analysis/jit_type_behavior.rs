//! The behavior/requirement for an operand's type.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitTypeBehavior`.
//!
//! # Differences from Java
//!
//! - Java is an `enum` with constant-specific method bodies for `type(int)` and
//!   `resolve(JitType)`. Rust has no constant-specific bodies, so both become a single `match self`
//!   in one `impl` block, matching the convention used throughout this crate for closed Java enums.
//! - The variants are declared in Java's constant order (`ANY`, `INTEGER`, `FLOAT`, `COPY`), so the
//!   derived [`Ord`] reproduces the `ordinal()` comparison [`JitTypeBehavior::compare`] is defined
//!   in terms of.
//! - Java's `Class<?>` argument to `forJavaType` is modeled as a JVM type descriptor string, the
//!   same convention [`jit_type`](crate::pcode::emu::jit::analysis::jit_type) uses for
//!   `SimpleJitType.forJavaType`. `Varnode.class` becomes the object descriptor for
//!   [`Varnode`](crate::program::model::pcode::Varnode); `int[].class` becomes `"[I"`.
//! - Java's final branch, `if (cls.isPrimitive()) throw new AssertionError();`, is unreachable: the
//!   eight JVM primitive descriptors (`Z`, `B`, `C`, `S`, `I`, `J`, `F`, `D`) are all handled by the
//!   preceding checks, so any descriptor that reaches the default case is never a primitive. Rust
//!   drops the dead assertion and just falls through to `None`, matching the one live default
//!   (`return null;`).

use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, DoubleJitType, FloatJitType, IntJitType, JitType, LongJitType, MpFloatJitType,
    MpIntJitType,
};

/// The JVM object descriptor for `Varnode.class`, as compared in `JitTypeBehavior.forJavaType`.
const VARNODE_DESCRIPTOR: &str = "Lghidra/program/model/pcode/Varnode;";

/// The behavior/requirement for an operand's type.
///
/// Port of `ghidra.pcode.emu.jit.analysis.JitTypeBehavior`.
///
/// See [`JitTypeModel`](crate::pcode::emu::jit::analysis::jit_type_model::JitTypeModel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum JitTypeBehavior {
    /// No type requirement or interpretation.
    Any,
    /// The bits are interpreted as an integer.
    Integer,
    /// The bits are interpreted as a floating-point value.
    Float,
    /// For `JitCopyOp` and
    /// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp): No type requirement or
    /// interpretation, but there is an implication that the output has the same interpretation as
    /// the inputs.
    Copy,
}

impl JitTypeBehavior {
    /// Compare two behaviors by preference. The behavior with the smaller ordinal is preferred.
    ///
    /// Port of `JitTypeBehavior.compare(JitTypeBehavior, JitTypeBehavior)`, whose
    /// comparator-style `int` becomes an [`Ordering`](std::cmp::Ordering).
    pub fn compare(b1: JitTypeBehavior, b2: JitTypeBehavior) -> std::cmp::Ordering {
        b1.cmp(&b2)
    }

    /// Apply this behavior to a value of the given size to determine its type.
    ///
    /// Port of `JitTypeBehavior.type(int)`. As in Java, [`Any`](Self::Any) defaults to integers.
    ///
    /// # Panics
    ///
    /// If `self` is [`JitTypeBehavior::Copy`], matching Java's `AssertionError` from `COPY.type(int)`.
    pub fn type_of(&self, size: i32) -> AnyJitType {
        match self {
            Self::Copy => panic!("AssertionError: JitTypeBehavior::Copy has no type"),
            Self::Float => match size {
                4 => AnyJitType::Float(FloatJitType::F4),
                8 => AnyJitType::Double(DoubleJitType::F8),
                _ => AnyJitType::MpFloat(MpFloatJitType::for_size(size)),
            },
            // If no type is specified, we default to ints.
            Self::Any | Self::Integer => {
                debug_assert!(size > 0);
                match size {
                    1..=4 => AnyJitType::Int(IntJitType::for_size(size)),
                    5..=8 => AnyJitType::Long(LongJitType::for_size(size)),
                    _ => AnyJitType::MpInt(MpIntJitType::for_size(size)),
                }
            }
        }
    }

    /// Re-apply this behavior to an existing type.
    ///
    /// For [`Any`](Self::Any) and [`Copy`](Self::Copy) the result is the given type.
    ///
    /// Port of `JitTypeBehavior.resolve(JitType)`.
    pub fn resolve(&self, var_type: &AnyJitType) -> AnyJitType {
        match self {
            Self::Any | Self::Copy => var_type.clone(),
            Self::Integer | Self::Float => self.type_of(var_type.size()),
        }
    }

    /// Derive the type behavior from a Java language type.
    ///
    /// This is used on userops declared with Java primitives for parameters. To work with
    /// [`JitTypeModel`](crate::pcode::emu::jit::analysis::jit_type_model::JitTypeModel), we need to
    /// specify the type behavior of each operand. We aim to select behaviors such that the model
    /// allocates JVM locals whose JVM types match the userop method's parameters. This optimizes
    /// type conversions during Direct invocation.
    ///
    /// `descriptor` is the JVM type descriptor for the Java parameter type: `"B"`, `"S"`, `"I"`,
    /// `"J"`, or `"[I"` map to [`Integer`](Self::Integer); `"F"` and `"D"` map to
    /// [`Float`](Self::Float); `"Z"` (`boolean`) maps to [`Integer`](Self::Integer); the
    /// [`Varnode`](crate::program::model::pcode::Varnode) descriptor maps to [`Any`](Self::Any).
    /// Returns `None` for `"C"` (`char`), `"V"` (`void`), and any other descriptor, matching Java's
    /// `return null;`.
    ///
    /// Port of `JitTypeBehavior.forJavaType(Class)`.
    ///
    /// See `JitDataFlowUseropLibrary`.
    pub fn for_java_type(descriptor: &str) -> Option<JitTypeBehavior> {
        match descriptor {
            "B" | "S" | "I" | "J" | "[I" | "Z" => Some(Self::Integer),
            "F" | "D" => Some(Self::Float),
            VARNODE_DESCRIPTOR => Some(Self::Any),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_and_integer_default_to_int_and_long_types_by_size() {
        // Java: ANY.type(size) == INTEGER.type(size); 1..4 -> IntJitType, 5..8 -> LongJitType,
        // 9+ -> MpIntJitType.
        assert_eq!(JitTypeBehavior::Any.type_of(3), AnyJitType::Int(IntJitType::I3));
        assert_eq!(JitTypeBehavior::Integer.type_of(3), AnyJitType::Int(IntJitType::I3));
        assert_eq!(JitTypeBehavior::Integer.type_of(6), AnyJitType::Long(LongJitType::I6));
        assert_eq!(
            JitTypeBehavior::Integer.type_of(9),
            AnyJitType::MpInt(MpIntJitType::for_size(9))
        );
    }

    #[test]
    fn float_maps_four_and_eight_to_float_and_double() {
        // Java: FLOAT.type(Float.BYTES) == F4, FLOAT.type(Double.BYTES) == F8, else MpFloatJitType.
        assert_eq!(JitTypeBehavior::Float.type_of(4), AnyJitType::Float(FloatJitType::F4));
        assert_eq!(JitTypeBehavior::Float.type_of(8), AnyJitType::Double(DoubleJitType::F8));
        assert_eq!(
            JitTypeBehavior::Float.type_of(10),
            AnyJitType::MpFloat(MpFloatJitType::for_size(10))
        );
    }

    #[test]
    #[should_panic(expected = "JitTypeBehavior::Copy has no type")]
    fn copy_type_panics() {
        // Java: COPY.type(int) throws AssertionError.
        JitTypeBehavior::Copy.type_of(4);
    }

    #[test]
    fn any_and_copy_resolve_to_the_given_type_unchanged() {
        // Java: ANY.resolve(varType) == varType; COPY.resolve(varType) == ANY.resolve(varType).
        let t = AnyJitType::Long(LongJitType::I6);
        assert_eq!(JitTypeBehavior::Any.resolve(&t), t);
        assert_eq!(JitTypeBehavior::Copy.resolve(&t), t);
    }

    #[test]
    fn integer_and_float_resolve_by_reapplying_type_for_the_size() {
        // Java: INTEGER.resolve(varType) == type(varType.size()); same for FLOAT.
        let t = AnyJitType::Double(DoubleJitType::F8);
        assert_eq!(JitTypeBehavior::Integer.resolve(&t), AnyJitType::Long(LongJitType::I8));
        assert_eq!(JitTypeBehavior::Float.resolve(&t), t);
    }

    #[test]
    fn compare_orders_by_declaration_order() {
        // Java: Objects.compare(b1, b2, JitTypeBehavior::compareTo), i.e., ordinal order:
        // ANY < INTEGER < FLOAT < COPY.
        assert_eq!(
            JitTypeBehavior::compare(JitTypeBehavior::Any, JitTypeBehavior::Integer),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            JitTypeBehavior::compare(JitTypeBehavior::Copy, JitTypeBehavior::Float),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            JitTypeBehavior::compare(JitTypeBehavior::Float, JitTypeBehavior::Float),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn for_java_type_maps_primitives_arrays_and_varnode() {
        // Java: byte/short/int/long/int[]/boolean -> INTEGER, float/double -> FLOAT,
        // Varnode.class -> ANY, char/void -> null.
        assert_eq!(JitTypeBehavior::for_java_type("B"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("S"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("I"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("J"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("[I"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("Z"), Some(JitTypeBehavior::Integer));
        assert_eq!(JitTypeBehavior::for_java_type("F"), Some(JitTypeBehavior::Float));
        assert_eq!(JitTypeBehavior::for_java_type("D"), Some(JitTypeBehavior::Float));
        assert_eq!(
            JitTypeBehavior::for_java_type(VARNODE_DESCRIPTOR),
            Some(JitTypeBehavior::Any)
        );
        assert_eq!(JitTypeBehavior::for_java_type("C"), None);
        assert_eq!(JitTypeBehavior::for_java_type("V"), None);
        assert_eq!(JitTypeBehavior::for_java_type("Ljava/lang/Integer;"), None);
    }
}
