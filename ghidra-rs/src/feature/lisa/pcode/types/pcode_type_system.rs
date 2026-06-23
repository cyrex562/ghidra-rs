/// A primitive type tag for the Pcode type system.
///
/// Mirrors the concrete type singletons from the LiSA `it.unive.lisa.program.type`
/// package that `PcodeTypeSystem` returns: `BoolType`, `StringType`, `Int32Type`,
/// and `Int64Type`.  An additional variant, `InMemory`, represents the LiSA
/// `InMemoryType` marker used by `canBeReferenced`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PcodeType {
    Bool,
    Str,
    Int32,
    Int64,
    /// A composite/pointer-like type that can be stored in memory.
    ///
    /// Corresponds to LiSA's `InMemoryType` interface. None of the four basic
    /// Pcode types are in-memory types, so `can_be_referenced` returns `false`
    /// for all of them.
    InMemory,
}

impl PcodeType {
    /// Returns `true` when this type is an in-memory (referenceable) type.
    ///
    /// Mirrors `Type.isInMemoryType()` from the LiSA framework.
    pub fn is_in_memory_type(self) -> bool {
        matches!(self, Self::InMemory)
    }
}

/// Type-system configuration for the Pcode LiSA frontend.
///
/// Provides canonical type instances and the reference-eligibility predicate
/// required by the LiSA analysis framework.
///
/// Corresponds to `ghidra.lisa.pcode.types.PcodeTypeSystem` in the Java source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PcodeTypeSystem;

impl PcodeTypeSystem {
    /// Returns the boolean type (`BoolType.INSTANCE` in Java).
    pub fn boolean_type(self) -> PcodeType {
        PcodeType::Bool
    }

    /// Returns the string type (`StringType.INSTANCE` in Java).
    pub fn string_type(self) -> PcodeType {
        PcodeType::Str
    }

    /// Returns the 32-bit integer type (`Int32Type.INSTANCE` in Java).
    pub fn integer_type(self) -> PcodeType {
        PcodeType::Int32
    }

    /// Returns the 64-bit integer type (`Int64Type.INSTANCE` in Java).
    pub fn long_type(self) -> PcodeType {
        PcodeType::Int64
    }

    /// Returns `true` when `ty` can be referred to via a pointer/reference.
    ///
    /// Mirrors `canBeReferenced(Type)` which delegates to
    /// `Type.isInMemoryType()`.  None of the four basic Pcode types
    /// (`Bool`, `Str`, `Int32`, `Int64`) satisfy this predicate.
    pub fn can_be_referenced(self, ty: PcodeType) -> bool {
        ty.is_in_memory_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_type_is_bool() {
        assert_eq!(PcodeTypeSystem.boolean_type(), PcodeType::Bool);
    }

    #[test]
    fn string_type_is_str() {
        assert_eq!(PcodeTypeSystem.string_type(), PcodeType::Str);
    }

    #[test]
    fn integer_type_is_int32() {
        assert_eq!(PcodeTypeSystem.integer_type(), PcodeType::Int32);
    }

    #[test]
    fn long_type_is_int64() {
        assert_eq!(PcodeTypeSystem.long_type(), PcodeType::Int64);
    }

    #[test]
    fn primitive_types_cannot_be_referenced() {
        let ts = PcodeTypeSystem;
        assert!(!ts.can_be_referenced(PcodeType::Bool));
        assert!(!ts.can_be_referenced(PcodeType::Str));
        assert!(!ts.can_be_referenced(PcodeType::Int32));
        assert!(!ts.can_be_referenced(PcodeType::Int64));
    }

    #[test]
    fn in_memory_type_can_be_referenced() {
        assert!(PcodeTypeSystem.can_be_referenced(PcodeType::InMemory));
    }

    #[test]
    fn is_in_memory_type_only_for_in_memory_variant() {
        assert!(!PcodeType::Bool.is_in_memory_type());
        assert!(!PcodeType::Str.is_in_memory_type());
        assert!(!PcodeType::Int32.is_in_memory_type());
        assert!(!PcodeType::Int64.is_in_memory_type());
        assert!(PcodeType::InMemory.is_in_memory_type());
    }

    #[test]
    fn pcode_type_system_is_copy_and_default() {
        let a = PcodeTypeSystem;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(PcodeTypeSystem::default(), PcodeTypeSystem);
    }
}
