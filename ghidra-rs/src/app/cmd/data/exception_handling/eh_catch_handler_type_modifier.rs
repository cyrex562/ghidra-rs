/// Adjectives (modifier flags) from an exception handling HandlerType data type.
///
/// Based on data type information from `ehdata.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EHCatchHandlerTypeModifier {
    modifiers: u32,
}

const CONST_BIT: u32 = 0x00000001;
const VOLATILE_BIT: u32 = 0x00000002;
const UNALIGNED_BIT: u32 = 0x00000004;
const REFERENCE_BIT: u32 = 0x00000008;
const RESUMABLE_BIT: u32 = 0x00000010;
const ALL_CATCH_BIT: u32 = 0x00000040;
const COMPLUS_BIT: u32 = 0x80000000;

impl EHCatchHandlerTypeModifier {
    /// Modifier value with no flags set.
    pub const NO_MODIFIERS: Self = Self { modifiers: 0 };

    /// Creates a new modifier wrapper from the raw adjectives field of a HandlerType.
    pub fn new(modifiers: u32) -> Self {
        Self { modifiers }
    }

    fn is_bit_set(&self, bit: u32) -> bool {
        (self.modifiers & bit) == bit
    }

    /// Returns `true` if the handler type referenced is `const`.
    pub fn is_const(&self) -> bool {
        self.is_bit_set(CONST_BIT)
    }

    /// Returns `true` if the handler type referenced is `volatile`.
    pub fn is_volatile(&self) -> bool {
        self.is_bit_set(VOLATILE_BIT)
    }

    /// Returns `true` if the handler type referenced is unaligned.
    pub fn is_unaligned(&self) -> bool {
        self.is_bit_set(UNALIGNED_BIT)
    }

    /// Returns `true` if the catch type is by reference.
    pub fn is_by_reference(&self) -> bool {
        self.is_bit_set(REFERENCE_BIT)
    }

    /// Returns `true` if the catch function can possibly resume.
    pub fn is_resumable(&self) -> bool {
        self.is_bit_set(RESUMABLE_BIT)
    }

    /// Returns `true` if the exception handler is a standard C++ catch-all (`...`).
    pub fn is_all_catch(&self) -> bool {
        self.is_bit_set(ALL_CATCH_BIT)
    }

    /// Returns `true` if this exception handler is COM+.
    pub fn is_complus(&self) -> bool {
        self.is_bit_set(COMPLUS_BIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_modifiers_has_no_flags_set() {
        let m = EHCatchHandlerTypeModifier::NO_MODIFIERS;
        assert!(!m.is_const());
        assert!(!m.is_volatile());
        assert!(!m.is_unaligned());
        assert!(!m.is_by_reference());
        assert!(!m.is_resumable());
        assert!(!m.is_all_catch());
        assert!(!m.is_complus());
    }

    #[test]
    fn const_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000001);
        assert!(m.is_const());
        assert!(!m.is_volatile());
    }

    #[test]
    fn volatile_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000002);
        assert!(!m.is_const());
        assert!(m.is_volatile());
    }

    #[test]
    fn unaligned_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000004);
        assert!(m.is_unaligned());
        assert!(!m.is_by_reference());
    }

    #[test]
    fn reference_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000008);
        assert!(m.is_by_reference());
    }

    #[test]
    fn resumable_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000010);
        assert!(m.is_resumable());
    }

    #[test]
    fn all_catch_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x00000040);
        assert!(m.is_all_catch());
    }

    #[test]
    fn complus_flag() {
        let m = EHCatchHandlerTypeModifier::new(0x80000000);
        assert!(m.is_complus());
        assert!(!m.is_const());
    }

    #[test]
    fn multiple_flags() {
        let m = EHCatchHandlerTypeModifier::new(0x00000003);
        assert!(m.is_const());
        assert!(m.is_volatile());
        assert!(!m.is_unaligned());
    }

    #[test]
    fn equality_and_hash() {
        use std::collections::HashSet;
        let a = EHCatchHandlerTypeModifier::new(0x05);
        let b = EHCatchHandlerTypeModifier::new(0x05);
        let c = EHCatchHandlerTypeModifier::new(0x06);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
