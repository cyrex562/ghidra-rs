/// Classification of an address space used in SLEIGH constructor definitions.
///
/// Models `ghidra.pcodeCPort.slgh_compile.space_class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpaceClass {
    RamSpace,
    RegisterSpace,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(SpaceClass::RamSpace, SpaceClass::RegisterSpace);
    }

    #[test]
    fn clone_and_copy() {
        let a = SpaceClass::RamSpace;
        let b = a;
        assert_eq!(a, b);

        let c = SpaceClass::RegisterSpace;
        let d = c.clone();
        assert_eq!(c, d);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", SpaceClass::RamSpace), "RamSpace");
        assert_eq!(format!("{:?}", SpaceClass::RegisterSpace), "RegisterSpace");
    }
}
