/// Discriminant tag for each class of address space in the p-code engine.
///
/// Models `ghidra.pcodeCPort.space.spacetype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpaceType {
    /// Special space used to represent constants.
    IptrConstant,
    /// Normal address spaces modelled by the processor.
    IptrProcessor,
    /// Spaces whose addresses are offsets from a base register.
    IptrSpacebase,
    /// Internally managed temporary space.
    IptrInternal,
    /// Special internal space (function specification).
    IptrFspec,
    /// Special internal space (indirect op).
    IptrIop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            SpaceType::IptrConstant,
            SpaceType::IptrProcessor,
            SpaceType::IptrSpacebase,
            SpaceType::IptrInternal,
            SpaceType::IptrFspec,
            SpaceType::IptrIop,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let a = SpaceType::IptrProcessor;
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", SpaceType::IptrConstant), "IptrConstant");
        assert_eq!(format!("{:?}", SpaceType::IptrIop), "IptrIop");
    }
}
