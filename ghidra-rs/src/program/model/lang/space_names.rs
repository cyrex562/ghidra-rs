/// Reserved AddressSpace names across architectures and associated attributes.
pub struct SpaceNames;

impl SpaceNames {
    /// P-code constants space name.
    pub const CONSTANT_SPACE_NAME: &'static str = "const";
    /// Temporary p-code registers space name.
    pub const UNIQUE_SPACE_NAME: &'static str = "unique";
    /// Storage for stack-relative varnodes space name.
    pub const STACK_SPACE_NAME: &'static str = "stack";
    /// Logical storage for joined varnodes space name.
    pub const JOIN_SPACE_NAME: &'static str = "join";
    /// Other space name.
    pub const OTHER_SPACE_NAME: &'static str = "OTHER";
    /// Internal p-code reference space name.
    pub const IOP_SPACE_NAME: &'static str = "iop";
    /// Internal CALL reference space name.
    pub const FSPEC_SPACE_NAME: &'static str = "fspec";

    /// Index for constant space; must match `ConstantSpace::INDEX` in space.hh.
    pub const CONSTANT_SPACE_INDEX: u32 = 0;
    /// Index for other space; must match `OtherSpace::INDEX` in space.hh.
    pub const OTHER_SPACE_INDEX: u32 = 1;

    /// Number of bytes for a unique offset.
    pub const UNIQUE_SPACE_SIZE: u32 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_constants_have_correct_values() {
        assert_eq!(SpaceNames::CONSTANT_SPACE_NAME, "const");
        assert_eq!(SpaceNames::UNIQUE_SPACE_NAME, "unique");
        assert_eq!(SpaceNames::STACK_SPACE_NAME, "stack");
        assert_eq!(SpaceNames::JOIN_SPACE_NAME, "join");
        assert_eq!(SpaceNames::OTHER_SPACE_NAME, "OTHER");
        assert_eq!(SpaceNames::IOP_SPACE_NAME, "iop");
        assert_eq!(SpaceNames::FSPEC_SPACE_NAME, "fspec");
    }

    #[test]
    fn index_constants_have_correct_values() {
        assert_eq!(SpaceNames::CONSTANT_SPACE_INDEX, 0);
        assert_eq!(SpaceNames::OTHER_SPACE_INDEX, 1);
    }

    #[test]
    fn unique_space_size_is_four_bytes() {
        assert_eq!(SpaceNames::UNIQUE_SPACE_SIZE, 4);
    }

    #[test]
    fn space_names_are_distinct() {
        let names = [
            SpaceNames::CONSTANT_SPACE_NAME,
            SpaceNames::UNIQUE_SPACE_NAME,
            SpaceNames::STACK_SPACE_NAME,
            SpaceNames::JOIN_SPACE_NAME,
            SpaceNames::OTHER_SPACE_NAME,
            SpaceNames::IOP_SPACE_NAME,
            SpaceNames::FSPEC_SPACE_NAME,
        ];
        let mut seen = std::collections::HashSet::new();
        for name in &names {
            assert!(seen.insert(*name), "duplicate space name: {name}");
        }
    }

    #[test]
    fn space_indices_are_distinct() {
        assert_ne!(SpaceNames::CONSTANT_SPACE_INDEX, SpaceNames::OTHER_SPACE_INDEX);
    }
}
