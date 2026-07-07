//! Trait representing an ELF relocation type.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.ElfRelocationType`.

/// Identifies an ELF relocation type, providing its name and numeric type identifier.
///
/// In Java this is an interface typically implemented by architecture-specific enums.
/// In Rust it is a trait; those enums become types that implement this trait.
pub trait ElfRelocationType {
    /// Returns the name of this relocation type (e.g., the variant name).
    fn name(&self) -> &str;

    /// Returns the numeric value associated with this relocation type.
    fn type_id(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyReloc {
        name: &'static str,
        type_id: i32,
    }

    impl ElfRelocationType for DummyReloc {
        fn name(&self) -> &str {
            self.name
        }

        fn type_id(&self) -> i32 {
            self.type_id
        }
    }

    #[test]
    fn name_returns_expected_string() {
        let r = DummyReloc { name: "R_X86_64_NONE", type_id: 0 };
        assert_eq!(r.name(), "R_X86_64_NONE");
    }

    #[test]
    fn type_id_returns_expected_value() {
        let r = DummyReloc { name: "R_X86_64_64", type_id: 1 };
        assert_eq!(r.type_id(), 1);
    }

    #[test]
    fn negative_type_id_is_preserved() {
        let r = DummyReloc { name: "R_NEGATIVE", type_id: -1 };
        assert_eq!(r.type_id(), -1);
    }

    #[test]
    fn trait_object_dispatch_works() {
        let r: &dyn ElfRelocationType = &DummyReloc { name: "R_COPY", type_id: 5 };
        assert_eq!(r.name(), "R_COPY");
        assert_eq!(r.type_id(), 5);
    }
}
