use crate::program::model::address::AddressFactory;
use crate::program::seam_stubs::{CompilerSpec, Language, LanguageCompilerSpecPair};

/// Identifies program architecture details required to utilize language/compiler-specific memory
/// and variable storage specifications.
///
/// Port of `ghidra.program.model.lang.ProgramArchitecture`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
pub trait ProgramArchitecture {
    /// Get the processor language.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the address factory for this architecture. In the case of a `Program` this should be
    /// the extended address factory that includes the stack space and any defined overlay spaces
    /// (i.e., `OverlayAddressSpace`).
    fn get_address_factory(&self) -> Box<dyn AddressFactory>;

    /// Get the compiler specification.
    fn get_compiler_spec(&self) -> Box<dyn CompilerSpec>;

    /// Get the language/compiler spec ID pair associated with this program architecture.
    fn get_language_compiler_spec_pair(&self) -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new(
            self.get_language().get_language_id(),
            self.get_compiler_spec().get_compiler_spec_id(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace};
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::CompilerSpecID;
    use std::sync::Arc;

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
    }

    struct MockCompilerSpec;

    impl CompilerSpec for MockCompilerSpec {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }
    }

    struct MockAddressFactory;

    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_address_space_by_name(&self, _name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_space_by_id(&self, _id: i32) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_num_address_spaces(&self) -> usize {
            0
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            false
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    struct MockProgramArchitecture;

    impl ProgramArchitecture for MockProgramArchitecture {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(MockAddressFactory)
        }

        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            Box::new(MockCompilerSpec)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let arch: Box<dyn ProgramArchitecture> = Box::new(MockProgramArchitecture);
        let pair = arch.get_language_compiler_spec_pair();
        assert_eq!(pair.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(pair.get_compiler_spec_id().get_id_as_string(), "gcc");
    }
}
