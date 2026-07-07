use crate::program::model::address::AddressFactory;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::seam_stubs::{Language, LanguageCompilerSpecPair};

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
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::seam_stubs::{
        CompilerSpecDescription, CompilerSpecID, Encoder, PcodeInjectLibrary, PrototypeModel,
    };
    use std::collections::HashSet;
    use std::sync::Arc;

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {}

    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockPrototypeModel;
    impl PrototypeModel for MockPrototypeModel {}

    struct MockCompilerSpec;

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription)
        }

        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }

        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }

        fn is_stack_right_justified(&self) -> bool {
            false
        }

        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_stack_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
        }

        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            self.get_stack_space()
        }

        fn stack_grows_negative(&self) -> bool {
            true
        }

        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            DecompilerLanguage::CLanguage
        }

        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn is_global(&self, _addr: &Address) -> bool {
            false
        }

        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            Box::new(MockPcodeInjectLibrary)
        }

        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn does_c_data_type_conversions(&self) -> bool {
            true
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }

        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
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
