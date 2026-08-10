use crate::program::model::lang::CompilerSpec;
use crate::trace::seam_stubs::{TraceGuestPlatform};
use crate::trace::model::guest::trace_platform::TracePlatform;

/// Allows the addition of "guest platforms" for disassembling in multiple languages.
///
/// Port of `ghidra.trace.model.guest.TracePlatformManager`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// TODO (inherited from Java): allow the placement of data units with alternative data
/// organization.
///
/// The Java interface declares all five methods abstract (no defaults). This trait keeps
/// [`Self::get_host_platform`] required, matching the sole method the placeholder this promotes
/// already exposed, but defaults the other four to panicking so existing marker/mock implementors
/// (which only ever supplied `get_host_platform`) keep compiling unchanged; concrete
/// implementations should override them.
pub trait TracePlatformManager {
    /// Get a platform representing the trace's base language and compiler spec. Mirrors
    /// `TracePlatformManager.getHostPlatform()`.
    fn get_host_platform(&self) -> Box<dyn TracePlatform>;

    /// Get all guest platforms. Mirrors `TracePlatformManager.getGuestPlatforms()`.
    fn get_guest_platforms(&self) -> Vec<Box<dyn TraceGuestPlatform>> {
        unimplemented!("TracePlatformManager::get_guest_platforms placeholder not overridden")
    }

    /// Add a guest platform for the given compiler spec, which cannot be the base compiler spec.
    /// Mirrors `TracePlatformManager.addGuestPlatform(CompilerSpec)`.
    fn add_guest_platform(
        &self,
        compiler_spec: &dyn CompilerSpec,
    ) -> Box<dyn TraceGuestPlatform> {
        let _ = compiler_spec;
        unimplemented!("TracePlatformManager::add_guest_platform placeholder not overridden")
    }

    /// Get the platform for the given compiler spec, or `None` if not found. Mirrors
    /// `TracePlatformManager.getPlatform(CompilerSpec)`.
    fn get_platform(&self, compiler_spec: &dyn CompilerSpec) -> Option<Box<dyn TracePlatform>> {
        let _ = compiler_spec;
        unimplemented!("TracePlatformManager::get_platform placeholder not overridden")
    }

    /// Get or add a platform for the given compiler spec. Mirrors
    /// `TracePlatformManager.getOrAddPlatform(CompilerSpec)`.
    fn get_or_add_platform(&self, compiler_spec: &dyn CompilerSpec) -> Box<dyn TracePlatform> {
        let _ = compiler_spec;
        unimplemented!("TracePlatformManager::get_or_add_platform placeholder not overridden")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::PcodeInjectLibrary;
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::sync::Arc;

    struct MockCompilerSpec;
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!("not exercised by this smoke test")
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
            false
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
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            true
        }
    }

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    struct MockGuestPlatform;
    impl TraceGuestPlatform for MockGuestPlatform {}

    struct MockPlatformManager {
        guests_added: Cell<u32>,
    }

    impl TracePlatformManager for MockPlatformManager {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            Box::new(MockPlatform)
        }

        fn get_guest_platforms(&self) -> Vec<Box<dyn TraceGuestPlatform>> {
            (0..self.guests_added.get())
                .map(|_| Box::new(MockGuestPlatform) as Box<dyn TraceGuestPlatform>)
                .collect()
        }

        fn add_guest_platform(
            &self,
            _compiler_spec: &dyn CompilerSpec,
        ) -> Box<dyn TraceGuestPlatform> {
            self.guests_added.set(self.guests_added.get() + 1);
            Box::new(MockGuestPlatform)
        }
    }

    #[test]
    fn add_guest_platform_grows_guest_platforms() {
        let manager = MockPlatformManager {
            guests_added: Cell::new(0),
        };
        assert!(manager.get_guest_platforms().is_empty());

        manager.add_guest_platform(&MockCompilerSpec);
        manager.add_guest_platform(&MockCompilerSpec);

        assert_eq!(manager.get_guest_platforms().len(), 2);
        assert!(manager.get_host_platform().is_host());
    }
}
