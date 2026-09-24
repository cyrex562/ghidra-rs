//! Port of `ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOffer`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::app::plugin::core::debug::mapping::DebuggerPlatformOffer;
use crate::program::model::lang::compiler_spec::CompilerSpec;

/// Shared state and behavior for [`DebuggerPlatformOffer`] implementations, standing in for
/// Java's `extends`.
///
/// Port of `ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOffer`, an abstract
/// class implementing [`DebuggerPlatformOffer`]'s `getDescription`/`getCompilerSpec` (plus
/// `Object`'s `hashCode`/`equals`) from two fields, while leaving `getConfidence`/`take`/
/// `isCreatorOf` for concrete subclasses. Composition over inheritance: a concrete offer holds a
/// `base: AbstractDebuggerPlatformOfferBase` field and delegates `get_description`/
/// `get_compiler_spec` to it from its own [`DebuggerPlatformOffer`] impl, exactly as Java
/// subclasses inherit those two methods.
///
/// Java's `hashCode()`/`equals(Object)` are ported as [`hash_code`](Self::hash_code) and
/// [`equals`](Self::equals) rather than the `Hash`/`PartialEq` traits: Java's `equals` also
/// requires `this.getClass() == obj.getClass()`, a same-concrete-type check with no direct
/// `PartialEq`-on-a-trait-object equivalent (Rust trait objects erase the concrete type once
/// coerced to `&dyn DebuggerPlatformOffer`). Implementors that want `Hash`/`PartialEq` can build
/// them from these two methods plus their own `TypeId`.
pub struct AbstractDebuggerPlatformOfferBase {
    description: String,
    c_spec: Box<dyn CompilerSpec>,
    hash: u64,
}

impl AbstractDebuggerPlatformOfferBase {
    /// Java: `AbstractDebuggerPlatformOffer(String description, CompilerSpec cSpec)`.
    ///
    /// The hash is computed once at construction, mirroring Java precomputing
    /// `Objects.hash(description, cSpec)` into a `final int hash` field. Since [`CompilerSpec`]
    /// has no `Hash` impl in this port, `c_spec`'s [`CompilerSpec::get_compiler_spec_id`] stands
    /// in for it (compiler specs are otherwise identified by that id throughout this crate).
    pub fn new(description: impl Into<String>, c_spec: Box<dyn CompilerSpec>) -> Self {
        let description = description.into();
        let mut hasher = DefaultHasher::new();
        description.hash(&mut hasher);
        c_spec.get_compiler_spec_id().hash(&mut hasher);
        let hash = hasher.finish();
        AbstractDebuggerPlatformOfferBase { description, c_spec, hash }
    }

    /// Java: `getDescription()`.
    pub fn get_description(&self) -> String {
        self.description.clone()
    }

    /// Java: `getCompilerSpec()`.
    pub fn get_compiler_spec(&self) -> &dyn CompilerSpec {
        self.c_spec.as_ref()
    }

    /// Java: `hashCode()`.
    pub fn hash_code(&self) -> u64 {
        self.hash
    }

    /// Java: `equals(Object obj)`, restricted to comparing against another offer's base state.
    /// The `this.getClass() != obj.getClass()` concrete-type check is left to the caller (see the
    /// struct docs); this compares only the `description`/`cSpec` state Java's override actually
    /// inspects once that check has passed.
    pub fn equals(&self, that: &AbstractDebuggerPlatformOfferBase) -> bool {
        self.description == that.description
            && self.c_spec.get_compiler_spec_id() == that.c_spec.get_compiler_spec_id()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;

    /// A `CompilerSpec` whose only method actually exercised by these tests is
    /// `get_compiler_spec_id` (used by [`AbstractDebuggerPlatformOfferBase::new`]'s hash and
    /// [`AbstractDebuggerPlatformOfferBase::equals`]); everything else panics if called.
    struct MockCompilerSpec {
        id: CompilerSpecID,
    }

    fn mock_compiler_spec(id: &str) -> Box<dyn CompilerSpec> {
        Box::new(MockCompilerSpec { id: CompilerSpecID::new(Some(id)) })
    }

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
        }
        fn get_stack_pointer(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_stack_right_justified(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_space(
            &self,
            _space_name: &str,
        ) -> Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_base_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn stack_grows_negative(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_conventions(
            &self,
        ) -> Vec<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_convention(
            &self,
            _name: &str,
        ) -> Option<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_models(
            &self,
        ) -> Vec<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_calling_convention(
            &self,
        ) -> Option<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_decompiler_output_language(
            &self,
        ) -> crate::program::model::lang::decompiler_language::DecompilerLanguage {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
        ) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_global(&self, _addr: &crate::program::model::address::Address) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_data_organization(
            &self,
        ) -> Arc<crate::program::model::data::data_organization_impl::DataOrganizationImpl> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::PcodeInjectLibrary> {
            unimplemented!("not exercised by this smoke test")
        }
        fn match_convention(
            &self,
            _convention_name: &str,
        ) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn crate::program::model::listing::parameter::Parameter],
        ) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn does_c_data_type_conversions(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn accessors_report_constructed_state() {
        let base = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("gcc"));
        assert_eq!(base.get_description(), "desc");
        assert_eq!(
            base.get_compiler_spec().get_compiler_spec_id(),
            mock_compiler_spec("gcc").get_compiler_spec_id()
        );
    }

    #[test]
    fn hash_code_is_stable_and_depends_on_state() {
        let a = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("gcc"));
        let b = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("gcc"));
        let c = AbstractDebuggerPlatformOfferBase::new("other", mock_compiler_spec("gcc"));
        assert_eq!(a.hash_code(), b.hash_code());
        assert_ne!(a.hash_code(), c.hash_code());
    }

    #[test]
    fn equals_compares_description_and_compiler_spec_id() {
        let a = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("gcc"));
        let b = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("gcc"));
        let c = AbstractDebuggerPlatformOfferBase::new("desc", mock_compiler_spec("clang"));
        let d = AbstractDebuggerPlatformOfferBase::new("other", mock_compiler_spec("gcc"));
        assert!(a.equals(&b));
        assert!(!a.equals(&c));
        assert!(!a.equals(&d));
    }

    /// A minimal concrete offer composing [`AbstractDebuggerPlatformOfferBase`], proving the
    /// "hold a `base` field and delegate" pattern the struct docs describe.
    struct ConcreteOffer {
        base: AbstractDebuggerPlatformOfferBase,
        confidence: i32,
    }

    impl DebuggerPlatformOffer for ConcreteOffer {
        fn get_description(&self) -> String {
            self.base.get_description()
        }

        fn get_confidence(&self) -> i32 {
            self.confidence
        }

        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            None
        }

        fn take(
            &self,
            _tool: &dyn crate::framework::seam_stubs::PluginTool,
            _trace: &dyn crate::trace::model::trace::Trace,
        ) -> Box<dyn crate::debug::api::platform::DebuggerPlatformMapper> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_creator_of(
            &self,
            _mapper: &dyn crate::debug::api::platform::DebuggerPlatformMapper,
        ) -> bool {
            false
        }
    }

    #[test]
    fn concrete_offer_delegates_get_description_to_base() {
        let offer = ConcreteOffer {
            base: AbstractDebuggerPlatformOfferBase::new("mock offer", mock_compiler_spec("gcc")),
            confidence: 10,
        };
        assert_eq!(offer.get_description(), "mock offer");
        assert!(!offer.is_override());
    }
}
