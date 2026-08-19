//! Port of `ghidra.program.model.lang.BasicCompilerSpec`.
//!
//! In Java this is a concrete class implementing [`CompilerSpec`] from static information parsed
//! out of a `.cspec` file: `Language`/`SleighLanguage` own one of these, `Program`s reuse (and, via
//! `ProgramCompilerSpec`, extend) it, and its own construction/XML-restore path pulls in
//! `SleighLanguage`, `ContextSetting`, `PrototypeModel`, `PrototypeModelMerged`, and
//! `PcodeInjectLibrary` -- none of which are fully ported yet. That web of back-and-forth
//! dependencies is exactly what made `BasicCompilerSpec` a dependency-cycle cut-point, so only the
//! part of its API that other, already-ported collaborators need -- the protected extension points
//! [`ProgramCompilerSpec`](crate::program::database::program_compiler_spec::ProgramCompilerSpec)
//! (and any other subclass) uses to layer program-specific state on top of a loaded spec -- is
//! captured here as a trait over [`CompilerSpec`].
//!
//! Left out of the trait, and why:
//!   - The three constructors and the private `initialize`/`restoreXml`/`buildInjectLibrary` and
//!     related `restore*`/`encode*` helpers: these assemble a `BasicCompilerSpec` from a `.cspec`
//!     XML document via `SleighLanguage`/`ResourceFile`/`XmlPullParser`, none of which are ported
//!     yet. They are also pure construction machinery, not part of the contract a trait needs to
//!     expose to already-ported callers.
//!   - `getErrorHandler(String)`: a `protected static` helper that builds a SAX `ErrorHandler` for
//!     the XML-restore constructors above; it has no connection to any already-ported caller.
//!   - `markPrototypeAsExtension(PrototypeModel)`: a `protected static` helper that mutates a
//!     `PrototypeModel`'s package-private `isExtension` field directly. The ported
//!     [`PrototypeModel`](crate::program::model::lang::prototype_model::PrototypeModel) trait only
//!     exposes the corresponding getter
//!     ([`is_program_extension`](crate::program::model::lang::prototype_model::PrototypeModel::is_program_extension)),
//!     not a setter, so this helper cannot be expressed without either changing that trait (out of
//!     scope for this port) or exposing interior mutability it doesn't have.
//!   - `setDefaultReturnAddressIfNeeded(PrototypeModel)`: same issue --
//!     [`PrototypeModel::get_return_address`](crate::program::model::lang::prototype_model::PrototypeModel::get_return_address)
//!     has no setter counterpart on the trait.
//!   - `equals(Object)`: [`CompilerSpec::is_equivalent`] already covers the trait-object-safe
//!     equivalence contract other ported code relies on.
//!
//! `addContextSetting(Register, BigInteger, Address, Address)` is kept, but reshaped: rather than
//! taking (or this crate stubbing) the unported `ContextSetting` value type, it takes the same four
//! primitive fields `ContextSetting`'s constructor stores, matching how `Register`/`Address`
//! parameters are already threaded through the ported [`CompilerSpec`] trait elsewhere. The
//! `BigInteger` context value is represented as `u128`, mirroring how
//! [`RegisterValue`](crate::program::seam_stubs::RegisterValue) (which has the same "arbitrary bit
//! pattern for a register-sized value" shape) already stubs `BigInteger` in this crate.

use crate::program::model::address::Address;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::inject_payload_sleigh::InjectPayloadSleigh;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::lang::register::RegisterRef;
use crate::util::xml::xml_parse_exception::XmlParseException;

/// A [`CompilerSpec`] built from static information in a particular `.cspec` file, plus the
/// protected extension points a subclass (in Java, primarily `ProgramCompilerSpec`) uses to layer
/// program-specific state -- context settings, prototype models, and inject payloads -- on top of
/// it.
///
/// Port of `ghidra.program.model.lang.BasicCompilerSpec`. See the module docs for what was
/// intentionally left out of this trait.
pub trait BasicCompilerSpec: CompilerSpec {
    /// Record a default context register setting to apply over the given address range.
    ///
    /// Stands in for the package-private `addContextSetting(Register, BigInteger, Address,
    /// Address)`, which builds and stores a `ContextSetting`; see the module docs for why the
    /// four fields are taken directly rather than through a ported `ContextSetting` type.
    fn add_context_setting(
        &mut self,
        register: RegisterRef,
        value: u128,
        begin_address: Address,
        end_address: Address,
    );

    /// Rebuild this spec's calling-convention model arrays and name-lookup table from a complete
    /// list of models, selecting `default_name` as the default calling convention and
    /// `eval_current`/`eval_called` (falling back to `default_name` when `None`) as the models
    /// used to evaluate the current/called function.
    ///
    /// Returns the name of a `PrototypeModel` that appeared more than once in `model_list`, if
    /// any, mirroring how the Java caller turns a non-`null` result into a
    /// `DuplicateNameException`.
    ///
    /// Stands in for the protected `modelXrefs(List<PrototypeModel>, String, String, String)`.
    ///
    /// # Errors
    /// Returns [`XmlParseException`] if no model in `model_list` matches `default_name` (excluding
    /// merged models).
    fn model_xrefs(
        &mut self,
        model_list: Vec<Box<dyn PrototypeModel>>,
        default_name: &str,
        eval_current: Option<&str>,
        eval_called: Option<&str>,
    ) -> Result<Option<String>, XmlParseException>;

    /// Remove any call-mechanism p-code injections associated with the given `PrototypeModel`s
    /// from this spec's inject library.
    ///
    /// Stands in for the protected `removeProgramMechanismPayloads(Collection<PrototypeModel>)`.
    fn remove_program_mechanism_payloads(&mut self, model_list: &[Box<dyn PrototypeModel>]);

    /// Register additional, Program-specific p-code inject payloads with this spec's inject
    /// library.
    ///
    /// Stands in for the protected `registerProgramInject(List<InjectPayloadSleigh>)`.
    fn register_program_inject(&mut self, inject_extensions: Vec<Box<dyn InjectPayloadSleigh>>);

    /// Clone this spec so a `Program` can safely extend it (new prototype models, inject
    /// payloads, context settings) without affecting the base spec owned by the `Language`.
    ///
    /// Stands in for the copy constructor `BasicCompilerSpec(BasicCompilerSpec)`.
    fn clone_spec(&self) -> Box<dyn BasicCompilerSpec>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::inject_payload::{InjectParameter, InjectPayload, InjectPayloadError};
    use crate::program::model::lang::language::Language;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::Encoder;
    use crate::program::model::lang::register::Register;
    use crate::program::seam_stubs::PcodeInjectLibrary;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    fn mock_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn mock_address(offset: i64) -> Address {
        Address::new(mock_address_space(), offset)
    }

    fn mock_register(name: &str) -> RegisterRef {
        Register::new(name, "", mock_address(0), 4, false, 0)
    }

    /// A minimal named [`PrototypeModel`] mock: only `get_name` and `is_merged`/`has_injection`
    /// are overridden since those are all [`MockBasicCompilerSpec`]'s methods below inspect.
    struct NamedModel {
        name: &'static str,
        merged: bool,
        has_injection: bool,
    }

    impl PrototypeModel for NamedModel {
        fn get_name(&self) -> Option<String> {
            Some(self.name.to_string())
        }

        fn is_merged(&self) -> bool {
            self.merged
        }

        fn has_injection(&self) -> bool {
            self.has_injection
        }
    }

    /// An [`InjectPayloadSleigh`] mock whose members are never exercised by
    /// [`register_program_inject`](BasicCompilerSpec::register_program_inject) -- only its count
    /// matters to the test below.
    struct StubInject;

    impl InjectPayload for StubInject {
        fn get_name(&self) -> String {
            "stub".to_string()
        }
        fn get_type(&self) -> i32 {
            0
        }
        fn get_source(&self) -> String {
            String::new()
        }
        fn get_param_shift(&self) -> i32 {
            0
        }
        fn get_input(&self) -> Vec<InjectParameter> {
            Vec::new()
        }
        fn get_output(&self) -> Vec<InjectParameter> {
            Vec::new()
        }
        fn is_error_placeholder(&self) -> bool {
            false
        }
        fn inject(
            &self,
            _context: &dyn crate::program::seam_stubs::InjectContext,
            _emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode(
            &self,
            _program: &dyn crate::program::model::listing::Program,
            _context: &dyn crate::program::seam_stubs::InjectContext,
        ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, InjectPayloadError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_fall_thru(&self) -> bool {
            true
        }
        fn is_incidental_copy(&self) -> bool {
            false
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _language: &crate::program::model::lang::sleigh::SleighLanguage,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_equivalent(&self, _other: &dyn InjectPayload) -> bool {
            false
        }
    }

    impl InjectPayloadSleigh for StubInject {
        fn release_parse_string(&mut self) -> Option<String> {
            None
        }
        fn set_template(&mut self, _template: crate::program::model::lang::sleigh::template::ConstructTpl) {}
    }

    /// A minimal [`BasicCompilerSpec`] mock that actually implements the model-xref/dedup,
    /// mechanism-payload-removal, and inject-registration bookkeeping the real class does, so the
    /// smoke tests below exercise real behavior rather than trivially-true assertions.
    struct MockBasicCompilerSpec {
        id: CompilerSpecID,
        ctx_settings: Vec<(RegisterRef, u128, Address, Address)>,
        model_names: Vec<String>,
        default_model_name: Option<String>,
        removed_mechanism_payloads: Vec<String>,
        registered_inject_count: usize,
    }

    impl Default for MockBasicCompilerSpec {
        fn default() -> Self {
            MockBasicCompilerSpec {
                id: CompilerSpecID::new(None),
                ctx_settings: Vec::new(),
                model_names: Vec::new(),
                default_model_name: None,
                removed_mechanism_payloads: Vec::new(),
                registered_inject_count: 0,
            }
        }
    }

    impl Clone for MockBasicCompilerSpec {
        fn clone(&self) -> Self {
            MockBasicCompilerSpec {
                id: self.id.clone(),
                ctx_settings: self.ctx_settings.clone(),
                model_names: self.model_names.clone(),
                default_model_name: self.default_model_name.clone(),
                removed_mechanism_payloads: self.removed_mechanism_payloads.clone(),
                registered_inject_count: self.registered_inject_count,
            }
        }
    }

    impl CompilerSpec for MockBasicCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
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
            mock_address_space()
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            mock_address_space()
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
        fn get_decompiler_output_language(
            &self,
        ) -> crate::program::model::lang::decompiler_language::DecompilerLanguage {
            crate::program::model::lang::decompiler_language::DecompilerLanguage::CLanguage
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            false
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
        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
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

    impl BasicCompilerSpec for MockBasicCompilerSpec {
        fn add_context_setting(
            &mut self,
            register: RegisterRef,
            value: u128,
            begin_address: Address,
            end_address: Address,
        ) {
            self.ctx_settings.push((register, value, begin_address, end_address));
        }

        fn model_xrefs(
            &mut self,
            model_list: Vec<Box<dyn PrototypeModel>>,
            default_name: &str,
            eval_current: Option<&str>,
            eval_called: Option<&str>,
        ) -> Result<Option<String>, XmlParseException> {
            let mut seen: HashMap<String, ()> = HashMap::new();
            let mut found_duplicate = None;
            let mut found_default = false;
            let mut names = Vec::new();
            for model in &model_list {
                if let Some(name) = model.get_name() {
                    if !model.is_merged() && name == default_name {
                        found_default = true;
                    }
                    if seen.insert(name.clone(), ()).is_some() {
                        found_duplicate = Some(name.clone());
                    }
                    names.push(name);
                }
            }
            if !found_default {
                return Err(XmlParseException::new(format!(
                    "Could not find default model {default_name}"
                )));
            }
            self.model_names = names;
            self.default_model_name = Some(default_name.to_string());
            let _ = eval_current.unwrap_or(default_name);
            let _ = eval_called.unwrap_or(default_name);
            Ok(found_duplicate)
        }

        fn remove_program_mechanism_payloads(&mut self, model_list: &[Box<dyn PrototypeModel>]) {
            for model in model_list {
                if model.has_injection() {
                    if let Some(name) = model.get_name() {
                        self.removed_mechanism_payloads.push(name);
                    }
                }
            }
        }

        fn register_program_inject(&mut self, inject_extensions: Vec<Box<dyn InjectPayloadSleigh>>) {
            self.registered_inject_count += inject_extensions.len();
        }

        fn clone_spec(&self) -> Box<dyn BasicCompilerSpec> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn add_context_setting_accumulates_settings() {
        let mut spec = MockBasicCompilerSpec::default();
        spec.add_context_setting(mock_register("r0"), 5, mock_address(0), mock_address(0x10));
        spec.add_context_setting(mock_register("r1"), 7, mock_address(0x20), mock_address(0x30));

        assert_eq!(spec.ctx_settings.len(), 2);
        assert_eq!(spec.ctx_settings[0].1, 5);
        assert_eq!(spec.ctx_settings[1].1, 7);
    }

    #[test]
    fn model_xrefs_detects_duplicate_names_and_finds_default() {
        let mut spec = MockBasicCompilerSpec::default();
        let models: Vec<Box<dyn PrototypeModel>> = vec![
            Box::new(NamedModel { name: "__cdecl", merged: false, has_injection: false }),
            Box::new(NamedModel { name: "__stdcall", merged: false, has_injection: false }),
            Box::new(NamedModel { name: "__stdcall", merged: false, has_injection: false }),
        ];

        let result = spec.model_xrefs(models, "__cdecl", None, Some("__stdcall")).unwrap();

        assert_eq!(result, Some("__stdcall".to_string()));
        assert_eq!(spec.default_model_name.as_deref(), Some("__cdecl"));
        assert_eq!(spec.model_names.len(), 3);
    }

    #[test]
    fn model_xrefs_errors_when_default_model_missing() {
        let mut spec = MockBasicCompilerSpec::default();
        let models: Vec<Box<dyn PrototypeModel>> =
            vec![Box::new(NamedModel { name: "__cdecl", merged: false, has_injection: false })];

        let err = spec.model_xrefs(models, "__stdcall", None, None).unwrap_err();
        assert!(err.to_string().contains("__stdcall"));
    }

    #[test]
    fn remove_program_mechanism_payloads_only_removes_injected_models() {
        let mut spec = MockBasicCompilerSpec::default();
        let models: Vec<Box<dyn PrototypeModel>> = vec![
            Box::new(NamedModel { name: "plain", merged: false, has_injection: false }),
            Box::new(NamedModel { name: "withfixup", merged: false, has_injection: true }),
        ];

        spec.remove_program_mechanism_payloads(&models);

        assert_eq!(spec.removed_mechanism_payloads, vec!["withfixup".to_string()]);
    }

    #[test]
    fn register_program_inject_counts_extensions() {
        let mut spec = MockBasicCompilerSpec::default();
        let extensions: Vec<Box<dyn InjectPayloadSleigh>> = vec![Box::new(StubInject), Box::new(StubInject)];

        spec.register_program_inject(extensions);

        assert_eq!(spec.registered_inject_count, 2);
    }

    #[test]
    fn clone_spec_is_a_deep_independent_copy() {
        let mut spec = MockBasicCompilerSpec::default();
        spec.add_context_setting(mock_register("r0"), 1, mock_address(0), mock_address(1));

        let mut cloned = spec.clone_spec();
        cloned.add_context_setting(mock_register("r1"), 2, mock_address(2), mock_address(3));

        assert_eq!(spec.ctx_settings.len(), 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let spec: Box<dyn BasicCompilerSpec> = Box::new(MockBasicCompilerSpec::default());
        assert_eq!(spec.get_compiler_spec_id(), CompilerSpecID::new(None));
    }
}
