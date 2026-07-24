//! Port of `ghidra.program.database.ProgramCompilerSpec`.
//!
//! In Java this is a concrete class (`ProgramCompilerSpec extends BasicCompilerSpec`) that
//! attaches a [`Program`]'s per-program option overrides (evaluation model choice, decompiler
//! output language, spec extensions) to the [`CompilerSpec`] loaded from its `Language`. It was
//! selected as a dependency-cycle cut-point, so only its public/protected API surface -- the part
//! other collaborators (notably `ProgramDB`) actually call -- is captured here as a trait; the
//! private helper methods that assemble prototype-model/inject-payload extensions
//! (`installPrototypeExtensions`, `establishEvaluationModelChoices`, `addPrototypeError`,
//! `addPayloadError`, `updateModelChoices`, `reportExtensionErrors`) are internal to the concrete
//! Java class and are not part of the contract a trait needs to expose.
//!
//! The package-private static factory `getProgramCompilerSpec(Program, CompilerSpec)` is also
//! omitted: it constructs a new concrete `ProgramCompilerSpec` from a `BasicCompilerSpec`, which
//! requires both a concrete implementation of this trait and a Rust port of `BasicCompilerSpec`
//! (currently unported) to downcast against -- neither exists yet, and no already-ported Rust code
//! calls this factory (`ProgramDB`'s Rust port does not reference `ProgramCompilerSpec`).
//!
//! `equals(Object)` is likewise omitted: `CompilerSpec::is_equivalent` already covers the
//! trait-object-safe equivalence contract other ported code relies on.

use crate::framework::model::DomainObject;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::listing::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Stands in for `ProgramCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME`.
pub const DECOMPILER_PROPERTY_LIST_NAME: &str = "Decompiler";
/// Stands in for `ProgramCompilerSpec.DECOMPILER_OUTPUT_LANGUAGE`.
pub const DECOMPILER_OUTPUT_LANGUAGE: &str = "Output Language";
/// Stands in for `ProgramCompilerSpec.DECOMPILER_OUTPUT_DEF`.
pub const DECOMPILER_OUTPUT_DEF: DecompilerLanguage = DecompilerLanguage::CLanguage;
/// Stands in for `ProgramCompilerSpec.DECOMPILER_OUTPUT_DESC`.
pub const DECOMPILER_OUTPUT_DESC: &str =
    "Select the source language output by the decompiler.";
/// Stands in for `ProgramCompilerSpec.EVALUATION_MODEL_PROPERTY_NAME`.
pub const EVALUATION_MODEL_PROPERTY_NAME: &str = "Prototype Evaluation";

/// A Program-specific version of [`CompilerSpec`], layering per-program option overrides
/// (evaluation model choice, decompiler output language, spec extensions) on top of the
/// [`CompilerSpec`] loaded from the `Program`'s `Language`.
///
/// Port of `ghidra.program.database.ProgramCompilerSpec`. See the module docs for what was
/// intentionally left out of this trait.
pub trait ProgramCompilerSpec: CompilerSpec {
    /// Update this object with any program-specific compiler specification extensions (new
    /// [`PrototypeModel`](crate::program::model::lang::prototype_model::PrototypeModel)s or
    /// inject payloads) recorded on the owning `Program`'s options.
    ///
    /// Stands in for the protected `installExtensions()`.
    fn install_extensions(&mut self);

    /// Register program-specific compiler-spec options (evaluation model choice, and the
    /// decompiler output language option if already present) on the owning `Program`.
    ///
    /// Stands in for the protected `registerProgramOptions()`.
    fn register_program_options(&mut self);

    /// Reset options to their defaults, for use when the `Program`'s language is being changed
    /// out from under this compiler spec.
    ///
    /// Stands in for the protected `resetProgramOptions(TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` reports cancellation.
    fn reset_program_options(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

/// Adds and enables an option on `program` to have the decompiler display Java instead of C.
///
/// Stands in for the static `ProgramCompilerSpec.enableJavaLanguageDecompilation(Program)`.
pub fn enable_java_language_decompilation(program: &dyn Program) {
    let mut decompiler_options = program.get_options(DECOMPILER_PROPERTY_LIST_NAME);
    decompiler_options.register_option(
        DECOMPILER_OUTPUT_LANGUAGE,
        Box::new(DECOMPILER_OUTPUT_DEF),
        None,
        DECOMPILER_OUTPUT_DESC,
    );
    decompiler_options.set_string(
        DECOMPILER_OUTPUT_LANGUAGE,
        &DecompilerLanguage::JavaLanguage.to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::options::options::Options;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::pcode::Encoder;
    use crate::program::model::address::{Address, AddressSetView};
    use crate::program::seam_stubs::PcodeInjectLibrary;
    use crate::util::task::CancelledListener;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// A minimal [`ProgramCompilerSpec`] mock. Since the trait extends [`CompilerSpec`], every
    /// `CompilerSpec` method needs *a* body to satisfy the trait, but only the identity
    /// (`get_compiler_spec_id`) and the [`ProgramCompilerSpec`]-specific methods below are
    /// actually exercised by the tests.
    struct MockProgramCompilerSpec {
        id: CompilerSpecID,
        install_count: u32,
        registered: bool,
    }

    impl CompilerSpec for MockProgramCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
        }

        fn get_stack_pointer(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
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
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
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

    impl ProgramCompilerSpec for MockProgramCompilerSpec {
        fn install_extensions(&mut self) {
            self.install_count += 1;
        }

        fn register_program_options(&mut self) {
            self.registered = true;
        }

        fn reset_program_options(
            &mut self,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.registered = false;
            Ok(())
        }
    }

    struct AlwaysCancelledMonitor;

    impl TaskMonitor for AlwaysCancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException("cancelled".to_string()))
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn usable_as_trait_object_and_tracks_state() {
        let mut spec: Box<dyn ProgramCompilerSpec> = Box::new(MockProgramCompilerSpec {
            id: CompilerSpecID::new(Some("gcc")),
            install_count: 0,
            registered: false,
        });

        assert_eq!(spec.get_compiler_spec_id().get_id_as_string(), "gcc");

        spec.install_extensions();
        spec.install_extensions();
        spec.register_program_options();

        assert_eq!(spec.reset_program_options(&crate::util::task::DummyMonitor).is_ok(), true);
    }

    #[test]
    fn reset_program_options_propagates_cancellation() {
        let mut spec = MockProgramCompilerSpec {
            id: CompilerSpecID::new(Some("gcc")),
            install_count: 0,
            registered: true,
        };

        let result = spec.reset_program_options(&AlwaysCancelledMonitor);

        assert!(result.is_err());
        // A failed reset (monitor cancelled before any state changed) must leave prior state
        // untouched, mirroring the Java method bailing out before touching any options.
        assert!(spec.registered);
    }

    /// A recording [`Options`] shared (via [`Arc<Mutex<_>>`]) with the [`MockProgram`] that hands
    /// it out, so the test can inspect what [`enable_java_language_decompilation`] did after the
    /// call returns.
    #[derive(Default)]
    struct RecordingOptionsState {
        registered_names: Vec<String>,
        strings: std::collections::HashMap<String, String>,
    }

    struct RecordingOptions(Arc<Mutex<RecordingOptionsState>>);

    impl Options for RecordingOptions {
        fn register_option(
            &mut self,
            option_name: &str,
            _default_value: Box<dyn std::any::Any>,
            _help: Option<Box<dyn crate::framework::seam_stubs::HelpLocation>>,
            _description: &str,
        ) {
            self.0.lock().unwrap().registered_names.push(option_name.to_string());
        }

        fn set_string(&mut self, option_name: &str, value: &str) {
            self.0
                .lock()
                .unwrap()
                .strings
                .insert(option_name.to_string(), value.to_string());
        }

        fn get_string(&self, option_name: &str, default_value: &str) -> String {
            self.0
                .lock()
                .unwrap()
                .strings
                .get(option_name)
                .cloned()
                .unwrap_or_else(|| default_value.to_string())
        }
    }

    struct MockProgram {
        decompiler_options: Arc<Mutex<RecordingOptionsState>>,
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    impl DomainObject for MockProgram {
        fn get_options(&self, property_list_name: &str) -> Box<dyn Options> {
            assert_eq!(property_list_name, DECOMPILER_PROPERTY_LIST_NAME);
            Box::new(RecordingOptions(self.decompiler_options.clone()))
        }
    }

    #[test]
    fn enable_java_language_decompilation_registers_and_sets_java() {
        let state = Arc::new(Mutex::new(RecordingOptionsState::default()));
        let program = MockProgram {
            decompiler_options: state.clone(),
        };

        enable_java_language_decompilation(&program);

        let state = state.lock().unwrap();
        assert_eq!(state.registered_names, vec![DECOMPILER_OUTPUT_LANGUAGE.to_string()]);
        assert_eq!(
            state.strings.get(DECOMPILER_OUTPUT_LANGUAGE).map(String::as_str),
            Some(DecompilerLanguage::JavaLanguage.to_string()).as_deref()
        );
    }
}
