use std::collections::HashSet;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::parameter::Parameter;
use crate::program::seam_stubs::{
    CompilerSpecDescription, CompilerSpecID, Encoder, Language, PcodeInjectLibrary, PrototypeModel,
};

/// Stands in for `CompilerSpec.CALLING_CONVENTION_unknown`.
pub const CALLING_CONVENTION_UNKNOWN: &str = "unknown";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_default`.
pub const CALLING_CONVENTION_DEFAULT: &str = "default";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_cdecl`.
pub const CALLING_CONVENTION_CDECL: &str = "__cdecl";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_pascal`.
pub const CALLING_CONVENTION_PASCAL: &str = "__pascal";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_thiscall`.
pub const CALLING_CONVENTION_THISCALL: &str = "__thiscall";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_stdcall`.
pub const CALLING_CONVENTION_STDCALL: &str = "__stdcall";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_fastcall`.
pub const CALLING_CONVENTION_FASTCALL: &str = "__fastcall";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_vectorcall`.
pub const CALLING_CONVENTION_VECTORCALL: &str = "__vectorcall";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_rustcall`.
pub const CALLING_CONVENTION_RUSTCALL: &str = "__rustcall";

/// Labels for [`PrototypeModel`]s that are used by default for various analysis/evaluation
/// use-cases, when the true model isn't known. The [`CompilerSpec`] maintains a specific
/// default `PrototypeModel` to be used for each use-case label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationModelType {
    /// A `PrototypeModel` used to evaluate the "current" function.
    EvalCurrent,
    /// A `PrototypeModel` used to evaluate a "called" function.
    EvalCalled,
}

/// Determine if the specified calling convention name is treated as the unknown calling
/// convention (blank or [`CALLING_CONVENTION_UNKNOWN`]). Other unrecognized names return
/// `false`. This function does not assume any specific compiler specification.
pub fn is_unknown_calling_convention(calling_convention_name: Option<&str>) -> bool {
    match calling_convention_name {
        None => true,
        Some(name) => name.trim().is_empty() || name == CALLING_CONVENTION_UNKNOWN,
    }
}

/// Interface for requesting specific information about the compiler used to build a Program
/// being analyzed. Major elements that can be queried include:
///   - `AddressSpace`s from the `Language` plus compiler specific ones like "stack"
///   - `DataOrganization` describing size and alignment of primitive data-types: int, long,
///     pointers, etc.
///   - `PrototypeModel`s describing calling conventions used by the compiler: `__stdcall`,
///     `__thiscall`, etc.
///   - `InjectPayload`s or p-code that can used for call-fixups and callother-fixups.
///   - Memory ranges that the compiler treats as global.
///   - Context and register values known to the compiler over specific memory ranges.
///
/// Port of `ghidra.program.model.lang.CompilerSpec`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared only
/// `get_compiler_spec_id`; that method is retained here as part of the full trait.
pub trait CompilerSpec {
    /// Get the Language this compiler spec is based on. Note that compiler specs may be reused
    /// across multiple languages in the cspec files on disk, but once loaded in memory are
    /// actually separate objects. (M:N on disk, 1:N in memory)
    fn get_language(&self) -> Box<dyn Language>;

    /// A brief description of the compiler spec.
    fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription>;

    /// The id string associated with this compiler spec.
    fn get_compiler_spec_id(&self) -> CompilerSpecID;

    /// Get the default Stack Pointer register for this language if there is one.
    fn get_stack_pointer(&self) -> Option<RegisterRef>;

    /// Indicates whether variables are right-justified within the stack alignment.
    fn is_stack_right_justified(&self) -> bool;

    /// Get an address space by name. This can be value added over the normal
    /// `AddressFactory::get_address_space` routine because the compiler spec can refer to
    /// special internal spaces like the stack space.
    fn get_address_space(&self, space_name: &str) -> Option<Arc<AddressSpace>>;

    /// Get the stack address space defined by this specification.
    fn get_stack_space(&self) -> Arc<AddressSpace>;

    /// Get the physical space used for stack data storage.
    fn get_stack_base_space(&self) -> Arc<AddressSpace>;

    /// Returns `true` if the stack grows with negative offsets.
    fn stack_grows_negative(&self) -> bool;

    /// Apply context settings to the `ProgramContext` as specified by the configuration.
    fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext);

    /// An array of the prototype models. Each prototype model specifies a calling convention.
    fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>>;

    /// Returns the Calling Convention Model with the given name, or `None` if there is none
    /// with that name.
    fn get_calling_convention(&self, name: &str) -> Option<Box<dyn PrototypeModel>>;

    /// All possible `PrototypeModel`s, including calling conventions and merge models.
    fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>>;

    /// Returns the prototype model that is the default calling convention, or `None`.
    fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>>;

    /// Get the language that the decompiler produces.
    fn get_decompiler_output_language(&self) -> DecompilerLanguage;

    /// Get the evaluation model matching the given type. If analysis needs to apply a
    /// `PrototypeModel` to a function but a specific model is not known, then this method can be
    /// used to select a putative `PrototypeModel` based on the analysis use-case:
    ///   - `EvalCurrent` indicates the model to use for the "current function" being analyzed
    ///   - `EvalCalled` indicates the model to use for a function called by the current function
    fn get_prototype_evaluation_model(
        &self,
        model_type: EvaluationModelType,
    ) -> Box<dyn PrototypeModel>;

    /// Returns `true` if the specified storage location (start of the storage) has been
    /// designated "global" in scope.
    fn is_global(&self, addr: &Address) -> bool;

    /// The data organization describing size and alignment of primitive data-types.
    fn get_data_organization(&self) -> Box<dyn DataOrganization>;

    /// The p-code inject library associated with this compiler spec.
    fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary>;

    /// Get the `PrototypeModel` which corresponds to the given calling convention name. If no
    /// match is found the default prototype model is returned.
    fn match_convention(&self, convention_name: &str) -> Box<dyn PrototypeModel>;

    /// Find the best guess at a calling convention model from this compiler spec given an
    /// ordered list of (potential) parameters with storage assignments.
    fn find_best_calling_convention(&self, params: &[&dyn Parameter]) -> Box<dyn PrototypeModel>;

    /// Returns whether this language has a property defined.
    fn has_property(&self, key: &str) -> bool;

    /// Return `true` if function prototypes respect the C-language data-type conversion
    /// conventions. This amounts to converting array data-types to pointer-to-element
    /// data-types. In C, arrays are passed by reference (structures are still passed by value).
    fn does_c_data_type_conversions(&self) -> bool;

    /// Gets the value of a property as an int, returning `default_int` if undefined.
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32;

    /// Gets the value of a property as a boolean, returning `default_boolean` if undefined.
    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool;

    /// Gets the value of a property as a string, returning `default_string` if undefined. Stands
    /// in for the two-argument overload of `CompilerSpec.getProperty`.
    fn get_property_or(&self, key: &str, default_string: &str) -> String;

    /// Gets a property defined for this language, or `None` if that property isn't defined.
    /// Stands in for the one-argument overload of `CompilerSpec.getProperty`.
    fn get_property(&self, key: &str) -> Option<String>;

    /// Returns a read-only set view of the property keys defined on this language.
    fn get_property_keys(&self) -> HashSet<String>;

    /// Encode this entire specification to a stream. A document is written with root element
    /// `<compiler_spec>`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Determine if this `CompilerSpec` is equivalent to another specified instance.
    fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {}

    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockPrototypeModel;
    impl PrototypeModel for MockPrototypeModel {}

    struct MockEncoder;
    impl Encoder for MockEncoder {}

    struct MockCompilerSpec {
        id: CompilerSpecID,
    }

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription)
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
            AddressSpace::new(
                "stack",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Stack,
                0,
            )
        }

        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            self.get_stack_space()
        }

        fn stack_grows_negative(&self) -> bool {
            true
        }

        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }

        fn get_calling_convention(&self, name: &str) -> Option<Box<dyn PrototypeModel>> {
            if name == CALLING_CONVENTION_CDECL {
                Some(Box::new(MockPrototypeModel))
            } else {
                None
            }
        }

        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }

        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            Some(Box::new(MockPrototypeModel))
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
            true
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

        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
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

    #[test]
    fn is_unknown_calling_convention_handles_blank_and_none() {
        assert!(is_unknown_calling_convention(None));
        assert!(is_unknown_calling_convention(Some("")));
        assert!(is_unknown_calling_convention(Some("   ")));
        assert!(is_unknown_calling_convention(Some(CALLING_CONVENTION_UNKNOWN)));
        assert!(!is_unknown_calling_convention(Some(CALLING_CONVENTION_CDECL)));
    }

    #[test]
    fn usable_as_trait_object() {
        let spec: Box<dyn CompilerSpec> = Box::new(MockCompilerSpec {
            id: CompilerSpecID::new(Some("gcc")),
        });

        assert_eq!(spec.get_compiler_spec_id().get_id_as_string(), "gcc");
        assert!(spec.stack_grows_negative());
        assert!(spec.get_calling_convention(CALLING_CONVENTION_CDECL).is_some());
        assert!(spec.get_calling_convention("bogus").is_none());
        assert_eq!(
            spec.get_decompiler_output_language(),
            DecompilerLanguage::CLanguage
        );
    }

    #[test]
    fn is_equivalent_compares_ids() {
        let a = MockCompilerSpec {
            id: CompilerSpecID::new(Some("gcc")),
        };
        let b = MockCompilerSpec {
            id: CompilerSpecID::new(Some("gcc")),
        };
        let c = MockCompilerSpec {
            id: CompilerSpecID::new(Some("visualstudio")),
        };

        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }
}
