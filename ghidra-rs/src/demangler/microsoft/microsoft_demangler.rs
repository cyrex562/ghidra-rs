use std::cell::{Ref, RefCell};
use std::sync::Arc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_object::DemangledObject;
use crate::demangler::demangler::Demangler;
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation;
use crate::demangler::seam_stubs::{
    self, DemangledDataTypeLike, MdDataTypeLike, MdMangGhidra, MdParsableItemLike,
    MicrosoftDemanglerOptions, MicrosoftMangledContext,
};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Executable format name reported by the (unported) `PeLoader`, mirrored here as a bare constant
/// since [`MicrosoftDemangler::can_demangle`] only ever needs the string value, not the loader's
/// full (18-method) surface. Mirrors `PeLoader.PE_NAME`.
const PE_NAME: &str = "Portable Executable (PE)";

/// Executable format name reported by the (unported) `MSCoffLoader`, the same treatment as
/// [`PE_NAME`]. Mirrors `MSCoffLoader.MSCOFF_NAME`.
const MSCOFF_NAME: &str = "MS Common Object File Format (COFF)";

/// A class for demangling debug symbols created using Microsoft Visual Studio.
///
/// Mirrors `ghidra.app.util.demangler.microsoft.MicrosoftDemangler`.
///
/// Only the `item`/`mdType` fields have public getters in the original (`getMdItem`/`getMdType`);
/// the `demangler`/`object`/`dataType` fields are pure locals of `demangle`/`demangleType` in this
/// port, since nothing outside those methods ever reads them. [`Demangler::demangle`] takes `&self`
/// (see that trait's docs), so `item`/`md_type` need interior mutability to mirror the original's
/// field assignments.
///
/// [`Demangler::demangle`]'s context/options are the base (non-Microsoft) types, since that's what
/// the already-ported `Demangler` trait's signature carries; the Microsoft-specific
/// `MicrosoftMangledContext`/`MicrosoftDemanglerOptions` fields (architecture size, interpretation)
/// therefore fall back to defaults rather than a caller's actual values in that path. Callers that
/// need full fidelity should use [`MicrosoftDemangler::demangle_type`], which takes the real
/// [`MicrosoftMangledContext`] (not constrained by any trait signature, since `demangleType` isn't
/// part of the `Demangler` interface in the original either).
pub struct MicrosoftDemangler {
    item: RefCell<Option<Box<dyn MdParsableItemLike>>>,
    md_type: RefCell<Option<Box<dyn MdDataTypeLike>>>,
}

impl MicrosoftDemangler {
    /// Mirrors `MicrosoftDemangler()`.
    pub fn new() -> Self {
        Self { item: RefCell::new(None), md_type: RefCell::new(None) }
    }

    /// Attempts to demangle the type string of the mangled context into a type.
    ///
    /// Mirrors `demangleType(MangledContext)`. Unlike [`Demangler::demangle`], this isn't
    /// constrained by any trait signature, so it takes the real [`MicrosoftMangledContext`]
    /// directly for full fidelity.
    pub fn demangle_type(
        &self,
        context: &MicrosoftMangledContext,
    ) -> Result<Option<Box<dyn DemangledDataTypeLike>>, DemangledException> {
        let options = context.options();
        let mangled = context.mangled().to_string();

        let mut demangler = MdMangGhidra::new();
        demangler.set_mangled_symbol(mangled.clone());
        demangler.set_error_on_remaining_chars(options.error_on_remaining_chars());
        demangler.set_demangle_only_known_patterns(options.demangle_only_known_patterns());
        demangler.set_architecture_size(context.architecture_size());
        demangler.set_is_function(context.should_interpret_as_function());

        let md_type = match demangler.demangle_type() {
            Ok(md_type) => md_type,
            Err(_e) => return Err(DemangledException::from_invalid_mangled_name(true)),
        };

        let original_demangled = md_type.to_string();

        demangler
            .output_options()
            .set_use_encoded_anonymous_namespace(options.use_encoded_anonymous_namespace());
        demangler
            .output_options()
            .set_apply_udt_argument_type_tag(options.apply_udt_argument_type_tag());

        let mut data_type =
            seam_stubs::convert_to_demangled_data_type(md_type.as_ref(), &mangled, &original_demangled);

        if let Some(dt) = data_type.as_mut() {
            let base_context = MangledContext::new(
                context.program(),
                options.base().clone(),
                mangled.clone(),
                context.address(),
            );
            dt.set_mangled_context(base_context);
        }

        *self.md_type.borrow_mut() = Some(md_type);

        Ok(data_type)
    }

    /// Returns the [`MdParsableItemLike`] used in demangling to a [`DemangledObject`]; can be
    /// `None` if nothing has been demangled yet, or the last item wasn't demangled.
    ///
    /// Mirrors `getMdItem()`.
    pub fn md_item(&self) -> Ref<'_, Option<Box<dyn MdParsableItemLike>>> {
        self.item.borrow()
    }

    /// Returns the [`MdDataTypeLike`] used in demangling to a [`DemangledDataTypeLike`]; can be
    /// `None` if nothing has been demangled yet, or the last type wasn't demangled.
    ///
    /// Mirrors `getMdType()`.
    pub fn md_type(&self) -> Ref<'_, Option<Box<dyn MdDataTypeLike>>> {
        self.md_type.borrow()
    }

    /// Creates default options for the Microsoft demangler, with the real covariant
    /// `MicrosoftDemanglerOptions` return type.
    ///
    /// Mirrors the actual declared return type of `createDefaultOptions()`; the `Demangler` trait
    /// method of the same name (implemented below) is limited to the base `DemanglerOptions`, see
    /// this struct's docs.
    pub fn create_default_microsoft_options(&self) -> MicrosoftDemanglerOptions {
        MicrosoftDemanglerOptions::new()
    }

    /// Creates a Microsoft mangled context, with the real covariant `MicrosoftMangledContext`
    /// return type.
    ///
    /// Mirrors the actual declared return type of
    /// `createMangledContext(String, DemanglerOptions, Program, Address)`; folds in the private
    /// `getMicrosoftOptions` helper.
    pub fn create_microsoft_mangled_context(
        &self,
        mangled: &str,
        options: Option<DemanglerOptions>,
        program: Option<Arc<dyn Program>>,
        address: Option<Address>,
    ) -> MicrosoftMangledContext {
        let options = match options {
            Some(options) => MicrosoftDemanglerOptions::from_base(&options),
            None => self.create_default_microsoft_options(),
        };
        MicrosoftMangledContext::new(program, options, mangled.to_string(), address)
    }
}

impl Default for MicrosoftDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionPoint for MicrosoftDemangler {}

impl Demangler for MicrosoftDemangler {
    /// Mirrors `canDemangle(Program)`.
    fn can_demangle(&self, program: &dyn Program) -> bool {
        let executable_format = program.get_executable_format();
        executable_format.contains(PE_NAME) || executable_format.contains(MSCOFF_NAME)
    }

    /// Mirrors `demangle(MangledContext)`. See this struct's docs for how the `instanceof
    /// MicrosoftMangledContext`/`instanceof MicrosoftDemanglerOptions` checks in the original are
    /// handled given this trait's fixed (base-typed) signature.
    fn demangle(
        &self,
        context: &MangledContext,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let options = MicrosoftDemanglerOptions::from_base(context.options());
        let mangled = context.mangled().to_string();
        let architecture_size = context
            .program()
            .and_then(|program| program.get_address_factory())
            .and_then(|factory| factory.get_default_address_space())
            .map(|space| space.size())
            .unwrap_or(0);
        let is_function = match options.interpretation() {
            MsCInterpretation::Function => true,
            MsCInterpretation::NonFunction => false,
            MsCInterpretation::FunctionIfExists => false,
        };

        let mut demangler = MdMangGhidra::new();
        demangler.set_mangled_symbol(mangled.clone());
        demangler.set_error_on_remaining_chars(options.error_on_remaining_chars());
        demangler.set_demangle_only_known_patterns(options.demangle_only_known_patterns());
        demangler.set_architecture_size(architecture_size);
        demangler.set_is_function(is_function);

        let item = match demangler.demangle() {
            Ok(Some(item)) => item,
            Ok(None) => return Ok(None),
            Err(_e) => return Err(DemangledException::from_invalid_mangled_name(true)),
        };

        // The item's toString() method is influenced by the demangler output options, so we get
        // the originalDemangled string before we change the output options to what we desire for
        // Ghidra processing.
        let original_demangled = item.to_string();

        demangler
            .output_options()
            .set_use_encoded_anonymous_namespace(options.use_encoded_anonymous_namespace());
        demangler
            .output_options()
            .set_apply_udt_argument_type_tag(options.apply_udt_argument_type_tag());

        let mut object =
            seam_stubs::convert_to_demangled_object(item.as_ref(), &mangled, &original_demangled)?;

        if let Some(object) = object.as_mut() {
            object.set_mangled_context(context.clone());
        }

        *self.item.borrow_mut() = Some(item);

        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    struct MockProgram {
        executable_format: String,
        address_factory: Option<Arc<DefaultAddressFactory>>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }

        fn get_executable_format(&self) -> String {
            self.executable_format.clone()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            self.address_factory
                .clone()
                .map(|f| f as Arc<dyn crate::program::model::address::AddressFactory>)
        }
    }

    fn pe_program() -> MockProgram {
        MockProgram { executable_format: PE_NAME.to_string(), address_factory: None }
    }

    #[test]
    fn can_demangle_accepts_pe_format() {
        let demangler = MicrosoftDemangler::new();
        let program = pe_program();
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_accepts_mscoff_format() {
        let demangler = MicrosoftDemangler::new();
        let program = MockProgram {
            executable_format: format!("Some {MSCOFF_NAME} variant"),
            address_factory: None,
        };
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_rejects_unrelated_format() {
        let demangler = MicrosoftDemangler::new();
        let program = MockProgram { executable_format: "ELF".to_string(), address_factory: None };
        assert!(!demangler.can_demangle(&program));
    }

    #[test]
    fn demangle_errors_on_blank_mangled_string() {
        // Mirrors MDMang.initState()'s "Mangled string is null or blank" check, faithfully
        // reproduced in MdMangGhidra::demangle even though the real grammar dispatch isn't
        // ported yet.
        let demangler = MicrosoftDemangler::new();
        let context = demangler.create_mangled_context("   ", None, None, None);

        let result = demangler.demangle(&context);

        match result {
            Err(err) => assert!(err.is_invalid_mangled_name()),
            Ok(_) => panic!("expected an error for a blank mangled string"),
        }
    }

    #[test]
    fn demangle_skips_symbol_not_matching_known_pattern() {
        // Default DemanglerOptions has demangle_only_known_patterns = true. '{' doesn't start a
        // known pattern (doesn't start with ?/./_ , and isn't < 'a' or an ASCII letter), so
        // MDMangGhidra.demangle() returns null (mapped here to Ok(None)) without ever reaching
        // the unported grammar dispatch.
        let demangler = MicrosoftDemangler::new();
        let context = demangler.create_mangled_context("{not_a_known_pattern", None, None, None);

        let result = demangler.demangle(&context).expect("known-pattern skip should not error");

        assert!(result.is_none());
    }

    #[test]
    fn demangle_reports_unported_grammar_for_well_formed_mangled_name() {
        let demangler = MicrosoftDemangler::new();
        let context = demangler.create_mangled_context("?foo@@YAHXZ", None, None, None);

        let result = demangler.demangle(&context);

        // The known-pattern filter passes ('?' prefix), but the actual grammar dispatch isn't
        // ported, so this surfaces as an "invalid mangled name" error rather than a panic or a
        // silently wrong success.
        match result {
            Err(err) => assert!(err.is_invalid_mangled_name()),
            Ok(_) => panic!("expected an error since the grammar dispatch isn't ported"),
        }
    }

    #[test]
    fn create_default_microsoft_options_matches_java_defaults() {
        let demangler = MicrosoftDemangler::new();
        let options = demangler.create_default_microsoft_options();

        assert!(options.error_on_remaining_chars());
        assert_eq!(options.interpretation(), MsCInterpretation::FunctionIfExists);
        assert!(options.use_encoded_anonymous_namespace());
        assert!(!options.apply_udt_argument_type_tag());
    }

    #[test]
    fn create_microsoft_mangled_context_computes_architecture_size_from_program() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let factory = Arc::new(DefaultAddressFactory::new(vec![space]));
        let program: Arc<dyn Program> =
            Arc::new(MockProgram { executable_format: PE_NAME.to_string(), address_factory: Some(factory) });
        let demangler = MicrosoftDemangler::new();

        let context =
            demangler.create_microsoft_mangled_context("?foo@@YAHXZ", None, Some(program), None);

        assert_eq!(context.architecture_size(), 64);
    }

    #[test]
    fn create_microsoft_mangled_context_architecture_size_is_zero_without_program() {
        let demangler = MicrosoftDemangler::new();

        let context = demangler.create_microsoft_mangled_context("?foo@@YAHXZ", None, None, None);

        assert_eq!(context.architecture_size(), 0);
    }

    #[test]
    fn demangle_type_errors_on_blank_mangled_string() {
        let demangler = MicrosoftDemangler::new();
        let context = demangler.create_microsoft_mangled_context("  ", None, None, None);

        let result = demangler.demangle_type(&context);

        match result {
            Err(err) => assert!(err.is_invalid_mangled_name()),
            Ok(_) => panic!("expected an error for a blank mangled string"),
        }
    }

    #[test]
    fn md_item_and_md_type_start_empty() {
        let demangler = MicrosoftDemangler::new();
        assert!(demangler.md_item().is_none());
        assert!(demangler.md_type().is_none());
    }
}
