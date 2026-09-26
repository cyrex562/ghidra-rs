//! Port of `ghidra.app.util.demangler.gnu.GnuDemangler`.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_object::DemangledObject;
use crate::demangler::demangler::Demangler;
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::demangler::seam_stubs::{
    self, DemangledAddressTable, DemangledFunction, GnuDemanglerOptions, GnuDemanglerParser,
};
use crate::app::util::opinion::elf_loader::ElfLoader;
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Executable format name reported by the (unported) `MachoLoader`, mirrored here as a bare
/// constant since [`GnuDemangler::is_macho`] only ever needs the string value, not the loader's
/// full surface -- the same treatment `MicrosoftDemangler` gives `PeLoader.PE_NAME`. Mirrors
/// `MachoLoader.MACH_O_NAME`.
const MACH_O_NAME: &str = "Mac OS X Mach-O";

/// A class for demangling debug symbols created using GNU GCC.
///
/// Mirrors `ghidra.app.util.demangler.gnu.GnuDemangler`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GnuDemangler;

impl GnuDemangler {
    /// Dwarf debug reference prefix. Mirrors `DWARF_REF`.
    const DWARF_REF: &'static str = "DW.ref.";
    /// Mirrors `GLOBAL_PREFIX`.
    const GLOBAL_PREFIX: &'static str = "_GLOBAL_";

    /// Mirrors the (no-op, "needed to instantiate dynamically") constructor `GnuDemangler()`.
    pub fn new() -> Self {
        Self
    }

    /// Mirrors the private `demangleInternal(MangledContext)`.
    fn demangle_internal(
        &self,
        mangled_context: &MangledContext,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let options = Self::get_gnu_options(mangled_context.options());
        let original_mangled = mangled_context.mangled().to_string();

        if Self::skip(&original_mangled, &options) {
            return Ok(None);
        }

        let mut mangled = original_mangled.clone();
        let mut global_prefix: Option<String> = None;
        if mangled.starts_with(Self::GLOBAL_PREFIX) {
            if let Some(index) = mangled.find("_Z") {
                if index > 0 {
                    global_prefix = Some(mangled[..index].to_string());
                    mangled = mangled[index..].to_string();
                }
            }
        } else if mangled.starts_with("__Z") {
            mangled = mangled[1..].to_string();
        }

        let mut is_dwarf = false;
        if mangled.starts_with(Self::DWARF_REF) {
            mangled = mangled[Self::DWARF_REF.len()..].to_string();
            is_dwarf = true;
        }

        let process = seam_stubs::get_demangler_native_process(
            options.demangler_name(),
            &options.demangler_application_arguments(),
        )
        .map_err(Self::map_io_error)?;

        let demangled = process
            .demangle(&mangled, options.timeout_seconds())
            .map_err(Self::map_io_error)?;

        let Some(demangled) = demangled else {
            return Err(DemangledException::from_invalid_mangled_name(false));
        };
        let demangled = demangled.trim();
        if demangled.is_empty() || mangled == demangled {
            return Err(DemangledException::from_invalid_mangled_name(true));
        }

        let Some(mut demangled_object) = Self::parse(&original_mangled, demangled, &options)
        else {
            return Ok(None);
        };

        if let Some(prefix) = global_prefix {
            let namespace = demangled_object.base_mut().namespace.take();
            let mut dfunc = DemangledFunction::new(
                original_mangled.clone(),
                demangled.to_string(),
                &format!("{prefix}{}", demangled_object.get_name()),
            );
            dfunc.set_namespace(namespace);
            demangled_object = Box::new(dfunc);
        }

        if is_dwarf {
            let mut dat =
                DemangledAddressTable::new(original_mangled.clone(), Some(demangled.to_string()), None, false);
            dat.set_special_prefix("DWARF Debug ");
            dat.set_name(&demangled_object.get_name());
            let namespace = demangled_object.base_mut().namespace.take();
            dat.set_namespace(namespace);
            return Ok(Some(Box::new(dat)));
        }

        Ok(Some(demangled_object))
    }

    /// Mirrors the private `getGnuOptions(DemanglerOptions)`. In Java this checks
    /// `instanceof GnuDemanglerOptions` and returns the argument unchanged when it already is
    /// one; in Rust `MangledContext::options()` always returns the base
    /// [`DemanglerOptions`] struct (never a [`GnuDemanglerOptions`], since Rust has no
    /// downcasting), so that branch can never be taken and this always wraps.
    fn get_gnu_options(options: &DemanglerOptions) -> GnuDemanglerOptions {
        GnuDemanglerOptions::from_base(options)
    }

    /// Mirrors the private `getNativeProcess` failure-path message construction: converts the
    /// underlying I/O error into a [`DemangledException`], special-casing the Windows
    /// "missing runtime libraries" case.
    ///
    /// The real message interpolates `Application.getInstallationDirectory()`, the process-wide
    /// application singleton; this port has no such singleton wired up at this call site, so the
    /// directory portion of the message is omitted rather than invented.
    fn map_io_error(e: std::io::Error) -> DemangledException {
        if e.to_string().ends_with("14001") {
            return DemangledException::from_message(
                "Missing runtime libraries. Please install support/install_windows_runtime_libraries.exe.",
            );
        }
        DemangledException::from_cause(e)
    }

    /// Mirrors the private `skip(String, GnuDemanglerOptions)`.
    ///
    /// Determines if the given mangled string should not be demangled. There are a couple
    /// patterns that will always be skipped. If
    /// [`GnuDemanglerOptions::demangle_only_known_patterns`] is true, then only mangled symbols
    /// matching a list of known start patterns will not be skipped.
    fn skip(mangled: &str, options: &GnuDemanglerOptions) -> bool {
        // Ignore versioned symbols which are generally duplicated at the same address.
        if mangled.find('@').is_some_and(|index| index > 0) {
            return true;
        }

        if mangled.starts_with("___") {
            // Not a mangled symbol, but the demangler will try anyway, so don't let it.
            return true;
        }

        if !options.demangle_only_known_patterns() {
            return false; // let it go through
        }

        // This is the current list of known demangler start patterns. Add to this list if we
        // find any other known GNU start patterns.
        if mangled.starts_with(Self::GLOBAL_PREFIX) {
            if let Some(index) = mangled.find("_Z") {
                if index > 0 {
                    return false;
                }
            }
        }
        if mangled.starts_with("_Z") {
            return false;
        }
        if mangled.starts_with("__Z") {
            return false;
        }
        if mangled.starts_with("h__") {
            return false; // not sure about this one
        }
        if mangled.starts_with('?') {
            return false; // not sure about this one
        }
        if Self::is_gnu2_or_3_pattern(mangled) {
            return false;
        }

        true
    }

    /// Mirrors the private `parse(String, GnuDemanglerNativeProcess, String,
    /// GnuDemanglerOptions)`. The `process` parameter is unused by the original method, so it is
    /// dropped here.
    fn parse(
        mangled: &str,
        demangled: &str,
        options: &GnuDemanglerOptions,
    ) -> Option<Box<dyn DemangledObject>> {
        let only_known_patterns = options.demangle_only_known_patterns();
        if only_known_patterns && !Self::is_known_mangled_string(mangled, demangled) {
            return None;
        }

        let replace_std_typedefs = options.should_use_standard_replacements();
        let parser = GnuDemanglerParser::new();
        parser.parse(mangled, demangled, replace_std_typedefs)
    }

    /// Mirrors the private `isKnownMangledString(String, String)`.
    ///
    /// We get requests to demangle strings that are not mangled. For newer mangled strings we
    /// know how to avoid that. However, older mangled strings can be of many forms. To detect
    /// whether a string is mangled, we have to resort to examining the output of the demangler.
    fn is_known_mangled_string(mangled: &str, demangled: &str) -> bool {
        // check for the case where good strings have '__' in them (which is valid GNU2 mangling)
        !Self::is_invalid_double_underscore_string(mangled, demangled)
    }

    /// Mirrors the private `isInvalidDoubleUnderscoreString(String, String)`.
    ///
    /// Bad string form: `text__moretext`. The demangler will output something like
    /// `text(..)(...)(...)` or `e::text(...)(...)`.
    fn is_invalid_double_underscore_string(mangled: &str, demangled: &str) -> bool {
        let Some(index) = mangled.find("__") else {
            return false;
        };
        let leading_text = &mangled[..index];
        demangled.contains(leading_text)
    }

    /// Mirrors the private `isGnu2Or3Pattern(String)`.
    fn is_gnu2_or_3_pattern(mangled: &str) -> bool {
        // Gnu2/3 constructs -- not sure if we still need these
        mangled.starts_with("_GLOBAL_.I.")
            || mangled.starts_with("_GLOBAL_.D.")
            || mangled.starts_with("_GLOBAL__I__Z")
            || mangled.starts_with("_GLOBAL__D__Z")
    }

    /// Mirrors the private `isMacho(String)`.
    fn is_macho(executable_format: &str) -> bool {
        executable_format.contains(MACH_O_NAME)
    }
}

impl ExtensionPoint for GnuDemangler {}

impl Demangler for GnuDemangler {
    /// Mirrors `canDemangle(Program)`.
    fn can_demangle(&self, program: &dyn Program) -> bool {
        let executable_format = program.get_executable_format();
        if ElfLoader::is_elf(&executable_format) || Self::is_macho(&executable_format) {
            return true;
        }

        let compiler = program.get_compiler();
        if compiler.contains("gcc") {
            return true;
        }

        if let Some(spec) = program.get_compiler_spec() {
            let spec_id = spec.get_compiler_spec_id();
            if !spec_id.get_id_as_string().to_lowercase().contains("windows") {
                return true;
            }
        }

        false
    }

    /// Mirrors `demangle(MangledContext)`.
    fn demangle(
        &self,
        context: &MangledContext,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let mut demangled = self.demangle_internal(context)?;
        if let Some(obj) = demangled.as_mut() {
            obj.set_mangled_context(context.clone());
        }
        Ok(demangled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::opinion::elf_loader::ELF_NAME;
    use crate::framework::model::DomainObject;

    #[derive(Default)]
    struct MockProgram {
        executable_format: String,
        compiler: String,
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

        fn get_compiler(&self) -> String {
            self.compiler.clone()
        }
    }

    fn context(mangled: &str) -> MangledContext {
        MangledContext::new(None, DemanglerOptions::new(), mangled.to_string(), None)
    }

    #[test]
    fn can_demangle_accepts_elf_format() {
        let demangler = GnuDemangler::new();
        let program = MockProgram { executable_format: ELF_NAME.to_string(), ..Default::default() };
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_accepts_macho_format() {
        let demangler = GnuDemangler::new();
        let program =
            MockProgram { executable_format: "Mac OS X Mach-O executable".to_string(), ..Default::default() };
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_accepts_gcc_compiler() {
        let demangler = GnuDemangler::new();
        let program = MockProgram { compiler: "gcc".to_string(), ..Default::default() };
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_rejects_program_with_no_signal() {
        // No ELF/Mach-O executable format, no gcc compiler, and no compiler spec (defaults to
        // None), so canDemangle falls through to `return false`.
        let demangler = GnuDemangler::new();
        let program = MockProgram::default();
        assert!(!demangler.can_demangle(&program));
    }

    #[test]
    fn demangle_skips_versioned_symbol() {
        let demangler = GnuDemangler::new();
        let ctx = context("_Z3fooi@GLIBC_2.2.5");
        let result = demangler.demangle(&ctx).expect("skip should not error");
        assert!(result.is_none());
    }

    #[test]
    fn demangle_skips_triple_underscore_prefix() {
        let demangler = GnuDemangler::new();
        let ctx = context("___not_mangled");
        let result = demangler.demangle(&ctx).expect("skip should not error");
        assert!(result.is_none());
    }

    #[test]
    fn demangle_skips_unknown_pattern_when_restricted_to_known_patterns() {
        let mut options = DemanglerOptions::new();
        assert!(options.demangle_only_known_patterns());
        options.set_demangle_only_known_patterns(true);
        let demangler = GnuDemangler::new();
        let ctx = MangledContext::new(None, options, "not_a_known_pattern".to_string(), None);
        let result = demangler.demangle(&ctx).expect("unknown pattern should be skipped");
        assert!(result.is_none());
    }

    #[test]
    fn demangle_reports_unported_native_process_for_known_pattern() {
        // "_Z..." passes the known-pattern filter, so `skip` returns false and control reaches
        // the (unported) native demangler process, which surfaces as an error -- mirroring how
        // MicrosoftDemangler's tests treat its own unported grammar dispatch.
        let demangler = GnuDemangler::new();
        let ctx = context("_Z3fooi");
        let result = demangler.demangle(&ctx);
        assert!(result.is_err(), "expected an error since the native process isn't ported");
    }

    #[test]
    fn skip_allows_gnu2_or_3_patterns_through() {
        assert!(!GnuDemangler::skip("_GLOBAL__I__Zfoo", &GnuDemanglerOptions::new()));
        assert!(!GnuDemangler::skip("_GLOBAL__D__Zfoo", &GnuDemanglerOptions::new()));
    }

    #[test]
    fn is_invalid_double_underscore_string_detects_bad_form() {
        // "text__moretext" is invalid when the demangler output still contains the leading text.
        assert!(GnuDemangler::is_invalid_double_underscore_string(
            "text__moretext",
            "text(...)(...)"
        ));
    }

    #[test]
    fn is_invalid_double_underscore_string_allows_valid_gnu2_mangling() {
        assert!(!GnuDemangler::is_invalid_double_underscore_string(
            "_._9ClassA",
            "ClassA::~ClassA(void)"
        ));
    }

    #[test]
    fn create_default_options_matches_java_defaults() {
        let demangler = GnuDemangler::new();
        let options = demangler.create_default_options();
        assert!(options.apply_signature());
        assert!(options.demangle_only_known_patterns());
    }
}
