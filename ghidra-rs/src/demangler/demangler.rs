use std::sync::Arc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::demangler::demangled_object::DemangledObject;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// NOTE: ALL DEMANGLER CLASSES MUST END IN "Demangler". If not, the ClassSearcher will not find
/// them.
///
/// Mirrors `ghidra.app.util.demangler.Demangler`.
pub trait Demangler: ExtensionPoint {
    /// Mirrors `canDemangle(Program)`.
    fn can_demangle(&self, program: &dyn Program) -> bool;

    /// Attempts to demangle the string of the mangled context and sets the mangled context on
    /// the [`DemangledObject`].
    ///
    /// Mirrors `demangle(MangledContext)`.
    fn demangle(
        &self,
        context: &MangledContext,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException>;

    /// Attempts to demangle the given string using a context
    /// ([`Demangler::create_mangled_context`]) with default options
    /// ([`Demangler::create_default_options`]).
    ///
    /// Mirrors `demangle(String)`. Note: mirrors a quirk in the original, which demangles the
    /// mangled context once to set it on the result (if the result doesn't already carry one),
    /// then demangles it a *second* time and returns that result, discarding the first. This is
    /// preserved here to match Java behavior.
    fn demangle_string(
        &self,
        mangled: &str,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let mangled_context = self.create_mangled_context(mangled, None, None, None);
        let demangled_object = self.demangle(&mangled_context)?;
        if let Some(mut obj) = demangled_object {
            if obj.get_mangled_context().is_none() {
                obj.set_mangled_context(mangled_context.clone());
            }
        }
        self.demangle(&mangled_context)
    }

    /// Attempts to demangle the given string using the given options.
    ///
    /// Mirrors `demangle(String, DemanglerOptions)`.
    #[deprecated(since = "11.3", note = "use `demangle_string` or `demangle` instead")]
    fn demangle_string_with_options(
        &self,
        mangled: &str,
        options: &DemanglerOptions,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let mangled_context =
            self.create_mangled_context(mangled, Some(options.clone()), None, None);
        let demangled_object = self.demangle(&mangled_context)?;
        if let Some(mut obj) = demangled_object {
            if obj.get_mangled_context().is_none() {
                obj.set_mangled_context(mangled_context.clone());
            }
        }
        self.demangle(&mangled_context)
    }

    /// Creates default options for this particular demangler.
    ///
    /// Mirrors `createDefaultOptions()`.
    fn create_default_options(&self) -> DemanglerOptions {
        DemanglerOptions::new()
    }

    /// Creates a mangled context. `options` defaults to [`Demangler::create_default_options`]
    /// when `None`.
    ///
    /// Mirrors `createMangledContext(String, DemanglerOptions, Program, Address)`.
    fn create_mangled_context(
        &self,
        mangled: &str,
        options: Option<DemanglerOptions>,
        program: Option<Arc<dyn Program>>,
        address: Option<Address>,
    ) -> MangledContext {
        let options = options.unwrap_or_else(|| self.create_default_options());
        MangledContext::new(program, options, mangled.to_string(), address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::demangled_object::tests::TestDemangledObject;
    use crate::framework::model::DomainObject;
    use std::sync::Mutex;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }
    }

    /// A demangler that only accepts mangled strings starting with "_Z" (an Itanium C++ mangling
    /// prefix), mirroring the shape of a real `canDemangle`/`demangle` implementor. Counts calls
    /// to `demangle` so tests can observe the original's double-call quirk (see
    /// [`Demangler::demangle_string`]).
    struct StubDemangler {
        demangle_calls: Mutex<u32>,
    }

    impl ExtensionPoint for StubDemangler {}

    impl Demangler for StubDemangler {
        fn can_demangle(&self, _program: &dyn Program) -> bool {
            true
        }

        fn demangle(
            &self,
            context: &MangledContext,
        ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
            *self.demangle_calls.lock().unwrap() += 1;
            if !context.mangled().starts_with("_Z") {
                return Err(DemangledException::from_invalid_mangled_name(true));
            }
            Ok(Some(Box::new(TestDemangledObject::new(context.mangled(), None, "foo"))))
        }
    }

    #[test]
    fn demangle_string_calls_demangle_twice_and_discards_the_first_result() {
        // Mirrors a quirk in the original `Demangler.demangle(String)`: it demangles the mangled
        // context once to set it on that result (if not already set), then demangles it again
        // and returns *that* result, discarding the first. Since each `demangle` call here
        // produces a fresh object, the returned object never observes the mangled context that
        // was set on the first, discarded one.
        let demangler = StubDemangler { demangle_calls: Mutex::new(0) };
        let result = demangler.demangle_string("_Z3fooi").unwrap();
        let obj = result.expect("expected a demangled object");
        assert_eq!(*demangler.demangle_calls.lock().unwrap(), 2);
        assert!(obj.get_mangled_context().is_none());
    }

    #[test]
    fn demangle_string_propagates_error() {
        let demangler = StubDemangler { demangle_calls: Mutex::new(0) };
        match demangler.demangle_string("not-mangled") {
            Err(err) => assert!(err.is_invalid_mangled_name()),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn create_default_options_matches_java_defaults() {
        let demangler = StubDemangler { demangle_calls: Mutex::new(0) };
        let options = demangler.create_default_options();
        assert!(options.apply_signature());
        assert!(options.apply_calling_convention());
    }

    #[test]
    fn create_mangled_context_uses_default_options_when_none_given() {
        let demangler = StubDemangler { demangle_calls: Mutex::new(0) };
        let context = demangler.create_mangled_context("_Z3fooi", None, None, None);
        assert_eq!(context.mangled(), "_Z3fooi");
        assert_eq!(context.options(), &demangler.create_default_options());
        assert!(context.program().is_none());
        assert!(context.address().is_none());
    }

    #[test]
    fn can_demangle_delegates_to_implementor() {
        let demangler = StubDemangler { demangle_calls: Mutex::new(0) };
        assert!(demangler.can_demangle(&MockProgram));
    }
}
