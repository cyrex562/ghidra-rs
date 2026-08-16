//! A demangler for mangled Swift symbols.
//!
//! Port of `ghidra.app.util.demangler.swift.SwiftDemangler`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_object::DemangledObject;
use crate::demangler::demangler::Demangler;
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::demangler::seam_stubs::{
    self, DemangledLabel, DemangledUnknown, MessageLog, SwiftNativeDemangler, SwiftTypeMetadata,
};
use crate::demangler::swift::nodes::swift_node::{self, SwiftNode};
use crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree;
use crate::demangler::swift::swift_demangler_options::SwiftDemanglerOptions;
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::task::DummyMonitor;

/// A demangler for mangled Swift symbols.
///
/// Mirrors `ghidra.app.util.demangler.swift.SwiftDemangler`.
///
/// [`Demangler::demangle`]/[`Demangler::can_demangle`] take `&self`, so the two fields mutated
/// from those methods (`cache`, `native_demangler`) need interior mutability -- the same
/// treatment [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`] gives its
/// own fields. `type_metadata`/`is64bit` are only ever set by [`SwiftDemangler::initialize`]
/// (`&mut self`, called only from the constructors), so they stay plain fields.
pub struct SwiftDemangler {
    cache: RefCell<HashMap<String, Option<Rc<dyn SwiftNode>>>>,
    type_metadata: Option<SwiftTypeMetadata>,
    native_demangler: RefCell<Option<SwiftNativeDemangler>>,
    is64bit: bool,
}

impl SwiftDemangler {
    /// Creates a new [`SwiftDemangler`] that is not associated with any [`Program`]. Call
    /// [`SwiftDemangler::initialize`] to associate it with a program, which will enable access
    /// to the Swift type metadata.
    ///
    /// Mirrors `SwiftDemangler()`.
    pub fn new() -> Self {
        let mut demangler = Self::empty();
        // Mirrors the try/catch around `initialize(null)`: initializing with no program never
        // actually raises, since there is no program to read type metadata from.
        let _ = demangler.initialize(None);
        demangler
    }

    /// Creates a new [`SwiftDemangler`] that is associated with the given [`Program`].
    ///
    /// Mirrors `SwiftDemangler(Program)`.
    ///
    /// # Errors
    /// Returns an error if there was a problem parsing the Swift type metadata.
    pub fn with_program(program: &mut dyn Program) -> std::io::Result<Self> {
        let mut demangler = Self::empty();
        demangler.initialize(Some(program))?;
        Ok(demangler)
    }

    fn empty() -> Self {
        Self {
            cache: RefCell::new(HashMap::new()),
            type_metadata: None,
            native_demangler: RefCell::new(None),
            is64bit: true,
        }
    }

    /// Associates this demangler with the given program (or disassociates it, given `None`),
    /// resetting the demangled-tree cache and native demangler.
    ///
    /// Mirrors `initialize(Program)`.
    ///
    /// # Errors
    /// Returns an error if there was a problem parsing the Swift type metadata. Mirrors the
    /// original's `catch (CancelledException e) { return; }`, which is collapsed onto the single
    /// `std::io::Error` this stub's [`SwiftTypeMetadata::new`] can produce, since the real
    /// metadata parsing (and so the cancellation it could hit) isn't ported yet.
    pub fn initialize(&mut self, program: Option<&mut dyn Program>) -> std::io::Result<()> {
        self.cache = RefCell::new(HashMap::new());
        self.native_demangler = RefCell::new(None);
        if let Some(program) = program {
            program.set_preferred_root_namespace_category_path(seam_stubs::swift_category_path());
            self.type_metadata =
                Some(SwiftTypeMetadata::new(program, &DummyMonitor, &MessageLog::new())?);
            self.is64bit = program.get_default_pointer_size() == 8;
        }
        Ok(())
    }

    /// Gets a new [`Demangled`] by demangling the given mangled string.
    ///
    /// Mirrors `getDemangled(String, SwiftDemanglerOptions)`. `op` mirrors the original's
    /// nullable parameter (`None` mirrors `null`), defaulting to fresh [`SwiftDemanglerOptions`].
    ///
    /// # Errors
    /// Returns a [`DemangledException`] if there was an issue demangling.
    pub fn get_demangled(
        &self,
        mangled: &str,
        op: Option<&SwiftDemanglerOptions>,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        if !self.is_swift_mangled_symbol(mangled) {
            return Ok(None);
        }

        let options = match op {
            Some(op) => op.clone(),
            None => SwiftDemanglerOptions::new(),
        };
        self.set_swift_native_demangler(&options)?;

        let cached = self.cache.borrow().get(mangled).cloned();
        let root = match cached {
            Some(root) => root,
            None => {
                let native_demangler = self.native_demangler.borrow();
                let tree = SwiftDemangledTree::new(
                    native_demangler.as_ref().expect("set_swift_native_demangler just ran"),
                    mangled,
                    self.is64bit,
                )?;
                tree.root()
            }
        };
        self.cache.borrow_mut().insert(mangled.to_string(), root.clone());

        let Some(root) = root else {
            return Ok(None);
        };

        let Some(mut demangled) = root.demangle(self)? else {
            return Ok(None);
        };

        if swift_node::walk_and_test(&*root, &mut |node| node.base().child_was_skipped()) {
            let new_name = format!("{}{}", options.incomplete_prefix(), demangled.get_name());
            demangled.set_name(&new_name);
        }

        Ok(Some(demangled))
    }

    /// Gets the [`SwiftTypeMetadata`], or `None` if it is not available.
    ///
    /// Mirrors `getTypeMetadata()`.
    pub fn get_type_metadata(&self) -> Option<&SwiftTypeMetadata> {
        self.type_metadata.as_ref()
    }

    /// Checks to see whether the given symbol name is a mangled Swift symbol.
    ///
    /// Mirrors `isSwiftMangledSymbol(String)`.
    pub fn is_swift_mangled_symbol(&self, symbol_name: &str) -> bool {
        const PREFIXES: [&str; 5] = ["$S", "$s", "_$S", "_$s", "_T"];
        PREFIXES.iter().any(|prefix| symbol_name.starts_with(prefix))
    }

    /// Gets the [`SwiftDemanglerOptions`] from the given [`DemanglerOptions`].
    ///
    /// Mirrors `getSwiftDemanglerOptions(DemanglerOptions)`. In the original, a `DemanglerOptions`
    /// that is already (dynamically) a `SwiftDemanglerOptions` is cast and returned as-is. In this
    /// port `opt` is always the base type -- it can never actually be a `SwiftDemanglerOptions`
    /// (composition, not inheritance; see that struct's docs) -- so this always synthesizes a
    /// fresh `SwiftDemanglerOptions` around `opt`'s fields instead, and so never fails the way the
    /// original's `throws DemangledException` suggests it might.
    pub fn get_swift_demangler_options(&self, opt: &DemanglerOptions) -> SwiftDemanglerOptions {
        SwiftDemanglerOptions::from_base(opt)
    }

    /// Ensures that this demangler has access to a [`SwiftNativeDemangler`].
    ///
    /// Mirrors the private `setSwiftNativeDemangler(SwiftDemanglerOptions)`.
    ///
    /// # Errors
    /// Returns a [`DemangledException`] if there was a problem getting the
    /// [`SwiftNativeDemangler`].
    fn set_swift_native_demangler(
        &self,
        options: &SwiftDemanglerOptions,
    ) -> Result<(), DemangledException> {
        let mut native_demangler = self.native_demangler.borrow_mut();
        if native_demangler.is_none() {
            let created = SwiftNativeDemangler::new(options.swift_dir().cloned())
                .map_err(DemangledException::from_cause)?;
            *native_demangler = Some(created);
        }
        Ok(())
    }
}

impl Default for SwiftDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionPoint for SwiftDemangler {}

impl Demangler for SwiftDemangler {
    /// Mirrors `canDemangle(Program)`.
    fn can_demangle(&self, program: &dyn Program) -> bool {
        let swift_id = seam_stubs::swift_source_language_id();
        program.get_source_language_ids().iter().any(|id| id == &swift_id)
    }

    /// Mirrors `demangle(MangledContext)`.
    fn demangle(
        &self,
        context: &MangledContext,
    ) -> Result<Option<Box<dyn DemangledObject>>, DemangledException> {
        let options = self.get_swift_demangler_options(context.options());
        let mangled = context.mangled().to_string();
        let Some(demangled) = self.get_demangled(&mangled, Some(&options))? else {
            return Ok(None);
        };

        // `dyn Demangled` upcasts to `dyn Any` (see that trait's docs), letting these stand in
        // for the `instanceof DemangledFunction`/`DemangledLabel`/`DemangledUnknown` checks Java
        // performs directly.
        let any_ref: &dyn std::any::Any = demangled.as_ref();
        let mut demangled_object: Box<dyn DemangledObject> = if any_ref.is::<DemangledLabel>() {
            // Mirrors `instanceof DemangledLabel label`.
            let any: Box<dyn std::any::Any> = demangled;
            any.downcast::<DemangledLabel>().ok().expect("just checked via is::<DemangledLabel>")
        } else if let Some(unknown) = any_ref.downcast_ref::<DemangledUnknown>() {
            // Mirrors the `instanceof DemangledUnknown unknown` branch.
            Box::new(DemangledLabel::new(
                mangled.clone(),
                unknown.get_original_demangled(),
                &format!("{}{}", options.unsupported_prefix(), unknown.get_original_demangled()),
            ))
        } else {
            // Mirrors the final `else return null`. Also covers `instanceof
            // DemangledFunction`: that branch is unreachable here because `DemangledFunction`
            // isn't ported yet (see the dependency-context notes), so no concrete `Demangled`
            // value produced in this crate can ever be one.
            return Ok(None);
        };

        demangled_object.set_mangled_context(context.clone());
        Ok(Some(demangled_object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::sourcelanguage::source_language_id::SourceLanguageIdValue;
    use crate::framework::model::DomainObject;

    struct MockProgram {
        source_language_ids: Vec<SourceLanguageIdValue>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }

        fn get_source_language_ids(&self) -> Vec<SourceLanguageIdValue> {
            self.source_language_ids.clone()
        }
    }

    #[test]
    fn is_swift_mangled_symbol_recognizes_all_known_prefixes() {
        let demangler = SwiftDemangler::new();
        for mangled in ["$S4main3fooV", "$s4main3fooV", "_$S4main3fooV", "_$s4main3fooV", "_T4main"]
        {
            assert!(demangler.is_swift_mangled_symbol(mangled), "expected {mangled} to match");
        }
    }

    #[test]
    fn is_swift_mangled_symbol_rejects_other_prefixes() {
        let demangler = SwiftDemangler::new();
        assert!(!demangler.is_swift_mangled_symbol("_Z3foov"));
        assert!(!demangler.is_swift_mangled_symbol("?foo@@YAXXZ"));
        assert!(!demangler.is_swift_mangled_symbol(""));
    }

    #[test]
    fn get_demangled_returns_none_for_non_swift_symbols() {
        let demangler = SwiftDemangler::new();
        let result = demangler.get_demangled("_Z3foov", None).expect("no error for non-swift input");
        assert!(result.is_none());
    }

    #[test]
    fn get_demangled_propagates_native_demangler_errors_for_swift_symbols() {
        // The native `swift`/`swift-demangle` invocation isn't ported (see
        // `seam_stubs::SwiftNativeDemangler`), so demangling a symbol that *does* look like a
        // Swift mangled name surfaces that as a `DemangledException` rather than silently
        // returning `None`.
        let demangler = SwiftDemangler::new();
        let result = demangler.get_demangled("$s4main3fooV", None);
        assert!(result.is_err());
    }

    #[test]
    fn can_demangle_accepts_a_program_with_the_swift_source_language_id() {
        let demangler = SwiftDemangler::new();
        let program = MockProgram { source_language_ids: vec![seam_stubs::swift_source_language_id()] };
        assert!(demangler.can_demangle(&program));
    }

    #[test]
    fn can_demangle_rejects_a_program_without_the_swift_source_language_id() {
        let demangler = SwiftDemangler::new();
        let program = MockProgram { source_language_ids: vec![] };
        assert!(!demangler.can_demangle(&program));

        let other_language_program = MockProgram {
            source_language_ids: vec![SourceLanguageIdValue::new("Rust").unwrap()],
        };
        assert!(!demangler.can_demangle(&other_language_program));
    }

    #[test]
    fn create_default_options_are_swift_defaults() {
        let demangler = SwiftDemangler::new();
        let options = demangler.create_default_options();
        // Mirrors `new SwiftDemanglerOptions()`'s inherited `DemanglerOptions` defaults.
        assert!(options.apply_signature());
        assert!(options.apply_calling_convention());
    }

    #[test]
    fn get_swift_demangler_options_preserves_base_fields() {
        let demangler = SwiftDemangler::new();
        let mut base = DemanglerOptions::new();
        base.set_apply_signature(false);

        let swift_options = demangler.get_swift_demangler_options(&base);
        assert!(!swift_options.apply_signature());
    }

    #[test]
    fn demangle_returns_none_for_non_swift_symbols() {
        let demangler = SwiftDemangler::new();
        let context = demangler.create_mangled_context("_Z3foov", None, None, None);
        let result = demangler.demangle(&context).expect("no error for non-swift input");
        assert!(result.is_none());
    }
}
