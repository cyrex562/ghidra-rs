//! Port of `ghidra.app.util.demangler.DemangledLabel`.
//!
//! A [`DemangledObject`] that should get represented as a Ghidra label.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_object::{DemangledObject, DemangledObjectBase};
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// A [`DemangledObject`] that should get represented as a Ghidra label.
///
/// Port of `ghidra.app.util.demangler.DemangledLabel`. Java `extends DemangledObject`; this port
/// follows the crate's composition-over-inheritance convention by embedding a
/// [`DemangledObjectBase`] rather than faking struct inheritance.
///
/// This class was previously stood in for as a placeholder in
/// [`crate::demangler::seam_stubs`], needed by
/// [`SwiftDemangler::demangle`](crate::demangler::swift::swift_demangler::SwiftDemangler); that
/// placeholder now re-exports this real port instead.
pub struct DemangledLabel {
    base: DemangledObjectBase,
}

impl DemangledLabel {
    /// Creates a new [`DemangledLabel`].
    ///
    /// Mirrors `DemangledLabel(String mangled, String originalDemangled, String name)`.
    pub fn new(
        mangled: impl Into<String>,
        original_demangled: impl Into<String>,
        name: &str,
    ) -> Self {
        let mut base = DemangledObjectBase::new(mangled, Some(original_demangled.into()));
        base.set_name(Some(name));
        Self { base }
    }
}

impl DemangledObject for DemangledLabel {
    fn base(&self) -> &DemangledObjectBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut DemangledObjectBase {
        &mut self.base
    }

    /// Mirrors the overridden `getSignature(boolean format)`, which ignores `format` and returns
    /// the (safe) name.
    fn get_signature_formatted(&self, _format: bool) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }

    /// Mirrors `applyTo(Program, Address, DemanglerOptions, TaskMonitor)`: applies this object's
    /// name as a (non-primary-forcing... actually primary-forcing) label symbol.
    ///
    /// Java: `Symbol symbol = applyDemangledName(address, true, false, program); return symbol !=
    /// null;` -- `setPrimary` is `true` and `functionNamespacePermitted` is `false`.
    fn apply_to(
        &self,
        program: &mut dyn Program,
        address: &Address,
        _options: &DemanglerOptions,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, DemangledException> {
        let symbol = self
            .base
            .apply_demangled_name(None, address, true, false, program)
            .map_err(DemangledException::from_cause)?;
        Ok(symbol.is_some())
    }
}

impl Demangled for DemangledLabel {
    fn set_mangled_context(&mut self, mangled_context: MangledContext) {
        self.base.mangled_context = Some(mangled_context);
    }

    fn get_mangled_context(&self) -> Option<MangledContext> {
        self.base.mangled_context.clone()
    }

    fn get_mangled_string(&self) -> String {
        self.base.get_mangled_string().to_string()
    }

    fn get_original_demangled(&self) -> String {
        self.base.original_demangled.clone().unwrap_or_default()
    }

    fn get_name(&self) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }

    fn set_name(&mut self, name: &str) {
        self.base.set_name(Some(name));
    }

    fn get_demangled_name(&self) -> String {
        self.base.get_demangled_name().unwrap_or_default().to_string()
    }

    fn get_namespace(&self) -> Option<&dyn Demangled> {
        self.base.get_namespace()
    }

    fn get_namespace_mut(&mut self) -> Option<&mut (dyn Demangled + 'static)> {
        self.base.namespace.as_deref_mut()
    }

    fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
        self.base.set_namespace(namespace);
    }

    fn get_namespace_string(&self) -> String {
        self.base.namespace_string_with(&self.get_namespace_name())
    }

    fn get_namespace_name(&self) -> String {
        self.get_name()
    }

    /// Mirrors `getSignature()`, which delegates to `getSignature(false)`; that override ignores
    /// `format` and returns the name (see [`DemangledObject::get_signature_formatted`] above), so
    /// this is inlined directly rather than reaching across traits.
    fn get_signature(&self) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{
        GLOBAL_NAMESPACE_ID, Namespace, SourceType, Symbol, SymbolTable, SymbolType,
    };
    use crate::util::task::DummyMonitor;
    use std::io;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn new_sets_name_and_demangled_state() {
        let label = DemangledLabel::new("_ZN3fooE", "foo::bar", "foo::bar");
        assert_eq!(label.get_mangled_string(), "_ZN3fooE");
        assert_eq!(label.get_original_demangled(), "foo::bar");
        assert_eq!(label.get_demangled_name(), "foo::bar");
        assert_eq!(label.get_name(), "foo::bar");
        assert!(label.base().demangled_name_successfully());
    }

    #[test]
    fn get_signature_ignores_format_and_returns_name() {
        // Mirrors `getSignature(boolean format)` returning `getName()` regardless of `format`.
        let label = DemangledLabel::new("_Z3foo", "foo", "my label");
        // "my label" has no superfluous signature spaces (no parens/commas/stars) to strip, so
        // `setName` only replaces the remaining space with an underscore.
        assert_eq!(label.get_signature_formatted(true), "my_label");
        assert_eq!(label.get_signature_formatted(false), "my_label");
        assert_eq!(<DemangledLabel as Demangled>::get_signature(&label), "my_label");
    }

    #[test]
    fn set_name_updates_both_demangled_object_and_demangled_views() {
        let mut label = DemangledLabel::new("_Z3foo", "foo", "foo");
        Demangled::set_name(&mut label, "bar baz");
        assert_eq!(label.get_demangled_name(), "bar baz");
        assert_eq!(label.get_name(), "bar_baz");
    }

    // --- A minimal mock `Program`/`SymbolTable`/`Namespace`/`Symbol`, mirroring the pattern
    // used by `symbol_utilities::tests::mock_program_with_symbol_table` -- just enough surface
    // for `apply_demangled_name`/`create_preferred_label_or_function_symbol` to run end to end.

    struct MockSymbol {
        address: Address,
        name: String,
        symbol_type: SymbolType,
        id: i64,
        primary: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            GLOBAL_NAMESPACE_ID
        }
    }

    struct MockSymbolTable {
        symbols: Vec<Arc<dyn Symbol>>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(&mut self, addr: &Address, name: &str, source: SourceType) -> io::Result<Arc<dyn Symbol>> {
            let _ = source;
            let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
                address: addr.clone(),
                name: name.to_string(),
                symbol_type: SymbolType::Label,
                id: self.symbols.len() as i64 + 1,
                primary: true,
            });
            self.symbols.push(symbol.clone());
            Ok(symbol)
        }
        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().find(|s| s.get_id() == id).cloned())
        }
        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().filter(|s| s.get_address() == *addr).cloned().collect())
        }
        fn get_symbols_by_name_namespace(
            &self,
            name: &str,
            _namespace: &dyn Namespace,
        ) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().filter(|s| s.get_name() == name).cloned().collect())
        }
        // Overridden (beyond the required four above) so `apply_demangled_name`'s `set_primary`
        // branch -- which reaches `SymbolTable::find_symbol_by_name_address_namespace` and
        // `SymbolTable::get_primary_symbol` through the private `set_label_primary` helper in
        // `demangled_object.rs` -- has real data to work with, instead of silently no-op'ing on
        // the trait's default `Ok(None)` and making `apply_to` look like it failed.
        fn find_symbol_by_name_address_namespace(
            &self,
            name: &str,
            addr: &Address,
            _namespace: &dyn Namespace,
        ) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().find(|s| s.get_name() == name && s.get_address() == *addr).cloned())
        }
        fn get_primary_symbol(&self, addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().find(|s| s.get_address() == *addr && s.is_primary()).cloned())
        }
        fn set_primary_symbol(&mut self, symbol_id: i64) -> io::Result<bool> {
            Ok(self.symbols.iter().any(|s| s.get_id() == symbol_id))
        }
    }

    struct MockGlobalNamespace(Arc<dyn Symbol>);

    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.0.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            GLOBAL_NAMESPACE_ID
        }
    }

    struct MockProgram {
        global_namespace: Option<Arc<dyn Namespace>>,
        symbol_table: MockSymbolTable,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.global_namespace.clone()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    fn program_with_global_namespace() -> MockProgram {
        let global_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_space().address(0),
            name: "Global".to_string(),
            symbol_type: SymbolType::Global,
            id: 0,
            primary: true,
        });
        MockProgram {
            global_namespace: Some(Arc::new(MockGlobalNamespace(global_symbol))),
            symbol_table: MockSymbolTable { symbols: Vec::new() },
        }
    }

    #[test]
    fn apply_to_creates_a_label_and_reports_it_as_applied() {
        // Java: `Symbol symbol = applyDemangledName(address, true, false, program); return
        // symbol != null;`
        let label = DemangledLabel::new("_Z3foo", "foo", "foo");
        let mut program = program_with_global_namespace();
        let address = ram_space().address(0x1000);

        let applied = label
            .apply_to(&mut program, &address, &DemanglerOptions::new(), &DummyMonitor)
            .expect("applying a successfully-demangled label should not error");
        assert!(applied);

        let symbol_table = program.get_symbol_table().unwrap();
        let symbols = symbol_table.get_symbols(&address).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "foo");
        assert_eq!(symbols[0].get_symbol_type(), SymbolType::Label);
    }

    #[test]
    fn apply_to_propagates_the_underlying_error_as_a_demangled_exception() {
        // With no global namespace and no symbol table available (the bare `Program` defaults),
        // `create_preferred_label_or_function_symbol` fails with an `InvalidInputException`,
        // which `DemangledLabel::apply_to` must surface as a `DemangledException::Cause`.
        struct BareProgram;
        impl crate::framework::model::DomainObject for BareProgram {}
        impl Program for BareProgram {
            fn get_name(&self) -> String {
                "bare".to_string()
            }
            fn get_language_id(&self) -> String {
                "mock_language".to_string()
            }
        }

        let label = DemangledLabel::new("_Z3foo", "foo", "foo");
        let mut program = BareProgram;
        let address = ram_space().address(0x1000);

        let err = label
            .apply_to(&mut program, &address, &DemanglerOptions::new(), &DummyMonitor)
            .expect_err("no symbol table is available on the bare program");
        assert!(
            matches!(err, DemangledException::Cause(_)),
            "expected the InvalidInputException to be wrapped as a Cause, got: {err:?}"
        );
    }
}
