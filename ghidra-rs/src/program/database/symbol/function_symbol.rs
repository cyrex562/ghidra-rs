use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Function;
use crate::program::model::symbol::{
    DefaultSymbolUtilities, Namespace, Reference, SetParentNamespaceError, Symbol,
    SourceType, SymbolType, SymbolUtilities, ThunkReference,
};
use crate::program::util::ProgramLocation;
use crate::util::task::TaskMonitor;

/// Symbol class for functions.
///
/// Port of `ghidra.program.database.symbol.FunctionSymbol` as a trait (cycle cut-point): the Java
/// class extends `MemorySymbol` (itself a `SymbolDB` subclass, still unported) and holds a
/// `FunctionManagerDB` field obtained from the owning `SymbolManager`. Those construction-time
/// wirings back into the symbol/function manager pair are what make this class a cycle
/// cut-point, so this port keeps only its overridden `Symbol`/`MemorySymbol` contract as an
/// object-safe trait extending [`Symbol`] directly (mirroring the
/// [`ClassSymbol`](crate::program::database::symbol::ClassSymbol) and
/// [`LibraryDb`](crate::program::database::symbol::LibraryDb) convention), rather than modeling
/// the `MemorySymbol`/`SymbolDB` superclass chain.
///
/// Behavior that in Java comes from calling `super.X()` (i.e. `MemorySymbol`/`SymbolDB`'s own
/// implementation) is modeled as required `base_*` methods a concrete implementor supplies
/// directly, rather than as a placeholder supertrait: [`base_reference_count`](Self::base_reference_count),
/// [`base_has_references`](Self::base_has_references), [`base_references`](Self::base_references).
/// Thunk-relationship lookups (`functionMgr.getThunkedFunctionId`/`getThunkFunctionIds` resolved
/// via `symbolMgr.getSymbol`) are likewise modeled as required accessors:
/// [`get_thunked_symbol`](Self::get_thunked_symbol) (the function this one thunks, if any) and
/// [`thunk_symbols`](Self::thunk_symbols) (the symbols of functions that thunk this one).
pub trait FunctionSymbol: Symbol {
    /// Stands in for `FunctionSymbol.getSymbolType()`, which always returns `SymbolType.FUNCTION`.
    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Function
    }

    /// Stands in for `FunctionSymbol.isThunk()`: `true` if this function symbol thunks another
    /// function. Defaults to whether [`get_thunked_symbol`](Self::get_thunked_symbol) resolves to
    /// a symbol, mirroring the Java method's underlying `functionMgr.isThunk(key)` (true iff the
    /// thunked function id is `>= 0`, the same condition `getThunkedSymbol()` checks).
    fn is_thunk(&self) -> bool {
        self.get_thunked_symbol().is_some()
    }

    /// Stands in for `FunctionSymbol.setNameAndNamespace(String, Namespace, SourceType)`. The
    /// real method additionally notifies the function manager of a namespace change and requires
    /// write-lock/database access not modeled here; left required for the concrete implementor.
    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: Arc<dyn Namespace>,
        source: SourceType,
    ) -> Result<(), SetParentNamespaceError>;

    /// Stands in for `FunctionSymbol.delete()`. Returns `true` if the function (and this symbol)
    /// were actually removed.
    fn delete(&mut self) -> bool;

    /// Stands in for `FunctionSymbol.getObject()`: the `Function` this symbol represents.
    fn get_object(&self) -> Option<Arc<dyn Function>>;

    /// Stands in for `FunctionSymbol.isPrimary()`, which always returns `true`.
    fn is_primary(&self) -> bool {
        true
    }

    /// Stands in for `FunctionSymbol.getProgramLocation()`.
    fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>>;

    /// Stands in for `FunctionSymbol.isValidParent(Namespace)`. The real method combines
    /// `MemorySymbol.isValidParent(Namespace)` with `SymbolType.FUNCTION.isValidParent(Program,
    /// Namespace, Address, boolean)`, both of which depend on program/database state not
    /// available through this trait; left as a required method for the concrete implementation.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;

    /// Accessor standing in for `FunctionSymbol.getThunkedSymbol()`: the symbol of the function
    /// this one thunks (i.e. `functionMgr.getThunkedFunctionId(key)` resolved via
    /// `symbolMgr.getSymbol`), or `None` if this is not a thunk.
    fn get_thunked_symbol(&self) -> Option<Arc<dyn Symbol>>;

    /// Accessor standing in for resolving `functionMgr.getThunkFunctionIds(key)` (the keys of
    /// thunk functions that reference this one) into their symbols via `symbolMgr.getSymbol`.
    /// Returns an empty vec if none, collapsing Java's `null` return.
    fn thunk_symbols(&self) -> Vec<Arc<dyn Symbol>>;

    /// Accessor standing in for `MemorySymbol.getExternalProgramAddress()`, used by
    /// [`do_get_name`](Self::do_get_name)'s external-symbol branch. Defaults to `None`, matching
    /// non-external symbols (`is_external()` false).
    fn external_program_address(&self) -> Option<Address> {
        None
    }

    /// Stands in for `FunctionSymbol.doGetName()`. Only used when this symbol's source is
    /// `SourceType.DEFAULT`; otherwise the concrete implementor's own stored name applies.
    ///
    /// Simplification: the Java method additionally checks whether the thunked symbol is *itself*
    /// a default, non-thunk `FunctionSymbol` (via an `instanceof FunctionSymbol` downcast) before
    /// prepending `"thunk_"`; that downcast isn't expressible generically against `Arc<dyn
    /// Symbol>` here, so this default always prepends `"thunk_"` when thunking a default-named
    /// symbol.
    fn do_get_name(&self) -> String {
        if self.get_source() != SourceType::Default {
            return self.get_name().to_string();
        }
        if self.is_external() {
            if let Some(addr) = self.external_program_address() {
                return DefaultSymbolUtilities.get_default_external_function_name(&addr);
            }
        }
        if let Some(thunked) = self.get_thunked_symbol() {
            let thunk_name = thunked.get_name().to_string();
            if thunked.get_source() == SourceType::Default {
                return format!("thunk_{thunk_name}");
            }
            return thunk_name;
        }
        DefaultSymbolUtilities.get_default_function_name(&self.get_address())
    }

    /// Stands in for `FunctionSymbol.doGetParentNamespace()`. When this is a default-named thunk,
    /// returns the thunked function's parent namespace; otherwise falls back to this symbol's own
    /// [`Symbol::get_parent_namespace`] (standing in for `super.doGetParentNamespace()`).
    fn do_get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        if self.get_source() == SourceType::Default {
            if let Some(thunked) = self.get_thunked_symbol() {
                return thunked.get_parent_namespace();
            }
        }
        self.get_parent_namespace()
    }

    /// Stands in for `FunctionSymbol.validateNameSource(String, SourceType)`. The real method
    /// depends on the owning program's `AddressFactory` (for `isReservedDynamicLabelName`) and
    /// dynamic-name generation not modeled here; left as a required method for the concrete
    /// implementation.
    fn validate_name_source(&self, new_name: Option<&str>, source: SourceType) -> SourceType;

    /// Stands in for `FunctionSymbol.getSymbolsDynamicallyRenamedByMyRename()`: the symbols of
    /// thunk functions that reference this one and are themselves default-named (and so would be
    /// dynamically renamed if this symbol's name changes).
    fn get_symbols_dynamically_renamed_by_my_rename(&self) -> Vec<Arc<dyn Symbol>> {
        self.thunk_symbols()
            .into_iter()
            .filter(|s| s.get_source() == SourceType::Default)
            .collect()
    }

    /// Accessor standing in for `super.getReferenceCount()` (`MemorySymbol`/`SymbolDB`'s own
    /// reference-counting logic), used by [`get_reference_count`](Self::get_reference_count).
    fn base_reference_count(&self) -> i32;

    /// Accessor standing in for `super.hasReferences()`, used by
    /// [`has_references`](Self::has_references).
    fn base_has_references(&self) -> bool;

    /// Accessor standing in for `super.getReferences(TaskMonitor)`, used by
    /// [`get_references`](Self::get_references).
    fn base_references(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Reference>>;

    /// Stands in for `FunctionSymbol.getReferences(TaskMonitor)`: the base references plus one
    /// synthetic [`ThunkReference`] per thunk function referencing this one.
    fn get_references(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Reference>> {
        let mut refs = self.base_references(monitor);
        if monitor.is_cancelled() {
            return refs;
        }
        for thunk in self.thunk_symbols() {
            if monitor.is_cancelled() {
                return refs;
            }
            refs.push(Arc::new(ThunkReference::new(
                thunk.get_address(),
                self.get_address(),
            )));
        }
        refs
    }

    /// Stands in for `FunctionSymbol.getReferenceCount()`: the base count plus the number of
    /// thunk functions referencing this one.
    fn get_reference_count(&self) -> i32 {
        self.base_reference_count() + self.thunk_symbols().len() as i32
    }

    /// Stands in for `FunctionSymbol.hasReferences()`.
    fn has_references(&self) -> bool {
        self.base_has_references() || !self.thunk_symbols().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    struct MockSymbol {
        name: String,
        address: Address,
        source: SourceType,
        external: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_external(&self) -> bool {
            self.external
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    struct MockNamespace {
        symbol: Arc<dyn Symbol>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            self.symbol.get_id()
        }
    }

    struct MockFunctionSymbol {
        symbol: MockSymbol,
        thunked_symbol: Option<Arc<dyn Symbol>>,
        thunk_symbols: Vec<Arc<dyn Symbol>>,
        base_reference_count: i32,
        base_has_references: bool,
        base_references: Vec<Arc<dyn Reference>>,
    }

    impl Symbol for MockFunctionSymbol {
        fn get_address(&self) -> Address {
            self.symbol.get_address()
        }
        fn get_name(&self) -> &str {
            self.symbol.get_name()
        }
        fn get_symbol_type(&self) -> SymbolType {
            FunctionSymbol::get_symbol_type(self)
        }
        fn get_source(&self) -> SourceType {
            self.symbol.get_source()
        }
        fn is_primary(&self) -> bool {
            FunctionSymbol::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            self.symbol.get_id()
        }
        fn get_parent_id(&self) -> i64 {
            self.symbol.get_parent_id()
        }
        fn is_external(&self) -> bool {
            self.symbol.is_external()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.symbol.get_parent_namespace()
        }
    }

    impl FunctionSymbol for MockFunctionSymbol {
        fn set_name_and_namespace(
            &mut self,
            new_name: &str,
            _new_namespace: Arc<dyn Namespace>,
            _source: SourceType,
        ) -> Result<(), SetParentNamespaceError> {
            self.symbol.name = new_name.to_string();
            Ok(())
        }

        fn delete(&mut self) -> bool {
            true
        }

        fn get_object(&self) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            None
        }

        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }

        fn get_thunked_symbol(&self) -> Option<Arc<dyn Symbol>> {
            self.thunked_symbol.clone()
        }

        fn thunk_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            self.thunk_symbols.clone()
        }

        fn validate_name_source(&self, new_name: Option<&str>, source: SourceType) -> SourceType {
            match new_name {
                None => SourceType::Default,
                Some(name) if name.is_empty() => SourceType::Default,
                _ => source,
            }
        }

        fn base_reference_count(&self) -> i32 {
            self.base_reference_count
        }

        fn base_has_references(&self) -> bool {
            self.base_has_references
        }

        fn base_references(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Reference>> {
            self.base_references.clone()
        }
    }

    fn plain_function_symbol(name: &str, source: SourceType) -> MockFunctionSymbol {
        MockFunctionSymbol {
            symbol: MockSymbol {
                name: name.to_string(),
                address: test_address(0x1000),
                source,
                external: false,
                parent: None,
            },
            thunked_symbol: None,
            thunk_symbols: Vec::new(),
            base_reference_count: 0,
            base_has_references: false,
            base_references: Vec::new(),
        }
    }

    #[test]
    fn defaults_match_java_function_symbol() {
        let sym = plain_function_symbol("actual_function", SourceType::UserDefined);
        assert_eq!(FunctionSymbol::get_symbol_type(&sym), SymbolType::Function);
        assert!(FunctionSymbol::is_primary(&sym));
        assert!(!FunctionSymbol::is_thunk(&sym));
        assert_eq!(sym.do_get_name(), "actual_function");
    }

    #[test]
    fn thunk_naming_prepends_thunk_prefix_for_default_named_target() {
        let thunked: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "real_func".to_string(),
            address: test_address(0x2000),
            source: SourceType::Default,
            external: false,
            parent: None,
        });
        let mut sym = plain_function_symbol("ignored_when_default", SourceType::Default);
        sym.thunked_symbol = Some(thunked);

        assert!(FunctionSymbol::is_thunk(&sym));
        assert_eq!(sym.do_get_name(), "thunk_real_func");
    }

    #[test]
    fn thunk_naming_does_not_prepend_prefix_for_named_target() {
        let thunked: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "named_func".to_string(),
            address: test_address(0x2000),
            source: SourceType::UserDefined,
            external: false,
            parent: None,
        });
        let mut sym = plain_function_symbol("ignored_when_default", SourceType::Default);
        sym.thunked_symbol = Some(thunked);

        assert_eq!(sym.do_get_name(), "named_func");
    }

    #[test]
    fn do_get_name_falls_back_to_dynamic_default_name_when_not_a_thunk() {
        let sym = plain_function_symbol("ignored_when_default", SourceType::Default);
        assert_eq!(
            sym.do_get_name(),
            DefaultSymbolUtilities.get_default_function_name(&test_address(0x1000))
        );
    }

    #[test]
    fn do_get_parent_namespace_defers_to_thunked_symbol_when_default() {
        let grandparent_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "Lib".to_string(),
            address: test_address(0x3000),
            source: SourceType::UserDefined,
            external: false,
            parent: None,
        });
        let thunked_parent: Arc<dyn Namespace> = Arc::new(MockNamespace {
            symbol: grandparent_symbol,
        });
        let thunked: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "real_func".to_string(),
            address: test_address(0x2000),
            source: SourceType::UserDefined,
            external: false,
            parent: Some(thunked_parent.clone()),
        });
        let mut sym = plain_function_symbol("ignored", SourceType::Default);
        sym.thunked_symbol = Some(thunked);

        let parent = sym.do_get_parent_namespace().expect("expected a namespace");
        assert_eq!(parent.get_id(), thunked_parent.get_id());
    }

    #[test]
    fn references_and_counts_include_synthetic_thunk_references() {
        let thunk_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "thunk_func".to_string(),
            address: test_address(0x4000),
            source: SourceType::Default,
            external: false,
            parent: None,
        });
        let mut sym = plain_function_symbol("real_func", SourceType::UserDefined);
        sym.thunk_symbols = vec![thunk_symbol];
        sym.base_reference_count = 2;
        sym.base_has_references = true;

        assert_eq!(FunctionSymbol::get_reference_count(&sym), 3);
        assert!(FunctionSymbol::has_references(&sym));

        let monitor = DummyMonitor;
        let refs = FunctionSymbol::get_references(&sym, &monitor);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from_address(), test_address(0x4000));
        assert_eq!(refs[0].to_address(), test_address(0x1000));

        let renamed = sym.get_symbols_dynamically_renamed_by_my_rename();
        assert_eq!(renamed.len(), 1);
        assert_eq!(renamed[0].get_name(), "thunk_func");
    }

    #[test]
    fn no_references_when_no_thunks_and_base_empty() {
        let sym = plain_function_symbol("real_func", SourceType::UserDefined);
        assert_eq!(FunctionSymbol::get_reference_count(&sym), 0);
        assert!(!FunctionSymbol::has_references(&sym));
        assert!(sym.get_symbols_dynamically_renamed_by_my_rename().is_empty());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut sym: Box<dyn FunctionSymbol> = Box::new(plain_function_symbol(
            "obj_safe_func",
            SourceType::UserDefined,
        ));

        assert_eq!(sym.get_name(), "obj_safe_func");
        assert!(sym.delete());
        sym.set_name_and_namespace(
            "renamed_func",
            Arc::new(MockNamespace {
                symbol: Arc::new(MockSymbol {
                    name: "Global".to_string(),
                    address: test_address(0),
                    source: SourceType::Default,
                    external: false,
                    parent: None,
                }),
            }),
            SourceType::UserDefined,
        )
        .unwrap();
        assert_eq!(sym.get_name(), "renamed_func");
        assert_eq!(
            sym.validate_name_source(Some(""), SourceType::UserDefined),
            SourceType::Default
        );
        assert_eq!(
            sym.validate_name_source(Some("valid"), SourceType::UserDefined),
            SourceType::UserDefined
        );
    }
}
