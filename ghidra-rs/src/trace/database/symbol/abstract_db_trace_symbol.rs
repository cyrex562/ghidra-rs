use thiserror::Error;

use crate::program::model::address::AddressSet;
use crate::program::model::symbol::namespace::SetParentNamespaceError;
use crate::program::model::symbol::{Namespace, SourceType, Symbol};
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::seam_stubs::{DBTraceOverlaySpaceAdapter, DBTraceProgramView};
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced by [`AbstractDBTraceSymbol::set_name`].
///
/// Combines the two checked exceptions declared on the Java method
/// `AbstractDBTraceSymbol.setName(String, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetSymbolNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// The database-backed base class for all trace symbols.
///
/// Port of `ghidra.trace.database.symbol.AbstractDBTraceSymbol` as a trait.
///
/// It was selected as a dependency-cycle cut-point: [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
/// extends it. This promotes the minimal placeholder that previously lived in
/// `crate::trace::seam_stubs` to the real port.
///
/// The Java class `extends DBAnnotatedObject implements TraceSymbol, DecodesAddresses`.
/// `DBAnnotatedObject` (low-level DB-record storage: fresh/refresh/update/table access) is
/// intentionally **not** modeled as a supertrait here: no current consumer of this cut-point
/// needs DB-record mechanics through this trait, and requiring it would force every implementor
/// (including test mocks) to also implement `DBAnnotatedObject`'s much larger, storage-specific
/// surface. Implementors that back this trait with a real DB record provide that separately.
/// [`TraceSymbol`] (which itself requires [`Symbol`]) is modeled as a supertrait, matching the
/// `implements TraceSymbol` clause. `DecodesAddresses` is a one-method interface
/// (`getOverlaySpaceAdapter()`); rather than introduce a separate marker trait for it, its single
/// method is folded directly into this trait as [`AbstractDBTraceSymbol::get_overlay_space_adapter`].
///
/// Many of the Java class's overrides restate behavior already declared on [`Symbol`]/[`TraceSymbol`]
/// and are therefore not redeclared here -- implementors provide them directly in their
/// `impl Symbol for X` / `impl TraceSymbol for X` blocks, per the Java overrides:
/// - `getID()` overrides [`Symbol::get_id`]: returns the global namespace ID when [`isGlobal`](AbstractDBTraceSymbol::is_global)
///   is true, else a packed `(symbolType, key)` ID.
/// - `getAddress()` overrides [`Symbol::get_address`]: defaults to a "no address" sentinel
///   (`SpecialAddress.NO_ADDRESS` in Java, not yet ported); label/variable symbols override this
///   with a real address.
/// - `getSource()` overrides [`Symbol::get_source`]: extracted from the packed `flags` byte, after
///   asserting the symbol is not global.
/// - `isExternal()` overrides [`Symbol::is_external`]: always `false`, which already matches that
///   trait's default.
/// - `isDynamic()` overrides the abstract `Symbol.isDynamic()`, always `false`, which already
///   matches [`Symbol::is_dynamic`]'s default.
/// - `isPinned()`/`setPinned(boolean)` override the abstract [`TraceSymbol::is_pinned`]/
///   [`TraceSymbol::set_pinned`]: `isPinned()` always returns `false` (traces don't support moving
///   memory) and `setPinned` is a no-op.
/// - `getThread()` overrides the abstract [`TraceSymbol::get_thread`]: always `None`.
/// - `getParentNamespace()`/`getParentSymbol()` both return the `parent` field, matching
///   [`TraceSymbol::get_parent_trace_namespace`] and its default delegation for
///   [`TraceSymbol::get_parent_trace_symbol`].
/// - `getReferenceCollection()` covariantly narrows [`TraceSymbol::get_reference_collection`]'s
///   element type from `TraceReference` to `DBTraceReference`; no new method is needed since Rust
///   trait objects already carry the concrete behavior behind the same method name.
///
/// [`AbstractDBTraceSymbol::get_path`] mirrors the abstract `Symbol.getPath()`, which
/// [`TraceNamespaceSymbol`](crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol)
/// also re-declares (as `TraceNamespaceSymbol::get_path`) purely to restate it -- so
/// [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
/// implementors end up providing both, the same way they already provide both
/// [`Namespace::is_global`](crate::program::model::symbol::Namespace::is_global) and
/// [`AbstractDBTraceSymbol::is_global`] side by side (disambiguating call sites with qualified
/// syntax where needed).
pub trait AbstractDBTraceSymbol: TraceSymbol {
    /// Mirrors `getOverlaySpaceAdapter()`, the sole method of the `DecodesAddresses` interface
    /// this class implements. The Java implementation returns `manager.overlayAdapter`.
    fn get_overlay_space_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter>;

    /// Mirrors `getLifespan()` (documented `// Internal` in Java): the union of the lifespans of
    /// every [`TraceAddressSnapRange`](crate::trace::model::trace_address_snap_range::TraceAddressSnapRange)
    /// this symbol occupies, or `null` if it occupies none. No default is provided: computing it
    /// requires iterating the owning manager's per-space ID index, which this trait does not
    /// expose.
    fn get_lifespan(&self) -> Lifespan;

    /// Mirrors `getAddressSet()` (documented `// Internal` in Java): the union of the address
    /// ranges this symbol occupies. No default is provided for the same reason as
    /// [`AbstractDBTraceSymbol::get_lifespan`].
    fn get_address_set(&self) -> AddressSet;

    /// Mirrors the abstract `Symbol.getPath()`: the full path name for this symbol as an ordered
    /// list of strings ending with the symbol's own name. The Java implementation walks the
    /// `parent` field (via `parent.doGetPath(list)`) up to the manager's global namespace while
    /// holding the manager's read lock; that same-class field walk is not expressible generically
    /// in terms of this trait's other methods (see the trait-level documentation), so no default
    /// is provided.
    fn get_path(&self) -> Vec<String>;

    /// Mirrors `getName(boolean includeNamespace)`: `getName()` unqualified when
    /// `include_namespace` is `false`, else the `"::"`-joined [`AbstractDBTraceSymbol::get_path`].
    fn get_name_with_namespace(&self, include_namespace: bool) -> String {
        if !include_namespace {
            return Symbol::get_name(self).to_string();
        }
        self.get_path().join("::")
    }

    /// Mirrors the abstract `Symbol.getProgram()`, overridden here to return
    /// `manager.trace.getProgramView()`. No default is provided: this trait has no way to reach
    /// the owning manager/trace.
    fn get_program(&self) -> Box<dyn DBTraceProgramView>;

    /// Mirrors the overridden `Symbol.getProgramLocation()` (Java default: `new
    /// ProgramLocation(getProgram(), getAddress())`). No default is provided here since building a
    /// [`ProgramLocation`] requires an `Arc<dyn Program>`, and [`AbstractDBTraceSymbol::get_program`]
    /// returns a `DBTraceProgramView` rather than a `Program` directly; implementors construct the
    /// location from their own `Program`-compatible view plus [`Symbol::get_address`].
    fn get_program_location(&self) -> Box<dyn ProgramLocation>;

    /// Mirrors the abstract `Symbol.isDescendant(Namespace)`: walks the `parent` field chain
    /// starting at `self`, returning `true` if `namespace` is (by reference identity, in Java) one
    /// of `self` or an ancestor of `self`. No default is provided: the same-class field walk is
    /// not expressible generically (see the trait-level documentation); implementors comparing by
    /// [`Symbol::get_id`] equality reproduce the same effective behavior.
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool;

    /// Mirrors the abstract `Symbol.isValidParent(Namespace)`: checks that `ns` belongs to the
    /// same manager (`manager.checkIsMine(ns)`) and that this symbol's `SymbolType` allows that
    /// namespace kind as a parent (via the manager's `MySymbolTypes` table). No default is
    /// provided since neither the owning manager nor `MySymbolTypes` is reachable from this trait.
    fn is_valid_parent(&self, ns: &dyn Namespace) -> bool;

    /// Mirrors the overridden `Symbol.getReferenceCount()` (Java default in `Symbol` uses
    /// `ReferenceManager.getReferenceCountTo`; this class instead overrides it to just
    /// `getReferenceCollection().size()`).
    fn get_reference_count(&self) -> usize {
        self.get_reference_collection().len()
    }

    /// Mirrors the overridden `Symbol.hasReferences()` (Java default in `Symbol` also checks
    /// `ReferenceManager`; this class instead overrides it to `!getReferenceCollection().isEmpty()`).
    fn has_references(&self) -> bool {
        !self.get_reference_collection().is_empty()
    }

    /// Mirrors `setName(String, SourceType)`. The Java implementation asserts the symbol is not
    /// global, validates the name/source pair, then -- holding the manager's write lock -- updates
    /// the name and/or source and fires the corresponding trace change events. No default is
    /// provided: none of that locking/eventing machinery is reachable from this trait.
    fn set_name(&mut self, new_name: &str, new_source: SourceType) -> Result<(), SetSymbolNameError>;

    /// Mirrors `setNamespace(Namespace)`. Superset of the placeholder trait's original signature
    /// (kept unchanged so existing implementors/callers still compile); see
    /// [`AbstractDBTraceSymbol::set_name`] for why no default is provided.
    fn set_namespace(&self, new_namespace: &dyn Namespace) -> std::io::Result<()>;

    /// Mirrors `setNameAndNamespace(String, Namespace, SourceType)`, which combines
    /// [`AbstractDBTraceSymbol::set_name`] and [`AbstractDBTraceSymbol::set_namespace`]'s checked
    /// exceptions (`DuplicateNameException`, `InvalidInputException`, `CircularDependencyException`)
    /// into one call under a single write-lock hold; hence [`SetParentNamespaceError`], which
    /// already models exactly that combination for [`Namespace::set_parent_namespace`]. No default
    /// is provided for the same reason as [`AbstractDBTraceSymbol::set_name`].
    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: &dyn Namespace,
        new_source: SourceType,
    ) -> Result<(), SetParentNamespaceError>;

    /// Mirrors `setSource(SourceType)`. Unlike [`AbstractDBTraceSymbol::set_name`], the Java method
    /// declares no checked exceptions: name/source validation failures are converted into an
    /// `AssertionError` internally (since the name itself is unchanged). No default is provided
    /// for the same locking/eventing reasons as [`AbstractDBTraceSymbol::set_name`].
    fn set_source(&mut self, new_source: SourceType);

    /// Mirrors `delete()`. Kept as an abstract method with no default, matching the placeholder
    /// trait's original signature: [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
    /// (and other subclasses) override it directly rather than through a `doDelete()` default
    /// provided here.
    fn delete(&self) -> bool;

    /// Mirrors `isGlobal()` (`parentID == -1`). Superset of the placeholder trait's original
    /// signature (kept unchanged so existing implementors/callers still compile). Note this
    /// duplicates [`Namespace::is_global`] by name on types (like
    /// [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol))
    /// that implement both traits; disambiguate with qualified syntax
    /// (`AbstractDBTraceSymbol::is_global(x)`) as already done at existing call sites.
    fn is_global(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{NamespaceType, SymbolType};
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::thread::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }



    struct MockOverlaySpaceAdapter;
    impl DBTraceOverlaySpaceAdapter for MockOverlaySpaceAdapter {}

    struct MockProgramView;
    impl DBTraceProgramView for MockProgramView {}

    /// A label-like symbol (not a namespace) exercising this trait directly, standing in for a
    /// concrete class like `DBTraceLabelSymbol`.
    struct MockLabelSymbol {
        id: i64,
        parent_id: i64,
        name: String,
        source: SourceType,
    }

    impl Symbol for MockLabelSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            self.parent_id
        }
    }

    impl TraceSymbol for MockLabelSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(
            &self,
        ) -> Option<Arc<dyn crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol>>
        {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }

    impl AbstractDBTraceSymbol for MockLabelSymbol {
        fn get_overlay_space_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter> {
            Box::new(MockOverlaySpaceAdapter)
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::from_address(self.get_address())
        }
        fn get_path(&self) -> Vec<String> {
            vec![self.name.clone()]
        }
        fn get_program(&self) -> Box<dyn DBTraceProgramView> {
            Box::new(MockProgramView)
        }
        fn get_program_location(&self) -> Box<dyn ProgramLocation> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
            namespace.get_id() == self.parent_id
        }
        fn is_valid_parent(&self, _ns: &dyn Namespace) -> bool {
            true
        }
        fn set_name(
            &mut self,
            new_name: &str,
            new_source: SourceType,
        ) -> Result<(), SetSymbolNameError> {
            self.name = new_name.to_string();
            self.source = new_source;
            Ok(())
        }
        fn set_namespace(&self, _new_namespace: &dyn Namespace) -> std::io::Result<()> {
            Ok(())
        }
        fn set_name_and_namespace(
            &mut self,
            new_name: &str,
            _new_namespace: &dyn Namespace,
            new_source: SourceType,
        ) -> Result<(), SetParentNamespaceError> {
            self.name = new_name.to_string();
            self.source = new_source;
            Ok(())
        }
        fn set_source(&mut self, new_source: SourceType) {
            self.source = new_source;
        }
        fn delete(&self) -> bool {
            true
        }
        fn is_global(&self) -> bool {
            self.parent_id == -1
        }
    }

    struct MockGlobalNamespace {
        id: i64,
    }

    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled")
        }
        fn get_name(&self) -> String {
            "Global".to_string()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }
        fn is_global(&self) -> bool {
            true
        }
    }

    fn make_label() -> MockLabelSymbol {
        MockLabelSymbol {
            id: 42,
            parent_id: 1,
            name: "foo".to_string(),
            source: SourceType::Default,
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let boxed: Box<dyn AbstractDBTraceSymbol> = Box::new(make_label());
        assert!(!boxed.is_global());
        assert_eq!(boxed.get_path(), vec!["foo".to_string()]);
        assert_eq!(boxed.get_reference_count(), 0);
        assert!(!boxed.has_references());
        assert!(!Symbol::is_dynamic(boxed.as_ref()));
    }

    #[test]
    fn get_name_with_namespace_joins_the_path_only_when_requested() {
        let sym = make_label();
        assert_eq!(sym.get_name_with_namespace(false), "foo");
        assert_eq!(sym.get_name_with_namespace(true), "foo");

        // A symbol nested under a namespace would report a multi-element path; simulate that
        // directly since `MockLabelSymbol::get_path` above is a stand-in for the real walk.
        struct NestedLabel(MockLabelSymbol);
        impl Symbol for NestedLabel {
            fn get_address(&self) -> Address {
                self.0.get_address()
            }
            fn get_name(&self) -> &str {
                Symbol::get_name(&self.0)
            }
            fn get_symbol_type(&self) -> SymbolType {
                self.0.get_symbol_type()
            }
            fn get_source(&self) -> SourceType {
                self.0.get_source()
            }
            fn is_primary(&self) -> bool {
                true
            }
            fn get_id(&self) -> i64 {
                self.0.get_id()
            }
            fn get_parent_id(&self) -> i64 {
                self.0.get_parent_id()
            }
        }
        impl TraceSymbol for NestedLabel {
            fn get_trace(&self) -> Box<dyn Trace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
                None
            }
            fn get_parent_trace_namespace(
                &self,
            ) -> Option<
                Arc<dyn crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol>,
            > {
                None
            }
            fn get_references_with_monitor(
                &self,
                _monitor: &dyn TaskMonitor,
            ) -> Vec<Arc<dyn TraceReference>> {
                Vec::new()
            }
            fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
                Vec::new()
            }
            fn set_pinned(&mut self, _pinned: bool) {}
            fn is_pinned(&self) -> bool {
                false
            }
        }
        impl AbstractDBTraceSymbol for NestedLabel {
            fn get_overlay_space_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter> {
                Box::new(MockOverlaySpaceAdapter)
            }
            fn get_lifespan(&self) -> Lifespan {
                Lifespan::span(0, 10)
            }
            fn get_address_set(&self) -> AddressSet {
                AddressSet::new()
            }
            fn get_path(&self) -> Vec<String> {
                vec!["parent".to_string(), "foo".to_string()]
            }
            fn get_program(&self) -> Box<dyn DBTraceProgramView> {
                Box::new(MockProgramView)
            }
            fn get_program_location(&self) -> Box<dyn ProgramLocation> {
                unimplemented!("not exercised by this smoke test")
            }
            fn is_descendant(&self, _namespace: &dyn Namespace) -> bool {
                false
            }
            fn is_valid_parent(&self, _ns: &dyn Namespace) -> bool {
                true
            }
            fn set_name(
                &mut self,
                _new_name: &str,
                _new_source: SourceType,
            ) -> Result<(), SetSymbolNameError> {
                Ok(())
            }
            fn set_namespace(&self, _new_namespace: &dyn Namespace) -> std::io::Result<()> {
                Ok(())
            }
            fn set_name_and_namespace(
                &mut self,
                _new_name: &str,
                _new_namespace: &dyn Namespace,
                _new_source: SourceType,
            ) -> Result<(), SetParentNamespaceError> {
                Ok(())
            }
            fn set_source(&mut self, _new_source: SourceType) {}
            fn delete(&self) -> bool {
                true
            }
            fn is_global(&self) -> bool {
                false
            }
        }

        let nested = NestedLabel(sym);
        assert_eq!(nested.get_name_with_namespace(false), "foo");
        assert_eq!(nested.get_name_with_namespace(true), "parent::foo");
    }

    #[test]
    fn is_descendant_matches_parent_id() {
        let sym = make_label();
        let parent = MockGlobalNamespace { id: 1 };
        let unrelated = MockGlobalNamespace { id: 99 };
        assert!(sym.is_descendant(&parent));
        assert!(!sym.is_descendant(&unrelated));
    }

    #[test]
    fn set_name_updates_name_and_source() {
        let mut sym = make_label();
        assert_eq!(Symbol::get_name(&sym), "foo");
        AbstractDBTraceSymbol::set_name(&mut sym, "bar", SourceType::UserDefined).unwrap();
        assert_eq!(Symbol::get_name(&sym), "bar");
        assert_eq!(Symbol::get_source(&sym), SourceType::UserDefined);
    }

    #[test]
    fn set_symbol_name_error_type_remains_usable() {
        let _: Result<(), SetSymbolNameError> =
            Err(SetSymbolNameError::InvalidInput(InvalidInputException::new()));
    }
}
