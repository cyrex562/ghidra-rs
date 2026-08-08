use crate::program::model::listing::CircularDependencyException;
use crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;

/// A trace namespace symbol backed by the database.
///
/// Port of `ghidra.trace.database.symbol.DBTraceNamespaceSymbol` as a trait.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractDBTraceSymbol implements TraceNamespaceSymbol`; both are
/// modeled as supertraits here.
///
/// Most of the class's overrides restate behavior already declared on one of those supertraits
/// (or on the [`Symbol`](crate::program::model::symbol::Symbol)/
/// [`Namespace`](crate::program::model::symbol::Namespace) traits `TraceNamespaceSymbol`
/// transitively requires) and are therefore not redeclared here — implementors provide them
/// directly in their `impl Symbol for X` / `impl Namespace for X` /
/// `impl AbstractDBTraceSymbol for X` blocks, per that trait's own default/abstract contract:
/// - `getLifespan()` overrides [`AbstractDBTraceSymbol::get_lifespan`] (abstract there), combining
///   the record's own lifespan with the min/max of all children's lifespans (note the Java source
///   uses `Math.min` for both the running min *and* max, which looks like a bug but is preserved
///   as documentation of the original rather than "fixed" here since no defaulted behavior is
///   modeled).
/// - `getAddressSet()` overrides [`AbstractDBTraceSymbol::get_address_set`] (abstract there),
///   returning the trace's full address set when [`Namespace::is_global`] is true, else the
///   inherited record-derived set.
/// - `getSymbolType()` overrides [`Symbol::get_symbol_type`](crate::program::model::symbol::Symbol::get_symbol_type)
///   (abstract there): `SymbolType::Global` when this symbol has no parent id, else
///   `SymbolType::Namespace`.
/// - `getBody()` overrides [`Namespace::get_body`](crate::program::model::symbol::Namespace::get_body)
///   (defaulted to an empty set there), delegating to `getAddressSet()`.
/// - `setParentNamespace(Namespace)` overrides
///   [`Namespace::set_parent_namespace`](crate::program::model::symbol::Namespace::set_parent_namespace)
///   (defaulted to rejecting there), delegating to [`AbstractDBTraceSymbol::set_namespace`].
/// - `setPrimary()` and `isPrimary()` override
///   [`Symbol::is_primary`](crate::program::model::symbol::Symbol::is_primary) (abstract there);
///   Java always returns `false`/`isGlobal()` respectively (namespace symbols are primary
///   exactly when they are the global namespace).
/// - `getChildren()` overrides [`TraceNamespaceSymbol::get_children`] (abstract there).
/// - `delete()` overrides [`AbstractDBTraceSymbol::delete`] (abstract there), first deleting all
///   children then, if every deletion succeeded, deleting this symbol's own record.
///
/// Two members have no home on any existing supertrait and are declared directly on this trait:
/// [`DBTraceNamespaceSymbol::check_circular`] and [`DBTraceNamespaceSymbol::do_get_path`]. Both
/// are left without a default body: the Java implementations walk the `parent` field of sibling
/// `DBTraceNamespaceSymbol`/`AbstractDBTraceSymbol` instances directly (same-class field access)
/// and consult the owning `DBTraceSymbolManager`'s global namespace, none of which is expressible
/// generically in terms of the trait methods modeled so far (in particular, this trait's own
/// supertrait [`TraceNamespaceSymbol::get_parent_trace_namespace_symbol`] returns
/// `Arc<dyn TraceNamespaceSymbol>`, not `Arc<dyn DBTraceNamespaceSymbol>`, so it cannot be used to
/// recurse into either method).
pub trait DBTraceNamespaceSymbol: AbstractDBTraceSymbol + TraceNamespaceSymbol {
    /// Mirrors the protected `checkCircular(DBTraceNamespaceSymbol)`: rejects `new_parent` with a
    /// [`CircularDependencyException`] if `self` is one of `new_parent`'s own ancestors (walking
    /// up the parent chain to the manager's global namespace), then performs the supertrait's own
    /// `super.checkCircular(newParent)` check.
    fn check_circular(
        &self,
        new_parent: &dyn DBTraceNamespaceSymbol,
    ) -> Result<(), CircularDependencyException>;

    /// Mirrors the protected `doGetPath(ArrayList<String>)`: appends this symbol's path
    /// components to `list`, called by descendant symbols (e.g. label/class symbols, once
    /// ported) to build their own full path. The Java implementation recurses into the parent
    /// first unless the parent is the manager's global namespace, then appends this symbol's own
    /// name.
    fn do_get_path(&self, list: &mut Vec<String>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::symbol::{
        Namespace, NamespaceType, SetParentNamespaceError, SourceType, Symbol, SymbolType,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    /// A namespace symbol whose `parent` is tracked both as a `TraceNamespaceSymbol` (satisfying
    /// the supertrait contract) and, redundantly, as an id chain -- standing in for the Java
    /// field-access chain `checkCircular`/`doGetPath` walk directly, since same-class field
    /// access across `Arc<dyn DBTraceNamespaceSymbol>` instances is not otherwise recoverable
    /// generically (see the trait's doc comment).
    struct MockNamespaceSymbol {
        id: i64,
        parent_id: i64,
        name: String,
        parent: Option<Arc<MockNamespaceSymbol>>,
    }

    impl Namespace for MockNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled; see TraceNamespaceSymbol trait docs")
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone().map(|p| p as Arc<dyn Namespace>)
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AbstractDBTraceSymbol::get_address_set(self))
        }

        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }

        fn is_global(&self) -> bool {
            self.parent_id == -1
        }
    }

    impl Symbol for MockNamespaceSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            if self.parent_id == -1 {
                SymbolType::Global
            } else {
                SymbolType::Namespace
            }
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
        }

        fn is_primary(&self) -> bool {
            Namespace::is_global(self)
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            self.parent_id
        }
    }

    impl TraceSymbol for MockNamespaceSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }

        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            self.parent
                .clone()
                .map(|p| p as Arc<dyn TraceNamespaceSymbol>)
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

    impl TraceNamespaceSymbol for MockNamespaceSymbol {
        fn get_parent_trace_namespace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            self.parent
                .clone()
                .map(|p| p as Arc<dyn TraceNamespaceSymbol>)
        }

        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }

        fn get_path(&self) -> Vec<String> {
            let mut list = Vec::new();
            DBTraceNamespaceSymbol::do_get_path(self, &mut list);
            list
        }
    }

    struct MockOverlaySpaceAdapter;
    impl crate::trace::seam_stubs::DBTraceOverlaySpaceAdapter for MockOverlaySpaceAdapter {}

    struct MockProgramView;
    impl crate::trace::seam_stubs::DBTraceProgramView for MockProgramView {}

    impl AbstractDBTraceSymbol for MockNamespaceSymbol {
        fn get_overlay_space_adapter(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::DBTraceOverlaySpaceAdapter> {
            Box::new(MockOverlaySpaceAdapter)
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: 0, max: 0 })
        }

        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }

        fn get_path(&self) -> Vec<String> {
            let mut list = Vec::new();
            DBTraceNamespaceSymbol::do_get_path(self, &mut list);
            list
        }

        fn get_program(&self) -> Box<dyn crate::trace::seam_stubs::DBTraceProgramView> {
            Box::new(MockProgramView)
        }

        fn get_program_location(&self) -> Box<dyn crate::program::util::program_location::ProgramLocation> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
            let mut cur = Some(self.id);
            while let Some(id) = cur {
                if id == namespace.get_id() {
                    return true;
                }
                cur = if id == self.id {
                    self.parent.as_ref().map(|p| p.id)
                } else {
                    None
                };
            }
            false
        }

        fn is_valid_parent(&self, _ns: &dyn Namespace) -> bool {
            true
        }

        fn set_name(
            &mut self,
            _new_name: &str,
            _new_source: SourceType,
        ) -> Result<(), crate::trace::database::symbol::abstract_db_trace_symbol::SetSymbolNameError>
        {
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
            Namespace::is_global(self)
        }
    }

    impl DBTraceNamespaceSymbol for MockNamespaceSymbol {
        fn check_circular(
            &self,
            new_parent: &dyn DBTraceNamespaceSymbol,
        ) -> Result<(), CircularDependencyException> {
            // Mirrors `checkCircular`'s "I cannot be one of my own ancestors" check. The real
            // Java loop walks the full `parent` field chain via same-class field access; this
            // mock only has generic access to one hop (`get_parent_id()`) through the trait
            // object, which is enough to exercise real reject/accept behavior for this smoke
            // test (see the trait's doc comment on why a full generic walk isn't expressible).
            if Symbol::get_id(new_parent) == self.id || new_parent.get_parent_id() == self.id {
                return Err(CircularDependencyException::new(
                    "cannot make a namespace its own descendant",
                ));
            }
            Ok(())
        }

        fn do_get_path(&self, list: &mut Vec<String>) {
            if let Some(parent) = &self.parent {
                if !Namespace::is_global(parent.as_ref()) {
                    DBTraceNamespaceSymbol::do_get_path(parent.as_ref(), list);
                }
            }
            list.push(self.name.clone());
        }
    }

    fn make_global() -> Arc<MockNamespaceSymbol> {
        Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            parent_id: -1,
            name: "Global".to_string(),
            parent: None,
        })
    }

    #[test]
    fn trait_object_usage_is_object_safe_and_builds_path() {
        let global = make_global();
        let child = Arc::new(MockNamespaceSymbol {
            id: 1,
            parent_id: 0,
            name: "child".to_string(),
            parent: Some(global.clone()),
        });
        let grandchild: Box<dyn DBTraceNamespaceSymbol> = Box::new(MockNamespaceSymbol {
            id: 2,
            parent_id: 1,
            name: "grandchild".to_string(),
            parent: Some(child.clone()),
        });

        let mut path = Vec::new();
        grandchild.do_get_path(&mut path);
        assert_eq!(path, vec!["child".to_string(), "grandchild".to_string()]);

        assert!(!AbstractDBTraceSymbol::is_global(grandchild.as_ref()));
        assert!(AbstractDBTraceSymbol::is_global(global.as_ref()));
    }

    #[test]
    fn check_circular_rejects_self_as_ancestor_of_new_parent() {
        let global = make_global();
        let child = MockNamespaceSymbol {
            id: 1,
            parent_id: 0,
            name: "child".to_string(),
            parent: Some(global.clone()),
        };
        let grandchild = MockNamespaceSymbol {
            id: 2,
            parent_id: 1,
            name: "grandchild".to_string(),
            parent: Some(Arc::new(MockNamespaceSymbol {
                id: 1,
                parent_id: 0,
                name: "child".to_string(),
                parent: Some(global.clone()),
            })),
        };

        // `child` is an ancestor of `grandchild`, so re-parenting `child` under `grandchild`
        // must be rejected.
        assert!(child.check_circular(&grandchild).is_err());
        // `global` is not a descendant of `child`, so this is a legal re-parent.
        assert!(child.check_circular(global.as_ref()).is_ok());
    }

    #[test]
    fn set_parent_namespace_error_type_remains_usable() {
        let _: Result<(), SetParentNamespaceError> = Err(SetParentNamespaceError::InvalidInput(
            crate::util::exception::InvalidInputException::new(),
        ));
    }
}
