use std::sync::Arc;

use crate::program::database::symbol::ClassSymbol;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::GhidraClass;
use crate::program::model::symbol::{Namespace, SetParentNamespaceError, Symbol};
use crate::program::seam_stubs::NamespaceManager;

/// Object to represent a "Class".
///
/// Port of `ghidra.program.database.symbol.GhidraClassDB` as a trait (cycle cut-point): the Java
/// class directly holds a `ClassSymbol` and a `NamespaceManager`. `ClassSymbol` is already ported
/// (as a trait extending [`Symbol`]), but `NamespaceManager` is not, so the backing manager is
/// modeled against the [`NamespaceManager`](crate::program::seam_stubs::NamespaceManager)
/// placeholder, mirroring the [`LibraryDb`](crate::program::database::symbol::LibraryDb) and
/// [`NamespaceDb`](crate::program::database::symbol::NamespaceDb) convention.
///
/// Method names match [`Namespace`] so a concrete implementor's `Namespace` impl can simply
/// forward to these defaults (see the smoke test).
pub trait GhidraClassDb: GhidraClass {
    /// Accessor for the backing `symbol` field (`GhidraClassDB.symbol`).
    fn symbol(&self) -> Arc<dyn ClassSymbol>;

    /// Stands in for `GhidraClassDB.getSymbol()`.
    fn get_symbol(&self) -> Arc<dyn Symbol> {
        self.symbol()
    }

    /// Stands in for `GhidraClassDB.isExternal()`.
    fn is_external(&self) -> bool {
        ClassSymbol::is_external(&*self.symbol())
    }

    /// Stands in for `GhidraClassDB.getName()`.
    fn get_name(&self) -> String {
        self.symbol().get_name().to_string()
    }

    /// Stands in for `GhidraClassDB.getID()`.
    fn get_id(&self) -> i64 {
        self.symbol().get_id()
    }

    /// Stands in for `GhidraClassDB.getParentNamespace()`.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.symbol().get_parent_namespace()
    }

    /// Stands in for `GhidraClassDB.getBody()` (`namespaceMgr.getAddressSet(this)`). Left as a
    /// required method: producing the `&dyn Namespace` view of `this` that the real
    /// `NamespaceManager.getAddressSet` call needs is only possible once `Self` is a concrete,
    /// known type, i.e. from within the concrete implementor's own method body (which can pass
    /// `self` directly). See
    /// [`get_body_via_namespace_manager`](crate::program::seam_stubs::get_body_via_namespace_manager)
    /// for a helper concrete implementors can delegate to.
    fn get_body(&self) -> Box<dyn AddressSetView>;

    /// Stands in for `GhidraClassDB.setParentNamespace(Namespace)` (`symbol.setNamespace(...)`).
    ///
    /// Left as a required method: `symbol()` returns `Arc<dyn ClassSymbol>` (shared ownership),
    /// but `ClassSymbol` inherits [`Symbol::set_namespace`]'s `&mut self` signature, which cannot
    /// be called through a shared `Arc`. A concrete implementor holding its symbol behind interior
    /// mutability (e.g. a lock) can bridge the two directly.
    fn set_parent_namespace(
        &mut self,
        parent_namespace: Arc<dyn Namespace>,
    ) -> Result<(), SetParentNamespaceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{NamespaceType, SourceType, SymbolType};

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }

    struct MockSymbol {
        name: String,
        external: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Class
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            9
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

    struct MockClassSymbol {
        symbol: MockSymbol,
    }

    impl Symbol for MockClassSymbol {
        fn get_address(&self) -> Address {
            self.symbol.get_address()
        }
        fn get_name(&self) -> &str {
            self.symbol.get_name()
        }
        fn get_symbol_type(&self) -> SymbolType {
            ClassSymbol::get_symbol_type(self)
        }
        fn get_source(&self) -> SourceType {
            self.symbol.get_source()
        }
        fn is_primary(&self) -> bool {
            ClassSymbol::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            self.symbol.get_id()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.symbol.get_parent_namespace()
        }
        fn get_parent_id(&self) -> i64 {
            self.symbol.get_parent_id()
        }
        fn is_external(&self) -> bool {
            ClassSymbol::is_external(self)
        }
    }

    impl ClassSymbol for MockClassSymbol {
        fn get_object(&self) -> Option<Arc<dyn crate::program::model::listing::GhidraClass>> {
            None
        }
        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }
    }

    /// A plain namespace wrapping a raw [`Symbol`] (as opposed to another `ClassSymbol`), used to
    /// terminate the parent chain in `is_external` tests: `ClassSymbol::is_external` always
    /// defers to the parent's own `is_external`, so a parent that is itself a `ClassSymbol` would
    /// just recurse into "no parent -> false" rather than exercising the delegation.
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

    struct MockNamespaceManager;

    impl NamespaceManager for MockNamespaceManager {
        fn get_address_set(&self, _namespace: &dyn Namespace) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            set.add_range(&test_address(), &test_address());
            Box::new(set)
        }
    }

    struct MockGhidraClassDb {
        symbol: Arc<dyn ClassSymbol>,
        namespace_manager: Arc<dyn NamespaceManager>,
    }

    impl Namespace for MockGhidraClassDb {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            GhidraClassDb::get_symbol(self)
        }
        fn is_external(&self) -> bool {
            GhidraClassDb::is_external(self)
        }
        fn get_name(&self) -> String {
            GhidraClassDb::get_name(self)
        }
        fn get_id(&self) -> i64 {
            GhidraClassDb::get_id(self)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            GhidraClassDb::get_parent_namespace(self)
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            GhidraClassDb::get_body(self)
        }
        fn set_parent_namespace(
            &mut self,
            parent_namespace: Arc<dyn Namespace>,
        ) -> Result<(), SetParentNamespaceError> {
            GhidraClassDb::set_parent_namespace(self, parent_namespace)
        }
    }

    impl GhidraClass for MockGhidraClassDb {}

    impl GhidraClassDb for MockGhidraClassDb {
        fn symbol(&self) -> Arc<dyn ClassSymbol> {
            self.symbol.clone()
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            crate::program::seam_stubs::get_body_via_namespace_manager(
                self.namespace_manager.as_ref(),
                self,
            )
        }

        fn set_parent_namespace(
            &mut self,
            _parent_namespace: Arc<dyn Namespace>,
        ) -> Result<(), SetParentNamespaceError> {
            Ok(())
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut class_db: Box<dyn GhidraClass> = Box::new(MockGhidraClassDb {
            symbol: Arc::new(MockClassSymbol {
                symbol: MockSymbol {
                    name: "MyClass".to_string(),
                    external: false,
                    parent: None,
                },
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        });

        assert_eq!(class_db.get_name(), "MyClass");
        assert_eq!(class_db.get_id(), 9);
        assert_eq!(GhidraClass::get_type(class_db.as_ref()), NamespaceType::Class);
        assert!(!class_db.is_external());
        assert!(!class_db.get_body().is_empty());

        let parent: Arc<dyn Namespace> = Arc::new(MockGhidraClassDb {
            symbol: Arc::new(MockClassSymbol {
                symbol: MockSymbol {
                    name: "Parent".to_string(),
                    external: false,
                    parent: None,
                },
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        });
        assert!(class_db.set_parent_namespace(parent).is_ok());
    }

    #[test]
    fn is_external_delegates_to_parent_symbol() {
        // `ClassSymbol::is_external` (like the real `ClassSymbol.isExternal()`) reflects whether
        // the *parent* symbol is external, not this symbol's own flag.
        let parent_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "ExternalLib".to_string(),
            external: true,
            parent: None,
        });
        let parent_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            symbol: parent_symbol,
        });

        let class_db = MockGhidraClassDb {
            symbol: Arc::new(MockClassSymbol {
                symbol: MockSymbol {
                    name: "MyClass".to_string(),
                    external: false,
                    parent: Some(parent_ns),
                },
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        };

        assert!(GhidraClassDb::is_external(&class_db));
        assert!(Namespace::is_external(&class_db));
    }
}
