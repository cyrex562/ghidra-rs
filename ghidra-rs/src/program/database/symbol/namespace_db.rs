use std::sync::Arc;

use crate::program::model::address::AddressSetView;
use crate::program::model::symbol::{Namespace, SetParentNamespaceError, Symbol};
use crate::program::seam_stubs::NamespaceSymbol;

/// Class to represent a set of related symbols. Symbols within a namespace must have unique
/// names.
///
/// Port of `ghidra.program.database.symbol.NamespaceDB` as a trait (cycle cut-point): the Java
/// class directly holds a `NamespaceSymbol` and a `NamespaceManager`, both still unported, which
/// would otherwise pull this port back into the `NamespaceSymbol`/`SymbolManager`/
/// `NamespaceManager` cycle. Declaring the backing symbol accessor against the
/// [`NamespaceSymbol`](crate::program::seam_stubs::NamespaceSymbol) placeholder keeps this trait
/// independent of that concrete DB class.
///
/// Mirrors the [`LibraryDb`](crate::program::database::symbol::library_db::LibraryDb) convention:
/// method names match [`Namespace`] so a concrete implementor's `Namespace` impl can simply
/// forward to these defaults (see the smoke test).
pub trait NamespaceDb: Namespace {
    /// Accessor for the backing `symbol` field (`NamespaceDB.symbol`).
    fn symbol(&self) -> Arc<dyn NamespaceSymbol>;

    /// Stands in for `NamespaceDB.getSymbol()`.
    fn get_symbol(&self) -> Arc<dyn Symbol> {
        self.symbol().as_symbol()
    }

    /// Stands in for `NamespaceDB.getName()`.
    fn get_name(&self) -> String {
        self.symbol().get_name()
    }

    /// Stands in for `NamespaceDB.getID()`.
    fn get_id(&self) -> i64 {
        self.symbol().get_id()
    }

    /// Stands in for `NamespaceDB.getParentNamespace()`.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.symbol().get_parent_namespace()
    }

    /// Stands in for `NamespaceDB.getBody()` (`namespaceMgr.getAddressSet(this)`). Left as a
    /// required method: producing the `&dyn Namespace` view of `this` that the real
    /// `NamespaceManager.getAddressSet` call needs is only possible once `Self` is a concrete,
    /// known type, i.e. from within the concrete implementor's own method body (which can pass
    /// `self` directly). See
    /// [`get_body_via_namespace_manager`](crate::program::seam_stubs::get_body_via_namespace_manager)
    /// for a helper concrete implementors can delegate to.
    fn get_body(&self) -> Box<dyn AddressSetView>;

    /// Stands in for `NamespaceDB.getName(boolean)`.
    fn get_name_with_path(&self, include_namespace_path: bool) -> String {
        self.symbol().get_name_with_path(include_namespace_path)
    }

    /// Stands in for `NamespaceDB.setParentNamespace(Namespace)`.
    fn set_parent_namespace(
        &mut self,
        parent_namespace: Arc<dyn Namespace>,
    ) -> Result<(), SetParentNamespaceError> {
        self.symbol().set_namespace(parent_namespace)
    }

    /// Stands in for `NamespaceDB.isExternal()`.
    fn is_external(&self) -> bool {
        self.symbol().is_external()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{NamespaceType, SourceType, SymbolType};
    use crate::program::seam_stubs::NamespaceManager;

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }

    struct MockSymbol {
        name: String,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            42
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_external(&self) -> bool {
            false
        }
    }

    struct MockNamespaceSymbol {
        name: std::sync::RwLock<String>,
        external: bool,
    }

    impl NamespaceSymbol for MockNamespaceSymbol {
        fn as_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.name.read().unwrap().clone(),
            })
        }

        fn get_name(&self) -> String {
            self.name.read().unwrap().clone()
        }

        fn get_id(&self) -> i64 {
            42
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }

        fn get_name_with_path(&self, include_namespace_path: bool) -> String {
            if include_namespace_path {
                format!("Global::{}", self.name.read().unwrap())
            } else {
                self.name.read().unwrap().clone()
            }
        }

        fn set_namespace(
            &self,
            _parent_namespace: Arc<dyn Namespace>,
        ) -> Result<(), SetParentNamespaceError> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            self.external
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

    struct MockNamespaceDb {
        symbol: Arc<dyn NamespaceSymbol>,
        namespace_manager: Arc<dyn NamespaceManager>,
    }

    impl Namespace for MockNamespaceDb {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            NamespaceDb::get_symbol(self)
        }

        fn is_external(&self) -> bool {
            NamespaceDb::is_external(self)
        }

        fn get_name(&self) -> String {
            NamespaceDb::get_name(self)
        }

        fn get_name_with_path(&self, include_namespace_path: bool) -> String {
            NamespaceDb::get_name_with_path(self, include_namespace_path)
        }

        fn get_id(&self) -> i64 {
            NamespaceDb::get_id(self)
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            NamespaceDb::get_parent_namespace(self)
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            NamespaceDb::get_body(self)
        }

        fn set_parent_namespace(
            &mut self,
            parent_namespace: Arc<dyn Namespace>,
        ) -> Result<(), SetParentNamespaceError> {
            NamespaceDb::set_parent_namespace(self, parent_namespace)
        }
    }

    impl NamespaceDb for MockNamespaceDb {
        fn symbol(&self) -> Arc<dyn NamespaceSymbol> {
            self.symbol.clone()
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            crate::program::seam_stubs::get_body_via_namespace_manager(
                self.namespace_manager.as_ref(),
                self,
            )
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut ns: Box<dyn Namespace> = Box::new(MockNamespaceDb {
            symbol: Arc::new(MockNamespaceSymbol {
                name: std::sync::RwLock::new("MyNamespace".to_string()),
                external: false,
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        });

        assert_eq!(ns.get_name(), "MyNamespace");
        assert_eq!(ns.get_id(), 42);
        assert_eq!(Namespace::get_type(ns.as_ref()), NamespaceType::Namespace);
        assert!(!ns.is_external());

        assert_eq!(ns.get_name_with_path(true), "Global::MyNamespace");
        assert!(!ns.get_body().is_empty());

        let parent: Arc<dyn Namespace> = Arc::new(MockNamespaceDb {
            symbol: Arc::new(MockNamespaceSymbol {
                name: std::sync::RwLock::new("Parent".to_string()),
                external: false,
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        });
        assert!(ns.set_parent_namespace(parent).is_ok());
    }

    #[test]
    fn is_external_delegates_to_symbol() {
        let ns = MockNamespaceDb {
            symbol: Arc::new(MockNamespaceSymbol {
                name: std::sync::RwLock::new("ExternalNs".to_string()),
                external: true,
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        };

        assert!(NamespaceDb::is_external(&ns));
        assert!(Namespace::is_external(&ns));
    }
}
