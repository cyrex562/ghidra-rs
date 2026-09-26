use std::sync::Arc;

use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Library;
use crate::program::model::symbol::{Namespace, SetParentNamespaceError, Symbol};
use crate::program::seam_stubs::LibrarySymbol;

/// Object to represent an external library.
///
/// Port of `ghidra.program.database.symbol.LibraryDB` as a trait (cycle cut-point): the Java
/// class directly holds a `LibrarySymbol` and a `NamespaceManager`, both still unported, which
/// would otherwise pull this port back into the `LibrarySymbol`/`SymbolManager`/`NamespaceManager`
/// cycle. Declaring the backing symbol accessor against the
/// [`LibrarySymbol`](crate::program::seam_stubs::LibrarySymbol) placeholder keeps this trait
/// independent of that concrete DB class.
///
/// Mirrors the [`ClassSymbol`](crate::program::database::symbol::ClassSymbol) convention: method
/// names match [`Library`]/[`Namespace`] so a concrete implementor's `Library`/`Namespace` impl
/// can simply forward to these defaults (see the smoke test).
pub trait LibraryDb: Library {
    /// Accessor for the backing `symbol` field (`LibraryDB.symbol`).
    fn symbol(&self) -> Arc<dyn LibrarySymbol>;

    /// Stands in for `LibraryDB.getSymbol()`.
    fn get_symbol(&self) -> Arc<dyn Symbol> {
        self.symbol().as_symbol()
    }

    /// Stands in for `LibraryDB.getName()`.
    fn get_name(&self) -> String {
        self.symbol().get_name()
    }

    /// Stands in for `LibraryDB.getID()`.
    fn get_id(&self) -> i64 {
        self.symbol().get_id()
    }

    /// Stands in for `LibraryDB.getParentNamespace()`.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.symbol().get_parent_namespace()
    }

    /// Stands in for `LibraryDB.getBody()` (`namespaceMgr.getAddressSet(this)`). Left as a
    /// required method: producing the `&dyn Namespace` view of `this` that the real
    /// `NamespaceManager.getAddressSet` call needs is only possible once `Self` is a concrete,
    /// known type, i.e. from within the concrete implementor's own method body (which can pass
    /// `self` directly). See
    /// [`get_body_via_namespace_manager`](crate::program::seam_stubs::get_body_via_namespace_manager)
    /// for a helper concrete implementors can delegate to.
    fn get_body(&self) -> Box<dyn AddressSetView>;

    /// Stands in for `LibraryDB.getName(boolean)`.
    fn get_name_with_path(&self, include_namespace_path: bool) -> String {
        self.symbol().get_name_with_path(include_namespace_path)
    }

    /// Stands in for `LibraryDB.setParentNamespace(Namespace)`.
    fn set_parent_namespace(
        &mut self,
        parent_namespace: Arc<dyn Namespace>,
    ) -> Result<(), SetParentNamespaceError> {
        self.symbol().set_namespace(parent_namespace)
    }

    /// Stands in for `LibraryDB.getAssociatedProgramPath()`.
    fn get_associated_program_path(&self) -> Option<String> {
        self.symbol().get_external_library_path()
    }

    /// Stands in for `LibraryDB.setAssociatedProgramPath(String)`.
    fn set_associated_program_path(
        &mut self,
        program_path: Option<&str>,
    ) -> Result<(), crate::util::exception::InvalidInputException> {
        self.symbol().set_external_library_path(program_path)
    }

    /// Stands in for `LibraryDB.isExternal()`, which always returns `true`.
    fn is_external(&self) -> bool {
        true
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
            SymbolType::Library
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            7
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_external(&self) -> bool {
            true
        }
    }

    struct MockLibrarySymbol {
        name: std::sync::RwLock<String>,
        library_path: std::sync::RwLock<Option<String>>,
    }

    impl LibrarySymbol for MockLibrarySymbol {
        fn as_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.name.read().unwrap().clone(),
            })
        }

        fn get_name(&self) -> String {
            self.name.read().unwrap().clone()
        }

        fn get_id(&self) -> i64 {
            7
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

        fn get_external_library_path(&self) -> Option<String> {
            self.library_path.read().unwrap().clone()
        }

        fn set_external_library_path(
            &self,
            library_path: Option<&str>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            *self.library_path.write().unwrap() = library_path.map(str::to_string);
            Ok(())
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

    struct MockLibraryDb {
        symbol: Arc<dyn LibrarySymbol>,
        namespace_manager: Arc<dyn NamespaceManager>,
    }

    impl Namespace for MockLibraryDb {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            LibraryDb::get_symbol(self)
        }

        fn is_external(&self) -> bool {
            LibraryDb::is_external(self)
        }

        fn get_name(&self) -> String {
            LibraryDb::get_name(self)
        }

        fn get_name_with_path(&self, include_namespace_path: bool) -> String {
            LibraryDb::get_name_with_path(self, include_namespace_path)
        }

        fn get_id(&self) -> i64 {
            LibraryDb::get_id(self)
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            LibraryDb::get_parent_namespace(self)
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            LibraryDb::get_body(self)
        }

        fn set_parent_namespace(
            &mut self,
            parent_namespace: Arc<dyn Namespace>,
        ) -> Result<(), SetParentNamespaceError> {
            LibraryDb::set_parent_namespace(self, parent_namespace)
        }
    }

    impl Library for MockLibraryDb {
        fn get_associated_program_path(&self) -> Option<String> {
            LibraryDb::get_associated_program_path(self)
        }

        fn set_associated_program_path(
            &mut self,
            program_path: Option<&str>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            LibraryDb::set_associated_program_path(self, program_path)
        }
    }

    impl LibraryDb for MockLibraryDb {
        fn symbol(&self) -> Arc<dyn LibrarySymbol> {
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
        let mut lib: Box<dyn Library> = Box::new(MockLibraryDb {
            symbol: Arc::new(MockLibrarySymbol {
                name: std::sync::RwLock::new("advapi32.dll".to_string()),
                library_path: std::sync::RwLock::new(None),
            }),
            namespace_manager: Arc::new(MockNamespaceManager),
        });

        assert_eq!(lib.get_name(), "advapi32.dll");
        assert_eq!(lib.get_id(), 7);
        assert_eq!(Library::get_type(lib.as_ref()), NamespaceType::Library);
        assert!(lib.get_associated_program_path().is_none());

        lib.set_associated_program_path(Some("/External/advapi32.dll"))
            .unwrap();
        assert_eq!(
            lib.get_associated_program_path(),
            Some("/External/advapi32.dll".to_string())
        );

        assert_eq!(lib.get_name_with_path(true), "Global::advapi32.dll");
        assert!(!lib.get_body().is_empty());
    }
}
