use crate::program::model::listing::GhidraClass;
use crate::program::model::symbol::{Namespace, Symbol, SymbolType};
use std::sync::Arc;

/// Symbol representing a class.
///
/// Port of `ghidra.program.database.symbol.ClassSymbol` as a trait: the Java class extends
/// `SymbolDB` and overrides `getSymbolType`/`getObject`/`isPrimary`/`isExternal`/`isValidParent`.
/// Broken out as a trait (cycle cut-point) so implementors can plug in the eventual
/// `SymbolManager`/DB-record-backed implementation without this crate depending on it here.
pub trait ClassSymbol: Symbol {
    /// Stands in for `ClassSymbol.getSymbolType()`, which always returns `SymbolType.CLASS`.
    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Class
    }

    /// Stands in for `ClassSymbol.getObject()`: the `GhidraClass` namespace object this symbol
    /// represents, lazily built/refreshed from the database. Returns `None` if the symbol could
    /// not be refreshed (mirrors the Java method's `null` return when `refreshIfNeeded()` fails).
    fn get_object(&self) -> Option<Arc<dyn GhidraClass>>;

    /// Stands in for `ClassSymbol.isPrimary()`, which always returns `true`.
    fn is_primary(&self) -> bool {
        true
    }

    /// Stands in for `ClassSymbol.isExternal()`: delegates to the parent symbol's externality,
    /// mirroring `getParentSymbol()` via [`Symbol::get_parent_namespace`]'s owning symbol.
    fn is_external(&self) -> bool {
        self.get_parent_namespace()
            .map(|parent| parent.get_symbol().is_external())
            .unwrap_or(false)
    }

    /// Stands in for `ClassSymbol.isValidParent(Namespace)`. The real method combines
    /// `SymbolDB.isValidParent(Namespace)` with `SymbolType.CLASS.isValidParent(Program,
    /// Namespace, Address, boolean)`, both of which depend on program/database state not
    /// available through this trait; left as a required method for the concrete implementation.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{NamespaceType, SourceType};

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

    struct MockGhidraClass {
        symbol: Arc<dyn Symbol>,
    }

    impl Namespace for MockGhidraClass {
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

    impl GhidraClass for MockGhidraClass {}

    struct MockClassSymbol {
        symbol: MockSymbol,
        class_obj: Option<Arc<dyn GhidraClass>>,
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

        fn get_parent_id(&self) -> i64 {
            self.symbol.get_parent_id()
        }

        fn is_external(&self) -> bool {
            ClassSymbol::is_external(self)
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.symbol.get_parent_namespace()
        }
    }

    impl ClassSymbol for MockClassSymbol {
        fn get_object(&self) -> Option<Arc<dyn GhidraClass>> {
            self.class_obj.clone()
        }

        fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
            parent.get_type() == NamespaceType::Namespace
        }
    }

    #[test]
    fn defaults_match_java_class_symbol() {
        let sym = MockClassSymbol {
            symbol: MockSymbol {
                name: "MyClass".to_string(),
                external: false,
                parent: None,
            },
            class_obj: None,
        };

        assert_eq!(ClassSymbol::get_symbol_type(&sym), SymbolType::Class);
        assert!(ClassSymbol::is_primary(&sym));
        assert!(!ClassSymbol::is_external(&sym));
        assert!(sym.get_object().is_none());
    }

    #[test]
    fn is_external_delegates_to_parent_symbol() {
        let parent_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            name: "ExternalLib".to_string(),
            external: true,
            parent: None,
        });
        let parent_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            symbol: parent_symbol,
        });
        let sym = MockClassSymbol {
            symbol: MockSymbol {
                name: "MyClass".to_string(),
                external: false,
                parent: Some(parent_ns),
            },
            class_obj: None,
        };

        assert!(ClassSymbol::is_external(&sym));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let class_obj: Arc<dyn GhidraClass> = Arc::new(MockGhidraClass {
            symbol: Arc::new(MockSymbol {
                name: "MyClass".to_string(),
                external: false,
                parent: None,
            }),
        });
        let sym: Box<dyn ClassSymbol> = Box::new(MockClassSymbol {
            symbol: MockSymbol {
                name: "MyClass".to_string(),
                external: false,
                parent: None,
            },
            class_obj: Some(class_obj),
        });

        assert!(sym.get_object().is_some());
        assert!(sym.is_valid_parent(&MockNamespace {
            symbol: Arc::new(MockSymbol {
                name: "Global".to_string(),
                external: false,
                parent: None,
            }),
        }));
    }
}
