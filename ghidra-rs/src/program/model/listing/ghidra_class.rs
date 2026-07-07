use crate::program::model::symbol::{Namespace, NamespaceType};

/// Interface for representing class objects in the program.
///
/// Port of `ghidra.program.model.listing.GhidraClass`.
pub trait GhidraClass: Namespace {
    /// The type of namespace this represents. Overrides the
    /// [`Namespace`](crate::program::model::symbol::Namespace) default.
    fn get_type(&self) -> NamespaceType {
        NamespaceType::Class
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::SourceType;
    use crate::program::model::symbol::Symbol;
    use std::sync::Arc;

    struct MockSymbol {
        name: String,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Class
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockGhidraClass {
        id: i64,
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
            self.id
        }
    }

    impl GhidraClass for MockGhidraClass {}

    #[test]
    fn get_type_returns_class() {
        let ghidra_class = MockGhidraClass {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "MyClass".to_string(),
            }),
        };
        assert_eq!(ghidra_class.get_type(), NamespaceType::Class);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let ghidra_class: Box<dyn GhidraClass> = Box::new(MockGhidraClass {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "MyClass".to_string(),
            }),
        });
        assert_eq!(ghidra_class.get_type(), NamespaceType::Class);
        assert_eq!(ghidra_class.get_name(), "MyClass");
    }

    #[test]
    fn inherits_namespace_behavior() {
        let ghidra_class = MockGhidraClass {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "MyClass".to_string(),
            }),
        };
        assert!(!ghidra_class.is_global());
    }
}
