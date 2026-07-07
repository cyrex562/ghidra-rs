//! The Namespace interface.
//!
//! Port of `ghidra.program.model.symbol.Namespace`.

use std::collections::VecDeque;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::{AddressSet, AddressSetView};
use crate::program::model::listing::library::Library;
use crate::program::model::listing::CircularDependencyException;
use crate::program::model::symbol::{Symbol, SymbolType};
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// The delimiter that is used to separate namespace nodes in a namespace string. For example,
/// `"Global::child1::symbolName"`.
pub const DELIMITER: &str = "::";

/// Replaced by [`DELIMITER`].
#[deprecated(note = "use DELIMITER")]
pub const NAMESPACE_DELIMITER: &str = "::";

/// The ID of the global namespace.
pub const GLOBAL_NAMESPACE_ID: i64 = 0;

/// Type of [`Namespace`].
///
/// Port of `ghidra.program.model.symbol.Namespace.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceType {
    Namespace,
    Library,
    Class,
    Function,
}

impl NamespaceType {
    /// A friendly name for use in messages.
    pub fn friendly_name(&self) -> &'static str {
        match self {
            NamespaceType::Namespace => "Namespace",
            NamespaceType::Library => "Library",
            NamespaceType::Class => "Class",
            NamespaceType::Function => "Function",
        }
    }
}

/// Error produced by [`Namespace::set_parent_namespace`].
///
/// Combines the three checked exceptions declared on the Java method
/// `Namespace.setParentNamespace(Namespace)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetParentNamespaceError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Circular(#[from] CircularDependencyException),
}

/// The Namespace interface.
///
/// Port of `ghidra.program.model.symbol.Namespace`.
pub trait Namespace: Send + Sync {
    /// Get the symbol for this namespace.
    fn get_symbol(&self) -> Arc<dyn Symbol>;

    /// Returns true if this namespace is external (i.e., associated with a Library).
    ///
    /// Defaults to `false` so existing implementors are unaffected; concrete implementations
    /// should override once external-namespace support is ported.
    fn is_external(&self) -> bool {
        false
    }

    /// Get the simple namespace name (without parent path).
    ///
    /// See [`Namespace::get_name_with_path`] for the namespace-qualified variant.
    ///
    /// Defaults to delegating to [`Namespace::get_symbol`] so existing implementors are
    /// unaffected; concrete implementations should override once fully ported.
    fn get_name(&self) -> String {
        self.get_symbol().get_name().to_string()
    }

    /// Returns the namespace name, optionally prepended with the full parent namespace path
    /// (using [`DELIMITER`] as separator), e.g. `"ClassA::InnerClass"`.
    ///
    /// Defaults to joining [`Namespace::get_path_list`] so existing implementors are unaffected;
    /// concrete implementations should override once fully ported.
    fn get_name_with_path(&self, include_namespace_path: bool) -> String {
        if !include_namespace_path {
            return self.get_name();
        }
        self.get_path_list(false).join(DELIMITER)
    }

    /// Get the namespace path as a list of namespace names. If `omit_library` is true, the
    /// Library name (if applicable) will be omitted from the returned list and treated the same
    /// as the global namespace.
    ///
    /// Returns an empty list for the global namespace.
    fn get_path_list(&self, omit_library: bool) -> Vec<String> {
        if self.is_global() {
            return Vec::new();
        }
        let mut list = VecDeque::new();
        list.push_front(self.get_name());
        let mut current = self.get_parent_namespace();
        while let Some(n) = current {
            if n.is_global() || (omit_library && n.is_library()) {
                break;
            }
            list.push_front(n.get_name());
            current = n.get_parent_namespace();
        }
        list.into_iter().collect()
    }

    /// Return the namespace id.
    ///
    /// Defaults to a non-global sentinel id (rather than [`GLOBAL_NAMESPACE_ID`]) so
    /// [`Namespace::is_global`] does not default to `true`; concrete implementations should
    /// override once fully ported.
    fn get_id(&self) -> i64 {
        -1
    }

    /// Get the parent scope, or `None` if this scope is the global scope.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>>;

    /// Get the address set for this namespace.
    ///
    /// Defaults to an empty address set so existing implementors are unaffected; concrete
    /// implementations should override once fully ported.
    fn get_body(&self) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::new())
    }

    /// Set the parent namespace for this namespace. Restrictions may apply.
    ///
    /// Defaults to rejecting the change so existing implementors are unaffected; concrete
    /// implementations should override once fully ported.
    ///
    /// # Errors
    /// Returns `Err` if the parent namespace is not applicable for this namespace, another
    /// symbol exists in the parent namespace with the same name as this namespace, or the parent
    /// namespace is a descendant of this namespace.
    fn set_parent_namespace(
        &mut self,
        parent_namespace: Arc<dyn Namespace>,
    ) -> Result<(), SetParentNamespaceError> {
        let _ = parent_namespace;
        Err(SetParentNamespaceError::InvalidInput(InvalidInputException::new()))
    }

    /// {@return the type of namespace, e.g., Library, Class, Namespace, Function}
    fn get_type(&self) -> NamespaceType {
        NamespaceType::Namespace
    }

    /// Return true if this is the global namespace.
    fn is_global(&self) -> bool {
        self.get_id() == GLOBAL_NAMESPACE_ID
    }

    /// Return true if this is a library.
    fn is_library(&self) -> bool {
        self.get_symbol().get_symbol_type() == SymbolType::Library
    }

    /// Narrows this namespace to a [`Library`] when it is one. Stands in for `instanceof
    /// Library`, since Rust trait objects cannot be downcast to another trait object without
    /// extra machinery.
    fn as_library(&self) -> Option<Arc<dyn Library>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::SourceType;

    struct MockSymbol {
        name: String,
        symbol_type: SymbolType,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
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

    struct MockNamespace {
        id: i64,
        symbol: Arc<dyn Symbol>,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }

        fn get_id(&self) -> i64 {
            self.id
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: GLOBAL_NAMESPACE_ID,
            symbol: Arc::new(MockSymbol {
                name: "Global".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: None,
        });
        let child: Box<dyn Namespace> = Box::new(MockNamespace {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "child".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: Some(global),
        });

        assert_eq!(child.get_name(), "child");
        assert_eq!(child.get_type(), NamespaceType::Namespace);
        assert!(!child.is_global());
        assert!(!child.is_library());
        assert!(child.as_library().is_none());
    }

    #[test]
    fn get_path_list_walks_parents() {
        let global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: GLOBAL_NAMESPACE_ID,
            symbol: Arc::new(MockSymbol {
                name: "Global".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: None,
        });
        let outer: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "ClassA".to_string(),
                symbol_type: SymbolType::Class,
            }),
            parent: Some(global),
        });
        let inner = MockNamespace {
            id: 2,
            symbol: Arc::new(MockSymbol {
                name: "InnerClass".to_string(),
                symbol_type: SymbolType::Class,
            }),
            parent: Some(outer),
        };

        assert_eq!(
            inner.get_path_list(false),
            vec!["ClassA".to_string(), "InnerClass".to_string()]
        );
        assert_eq!(inner.get_name_with_path(true), "ClassA::InnerClass");
        assert_eq!(inner.get_name_with_path(false), "InnerClass");
    }

    #[test]
    fn set_parent_namespace_default_is_rejected() {
        let mut ns = MockNamespace {
            id: 1,
            symbol: Arc::new(MockSymbol {
                name: "child".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: None,
        };
        let parent: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 2,
            symbol: Arc::new(MockSymbol {
                name: "parent".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: None,
        });
        assert!(ns.set_parent_namespace(parent).is_err());
    }

    #[test]
    fn friendly_name_matches_java() {
        assert_eq!(NamespaceType::Namespace.friendly_name(), "Namespace");
        assert_eq!(NamespaceType::Library.friendly_name(), "Library");
        assert_eq!(NamespaceType::Class.friendly_name(), "Class");
        assert_eq!(NamespaceType::Function.friendly_name(), "Function");
    }
}
