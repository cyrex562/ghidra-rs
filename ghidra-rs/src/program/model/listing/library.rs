use std::sync::Arc;

use crate::program::model::symbol::{Symbol, SymbolType};
use crate::program::seam_stubs::{Namespace, NamespaceType};
use crate::util::exception::InvalidInputException;

/// Symbol name used for a [`Library`] whose associated program path is unknown.
pub const UNKNOWN: &str = "<EXTERNAL>";

/// Interface for a Library dependency and namespace.
///
/// Port of `ghidra.program.model.listing.Library`.
pub trait Library: Namespace {
    /// The type of namespace this represents. Overrides the
    /// [`Namespace`](crate::program::seam_stubs::Namespace) default.
    fn get_type(&self) -> NamespaceType {
        NamespaceType::Library
    }

    /// The associated program file pathname within the project which corresponds to this
    /// library, or `None` if not set.
    fn get_associated_program_path(&self) -> Option<String>;

    /// Sets the program file pathname within the project which corresponds to this library.
    ///
    /// NOTE: Assigning a path to the [`UNKNOWN`] library is ignored.
    ///
    /// # Errors
    /// Returns `Err` if `program_path` is invalid.
    fn set_associated_program_path(
        &mut self,
        program_path: Option<&str>,
    ) -> Result<(), InvalidInputException>;
}

/// Get the Library which contains the specified external symbol.
///
/// Returns `None` if `symbol` is `None` or not external.
///
/// Port of the static method `ghidra.program.model.listing.Library.getContainingLibrary`.
pub fn get_containing_library(symbol: Option<Arc<dyn Symbol>>) -> Option<Arc<dyn Library>> {
    let mut symbol = symbol?;
    if symbol.get_symbol_type() == SymbolType::Library {
        return symbol.as_namespace()?.as_library();
    }
    if !matches!(
        symbol.get_symbol_type(),
        SymbolType::Namespace | SymbolType::Class
    ) {
        return None;
    }
    loop {
        if !symbol.is_external() {
            return None;
        }
        let namespace = symbol.as_namespace()?;
        if let Some(lib) = namespace.as_library() {
            return Some(lib);
        }
        symbol = namespace.get_parent_namespace()?.get_symbol();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::SourceType;

    #[derive(Clone)]
    struct MockLibrary {
        name: String,
        program_path: Option<String>,
    }

    impl Namespace for MockLibrary {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }

        fn as_library(&self) -> Option<Arc<dyn Library>> {
            Some(Arc::new(self.clone()))
        }
    }

    impl Library for MockLibrary {
        fn get_associated_program_path(&self) -> Option<String> {
            self.program_path.clone()
        }

        fn set_associated_program_path(
            &mut self,
            program_path: Option<&str>,
        ) -> Result<(), InvalidInputException> {
            if self.name == UNKNOWN {
                return Ok(());
            }
            self.program_path = program_path.map(str::to_string);
            Ok(())
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut lib: Box<dyn Library> = Box::new(MockLibrary {
            name: "advapi32.dll".to_string(),
            program_path: None,
        });
        assert_eq!(Library::get_type(lib.as_ref()), NamespaceType::Library);
        lib.set_associated_program_path(Some("/External/advapi32.dll"))
            .unwrap();
        assert_eq!(
            lib.get_associated_program_path(),
            Some("/External/advapi32.dll".to_string())
        );
    }

    struct MockSymbol {
        symbol_type: SymbolType,
        external: bool,
        namespace: Option<Arc<dyn Namespace>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }
        fn get_name(&self) -> &str {
            "mock"
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
        fn is_external(&self) -> bool {
            self.external
        }
        fn as_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.namespace.clone()
        }
    }

    #[test]
    fn get_containing_library_returns_none_for_missing_symbol() {
        assert!(get_containing_library(None).is_none());
    }

    #[test]
    fn get_containing_library_resolves_direct_library_symbol() {
        let lib: Arc<dyn Namespace> = Arc::new(MockLibrary {
            name: "advapi32.dll".to_string(),
            program_path: None,
        });
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            symbol_type: SymbolType::Library,
            external: true,
            namespace: Some(lib),
        });
        let found = get_containing_library(Some(symbol)).expect("library symbol resolves");
        assert_eq!(found.get_associated_program_path(), None);
    }

    #[test]
    fn get_containing_library_returns_none_for_non_external_namespace_symbol() {
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            symbol_type: SymbolType::Namespace,
            external: false,
            namespace: None,
        });
        assert!(get_containing_library(Some(symbol)).is_none());
    }
}
