use std::cmp::Ordering;
use std::sync::Arc;

use crate::framework::store::SEPARATOR_CHAR;
use crate::program::model::listing::library::{self, Library};
use crate::program::model::symbol::{Namespace, Symbol, SymbolType};
use crate::util::exception::InvalidInputException;

/// Symbol class for library symbols.
///
/// Port of `ghidra.program.database.symbol.LibrarySymbol` as a trait: the Java class extends
/// `SymbolDB` and overrides `isPrimary`/`isExternal`/`getSymbolType`/`getObject`/`isValidParent`,
/// following the same convention already used for
/// [`ClassSymbol`](crate::program::database::symbol::ClassSymbol) and
/// [`NamespaceSymbol`](crate::program::database::symbol::NamespaceSymbol). Broken out as a trait
/// (cycle cut-point) so implementors can plug in the eventual `SymbolManager`/DB-record-backed
/// implementation without this crate depending on it here.
///
/// Not wired to [`LibraryDb`](crate::program::database::symbol::LibraryDb) (which still depends
/// on the [`LibrarySymbol`](crate::program::seam_stubs::LibrarySymbol) placeholder trait, a
/// narrower cycle-cutting stand-in for this very class): unifying the two is left for whichever
/// concrete type implements both, same as [`NamespaceSymbol`]'s relationship to
/// [`NamespaceDb`](crate::program::database::symbol::NamespaceDb).
///
/// Left out: `setNameAndNamespace` and `delete()` (the ordinal-reassignment bookkeeping they
/// perform requires a live `SymbolManager` with a mutable library-symbol list, which is
/// out-of-scope cross-cutting DB state, not pure per-symbol logic) and the static
/// `setRecordFields` helper (writes directly to a `DBRecord` column layout that has no concrete
/// counterpart yet, since [`SymbolDB`](crate::program::database::symbol::SymbolDB) in this port is
/// a plain in-memory struct rather than a `DBRecord`-backed type).
pub trait LibrarySymbol: Symbol {
    /// Stands in for `LibrarySymbol.getSymbolType()`, which always returns `SymbolType.LIBRARY`.
    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Library
    }

    /// Stands in for `LibrarySymbol.isExternal()`, which always returns `true`.
    fn is_external(&self) -> bool {
        true
    }

    /// Stands in for `LibrarySymbol.isPrimary()`, which always returns `true`.
    fn is_primary(&self) -> bool {
        true
    }

    /// Stands in for `LibrarySymbol.getObject()`: the `Library` this symbol represents, lazily
    /// built/refreshed from the database. Returns `None` if the symbol could not be refreshed
    /// (mirrors the Java method's `null` return when `refreshIfNeeded()` fails).
    fn get_object(&self) -> Option<Arc<dyn Library>>;

    /// Stands in for `LibrarySymbol.isValidParent(Namespace)`. The real method combines
    /// `SymbolDB.isValidParent(Namespace)` with `SymbolType.LIBRARY.isValidParent(Program,
    /// Namespace, Address, boolean)`, both of which depend on program/database state not
    /// available through this trait; left as a required method for the concrete implementation.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;

    /// Stands in for `LibrarySymbol.doGetOrdinalFromRecord()`: the ordinal as stored in the
    /// database, or `-1` if one has not yet been established.
    fn ordinal_from_record(&self) -> i32;

    /// Stands in for `SymbolManager.computeLibraryOrdinal(LibrarySymbol)`, the fallback
    /// [`Self::get_ordinal`] uses when no ordinal has been stored yet. Depends on the full set of
    /// library symbols in the program (via `compareTo`), which is `SymbolManager` state not
    /// available through this trait.
    fn compute_ordinal(&self) -> i32;

    /// Get this Library's ordinal placement within the ordered library list.
    ///
    /// Stands in for `LibrarySymbol.getOrdinal()`.
    fn get_ordinal(&self) -> i32 {
        let stored = self.ordinal_from_record();
        if stored < 0 {
            self.compute_ordinal()
        } else {
            stored
        }
    }

    /// Get the library program path within the project (may be `None`).
    ///
    /// Stands in for `LibrarySymbol.getExternalLibraryPath()`.
    fn get_external_library_path(&self) -> Option<String>;

    /// Writes `library_path` to the backing record and notifies the symbol manager of the data
    /// change. Stands in for the record-mutation tail of
    /// `LibrarySymbol.setExternalLibraryPath(String)` (after validation), i.e. `record.setString`
    /// + `updateRecord` + `symbolMgr.symbolDataChanged(this)`.
    fn store_external_library_path(
        &self,
        library_path: Option<&str>,
    ) -> Result<(), InvalidInputException>;

    /// Set the library program path within the project. The [`library::UNKNOWN`] library's path
    /// may only ever be cleared.
    ///
    /// Stands in for `LibrarySymbol.setExternalLibraryPath(String)`. Takes `&self` (rather than
    /// `&mut self`) since real record-backed symbols mutate their underlying database record
    /// through interior locking shared across every handle to the same row, not exclusive Rust
    /// ownership -- matching the convention used by the
    /// [`LibrarySymbol`](crate::program::seam_stubs::LibrarySymbol) placeholder's
    /// `set_external_library_path`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInputException`] if `library_path` is non-empty but does not begin with
    /// [`SEPARATOR_CHAR`].
    fn set_external_library_path(
        &self,
        library_path: Option<&str>,
    ) -> Result<(), InvalidInputException> {
        let effective_path = if self.get_name() == library::UNKNOWN {
            None
        } else {
            library_path
        };
        validate_external_path(effective_path)?;
        self.store_external_library_path(effective_path)
    }
}

/// Perform path validation for an external library path within the project.
///
/// Stands in for the static method `LibrarySymbol.validateExternalPath(String)`.
///
/// # Errors
///
/// Returns [`InvalidInputException`] if `path` is `Some` but does not begin with
/// [`SEPARATOR_CHAR`] (a `None` path is always allowed, used to clear the path).
pub fn validate_external_path(path: Option<&str>) -> Result<(), InvalidInputException> {
    let Some(path) = path else {
        return Ok(()); // null is an allowed value (used to clear)
    };
    if path.is_empty() || !path.starts_with(SEPARATOR_CHAR) {
        return Err(InvalidInputException::with_message(format!(
            "Absolute path must begin with '{SEPARATOR_CHAR}'"
        )));
    }
    Ok(())
}

/// Compares two library symbols by their database-stored ordinal (i.e.
/// [`LibrarySymbol::ordinal_from_record`], *not* the resolved [`LibrarySymbol::get_ordinal`]),
/// falling back to symbol ID when both report the same stored ordinal (including the common case
/// where neither has one assigned yet, i.e. both report `-1`).
///
/// Stands in for `LibrarySymbol.compareTo(LibrarySymbol)`. Note: mirrors the Java method's own
/// documented caveat that this is only meaningful when comparing library symbols from the same
/// program.
pub fn compare_library_symbols(a: &dyn LibrarySymbol, b: &dyn LibrarySymbol) -> Ordering {
    a.ordinal_from_record()
        .cmp(&b.ordinal_from_record())
        .then_with(|| a.get_id().cmp(&b.get_id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::SourceType;
    use std::sync::RwLock;

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }

    struct MockLibrarySymbol {
        name: String,
        id: i64,
        ordinal: RwLock<i32>,
        computed_ordinal: i32,
        path: RwLock<Option<String>>,
    }

    impl Symbol for MockLibrarySymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            LibrarySymbol::get_symbol_type(self)
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            LibrarySymbol::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_external(&self) -> bool {
            LibrarySymbol::is_external(self)
        }
    }

    impl LibrarySymbol for MockLibrarySymbol {
        fn get_object(&self) -> Option<Arc<dyn Library>> {
            None
        }
        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }
        fn ordinal_from_record(&self) -> i32 {
            *self.ordinal.read().unwrap()
        }
        fn compute_ordinal(&self) -> i32 {
            self.computed_ordinal
        }
        fn get_external_library_path(&self) -> Option<String> {
            self.path.read().unwrap().clone()
        }
        fn store_external_library_path(
            &self,
            library_path: Option<&str>,
        ) -> Result<(), InvalidInputException> {
            *self.path.write().unwrap() = library_path.map(str::to_string);
            Ok(())
        }
    }

    fn mock(name: &str, id: i64, ordinal: i32, computed_ordinal: i32) -> MockLibrarySymbol {
        MockLibrarySymbol {
            name: name.to_string(),
            id,
            ordinal: RwLock::new(ordinal),
            computed_ordinal,
            path: RwLock::new(None),
        }
    }

    #[test]
    fn defaults_match_java_library_symbol() {
        let sym = mock("advapi32.dll", 7, -1, 3);
        assert_eq!(LibrarySymbol::get_symbol_type(&sym), SymbolType::Library);
        assert!(LibrarySymbol::is_primary(&sym));
        assert!(LibrarySymbol::is_external(&sym));
    }

    #[test]
    fn get_ordinal_falls_back_to_computed_when_unset() {
        let sym = mock("advapi32.dll", 7, -1, 3);
        assert_eq!(sym.get_ordinal(), 3);
    }

    #[test]
    fn get_ordinal_prefers_stored_value() {
        let sym = mock("advapi32.dll", 7, 5, 3);
        assert_eq!(sym.get_ordinal(), 5);
    }

    #[test]
    fn set_external_library_path_validates_absolute_path() {
        let sym = mock("advapi32.dll", 7, -1, 0);
        assert!(sym.set_external_library_path(Some("relative/path")).is_err());
        assert!(sym.get_external_library_path().is_none());

        assert!(sym
            .set_external_library_path(Some("/External/advapi32.dll"))
            .is_ok());
        assert_eq!(
            sym.get_external_library_path(),
            Some("/External/advapi32.dll".to_string())
        );

        assert!(sym.set_external_library_path(None).is_ok());
        assert!(sym.get_external_library_path().is_none());
    }

    #[test]
    fn set_external_library_path_ignored_for_unknown_library() {
        let sym = mock(library::UNKNOWN, 1, -1, 0);
        // Even a validly-formed path is dropped for the UNKNOWN library.
        assert!(sym
            .set_external_library_path(Some("/External/whatever"))
            .is_ok());
        assert!(sym.get_external_library_path().is_none());
    }

    #[test]
    fn compare_library_symbols_orders_by_stored_ordinal_then_id() {
        let a = mock("a.dll", 1, 0, 0);
        let b = mock("b.dll", 2, 1, 0);
        assert_eq!(compare_library_symbols(&a, &b), Ordering::Less);
        assert_eq!(compare_library_symbols(&b, &a), Ordering::Greater);

        // Same (unassigned) stored ordinal: falls back to ID.
        let c = mock("c.dll", 3, -1, 0);
        let d = mock("d.dll", 4, -1, 0);
        assert_eq!(compare_library_symbols(&c, &d), Ordering::Less);
        assert_eq!(compare_library_symbols(&d, &c), Ordering::Greater);
        assert_eq!(compare_library_symbols(&c, &c), Ordering::Equal);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let sym: Box<dyn LibrarySymbol> = Box::new(mock("advapi32.dll", 7, -1, 2));
        assert_eq!(sym.get_ordinal(), 2);
        assert!(sym.get_object().is_none());
    }
}
