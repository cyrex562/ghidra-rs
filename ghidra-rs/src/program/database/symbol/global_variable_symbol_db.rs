//! Port of `ghidra.program.database.symbol.GlobalVariableSymbolDB` as a trait (cycle cut-point).
//!
//! The Java class extends `VariableSymbolDB` (itself a `MemorySymbol`/`SymbolDB` subclass, none of
//! which are ported yet) and holds a `VariableStorageManagerDB` obtained from the owning
//! `SymbolManager`. Those construction-time wirings are what make this class a cycle cut-point, so
//! this port keeps only its overridden `Symbol`/`VariableSymbolDB` contract as an object-safe
//! trait extending [`Symbol`] directly, mirroring the
//! [`FunctionSymbol`](crate::program::database::symbol::FunctionSymbol) convention (required
//! `base_*`/accessor methods stand in for what in Java comes from `super.X()` or manager
//! callbacks).
//!
//! Note: global variable symbols are not yet supported by the real Ghidra API either (the Java
//! doc comment says as much); [`GlobalVariableSymbolDb::get_object`] mirrors this by always
//! panicking, matching `GlobalVariableSymbolDB.getObject()`'s unconditional
//! `UnsupportedOperationException`.

use std::sync::Arc;

use crate::program::model::lang::Register;
use crate::program::model::listing::function::DEFAULT_LOCAL_PREFIX;
use crate::program::model::listing::Variable;
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};

/// Symbol class for global variables (restricted to the program's global namespace).
///
/// Port of `ghidra.program.database.symbol.GlobalVariableSymbolDB`. See the module docs for what
/// was intentionally left out (the `VariableSymbolDB`/`MemorySymbol` superclass chain).
pub trait GlobalVariableSymbolDb: Symbol {
    /// Stands in for `GlobalVariableSymbolDB.getSymbolType()`, which always returns
    /// `SymbolType.GLOBAL_VAR`.
    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::GlobalVar
    }

    /// Stands in for `GlobalVariableSymbolDB.isValidParent(Namespace)`: a global variable symbol
    /// is locked to the owning program's global namespace. Left as a required method since
    /// comparing against "the program's global namespace" depends on program state not available
    /// through this trait.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;

    /// Stands in for `GlobalVariableSymbolDB.getObject()`, which always throws
    /// `UnsupportedOperationException` (global variable symbols are not yet supported -- the API
    /// does not yet facilitate their creation).
    fn get_object(&self) -> Option<Arc<dyn Variable>> {
        panic!("global variable symbols are not yet supported")
    }

    /// Accessor standing in for `refreshIfNeeded()`, used by [`do_get_name`](Self::do_get_name).
    /// Defaults to `true` (always valid/refreshed) so existing implementors are unaffected;
    /// concrete DB-backed implementations should override once refresh tracking is wired up.
    fn is_refreshable(&self) -> bool {
        true
    }

    /// Accessor standing in for `VariableSymbolDB.getVariableStorage()`, used by
    /// [`do_get_name`](Self::do_get_name). Returns `None` for storage that could not be resolved
    /// (mirroring the Java method's `null` return), distinct from storage that resolved but is
    /// marked bad (see [`VariableStorage::is_bad_storage`](crate::program::model::listing::VariableStorage::is_bad_storage)).
    fn variable_storage(&self) -> Option<Arc<dyn crate::program::model::listing::VariableStorage + Send + Sync>>;

    /// Accessor standing in for `Program.getRegister(Varnode)`, used by
    /// [`default_local_name`](Self::default_local_name) to prefer a register's name over its raw
    /// address when naming a storage varnode. Defaults to `None` so existing implementors are
    /// unaffected.
    fn program_register(&self, varnode: &Varnode) -> Option<Register> {
        let _ = varnode;
        None
    }

    /// Accessor standing in for `super.doGetName()` (`MemorySymbol`/`SymbolDB`'s own naming
    /// logic), used by [`do_get_name`](Self::do_get_name) for the non-default-source,
    /// good-storage case.
    fn base_do_get_name(&self) -> String;

    /// Stands in for `GlobalVariableSymbolDB.doGetName()`.
    fn do_get_name(&self) -> String {
        if !self.is_refreshable() {
            // TODO: SCR
            return "[Invalid Global Variable Symbol - Deleted!]".to_string();
        }

        let storage = self.variable_storage();
        let is_bad = storage.as_ref().map(|s| s.is_bad_storage()).unwrap_or(true);
        if is_bad {
            return format!("{DEFAULT_LOCAL_PREFIX}_!BAD!");
        }

        if self.get_source() == SourceType::Default {
            return self.default_local_name(storage.as_deref().unwrap());
        }

        self.base_do_get_name()
    }

    /// Stands in for the private static `GlobalVariableSymbolDB.getDefaultLocalName(Program,
    /// VariableStorage)`.
    ///
    /// // TODO: move method to SymbolUtilities when support for global variables has been added
    /// (kept from the Java source, which carries the same TODO).
    fn default_local_name(&self, storage: &(dyn crate::program::model::listing::VariableStorage + Send + Sync)) -> String {
        let mut name = String::from("global");
        for v in storage.get_varnodes() {
            name.push('_');
            if let Some(reg) = self.program_register(&v) {
                name.push_str(reg.name());
            } else {
                let addr = v.get_address();
                name.push_str(addr.space().name());
                name.push_str(&format!("{:x}", addr.offset()));
            }
        }
        name
    }

    /// Stands in for `GlobalVariableSymbolDB.isPrimary()`, inherited unchanged from
    /// `VariableSymbolDB`/`MemorySymbol`/`SymbolDB` (all variable symbols are primary). Kept here
    /// as a convenience default since the superclass chain is not ported.
    fn is_primary(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::VariableStorage;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn test_address() -> Address {
        Address::new(space(), 0)
    }

    struct MockStorage {
        varnodes: Vec<Varnode>,
        bad: bool,
    }

    impl VariableStorage for MockStorage {
        fn get_varnodes(&self) -> Vec<Varnode> {
            self.varnodes.clone()
        }
        fn is_bad_storage(&self) -> bool {
            self.bad
        }
    }

    struct MockSymbol {
        name: String,
        source: SourceType,
        storage: Option<Arc<dyn crate::program::model::listing::VariableStorage + Send + Sync>>,
        refreshable: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            GlobalVariableSymbolDb::get_symbol_type(self)
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            GlobalVariableSymbolDb::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    impl GlobalVariableSymbolDb for MockSymbol {
        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }

        fn is_refreshable(&self) -> bool {
            self.refreshable
        }

        fn variable_storage(&self) -> Option<Arc<dyn crate::program::model::listing::VariableStorage + Send + Sync>> {
            self.storage.clone()
        }

        fn base_do_get_name(&self) -> String {
            format!("base:{}", self.name)
        }
    }

    #[test]
    fn defaults_match_java_global_variable_symbol() {
        let sym = MockSymbol {
            name: "ignored".to_string(),
            source: SourceType::UserDefined,
            storage: Some(Arc::new(MockStorage {
                varnodes: Vec::new(),
                bad: false,
            })),
            refreshable: true,
        };
        assert_eq!(GlobalVariableSymbolDb::get_symbol_type(&sym), SymbolType::GlobalVar);
        assert!(GlobalVariableSymbolDb::is_primary(&sym));
        assert_eq!(sym.do_get_name(), "base:ignored");
    }

    #[test]
    fn missing_or_bad_storage_yields_bad_name() {
        let sym = MockSymbol {
            name: "x".to_string(),
            source: SourceType::UserDefined,
            storage: None,
            refreshable: true,
        };
        assert_eq!(sym.do_get_name(), "local__!BAD!");

        let sym_bad = MockSymbol {
            name: "x".to_string(),
            source: SourceType::UserDefined,
            storage: Some(Arc::new(MockStorage {
                varnodes: Vec::new(),
                bad: true,
            })),
            refreshable: true,
        };
        assert_eq!(sym_bad.do_get_name(), "local__!BAD!");
    }

    #[test]
    fn deleted_symbol_reports_invalid() {
        let sym = MockSymbol {
            name: "x".to_string(),
            source: SourceType::UserDefined,
            storage: Some(Arc::new(MockStorage {
                varnodes: Vec::new(),
                bad: false,
            })),
            refreshable: false,
        };
        assert_eq!(sym.do_get_name(), "[Invalid Global Variable Symbol - Deleted!]");
    }

    #[test]
    fn default_source_builds_dynamic_name_from_storage_addresses() {
        let space = space();
        let varnode = Varnode::new(space.address(0x1000), 4);
        let sym = MockSymbol {
            name: "ignored".to_string(),
            source: SourceType::Default,
            storage: Some(Arc::new(MockStorage {
                varnodes: vec![varnode],
                bad: false,
            })),
            refreshable: true,
        };
        assert_eq!(sym.do_get_name(), "global_ram1000");
    }

    #[test]
    #[should_panic]
    fn get_object_always_panics() {
        let sym = MockSymbol {
            name: "x".to_string(),
            source: SourceType::UserDefined,
            storage: None,
            refreshable: true,
        };
        sym.get_object();
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let sym: Box<dyn GlobalVariableSymbolDb> = Box::new(MockSymbol {
            name: "obj_safe".to_string(),
            source: SourceType::UserDefined,
            storage: Some(Arc::new(MockStorage {
                varnodes: Vec::new(),
                bad: false,
            })),
            refreshable: true,
        });
        assert_eq!(sym.do_get_name(), "base:obj_safe");
    }
}
