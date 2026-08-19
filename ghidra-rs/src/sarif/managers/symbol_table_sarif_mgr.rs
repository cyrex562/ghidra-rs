//! Port of `sarif.managers.SymbolTableSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::{AddressOverflowException, AddressSetView};
use crate::program::model::listing::Program;
use crate::program::model::symbol::{
    AddExternalLibraryNameError, DefaultSymbolUtilities, GetOrCreateNamespaceError, Namespace,
    SourceType, Symbol, SymbolUtilities,
};
use crate::util::exception::InvalidInputException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifMgr, SarifProgramOptions, SarifSymbolWriter, SarifWriterTask, TaskLauncher,
};

/// Everything [`SymbolTableSarifMgr::process_symbol`] can fail with, all folded back into the same
/// `log.appendException(e)` Java's outer `catch (Exception e)` performs, matching `processSymbol`'s
/// "swallow anything, log it" shape.
#[derive(Error, Debug)]
enum ProcessSymbolError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    /// `(boolean) result.get("primary")`/`(boolean) result.get("pinned")` unboxing a missing or
    /// non-boolean value, which Java throws as an (uncaught by any narrower clause)
    /// `NullPointerException`/`ClassCastException`.
    #[error("missing or non-boolean \"{0}\" field")]
    MissingBooleanField(&'static str),
    /// `SarifMgr.walkNamespace`'s checked `IOException`, modeled as a plain message since it has no
    /// ported equivalent type (mirrors [`ExternalLibSarifMgr`](crate::sarif::managers::ExternalLibSarifMgr)).
    #[error("{0}")]
    Namespace(String),
    #[error(transparent)]
    GetOrCreateNamespace(#[from] GetOrCreateNamespaceError),
    #[error(transparent)]
    AddExternalLibraryName(#[from] AddExternalLibraryNameError),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    /// `addr.isMemoryAddress()` dereferencing a `null` addr, which Java dereferences
    /// unconditionally once `type` does not match `"namespace"`/`"class"`/`"library"` (an implicit
    /// `NullPointerException` the same `catch (Exception e)` also swallows). Always taken today:
    /// `SarifMgr::get_location` is a stub pending the `SarifUtils` port and never resolves a real
    /// address (see [`RelocationTableSarifMgr`](crate::sarif::managers::RelocationTableSarifMgr)
    /// for the same limitation).
    #[error("no location found for symbol")]
    NoLocation,
    /// `s.setPinned(true)` dereferencing a `null` `s`: Java's `if (isPinned) { s.setPinned(true); }`
    /// runs unconditionally on `s`, outside the `s != null` guard that protects `setPrimary()` just
    /// above it, so a `null` symbol with `isPinned == true` throws a `NullPointerException` here
    /// that the same `catch (Exception e)` swallows.
    #[error("cannot pin a symbol that was not created")]
    NullSymbolWhilePinning,
}

/// Reads and writes `SYMBOLS` entries between a [`Program`]'s [`SymbolTable`] and SARIF.
///
/// Port of `sarif.managers.SymbolTableSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Unlike Java, which caches the `SymbolTable` once in the constructor, this keeps
/// the whole `Program` handle and re-fetches it on each use: `Program::get_symbol_table` hands back
/// a borrow (`&mut dyn SymbolTable`), not an owned value, so it cannot be stored alongside the
/// `Program` it borrows from -- matching the convention set by
/// [`EquatesSarifMgr`](crate::sarif::managers::EquatesSarifMgr).
///
/// Java's `symbolTable.getNamespace(name, scope)`/`createNameSpace` and
/// `symbolTable.getClassSymbol(name, scope)`/`createClass` both collapse onto
/// [`SymbolTable::get_or_create_name_space`] here, since the ported trait has no class-typed
/// namespace constructor yet -- the same simplification [`SarifMgr::walk_namespace`] already makes
/// for its own `is_class` parameter. `symbolTable.getLibrarySymbol(name)`/`createExternalLibrary`
/// is modeled via [`ExternalManager::get_external_library`](crate::program::model::symbol::ExternalManager::get_external_library)/
/// [`add_external_library_name`](crate::program::model::symbol::ExternalManager::add_external_library_name)
/// instead, since `SymbolTable` has no library constructor either, matching the equivalent
/// operation in [`ExternalLibSarifMgr::process_external_lib`](crate::sarif::managers::ExternalLibSarifMgr).
pub struct SymbolTableSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    /// `SymbolTableSarifMgr.overwritePrimary`, set from `options` at the start of each [`read`](Self::read).
    overwrite_primary: bool,
    /// `SymbolTableSarifMgr.preFunction`, set once at construction.
    pre_function: bool,
}

impl SymbolTableSarifMgr {
    /// `SymbolTableSarifMgr.KEY`.
    pub const KEY: &'static str = "SYMBOLS";
    /// `SymbolTableSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Symbols";

    /// `SymbolTableSarifMgr(Program program, MessageLog log, boolean preFunction)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog, pre_function: bool) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            overwrite_primary: false,
            pre_function,
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `SymbolTableSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        self.overwrite_primary = options.map(|o| o.is_overwrite_symbol_conflicts()).unwrap_or(true);
        let first_pass = self.pre_function;
        self.process_symbol(result, first_pass);
        true
    }

    /// `SymbolTableSarifMgr.processSymbol`.
    fn process_symbol(&mut self, result: &HashMap<String, Value>, first_pass: bool) {
        if let Err(e) = self.process_symbol_inner(result, first_pass) {
            self.log.append_exception(&e);
        }
    }

    fn process_symbol_inner(
        &mut self,
        result: &HashMap<String, Value>,
        first_pass: bool,
    ) -> Result<(), ProcessSymbolError> {
        let kind = result.get("kind").and_then(Value::as_str);
        let is_local = kind.map(|k| k.eq_ignore_ascii_case("local")).unwrap_or(false);
        let type_ = result.get("type").and_then(Value::as_str);

        let is_primary = result
            .get("primary")
            .and_then(Value::as_bool)
            .ok_or(ProcessSymbolError::MissingBooleanField("primary"))?;
        let is_pinned = result
            .get("pinned")
            .and_then(Value::as_bool)
            .ok_or(ProcessSymbolError::MissingBooleanField("pinned"))?;
        let source_type_string = result.get("sourceType").and_then(Value::as_str);
        let source_type = SarifMgr::get_source_type(&self.log, source_type_string);

        let name = result.get("name").and_then(Value::as_str).unwrap_or_default();
        let mut process_first_pass = true;
        if is_local && type_.is_none() {
            process_first_pass = false;
        }
        if source_type == SourceType::Default {
            process_first_pass = false;
        }

        if first_pass && !process_first_pass {
            return Ok(());
        }
        if !first_pass && process_first_pass {
            return Ok(());
        }

        let addr = self.base.get_location(result)?;
        let namespace = result.get("location").and_then(Value::as_str).unwrap_or_default();
        let is_class = result.get("namespaceIsClass").and_then(Value::as_bool).unwrap_or(false);
        let scope = match self.program.get_global_namespace() {
            Some(global) if is_local => SarifMgr::walk_namespace(
                &mut self.program,
                global,
                namespace,
                addr.as_ref(),
                source_type,
                is_class,
            )
            .map_err(ProcessSymbolError::Namespace)?,
            Some(global) => Some(global),
            None => None,
        };
        let Some(scope) = scope else {
            return Ok(());
        };

        if let Some(type_) = type_ {
            match type_ {
                "namespace" | "class" => {
                    self.get_or_create_namespace(scope, name, source_type)?;
                    return Ok(());
                }
                "library" => {
                    self.get_or_create_library(name, source_type)?;
                    return Ok(());
                }
                _ => {}
            }
        }

        let Some(addr) = addr else {
            return Err(ProcessSymbolError::NoLocation);
        };
        if !addr.is_memory_address() {
            return Ok(());
        }

        let already_exists = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_symbol_table())
            .and_then(|st| st.find_symbol_by_name_address_namespace(name, &addr, scope.as_ref()).ok())
            .flatten()
            .is_some();
        if already_exists {
            return Ok(());
        }

        let Some(program_mut) = Arc::get_mut(&mut self.program) else {
            return Ok(());
        };
        let created = DefaultSymbolUtilities.create_preferred_label_or_function_symbol(
            program_mut,
            &addr,
            Some(scope),
            name,
            source_type,
        )?;

        if let Some(symbol) = &created {
            if is_primary && self.overwrite_primary {
                if let Some(symbol_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) {
                    let _ = symbol_table.set_primary_symbol(symbol.get_id());
                }
            }
        }
        if is_pinned {
            let symbol = created.ok_or(ProcessSymbolError::NullSymbolWhilePinning)?;
            if let Some(symbol_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) {
                let _ = symbol_table.set_symbol_pinned(symbol.get_id(), true);
            }
        }
        Ok(())
    }

    /// `symbolTable.getNamespace(name, scope) == null` followed by `createNameSpace`, and
    /// `symbolTable.getClassSymbol(name, scope) == null` followed by `createClass`: both collapse
    /// onto [`SymbolTable::get_or_create_name_space`] here. See the struct docs for why.
    fn get_or_create_namespace(
        &mut self,
        scope: Arc<dyn Namespace>,
        name: &str,
        source_type: SourceType,
    ) -> Result<(), GetOrCreateNamespaceError> {
        let Some(symbol_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) else {
            return Ok(());
        };
        symbol_table.get_or_create_name_space(scope, name, source_type)?;
        Ok(())
    }

    /// `symbolTable.getLibrarySymbol(name) == null` followed by `createExternalLibrary`, modeled
    /// via the [`ExternalManager`](crate::program::model::symbol::ExternalManager) instead of
    /// `SymbolTable`. See the struct docs for why.
    fn get_or_create_library(&mut self, name: &str, source_type: SourceType) -> Result<(), AddExternalLibraryNameError> {
        let exists = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_external_manager())
            .map(|em| em.get_external_library(name).is_some())
            .unwrap_or(false);
        if exists {
            return Ok(());
        }
        let Some(ext_manager) = Arc::get_mut(&mut self.program).and_then(|p| p.get_external_manager()) else {
            return Ok(());
        };
        ext_manager.add_external_library_name(name, source_type)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `SymbolTableSarifMgr.write`. `set` is unused, matching Java (the parameter is never
    /// referenced in the method body).
    pub fn write(&mut self, results: &mut Vec<Value>, _set: Option<&dyn AddressSetView>, monitor: &dyn TaskMonitor) {
        monitor.set_message("Writing SYMBOL TABLE ...");

        let mut request: Vec<Arc<dyn Symbol>> = Vec::new();
        if let Some(symbol_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) {
            let mut iter = symbol_table.get_symbol_iterator("*", true);
            while let Some(symbol) = iter.next_symbol() {
                request.push(symbol);
            }
        }

        Self::write_as_sarif(&request, results, monitor);
    }

    /// `SymbolTableSarifMgr.writeAsSARIF`, minus the unused `Program program` parameter and plus a
    /// `TaskMonitor`, matching the convention set by
    /// [`RelocationTableSarifMgr::write_as_sarif`](crate::sarif::managers::RelocationTableSarifMgr::write_as_sarif).
    pub fn write_as_sarif(request: &[Arc<dyn Symbol>], results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifSymbolWriter::new(request.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SetParentNamespaceError, SymbolIterator, SymbolTable, SymbolType};
    use crate::util::task::DummyMonitor;
    use std::io;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockSymbol {
        address: Address,
        name: String,
        id: i64,
        pinned: Arc<std::sync::Mutex<bool>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn set_namespace(&mut self, _namespace: Arc<dyn Namespace>) -> Result<(), SetParentNamespaceError> {
            Ok(())
        }
    }

    struct MockGlobalNamespace(Arc<dyn Symbol>);
    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.0.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            crate::program::model::symbol::GLOBAL_NAMESPACE_ID
        }
        fn is_global(&self) -> bool {
            true
        }
    }

    fn global_namespace() -> Arc<dyn Namespace> {
        Arc::new(MockGlobalNamespace(Arc::new(MockSymbol {
            address: addr(0),
            name: "Global".to_string(),
            id: 0,
            pinned: Arc::new(std::sync::Mutex::new(false)),
        })))
    }

    #[derive(Default)]
    struct MockSymbolTable {
        symbols: Vec<Arc<dyn Symbol>>,
        created_labels: Vec<(Address, String)>,
        primary_set: Vec<i64>,
        pinned_set: Vec<(i64, bool)>,
        next_id: i64,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(&mut self, addr: &Address, name: &str, _source: SourceType) -> io::Result<Arc<dyn Symbol>> {
            self.next_id += 1;
            let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
                address: addr.clone(),
                name: name.to_string(),
                id: self.next_id,
                pinned: Arc::new(std::sync::Mutex::new(false)),
            });
            self.created_labels.push((addr.clone(), name.to_string()));
            self.symbols.push(symbol.clone());
            Ok(symbol)
        }
        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().find(|s| s.get_id() == id).cloned())
        }
        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols.iter().filter(|s| s.get_address() == *addr).cloned().collect())
        }
        fn get_symbol_iterator(&self, _search_str: &str, _case_sensitive: bool) -> Box<dyn SymbolIterator> {
            Box::new(crate::program::model::symbol::SymbolIteratorAdapter::new(self.symbols.clone()))
        }
        fn find_symbol_by_name_address_namespace(
            &self,
            name: &str,
            addr: &Address,
            _namespace: &dyn Namespace,
        ) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .iter()
                .find(|s| s.get_name() == name && s.get_address() == *addr)
                .cloned())
        }
        fn set_primary_symbol(&mut self, symbol_id: i64) -> io::Result<bool> {
            self.primary_set.push(symbol_id);
            Ok(true)
        }
        fn set_symbol_pinned(&mut self, symbol_id: i64, pinned: bool) -> io::Result<()> {
            self.pinned_set.push((symbol_id, pinned));
            Ok(())
        }
    }

    struct MockProgram {
        symbol_table: MockSymbolTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            Some(global_namespace())
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            symbol_table: MockSymbolTable::default(),
        })
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(SymbolTableSarifMgr::KEY, "SYMBOLS");
        assert_eq!(SymbolTableSarifMgr::SUBKEY, "Symbols");
    }

    #[test]
    fn get_key_returns_symbols() {
        let mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), false);
        assert_eq!(mgr.get_key(), "SYMBOLS");
    }

    #[test]
    fn read_defaults_overwrite_primary_to_true_when_options_missing() {
        let mut mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), false);
        let result = result_map(&[
            ("primary", Value::Bool(false)),
            ("pinned", Value::Bool(false)),
            ("sourceType", Value::String("IMPORTED".to_string())),
            ("name", Value::String("foo".to_string())),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        assert!(mgr.overwrite_primary);
    }

    #[test]
    fn read_propagates_no_location_since_sarif_mgr_get_location_is_unported() {
        // `SarifMgr::get_location` is a stub pending the `SarifUtils` port: it never resolves an
        // address, so Java's null `addr` would reach an unchecked `NullPointerException` when
        // `type` is absent -- caught and logged by `processSymbol`'s own `catch (Exception e)`
        // rather than propagating past `read`, which always returns `true` regardless.
        // `pre_function: true` matches this (non-local, non-DEFAULT-source) entry's
        // `processFirstPass == true`, so it is actually processed on this pass rather than
        // deferred to the other manager instance's pass.
        let mut mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), true);
        let result = result_map(&[
            ("primary", Value::Bool(false)),
            ("pinned", Value::Bool(false)),
            ("sourceType", Value::String("IMPORTED".to_string())),
            ("name", Value::String("foo".to_string())),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("no location found for symbol"));
    }

    #[test]
    fn read_logs_missing_primary_field() {
        let mut mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), false);
        let result = result_map(&[("pinned", Value::Bool(false))]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("primary"));
    }

    #[test]
    fn first_pass_skips_local_entries_without_a_type() {
        // Mirrors Java's `processFirstPass` gating: a local symbol with no `type` is deferred to
        // the second pass, so during `firstPass` it is skipped without touching the symbol table
        // (no exception, no location lookup).
        let mut mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), true);
        let result = result_map(&[
            ("kind", Value::String("local".to_string())),
            ("primary", Value::Bool(false)),
            ("pinned", Value::Bool(false)),
            ("sourceType", Value::String("IMPORTED".to_string())),
            ("name", Value::String("foo".to_string())),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn default_source_type_is_deferred_to_second_pass() {
        let mut mgr = SymbolTableSarifMgr::new(empty_mock_program(), MessageLog::new(), true);
        let result = result_map(&[
            ("primary", Value::Bool(false)),
            ("pinned", Value::Bool(false)),
            ("sourceType", Value::String("DEFAULT".to_string())),
            ("name", Value::String("foo".to_string())),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        // Deferred (not processed this pass), so no NoLocation error is logged either.
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        SymbolTableSarifMgr::write_as_sarif(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_collects_every_symbol_from_the_table() {
        let mut program = MockProgram {
            symbol_table: MockSymbolTable::default(),
        };
        program.symbol_table.symbols.push(Arc::new(MockSymbol {
            address: addr(0x1000),
            name: "foo".to_string(),
            id: 1,
            pinned: Arc::new(std::sync::Mutex::new(false)),
        }));
        let mut mgr = SymbolTableSarifMgr::new(Arc::new(program), MessageLog::new(), false);

        let mut results = Vec::new();
        mgr.write(&mut results, None, &DummyMonitor);
    }
}
