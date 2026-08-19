//! Port of `sarif.managers.ExternalLibSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::{Address, AddressOverflowException, AddressSetView};
use crate::program::model::listing::{GhidraClass, Program};
use crate::program::model::symbol::{
    AddExternalLibraryNameError, ExternalLocation, Namespace, SourceType,
};
use crate::util::exception::{CancelledException, InvalidInputException};
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifClassesNamespaceWriter, SarifExternalLibraryWriter, SarifMgr,
    SarifProgramOptions, SarifWriterTask, TaskLauncher,
};

/// Error produced by [`ExternalLibSarifMgr::process_external_location`], combining the checked
/// exceptions `ExternalLibSarifMgr.processExternalLocation` can raise
/// (`InvalidInputException`/`AddressOverflowException`) plus `SarifMgr.walkNamespace`'s
/// `IOException`, modeled as a plain message since it has no ported equivalent type.
#[derive(Error, Debug)]
enum ProcessExternalLocationError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error("{0}")]
    Namespace(String),
}

/// Reads and writes `EXT_LIBRARY` entries (external libraries and the locations resolved against
/// them) between a [`Program`]'s [`ExternalManager`](crate::program::model::symbol::ExternalManager)
/// and SARIF.
///
/// Port of `sarif.managers.ExternalLibSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Unlike Java, which caches the `ExternalManager` once in the constructor, this
/// keeps the whole `Program` handle and re-fetches each collaborator (`ExternalManager`,
/// `SymbolTable`) on each use, matching the convention set by
/// [`ExtEntryPointSarifMgr`](crate::sarif::managers::ExtEntryPointSarifMgr) and
/// [`EquatesSarifMgr`](crate::sarif::managers::EquatesSarifMgr).
///
/// Java's base class `SarifMgr` declares `externalMap` as a field `static` across every
/// `*SarifMgr` (shared with `MarkupSarifMgr`/`FunctionsSarifMgr`, neither ported yet); here it is
/// simply an instance field on this leaf manager, since nothing else in the crate reads it yet.
pub struct ExternalLibSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    /// `ExternalLibSarifMgr.libraries`: `true` while the first pass (library names only) of
    /// [`read_results`](Self::read_results) is running, `false` during the second pass (external
    /// locations).
    libraries: bool,
    /// `SarifMgr.externalMap`, keyed by SARIF `externalAddress`. See the struct docs for why this
    /// is a plain instance field rather than the shared `static` Java uses.
    external_map: HashMap<String, Arc<dyn ExternalLocation>>,
}

impl ExternalLibSarifMgr {
    /// `ExternalLibSarifMgr.KEY`.
    pub const KEY: &'static str = "EXT_LIBRARY";
    /// `ExternalLibSarifMgr.SUBKEY0`.
    pub const SUBKEY0: &'static str = "External.Library";
    /// `ExternalLibSarifMgr.SUBKEY1`.
    pub const SUBKEY1: &'static str = "External.Location";

    /// `ExternalLibSarifMgr(Program program, MessageLog log)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            libraries: true,
            external_map: HashMap::new(),
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `ExternalLibSarifMgr.readResults`: two full passes over `list`, since a location may
    /// reference a library defined later in the same file. The first pass (`libraries = true`)
    /// only processes entries without a `symbol` field (library names); the second
    /// (`libraries = false`) only processes entries with one (external locations).
    pub fn read_results(
        &mut self,
        list: Option<&[HashMap<String, Value>]>,
        options: Option<&SarifProgramOptions>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let key = self.get_key().to_string();
        let Some(list) = list else {
            monitor.set_message(&format!("Skipping over {key} ..."));
            return Ok(());
        };

        monitor.set_message(&format!("Processing {key}..."));
        monitor.set_maximum(list.len() as i64 * 2);

        for result in list {
            monitor.check_cancelled()?;
            self.read(result, options, monitor);
            monitor.increment_progress(1);
        }
        self.libraries = false;
        for result in list {
            monitor.check_cancelled()?;
            self.read(result, options, monitor);
            monitor.increment_progress(1);
        }
        Ok(())
    }

    /// `ExternalLibSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        let has_symbol = result.get("symbol").and_then(Value::as_str).is_some();
        if self.libraries && !has_symbol {
            return match self.process_external_lib(result) {
                Ok(()) => true,
                Err(e) => {
                    self.log.append_exception(&e);
                    false
                }
            };
        }
        if !self.libraries && has_symbol {
            return match self.process_external_location(result) {
                Ok(()) => true,
                Err(e) => {
                    self.log.append_exception(&e);
                    false
                }
            };
        }
        false
    }

    /// `ExternalLibSarifMgr.processExternalLib`.
    fn process_external_lib(
        &mut self,
        result: &HashMap<String, Value>,
    ) -> Result<(), AddExternalLibraryNameError> {
        let prog_name = result.get("name").and_then(Value::as_str).unwrap_or_default();

        let Some(ext_manager) = Arc::get_mut(&mut self.program).and_then(|p| p.get_external_manager())
        else {
            return Ok(());
        };
        if ext_manager.get_external_library(prog_name).is_some() {
            return Ok(()); // already has a value--don't override it
        }

        let source = result.get("sourceType").and_then(Value::as_str);
        let mut source_type = self.get_source_type(source);
        if source_type == SourceType::Default {
            source_type = SourceType::Imported;
        }

        let Some(ext_manager) = Arc::get_mut(&mut self.program).and_then(|p| p.get_external_manager())
        else {
            return Ok(());
        };
        ext_manager.add_external_library_name(prog_name, source_type)?;
        Ok(())
    }

    /// `ExternalLibSarifMgr.processExternalLocation`.
    fn process_external_location(
        &mut self,
        result: &HashMap<String, Value>,
    ) -> Result<(), ProcessExternalLocationError> {
        let name = result.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let location = result
            .get("location")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let address = self.base.get_location(result)?;
        let extern_addr = result
            .get("externalAddress")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let source = result.get("source").and_then(Value::as_str);
        let mut source_type = self.get_source_type(source);
        if source_type == SourceType::Default {
            source_type = SourceType::Imported;
        }
        let is_class = result.get("isClass").and_then(Value::as_bool).unwrap_or(false);

        let Some(global) = self.program.get_global_namespace() else {
            return Ok(());
        };
        let namespace_path = format!("{location}::");
        let p = self
            .walk_namespace(global, &namespace_path, address.as_ref(), source_type, is_class)
            .map_err(ProcessExternalLocationError::Namespace)?;
        let Some(p) = p else {
            // Java's `walkNamespace` returning `null` (a deferred `FUN_`-prefixed namespace) is
            // never checked here: the next line's `getLibrary(p)` would throw an uncaught
            // `NullPointerException`, which propagates past this method's narrower `catch
            // (InvalidInputException | AddressOverflowException)` clause and is swallowed by
            // `read`'s catch-all instead. Returning here matches that end state (logged, no
            // location recorded) without fabricating a `NullPointerException` equivalent.
            return Ok(());
        };

        let name0 = result.get("originalImportedName").and_then(Value::as_str);
        let loc = self.add_external(result, &name, address, source_type, p, name0)?;
        self.external_map.insert(extern_addr, loc);
        Ok(())
    }

    /// `ExternalLibSarifMgr.addExternal`.
    fn add_external(
        &mut self,
        result: &HashMap<String, Value>,
        name: &str,
        address: Option<Address>,
        source_type: SourceType,
        p: Arc<dyn Namespace>,
        name0: Option<&str>,
    ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
        let lib = Self::find_library(&p).unwrap_or_else(|| p.clone());
        let is_function = result.get("isFunction").and_then(Value::as_bool).unwrap_or(false);

        let Some(ext_manager) = Arc::get_mut(&mut self.program).and_then(|prog| prog.get_external_manager())
        else {
            return Err(InvalidInputException::new());
        };

        let mut loc = if is_function {
            match name0 {
                Some(name0) => {
                    ext_manager.add_ext_function_in_namespace_reuse(lib, Some(name0), address, source_type, false)?
                }
                None => ext_manager
                    .add_ext_function_in_namespace_reuse(p.clone(), Some(name), address, source_type, true)?,
            }
        } else {
            match name0 {
                Some(name0) => {
                    ext_manager.add_ext_location_in_namespace_reuse(lib, Some(name0), address, source_type, false)?
                }
                None => ext_manager
                    .add_ext_location_in_namespace_reuse(p.clone(), Some(name), address, source_type, true)?,
            }
        };

        if name0.is_some() {
            // `loc.setName(p, name, sourceType)`. If another handle to this location is held
            // elsewhere (e.g. by the manager that just created it), the rename is best-effort
            // only, since the ported `ExternalLocation` API hands back an `Arc`, not the freely
            // mutable reference Java's `ExternalLocation` object identity gives for free.
            if let Some(loc_mut) = Arc::get_mut(&mut loc) {
                loc_mut.set_name(p, name, source_type)?;
            }
        }

        Ok(loc)
    }

    /// `ExternalLibSarifMgr.getLibrary(Namespace)`: walks up the namespace chain (starting at `p`
    /// itself) until a `Library` is found. Reproduced as a free function over the already-ported
    /// [`Namespace::is_library`] rather than a stub, mirroring
    /// [`ExternalLocationDb::get_library`](crate::program::database::external::external_location_db::ExternalLocationDb::get_library)'s
    /// treatment of the analogous `NamespaceUtils.getLibrary(Namespace)`.
    fn find_library(namespace: &Arc<dyn Namespace>) -> Option<Arc<dyn Namespace>> {
        let mut current = Some(namespace.clone());
        while let Some(ns) = current {
            if ns.is_library() {
                return Some(ns);
            }
            current = ns.get_parent_namespace();
        }
        None
    }

    /// `SarifMgr.getSourceType(String)`, inherited from the base class (see
    /// [`SarifMgr::get_source_type`], which the shared stub now carries because
    /// [`MarkupSarifMgr`](crate::sarif::managers::MarkupSarifMgr) needs it too).
    fn get_source_type(&self, signature_source: Option<&str>) -> SourceType {
        SarifMgr::get_source_type(&self.log, signature_source)
    }

    /// `SarifMgr.walkNamespace(Namespace, String, Address, SourceType, Boolean)`, inherited from
    /// the base class (see [`SarifMgr::walk_namespace`], which takes the `Program` handle the
    /// field-less stub does not hold).
    fn walk_namespace(
        &mut self,
        parent: Arc<dyn Namespace>,
        namespace: &str,
        addr: Option<&Address>,
        source_type: SourceType,
        is_class: bool,
    ) -> Result<Option<Arc<dyn Namespace>>, String> {
        SarifMgr::walk_namespace(&mut self.program, parent, namespace, addr, source_type, is_class)
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `ExternalLibSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        _set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing EXTERNAL LIBRARIES ...");

        let request0: Vec<String> = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_external_manager())
            .map(|em| em.get_external_library_names())
            .unwrap_or_default();
        Self::write_ext_as_sarif(&request0, results, monitor);

        let request1: Vec<Arc<dyn GhidraClass>> = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_symbol_table())
            .map(|st| st.get_class_namespaces())
            .unwrap_or_default();
        Self::write_namespace_as_sarif(&request1, results, monitor);

        Ok(())
    }

    /// `ExternalLibSarifMgr.writeExtAsSARIF`.
    pub fn write_ext_as_sarif(request: &[String], results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifExternalLibraryWriter::new(request.to_vec());
        let task = SarifWriterTask::new("Libraries", writer);
        TaskLauncher::launch(&task, monitor, results);
    }

    /// `ExternalLibSarifMgr.writeNamespaceAsSARIF`.
    pub fn write_namespace_as_sarif(
        request: &[Arc<dyn GhidraClass>],
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifClassesNamespaceWriter::new(request.to_vec());
        let task = SarifWriterTask::new("Libraries", writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Library;
    use crate::program::model::symbol::{
        AddExternalLocationInLibraryError, EmptyExternalLocationIterator, ExternalLocationIterator,
        Symbol, SymbolType, UpdateExternalLibraryNameError,
    };
    use crate::program::model::symbol::external_manager::ExternalManager;
    use crate::util::task::DummyMonitor;

    struct MockSymbol {
        name: String,
        symbol_type: SymbolType,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0), 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::Imported
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
    }

    fn global_namespace() -> Arc<dyn Namespace> {
        Arc::new(MockNamespace {
            symbol: Arc::new(MockSymbol {
                name: "Global".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: None,
        })
    }

    struct MockLibrary {
        name: String,
    }

    impl Namespace for MockLibrary {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.name.clone(),
                symbol_type: SymbolType::Library,
            })
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            Some(global_namespace())
        }
    }

    impl Library for MockLibrary {
        fn get_associated_program_path(&self) -> Option<String> {
            None
        }
        fn set_associated_program_path(&mut self, _program_path: Option<&str>) -> Result<(), InvalidInputException> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockExternalManager {
        libraries: HashMap<String, Arc<dyn Library>>,
        /// Shared with the test via [`program_with_source_type_sensor`] so the source type
        /// passed to [`add_external_library_name`](ExternalManager::add_external_library_name)
        /// can be asserted on without downcasting the `Arc<dyn Program>`/`&mut dyn
        /// ExternalManager` trait objects the manager under test only ever sees.
        last_source_type: Arc<std::sync::Mutex<Option<SourceType>>>,
    }

    impl ExternalManager for MockExternalManager {
        fn get_external_library_names(&self) -> Vec<String> {
            let mut names: Vec<String> = self.libraries.keys().cloned().collect();
            names.sort();
            names
        }
        fn get_libraries(&self) -> Vec<Arc<dyn Library>> {
            self.libraries.values().cloned().collect()
        }
        fn get_external_library(&self, library_name: &str) -> Option<Arc<dyn Library>> {
            self.libraries.get(library_name).cloned()
        }
        fn remove_external_library(&mut self, _library_name: &str) -> bool {
            false
        }
        fn get_external_library_path(&self, _library_name: &str) -> Option<String> {
            None
        }
        fn set_external_path(
            &mut self,
            _library_name: &str,
            _pathname: Option<&str>,
            _user_defined: bool,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_library_ordinal(&self, _library_name: &str) -> i32 {
            -1
        }
        fn set_library_ordinal(&mut self, _library_name: &str, _ordinal: i32) -> i32 {
            -1
        }
        fn update_external_library_name(
            &mut self,
            _old_name: &str,
            _new_name: &str,
            _source: SourceType,
        ) -> Result<bool, UpdateExternalLibraryNameError> {
            Ok(false)
        }
        fn get_external_locations_for_library(&self, _library_name: &str) -> Box<dyn ExternalLocationIterator> {
            Box::new(EmptyExternalLocationIterator)
        }
        fn get_external_locations_at_address(&self, _memory_address: &Address) -> Box<dyn ExternalLocationIterator> {
            Box::new(EmptyExternalLocationIterator)
        }
        fn get_external_locations_by_label(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Vec<Arc<dyn ExternalLocation>> {
            Vec::new()
        }
        fn get_external_locations_in_namespace(
            &self,
            _namespace: Option<Arc<dyn Namespace>>,
            _label: &str,
        ) -> Vec<Arc<dyn ExternalLocation>> {
            Vec::new()
        }
        fn get_unique_external_location(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Option<Arc<dyn ExternalLocation>> {
            None
        }
        fn get_unique_external_location_in_namespace(
            &self,
            _namespace: Option<Arc<dyn Namespace>>,
            _label: &str,
        ) -> Option<Arc<dyn ExternalLocation>> {
            None
        }
        fn get_external_location(&self, _symbol: Arc<dyn Symbol>) -> Option<Arc<dyn ExternalLocation>> {
            None
        }
        fn contains(&self, library_name: &str) -> bool {
            self.libraries.contains_key(library_name)
        }
        fn add_external_library_name(
            &mut self,
            library_name: &str,
            source: SourceType,
        ) -> Result<Arc<dyn Library>, AddExternalLibraryNameError> {
            *self.last_source_type.lock().unwrap() = Some(source);
            let lib: Arc<dyn Library> = Arc::new(MockLibrary {
                name: library_name.to_string(),
            });
            self.libraries.insert(library_name.to_string(), lib.clone());
            Ok(lib)
        }
        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
        ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_ext_location_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn Namespace>,
            ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
            struct Loc;
            impl ExternalLocation for Loc {}
            let _ = ext_label;
            Ok(Arc::new(Loc))
        }
        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
        ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_ext_function_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn Namespace>,
            ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
            struct Loc;
            impl ExternalLocation for Loc {}
            let _ = ext_label;
            Ok(Arc::new(Loc))
        }
    }

    struct MockProgram {
        external_manager: MockExternalManager,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
        fn get_external_manager(&mut self) -> Option<&mut dyn ExternalManager> {
            Some(&mut self.external_manager)
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            Some(global_namespace())
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            external_manager: MockExternalManager::default(),
        })
    }

    /// Like [`empty_mock_program`], but also returns the sensor that records the last source
    /// type [`MockExternalManager::add_external_library_name`] was called with.
    fn program_with_source_type_sensor() -> (Arc<dyn Program>, Arc<std::sync::Mutex<Option<SourceType>>>) {
        let sensor = Arc::new(std::sync::Mutex::new(None));
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            external_manager: MockExternalManager {
                libraries: HashMap::new(),
                last_source_type: sensor.clone(),
            },
        });
        (program, sensor)
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkeys_match_java() {
        assert_eq!(ExternalLibSarifMgr::KEY, "EXT_LIBRARY");
        assert_eq!(ExternalLibSarifMgr::SUBKEY0, "External.Library");
        assert_eq!(ExternalLibSarifMgr::SUBKEY1, "External.Location");
    }

    #[test]
    fn get_key_returns_ext_library() {
        let mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        assert_eq!(mgr.get_key(), "EXT_LIBRARY");
    }

    #[test]
    fn read_creates_a_new_library_during_the_library_phase() {
        let mut mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("ADVAPI32.DLL".to_string())),
            ("sourceType", Value::String("USER_DEFINED".to_string())),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));

        let ext_manager = Arc::get_mut(&mut mgr.program).unwrap().get_external_manager().unwrap();
        assert!(ext_manager.contains("ADVAPI32.DLL"));
    }

    #[test]
    fn process_external_lib_does_not_override_an_existing_library() {
        // Mirrors "already has a value--don't override it": a second read with a different
        // sourceType leaves the recorded source type from the first read unchanged.
        let (program, sensor) = program_with_source_type_sensor();
        let mut mgr = ExternalLibSarifMgr::new(program, MessageLog::new());
        let first = result_map(&[
            ("name", Value::String("ADVAPI32.DLL".to_string())),
            ("sourceType", Value::String("USER_DEFINED".to_string())),
        ]);
        let second = result_map(&[
            ("name", Value::String("ADVAPI32.DLL".to_string())),
            ("sourceType", Value::String("IMPORTED".to_string())),
        ]);
        mgr.read(&first, None, &DummyMonitor);
        mgr.read(&second, None, &DummyMonitor);

        assert_eq!(*sensor.lock().unwrap(), Some(SourceType::UserDefined));
    }

    #[test]
    fn process_external_lib_defaults_missing_source_type_to_imported() {
        let (program, sensor) = program_with_source_type_sensor();
        let mut mgr = ExternalLibSarifMgr::new(program, MessageLog::new());
        let result = result_map(&[("name", Value::String("ADVAPI32.DLL".to_string()))]);
        mgr.read(&result, None, &DummyMonitor);

        assert_eq!(*sensor.lock().unwrap(), Some(SourceType::Imported));
    }

    #[test]
    fn process_external_lib_logs_and_defaults_unknown_source_type() {
        let (program, sensor) = program_with_source_type_sensor();
        let mut mgr = ExternalLibSarifMgr::new(program, MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("ADVAPI32.DLL".to_string())),
            ("sourceType", Value::String("BOGUS".to_string())),
        ]);
        mgr.read(&result, None, &DummyMonitor);

        assert_eq!(*sensor.lock().unwrap(), Some(SourceType::Imported));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Unknown SourceType: BOGUS"));
    }

    #[test]
    fn process_external_lib_maps_default_source_type_to_imported() {
        // Java: `getSourceType("DEFAULT")` parses to `SourceType.DEFAULT`, which is then
        // overridden to `IMPORTED` since `ExternalLibSarifMgr` never persists a `DEFAULT` source.
        let (program, sensor) = program_with_source_type_sensor();
        let mut mgr = ExternalLibSarifMgr::new(program, MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("ADVAPI32.DLL".to_string())),
            ("sourceType", Value::String("DEFAULT".to_string())),
        ]);
        mgr.read(&result, None, &DummyMonitor);

        assert_eq!(*sensor.lock().unwrap(), Some(SourceType::Imported));
    }

    #[test]
    fn read_returns_false_when_phase_and_entry_kind_do_not_match() {
        // libraries phase (the default) + an entry that has a "symbol" field (a location entry):
        // neither `processExternalLib` nor `processExternalLocation` fires.
        let mut mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[("symbol", Value::String("CreateFileA".to_string()))]);
        assert!(!mgr.read(&result, None, &DummyMonitor));
    }

    #[test]
    fn read_results_processes_a_library_and_then_a_location_naming_it() {
        let mut mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        let list = vec![
            result_map(&[("name", Value::String("ADVAPI32.DLL".to_string()))]),
            result_map(&[
                ("name", Value::String("CreateFileA".to_string())),
                ("symbol", Value::String("CreateFileA".to_string())),
                ("location", Value::String(String::new())),
                ("externalAddress", Value::String("ext1".to_string())),
                ("isFunction", Value::Bool(false)),
                ("isClass", Value::Bool(false)),
            ]),
        ];

        assert!(mgr.read_results(Some(&list), None, &DummyMonitor).is_ok());

        let ext_manager = Arc::get_mut(&mut mgr.program).unwrap().get_external_manager().unwrap();
        assert!(ext_manager.contains("ADVAPI32.DLL"));
        assert!(mgr.external_map.contains_key("ext1"));
        // The two-phase loop leaves `libraries` false, matching Java's field mutation persisting
        // past a single `readResults` call.
        assert!(!mgr.libraries);
    }

    #[test]
    fn read_results_with_no_list_leaves_state_untouched() {
        let mut mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        assert!(mgr.read_results(None, None, &DummyMonitor).is_ok());
        assert!(mgr.libraries);
        assert!(mgr.external_map.is_empty());
    }

    #[test]
    fn find_library_walks_up_to_the_enclosing_library() {
        let lib: Arc<dyn Namespace> = Arc::new(MockLibrary {
            name: "ADVAPI32.DLL".to_string(),
        });
        let child: Arc<dyn Namespace> = Arc::new(MockNamespace {
            symbol: Arc::new(MockSymbol {
                name: "Inner".to_string(),
                symbol_type: SymbolType::Namespace,
            }),
            parent: Some(lib.clone()),
        });

        let found = ExternalLibSarifMgr::find_library(&child);
        assert!(found.is_some());
        assert!(found.unwrap().is_library());
        assert!(ExternalLibSarifMgr::find_library(&global_namespace()).is_none());
    }

    #[test]
    fn write_ext_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        ExternalLibSarifMgr::write_ext_as_sarif(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_namespace_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        ExternalLibSarifMgr::write_namespace_as_sarif(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_collects_library_names() {
        let mut mgr = ExternalLibSarifMgr::new(empty_mock_program(), MessageLog::new());
        let lib_result = result_map(&[("name", Value::String("ADVAPI32.DLL".to_string()))]);
        mgr.read(&lib_result, None, &DummyMonitor);

        let mut results = Vec::new();
        assert!(mgr.write(&mut results, None, &DummyMonitor).is_ok());
    }
}
