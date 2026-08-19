//! Port of `sarif.managers.ExtEntryPointSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;
use crate::util::exception::{CancelledException, NoValueException};
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifEntryPointWriter, SarifMgr, SarifProgramOptions, SarifWriterTask, TaskLauncher,
};

/// Reads and writes `ENTRY_POINTS` entries between a [`Program`]'s [`SymbolTable`](crate::program::model::symbol::SymbolTable)
/// and SARIF.
///
/// Port of `sarif.managers.ExtEntryPointSarifMgr`, which extends the abstract `SarifMgr`; that
/// base class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which
/// Rust does not have. Unlike Java, which caches the `SymbolTable` once in the constructor, this
/// keeps the whole `Program` handle and re-fetches the table on each use: `Program::get_symbol_table`
/// hands back a borrow (`&mut dyn SymbolTable`), not an owned value, so it cannot be stored
/// alongside the `Program` it borrows from.
pub struct ExtEntryPointSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl ExtEntryPointSarifMgr {
    /// `ExtEntryPointSarifMgr.KEY`.
    pub const KEY: &'static str = "ENTRY_POINTS";
    /// `ExtEntryPointSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Entry Point";

    /// `ExtEntryPointSarifMgr(Program program, MessageLog log)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `ExtEntryPointSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        self.process_entry_point(result)
    }

    fn process_entry_point(&mut self, result: &HashMap<String, Value>) -> bool {
        let addr = match self.base.get_location(result) {
            Ok(Some(addr)) => addr,
            // Java calls `symbolTable.addExternalEntryPoint(addr)` unconditionally, so a `null`
            // location falls through to the generic `catch (Exception e)` arm (a
            // `NullPointerException`) rather than being checked explicitly.
            Ok(None) => {
                self.log.append_exception(&NoValueException::new());
                return false;
            }
            Err(e) => {
                self.log.append_exception(&e);
                return false;
            }
        };

        let Some(symbol_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) else {
            self.log.append_exception(&NoValueException::new());
            return false;
        };

        match symbol_table.add_external_entry_point(&addr) {
            Ok(()) => true,
            Err(e) => {
                self.log.append_exception(&e);
                false
            }
        }
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `ExtEntryPointSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        _set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing ENTRY POINTS ...");

        let request: Vec<_> = match Arc::get_mut(&mut self.program).and_then(|p| p.get_symbol_table()) {
            Some(symbol_table) => symbol_table.get_external_entry_point_iterator().collect(),
            None => Vec::new(),
        };

        Self::write_as_sarif(&request, results, monitor);
        Ok(())
    }

    /// `ExtEntryPointSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(
        request: &[crate::program::model::address::Address],
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifEntryPointWriter::new(request.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Symbol, SymbolTable};
    use crate::util::task::DummyMonitor;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    struct MockSymbolTable {
        entry_points: Vec<Address>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: crate::program::model::symbol::source_type::SourceType,
        ) -> std::io::Result<Arc<dyn Symbol>> {
            unimplemented!("not needed for smoke tests")
        }

        fn get_symbol(&self, _id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }

        fn get_symbols(&self, _addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }

        fn add_external_entry_point(&mut self, addr: &Address) -> std::io::Result<()> {
            self.entry_points.push(addr.clone());
            Ok(())
        }

        fn get_external_entry_point_iterator(
            &self,
        ) -> crate::program::model::address::BoxedAddressIterator {
            Box::new(self.entry_points.clone().into_iter())
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
            "mock:LE:64:default".to_string()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            symbol_table: MockSymbolTable {
                entry_points: Vec::new(),
            },
        })
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(ExtEntryPointSarifMgr::KEY, "ENTRY_POINTS");
        assert_eq!(ExtEntryPointSarifMgr::SUBKEY, "Entry Point");
    }

    #[test]
    fn get_key_returns_entry_points() {
        let mgr = ExtEntryPointSarifMgr::new(empty_mock_program(), MessageLog::new());
        assert_eq!(mgr.get_key(), "ENTRY_POINTS");
    }

    #[test]
    fn read_without_location_logs_and_returns_false() {
        // `SarifMgr::get_location` is a stub pending `SarifUtils`, so it never resolves an
        // address; mirrors the Java code hitting `addExternalEntryPoint(null)` and being caught
        // by the generic `Exception` handler.
        let mut mgr = ExtEntryPointSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[]);
        assert!(!mgr.read(&result, None, &DummyMonitor));
        assert_eq!(mgr.log.messages().len(), 1);
    }

    #[test]
    fn process_entry_point_adds_address_to_symbol_table() {
        let mut mgr = ExtEntryPointSarifMgr::new(empty_mock_program(), MessageLog::new());
        let addr = test_address(0x1000);

        let symbol_table = Arc::get_mut(&mut mgr.program).unwrap().get_symbol_table().unwrap();
        assert!(symbol_table.add_external_entry_point(&addr).is_ok());

        let symbol_table = Arc::get_mut(&mut mgr.program).unwrap().get_symbol_table().unwrap();
        let entries: Vec<Address> = symbol_table.get_external_entry_point_iterator().collect();
        assert_eq!(entries, vec![addr]);
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        ExtEntryPointSarifMgr::write_as_sarif(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_collects_every_entry_point() {
        let mut mgr = ExtEntryPointSarifMgr::new(empty_mock_program(), MessageLog::new());
        let one = test_address(0x1000);
        let two = test_address(0x2000);
        {
            let symbol_table = Arc::get_mut(&mut mgr.program).unwrap().get_symbol_table().unwrap();
            symbol_table.add_external_entry_point(&one).unwrap();
            symbol_table.add_external_entry_point(&two).unwrap();
        }

        let mut results = Vec::new();
        assert!(mgr.write(&mut results, None, &DummyMonitor).is_ok());
    }
}
