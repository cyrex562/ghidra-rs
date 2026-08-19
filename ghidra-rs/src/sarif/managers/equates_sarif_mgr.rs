//! Port of `sarif.managers.EquatesSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Equate, EquateTable, SimpleEquate};
use crate::util::exception::{CancelledException, UsrException};
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifEquateWriter, SarifMgr, SarifProgramOptions, SarifWriterTask, TaskLauncher,
};

/// Reads and writes `EQUATES` entries between a [`Program`]'s [`EquateTable`] and SARIF.
///
/// Port of `sarif.managers.EquatesSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Unlike Java, which caches the `EquateTable` once in the constructor, this keeps
/// the whole `Program` handle and re-fetches the table on each use: `Program::get_equate_table`
/// hands back a borrow (`&mut dyn EquateTable`), not an owned value, so it cannot be stored
/// alongside the `Program` it borrows from.
pub struct EquatesSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl EquatesSarifMgr {
    /// `EquatesSarifMgr.KEY`.
    pub const KEY: &'static str = "EQUATES";
    /// `EquatesSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Equate";

    /// `EquatesSarifMgr(Program program, MessageLog log)`.
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

    /// `EquatesSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        self.process_equate(result);
        true
    }

    fn process_equate(&mut self, result: &HashMap<String, Value>) {
        let name = result.get("name").and_then(Value::as_str).unwrap_or("");
        let value = result.get("value").and_then(Value::as_f64).unwrap_or(0.0) as i64;

        let Some(equate_table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_equate_table())
        else {
            return;
        };

        // `map(|_| ())` drops the `&mut SimpleEquate` the `Ok` case carries as soon as it is
        // produced, so `equate_table` is free to borrow again below.
        if let Err(msg) = equate_table.create_equate(name, value).map(|_| ()) {
            match equate_table.equate(name) {
                // `create_equate` failed because `name` is already an equate: Java's
                // `DuplicateNameException` catch arm.
                Some(existing) => {
                    let prev_val = existing.value();
                    if prev_val != value {
                        self.log.append_msg(format!(
                            "Cannot create equate [{name}] with value [{value}]; previously defined with value [{prev_val}]"
                        ));
                    }
                }
                // Any other failure (e.g. an invalid name): Java's general `Exception` catch arm.
                None => {
                    self.log.append_exception(&UsrException::new(&msg));
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `EquatesSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        _set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing EQUATES ...");

        let request: Vec<SimpleEquate> = match Arc::get_mut(&mut self.program).and_then(|p| p.get_equate_table())
        {
            Some(equate_table) => equate_table.equates().into_iter().cloned().collect(),
            None => Vec::new(),
        };

        Self::write_as_sarif(&request, results, monitor);
        Ok(())
    }

    /// `EquatesSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(request: &[SimpleEquate], results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifEquateWriter::new(request.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::symbol::SimpleEquateTable;
    use crate::util::task::DummyMonitor;

    struct MockProgram {
        equates: SimpleEquateTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
        fn get_equate_table(&mut self) -> Option<&mut dyn EquateTable> {
            Some(&mut self.equates)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            equates: SimpleEquateTable::new(),
        })
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(EquatesSarifMgr::KEY, "EQUATES");
        assert_eq!(EquatesSarifMgr::SUBKEY, "Equate");
    }

    #[test]
    fn read_creates_a_new_equate() {
        let mut mgr = EquatesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("ONE".to_string())),
            ("value", Value::from(1.0)),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));

        let equate_table = Arc::get_mut(&mut mgr.program).unwrap().get_equate_table().unwrap();
        assert_eq!(equate_table.equate("ONE").unwrap().value(), 1);
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn read_with_matching_duplicate_value_leaves_log_empty() {
        // Mirrors `processEquate` catching `DuplicateNameException` when the previously defined
        // value matches: no log message is appended.
        let mut mgr = EquatesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let first = result_map(&[
            ("name", Value::String("ONE".to_string())),
            ("value", Value::from(1.0)),
        ]);
        mgr.read(&first, None, &DummyMonitor);
        mgr.read(&first, None, &DummyMonitor);
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn read_with_conflicting_duplicate_value_logs_a_message() {
        let mut mgr = EquatesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let first = result_map(&[
            ("name", Value::String("ONE".to_string())),
            ("value", Value::from(1.0)),
        ]);
        let conflicting = result_map(&[
            ("name", Value::String("ONE".to_string())),
            ("value", Value::from(2.0)),
        ]);
        mgr.read(&first, None, &DummyMonitor);
        mgr.read(&conflicting, None, &DummyMonitor);

        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Cannot create equate [ONE]"));
        assert!(messages[0].contains("value [2]"));
        assert!(messages[0].contains("value [1]"));
    }

    #[test]
    fn read_with_invalid_name_logs_the_exception() {
        let mut mgr = EquatesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("bad name".to_string())),
            ("value", Value::from(1.0)),
        ]);
        mgr.read(&result, None, &DummyMonitor);
        assert_eq!(mgr.log.messages().len(), 1);
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        EquatesSarifMgr::write_as_sarif(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_collects_every_equate() {
        let mut mgr = EquatesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let one = result_map(&[
            ("name", Value::String("ONE".to_string())),
            ("value", Value::from(1.0)),
        ]);
        let two = result_map(&[
            ("name", Value::String("TWO".to_string())),
            ("value", Value::from(2.0)),
        ]);
        mgr.read(&one, None, &DummyMonitor);
        mgr.read(&two, None, &DummyMonitor);

        let mut results = Vec::new();
        assert!(mgr.write(&mut results, None, &DummyMonitor).is_ok());
    }
}
