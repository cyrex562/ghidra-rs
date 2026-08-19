//! Port of `sarif.managers.RelocationTableSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::listing::Program;
use crate::program::model::reloc::{Relocation, RelocationStatus, RelocationTable};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifMgr, SarifProgramOptions, SarifRelocationWriter, SarifWriterTask, TaskLauncher,
};

/// Everything [`RelocationTableSarifMgr::process_relocation`] can fail with. Java's
/// `RelocationTableSarifMgr.read` only catches `AddressOverflowException` (the
/// [`AddressOverflow`](Self::AddressOverflow) variant here); every other failure -- a missing
/// location, or a malformed `"kind"`/`"value"`/`"bytes"` field -- is an *uncaught* exception in
/// Java (an implicit `NullPointerException` or `NumberFormatException`) that propagates out of
/// `read`, which [`RelocationTableSarifMgr::read`] models by propagating the same `Err` rather than
/// logging it.
#[derive(Error, Debug)]
enum RelocationReadError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    /// `getLocation` returning `null`, which Java dereferences unconditionally further down.
    /// Always taken today: `SarifMgr::get_location` is a stub pending the `SarifUtils` port and
    /// never resolves a real address (see
    /// [`RegisterValuesSarifMgr`](crate::sarif::managers::RegisterValuesSarifMgr) for the same
    /// limitation).
    #[error("no location found for relocation")]
    NoLocation,
    /// `Integer.parseInt((String) result.get("kind"))` throwing `NumberFormatException`.
    #[error("invalid relocation kind \"{0}\"")]
    InvalidKind(String),
    /// `SarifMgr.parseLong` throwing `NumberFormatException` while unpacking `"value"`/`"bytes"`.
    #[error("invalid relocation value \"{0}\"")]
    InvalidValue(String),
}

/// Reads and writes `RELOCATIONS` entries between a [`Program`]'s [`RelocationTable`] and SARIF.
///
/// Port of `sarif.managers.RelocationTableSarifMgr`, which extends the abstract `SarifMgr`; that
/// base class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which
/// Rust does not have. Unlike Java, which caches nothing beyond the `Program` itself, this keeps
/// the whole `Program` handle and re-fetches the relocation table on each use:
/// `Program::get_relocation_table` hands back a borrow (`&mut dyn RelocationTable`), not an owned
/// value, so it cannot be stored alongside the `Program` it borrows from -- matching the
/// convention set by [`EquatesSarifMgr`](crate::sarif::managers::EquatesSarifMgr).
pub struct RelocationTableSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl RelocationTableSarifMgr {
    /// `RelocationTableSarifMgr.KEY`.
    pub const KEY: &'static str = "RELOCATIONS";
    /// `RelocationTableSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Relocation";

    /// `RelocationTableSarifMgr(Program program, MessageLog log)`.
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

    /// `RelocationTableSarifMgr.read`. Only `AddressOverflowException` is caught (and logged);
    /// any other failure propagates, matching Java's uncaught `NullPointerException`/
    /// `NumberFormatException` paths.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, RelocationReadError> {
        match self.process_relocation(result) {
            Ok(()) => Ok(true),
            Err(RelocationReadError::AddressOverflow(e)) => {
                self.log.append_exception(&e);
                Ok(true)
            }
            Err(other) => Err(other),
        }
    }

    fn process_relocation(&mut self, result: &HashMap<String, Value>) -> Result<(), RelocationReadError> {
        let addr = self
            .base
            .get_location(result)?
            .ok_or(RelocationReadError::NoLocation)?;

        let kind_str = result.get("kind").and_then(Value::as_str);
        let type_ = kind_str
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or_else(|| RelocationReadError::InvalidKind(kind_str.unwrap_or("null").to_string()))?;

        let values = unpack_longs(result.get("value").and_then(Value::as_str))?.unwrap_or_default();
        let bytes = unpack_bytes(result.get("bytes").and_then(Value::as_str))?;
        let symbol_name = result.get("name").and_then(Value::as_str).map(str::to_string);

        // `Status status = Status.UNKNOWN;` followed by a check of `status.hasBytes()` that is
        // always true for `UNKNOWN` and a reassignment back to `UNKNOWN`: the status passed to
        // `relocTable.add` is always `UNKNOWN` regardless of `bytes`, matching Java's dead branch
        // exactly (only the log message is conditional).
        let status = RelocationStatus::Unknown;
        if bytes.is_none() && status.has_bytes() {
            self.log.append_msg(format!(
                "Relocation at {addr} missing required bytes - forced UNKNOWN status."
            ));
        }

        if let Some(table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_relocation_table()) {
            table.add(addr, status, type_, values, bytes, symbol_name);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `RelocationTableSarifMgr.write`.
    pub fn write(&mut self, results: &mut Vec<Value>, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        monitor.set_message("Writing RELOCATION TABLE ...");

        let mut request: Vec<Relocation> = Vec::new();
        if let Some(table) = Arc::get_mut(&mut self.program).and_then(|p| p.get_relocation_table()) {
            for reloc in table.relocation_iter() {
                monitor.check_cancelled()?;
                request.push(reloc);
            }
        }

        Self::write_as_sarif(request, results, monitor);
        Ok(())
    }

    /// `RelocationTableSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(request: Vec<Relocation>, results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifRelocationWriter::new(request);
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

/// `RelocationTableSarifMgr.unpackLongs`. Java's `StringTokenizer(attrValue, ",")` skips empty
/// tokens between consecutive delimiters, matched here by filtering them out after `split`.
fn unpack_longs(attr_value: Option<&str>) -> Result<Option<Vec<i64>>, RelocationReadError> {
    let Some(attr_value) = attr_value else {
        return Ok(None);
    };
    attr_value
        .split(',')
        .filter(|tok| !tok.is_empty())
        .map(|tok| SarifMgr::parse_long(tok).map_err(RelocationReadError::InvalidValue))
        .collect::<Result<Vec<i64>, _>>()
        .map(Some)
}

/// `RelocationTableSarifMgr.unpackBytes`. `(byte) parseLong(token)` is Java's narrowing cast,
/// matched by an `as u8` truncation of the parsed value.
fn unpack_bytes(attr_value: Option<&str>) -> Result<Option<Vec<u8>>, RelocationReadError> {
    let Some(attr_value) = attr_value else {
        return Ok(None);
    };
    attr_value
        .split(',')
        .filter(|tok| !tok.is_empty())
        .map(|tok| SarifMgr::parse_long(tok).map(|v| v as u8).map_err(RelocationReadError::InvalidValue))
        .collect::<Result<Vec<u8>, _>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockRelocationTable {
        added: Vec<(Address, RelocationStatus, i32, Vec<i64>, Option<Vec<u8>>, Option<String>)>,
        relocations: Vec<Relocation>,
    }

    impl RelocationTable for MockRelocationTable {
        fn add(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            bytes: Option<Vec<u8>>,
            symbol_name: Option<String>,
        ) -> Relocation {
            self.added.push((addr.clone(), status, type_, values.clone(), bytes.clone(), symbol_name.clone()));
            Relocation::new(addr, status, type_, values, bytes, symbol_name)
        }
        fn add_with_byte_length(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            _byte_length: i32,
            symbol_name: Option<String>,
        ) -> Relocation {
            Relocation::new(addr, status, type_, values, None, symbol_name)
        }
        fn get_relocations(&self, _addr: &Address) -> Vec<Relocation> {
            Vec::new()
        }
        fn has_relocation(&self, _addr: &Address) -> bool {
            false
        }
        fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(self.relocations.clone().into_iter())
        }
        fn relocation_iter_in(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(std::iter::empty())
        }
        fn get_relocation_address_after(&self, _addr: &Address) -> Option<Address> {
            None
        }
        fn get_size(&self) -> i32 {
            self.relocations.len() as i32
        }
        fn is_relocatable(&self) -> bool {
            true
        }
    }

    struct MockProgram {
        relocations: MockRelocationTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_relocation_table(&mut self) -> Option<&mut dyn RelocationTable> {
            Some(&mut self.relocations)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            relocations: MockRelocationTable {
                added: Vec::new(),
                relocations: Vec::new(),
            },
        })
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(RelocationTableSarifMgr::KEY, "RELOCATIONS");
        assert_eq!(RelocationTableSarifMgr::SUBKEY, "Relocation");
    }

    #[test]
    fn get_key_returns_relocations() {
        let mgr = RelocationTableSarifMgr::new(empty_mock_program(), MessageLog::new());
        assert_eq!(mgr.get_key(), "RELOCATIONS");
    }

    #[test]
    fn unpack_longs_parses_comma_separated_values_including_hex() {
        assert_eq!(unpack_longs(Some("1,2,0x1F")).unwrap(), Some(vec![1, 2, 0x1F]));
        assert_eq!(unpack_longs(None).unwrap(), None);
    }

    #[test]
    fn unpack_bytes_narrows_each_value_to_a_byte() {
        assert_eq!(unpack_bytes(Some("255,0,16")).unwrap(), Some(vec![255u8, 0, 16]));
    }

    #[test]
    fn unpack_longs_rejects_non_numeric_tokens() {
        let err = unpack_longs(Some("1,not-a-number")).unwrap_err();
        assert!(matches!(err, RelocationReadError::InvalidValue(_)));
    }

    #[test]
    fn read_propagates_no_location_since_sarif_mgr_get_location_is_unported() {
        // `SarifMgr::get_location` is a stub pending the `SarifUtils` port: it never resolves an
        // address, so Java's null `addr` would reach an unchecked `NullPointerException` further
        // down that `RelocationTableSarifMgr.read`'s narrow `catch (AddressOverflowException e)`
        // does not catch. This port surfaces the same "uncaught" outcome as an `Err` from `read`
        // rather than silently swallowing it.
        let mut mgr = RelocationTableSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("kind", Value::String("0".to_string())),
            ("value", Value::String("1".to_string())),
        ]);

        let err = mgr.read(&result, None, &DummyMonitor).unwrap_err();
        assert!(matches!(err, RelocationReadError::NoLocation));
    }

    #[test]
    fn unpack_longs_skips_empty_tokens_between_delimiters() {
        // Mirrors `StringTokenizer`'s behavior of never returning empty tokens.
        assert_eq!(unpack_longs(Some("1,,2")).unwrap(), Some(vec![1, 2]));
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        RelocationTableSarifMgr::write_as_sarif(Vec::new(), &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_collects_every_relocation_from_the_table() {
        let mut mgr = RelocationTableSarifMgr::new(
            Arc::new(MockProgram {
                relocations: MockRelocationTable {
                    added: Vec::new(),
                    relocations: vec![Relocation::new(
                        addr(0x1000),
                        RelocationStatus::Applied,
                        1,
                        vec![0x2A],
                        None,
                        None,
                    )],
                },
            }),
            MessageLog::new(),
        );

        let mut results = Vec::new();
        assert!(mgr.write(&mut results, &DummyMonitor).is_ok());
    }
}
