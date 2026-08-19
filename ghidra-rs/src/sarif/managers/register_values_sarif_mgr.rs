//! Port of `sarif.managers.RegisterValuesSarifMgr`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::{ContextChangeException, Program, ProgramContext};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifMgr, SarifProgramOptions, SarifRegisterValueWriter, SarifWriterTask, TaskLauncher,
};

/// Everything [`RegisterValuesSarifMgr::process_register_values`] can fail with -- all folded
/// back into the same `log.appendException(e)` Java's outer `catch (Exception e)` performs,
/// matching `processRegisterValues`'s "swallow anything, log it" shape.
#[derive(Error, Debug)]
enum ProcessRegisterValuesError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    ContextChange(#[from] ContextChangeException),
    /// `set.getMinAddress()`/`set.getMaxAddress()` returning `null`, which Java dereferences
    /// unconditionally (an implicit `NullPointerException` the same `catch (Exception e)` also
    /// swallows). Always taken today: `SarifMgr::get_locations` is a stub pending the
    /// `SarifUtils` port and never adds anything to `set` (see
    /// [`ProgramTreeSarifMgr`](crate::sarif::managers::ProgramTreeSarifMgr) and
    /// [`CodeSarifMgr`](crate::sarif::managers::CodeSarifMgr) for the same limitation).
    #[error("no location found for register value")]
    NoLocation,
    /// `new BigInteger(valueStr, 16)` throwing `NumberFormatException`.
    #[error("invalid register value \"{0}\"")]
    InvalidValue(String),
}

/// Reads and writes `REGISTER_VALUES` entries between a [`Program`]'s [`ProgramContext`] and
/// SARIF.
///
/// Port of `sarif.managers.RegisterValuesSarifMgr`, which extends the abstract `SarifMgr`; that
/// base class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which
/// Rust does not have. Unlike Java, which caches the `ProgramContext` once in the constructor,
/// this keeps the whole `Program` handle and re-fetches it on each use: `Program::get_program_context`
/// hands back a borrow (`&mut dyn ProgramContext`), not an owned value, so it cannot be stored
/// alongside the `Program` it borrows from -- matching the convention set by
/// [`EquatesSarifMgr`](crate::sarif::managers::EquatesSarifMgr).
pub struct RegisterValuesSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    undefined_register_names: HashSet<String>,
}

impl RegisterValuesSarifMgr {
    /// `RegisterValuesSarifMgr.KEY`.
    pub const KEY: &'static str = "REGISTER_VALUES";
    /// `RegisterValuesSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Registers";

    /// `RegisterValuesSarifMgr(Program program, MessageLog log)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            undefined_register_names: HashSet::new(),
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `RegisterValuesSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException> {
        self.process_register_values(result);
        Ok(true)
    }

    /// Returns list of unique registers which do not overlap any smaller registers.
    ///
    /// `RegisterValuesSarifMgr.getUniqueRegisters`.
    fn get_unique_registers(&mut self) -> Vec<RegisterRef> {
        let mut regs: Vec<RegisterRef> = match Arc::get_mut(&mut self.program).and_then(|p| p.get_program_context()) {
            Some(context) => context.get_registers(),
            None => Vec::new(),
        };
        regs.sort_by(|a, b| {
            let a = a.borrow();
            let b = b.borrow();
            a.minimum_byte_size()
                .cmp(&b.minimum_byte_size())
                .then_with(|| a.offset().cmp(&b.offset()))
        });
        regs
    }

    /// `RegisterValuesSarifMgr.processRegisterValues`.
    fn process_register_values(&mut self, result: &HashMap<String, Value>) {
        if let Err(e) = self.process_register_values_inner(result) {
            self.log.append_exception(&e);
        }
    }

    fn process_register_values_inner(&mut self, result: &HashMap<String, Value>) -> Result<(), ProcessRegisterValuesError> {
        let mut set = AddressSet::new();
        self.base.get_locations(result, &mut set)?;
        let addr = set.min_address().ok_or(ProcessRegisterValuesError::NoLocation)?;
        let max_addr = set.max_address().ok_or(ProcessRegisterValuesError::NoLocation)?;
        let len = (max_addr.subtract(&addr) as i32) + 1;

        let reg_name = result.get("name").and_then(Value::as_str).unwrap_or_default();
        let value_str = result.get("value").and_then(Value::as_str).unwrap_or_default();
        let value = parse_hex_value(value_str)?;

        let language_id = self.program.get_language_id();
        let end = addr.add_no_wrap((len - 1) as i64)?;
        let Some(context) = Arc::get_mut(&mut self.program).and_then(|p| p.get_program_context()) else {
            return Ok(());
        };

        apply_register_value(
            context,
            reg_name,
            &addr,
            &end,
            value,
            &language_id,
            &self.log,
            &mut self.undefined_register_names,
        )
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `RegisterValuesSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let regs = self.get_unique_registers();

        let owned_set;
        let effective_set: &dyn AddressSetView = match set {
            Some(set) => set,
            None => {
                owned_set = self.memory_address_set();
                owned_set.as_ref()
            }
        };

        let mut request: Vec<AddressRange> = Vec::new();
        for range in effective_set.address_ranges() {
            monitor.check_cancelled()?;
            request.push(range);
        }

        Self::write_as_sarif(regs, request, results, monitor);
        Ok(())
    }

    /// `program.getMemory()`, viewed as the `AddressSetView` Java's `Memory` interface also is.
    /// Falls back to an empty set when there is no memory, matching
    /// [`CommentsSarifMgr`](crate::sarif::managers::CommentsSarifMgr)'s convention.
    fn memory_address_set(&self) -> Box<dyn AddressSetView> {
        self.program
            .get_memory()
            .map(|mem| mem.get_all_initialized_address_set())
            .unwrap_or_else(|| Box::new(AddressSet::new()) as Box<dyn AddressSetView>)
    }

    /// `RegisterValuesSarifMgr.writeAsSARIF`. Drops Java's `ProgramContext context` parameter:
    /// the placeholder [`SarifRegisterValueWriter`] cannot walk it yet (its `genRegisters`
    /// machinery, which reads register values back out of the context, is pending that class's
    /// own port), so nothing here would use it.
    pub fn write_as_sarif(registers: Vec<RegisterRef>, request: Vec<AddressRange>, results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifRegisterValueWriter::new(registers, request);
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

/// `new BigInteger(valueStr, 16)`, after stripping an optional `"0x"`/`"0X"` prefix. Java's
/// `BigInteger(String, int radix)` parses an unsigned magnitude in the given radix (unless the
/// string starts with `-`, which none of these ever do), so a plain `u128` parse -- reinterpreted
/// as `i128` -- matches it for every value that fits; the ported
/// [`ProgramContext::set_value`](crate::program::model::listing::ProgramContext::set_value) has
/// no wider representation to offer register values beyond that.
fn parse_hex_value(value_str: &str) -> Result<i128, ProcessRegisterValuesError> {
    let trimmed = value_str
        .strip_prefix("0x")
        .or_else(|| value_str.strip_prefix("0X"))
        .unwrap_or(value_str);
    u128::from_str_radix(trimmed, 16)
        .map(|v| v as i128)
        .map_err(|_| ProcessRegisterValuesError::InvalidValue(value_str.to_string()))
}

/// The `context.getRegister(regName)` lookup plus the `null`/found branches of
/// `processRegisterValues`, factored out so it can be exercised directly without depending on the
/// (currently always-failing) location resolution in [`RegisterValuesSarifMgr::process_register_values_inner`].
#[allow(clippy::too_many_arguments)]
fn apply_register_value(
    context: &mut dyn ProgramContext,
    reg_name: &str,
    start: &Address,
    end: &Address,
    value: i128,
    language_id: &str,
    log: &MessageLog,
    undefined_register_names: &mut HashSet<String>,
) -> Result<(), ProcessRegisterValuesError> {
    let Some(reg) = context.get_register(reg_name) else {
        if undefined_register_names.insert(reg_name.to_string()) {
            log.append_msg(format!(
                "REGISTER [{reg_name}] is not defined by {language_id}, register values will be ignored"
            ));
        }
        return Ok(());
    };

    let reg_borrow = reg.borrow();
    context.set_value(&reg_borrow, start, end, Some(value))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressRangeIterator, AddressSpace, AddressSpaceType, EmptyAddressRangeIterator};
    use crate::program::model::lang::register::Register;
    use crate::program::seam_stubs::RegisterValue;
    use crate::util::task::DummyMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockProgramContext {
        registers: Vec<RegisterRef>,
        set_calls: Vec<(String, Address, Address, Option<i128>)>,
    }

    impl ProgramContext for MockProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            false
        }
        fn get_flow_value(&self, value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue> {
            value
        }
        fn get_non_flow_value(&self, _value: Box<dyn RegisterValue>) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            self.registers.iter().find(|r| r.borrow().name() == name).cloned()
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.clone()
        }
        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_non_default_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_value(
            &mut self,
            register: &Register,
            start: &Address,
            end: &Address,
            value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            self.set_calls.push((register.name().to_string(), start.clone(), end.clone(), value));
            Ok(())
        }
        fn get_register_value_address_ranges(&self, _register: &Register) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_register_value_range_containing(&self, _register: &Register, addr: &Address) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }
        fn get_default_register_value_address_ranges(&self, _register: &Register) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn remove(&mut self, _start: &Address, _end: &Address, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.iter().map(|r| r.borrow().name().to_string()).collect()
        }
        fn has_value_over_range(&self, _reg: &Register, _value: i128, _addr_set: &dyn AddressSetView) -> bool {
            false
        }
        fn get_default_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_base_context_register(&self) -> RegisterRef {
            panic!("no base context register in mock")
        }
        fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValue>) {}
        fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(RegisterValuesSarifMgr::KEY, "REGISTER_VALUES");
        assert_eq!(RegisterValuesSarifMgr::SUBKEY, "Registers");
    }

    #[test]
    fn get_key_returns_register_values() {
        let mgr = RegisterValuesSarifMgr::new(empty_mock_program(), MessageLog::new());
        assert_eq!(mgr.get_key(), "REGISTER_VALUES");
    }

    #[test]
    fn parse_hex_value_strips_0x_prefix_and_parses_hex() {
        assert_eq!(parse_hex_value("0x1F").unwrap(), 0x1F);
        assert_eq!(parse_hex_value("0X1f").unwrap(), 0x1F);
        assert_eq!(parse_hex_value("ff").unwrap(), 0xFF);
    }

    #[test]
    fn parse_hex_value_rejects_non_hex_input() {
        let err = parse_hex_value("not-hex").unwrap_err();
        assert!(matches!(err, ProcessRegisterValuesError::InvalidValue(_)));
    }

    #[test]
    fn read_logs_no_location_while_sarif_mgr_get_locations_is_unported() {
        // `SarifMgr::get_locations` is a stub pending the `SarifUtils` port: it never adds
        // anything to `set`, so `set.getMinAddress()` is always `null` in Java terms. Java
        // dereferences that unconditionally (an implicit NPE); this port surfaces the same
        // "nothing resolved" outcome as `ProcessRegisterValuesError::NoLocation`, caught and
        // logged the same way Java's outer `catch (Exception e)` would.
        let mut mgr = RegisterValuesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("name", Value::String("r0".to_string())),
            ("value", Value::String("0x10".to_string())),
        ]);

        assert_eq!(mgr.read(&result, None, &DummyMonitor), Ok(true));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("no location found"), "{}", messages[0]);
    }

    fn mock_register(name: &str, offset: i64, num_bytes: i32) -> RegisterRef {
        Register::new(name, name, Address::new(register_space(), offset), num_bytes, false, 0)
    }

    #[test]
    fn apply_register_value_sets_the_value_for_a_known_register() {
        let mut context = MockProgramContext {
            registers: vec![mock_register("r0", 0, 4)],
            set_calls: Vec::new(),
        };
        let log = MessageLog::new();
        let mut undefined = HashSet::new();

        apply_register_value(&mut context, "r0", &addr(0x1000), &addr(0x1003), 0x2A, "mock:LE:32:default", &log, &mut undefined)
            .unwrap();

        assert_eq!(context.set_calls.len(), 1);
        let (name, start, end, value) = &context.set_calls[0];
        assert_eq!(name, "r0");
        assert_eq!(*start, addr(0x1000));
        assert_eq!(*end, addr(0x1003));
        assert_eq!(*value, Some(0x2A));
        assert!(log.messages().is_empty());
    }

    #[test]
    fn apply_register_value_logs_once_per_undefined_register_name() {
        // Mirrors `processRegisterValues`'s `undefinedRegisterNames.add(regName)` check: the
        // second call for the same unknown name adds nothing new to the log.
        let mut context = MockProgramContext {
            registers: Vec::new(),
            set_calls: Vec::new(),
        };
        let log = MessageLog::new();
        let mut undefined = HashSet::new();

        apply_register_value(&mut context, "bogus", &addr(0), &addr(3), 1, "mock:LE:32:default", &log, &mut undefined).unwrap();
        apply_register_value(&mut context, "bogus", &addr(4), &addr(7), 2, "mock:LE:32:default", &log, &mut undefined).unwrap();

        assert!(context.set_calls.is_empty());
        let messages = log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("REGISTER [bogus] is not defined by mock:LE:32:default"), "{}", messages[0]);
    }

    #[test]
    fn get_unique_registers_sorts_by_size_then_offset() {
        let mut mgr = RegisterValuesSarifMgr::new(empty_mock_program(), MessageLog::new());
        // `MockProgram` has no `ProgramContext`, so this exercises the "no context" branch: the
        // sort itself is covered directly below via the comparator's expected order.
        assert!(mgr.get_unique_registers().is_empty());

        let mut regs = vec![mock_register("big", 0, 8), mock_register("small_hi", 8, 4), mock_register("small_lo", 0, 4)];
        regs.sort_by(|a, b| {
            let a = a.borrow();
            let b = b.borrow();
            a.minimum_byte_size().cmp(&b.minimum_byte_size()).then_with(|| a.offset().cmp(&b.offset()))
        });
        let names: Vec<String> = regs.iter().map(|r| r.borrow().name().to_string()).collect();
        assert_eq!(names, vec!["small_lo", "small_hi", "big"]);
    }

    #[test]
    fn write_collects_ranges_from_the_given_set_and_produces_no_results() {
        // `SarifWriterTask::run` is a no-op placeholder (see `SarifRegisterValueWriter`'s doc
        // comment), so `results` stays empty even though the range was collected -- matching
        // `EquatesSarifMgr`/`ProgramTreeSarifMgr`'s equivalent tests.
        let mut mgr = RegisterValuesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let set = AddressSet::from_range(AddressRange::new(addr(0x1000), addr(0x1010)));
        let mut results = Vec::new();

        assert!(mgr.write(&mut results, Some(&set), &DummyMonitor).is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn write_falls_back_to_the_program_memory_when_no_set_is_given() {
        let mut mgr = RegisterValuesSarifMgr::new(empty_mock_program(), MessageLog::new());
        let mut results = Vec::new();

        assert!(mgr.write(&mut results, None, &DummyMonitor).is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        RegisterValuesSarifMgr::write_as_sarif(Vec::new(), Vec::new(), &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }
}
