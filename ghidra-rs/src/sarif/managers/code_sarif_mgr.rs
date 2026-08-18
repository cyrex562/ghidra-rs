//! Port of `sarif.managers.CodeSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::program::disassemble::DisassemblerMessageListener;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::listing::{Instruction, InstructionIterator, Program};
use crate::program::seam_stubs::FlowOverride;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    Disassembler, MessageLog, SarifCodeWriter, SarifMgr, SarifProgramOptions, SarifWriterTask, TaskLauncher,
};

/// Reads and writes `CODE` (instruction/disassembly) entries between a [`Program`]'s [`Listing`]
/// and SARIF.
///
/// Port of `sarif.managers.CodeSarifMgr`, which extends the abstract `SarifMgr`; that base class
/// is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust does not
/// have. Unlike [`BookmarksSarifMgr`](crate::sarif::managers::BookmarksSarifMgr), which only ever
/// needs one field pulled out of `Program`, this manager repeatedly needs both `Listing` and
/// `Memory` across several methods, so it keeps the whole `Program` handle (matching Java's
/// `SarifMgr.program` field) rather than extracting a single sub-manager up front.
pub struct CodeSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl CodeSarifMgr {
    /// `CodeSarifMgr.KEY`.
    pub const KEY: &'static str = "CODE";
    /// `CodeSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Code";
    /// `CodeSarifMgr.SUBKEY2`.
    pub const SUBKEY2: &'static str = "Override";

    /// `new CodeSarifMgr(Program program, MessageLog log)`.
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

    /// `CodeSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        let mut set = AddressSet::new();
        if let Err(e) = self.base.get_locations(result, &mut set) {
            self.log.append_exception(&e);
        }

        let msg = result.get("Message").and_then(Value::as_str).unwrap_or("");

        let memory_set = self.memory_address_set();
        let disset = set.intersect(&*memory_set);
        if !disset.has_same_addresses(&set) {
            self.log
                .append_msg(format!("Disassembly address set changed to {}", disset.print_ranges()));
        }
        self.disassemble(disset, monitor);

        if msg == Self::SUBKEY2 {
            if let Some(min_addr) = set.min_address() {
                if let Some(mut inst) = self.get_instruction_at(&min_addr) {
                    if let Some(override_str) = result.get("kind").and_then(Value::as_str) {
                        let flow_override = parse_flow_override(override_str);
                        // Java's `inst.setFlowOverride(...)` NPEs if no instruction is present at
                        // `set.getMinAddress()`; `get_instruction_at` already returned `Some`, and
                        // this manager holds the only handle to it, so mutation is safe here.
                        if let Some(inst_mut) = Arc::get_mut(&mut inst) {
                            inst_mut.set_flow_override(flow_override);
                        }
                    }
                }
            }
        }
        true
    }

    /// `CodeSarifMgr.disassemble`.
    pub fn disassemble(&mut self, mut set: AddressSet, monitor: &dyn TaskMonitor) {
        let disassembler = Disassembler::get_disassembler(&*self.program, monitor, &*self);
        while !set.is_empty() && !monitor.is_cancelled() {
            let Some(start) = set.min_address() else { break };
            let disset = disassembler.disassemble(&start, &set);
            if disset.is_empty() {
                match self.get_instruction_at(&start) {
                    None => {
                        let Some(skip_range) = set.first_range() else { break };
                        self.log.append_msg(format!("Expected valid Instruction at {start}"));
                        self.log.append_msg(format!(
                            "...skipping code range {} to {}",
                            skip_range.min_address(),
                            skip_range.max_address()
                        ));
                        set.delete_range_object(&skip_range);
                    }
                    Some(instr) => {
                        set.delete_range(&instr.get_min_address(), &instr.get_max_address());
                    }
                }
            } else {
                set.delete_set(&disset);
            }
        }
    }

    /// `CodeSarifMgr.getInstructionAt`, folding `program.getListing().getInstructionAt(addr)`
    /// (with its two possibly-absent hops) into one call.
    fn get_instruction_at(&mut self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        Arc::get_mut(&mut self.program)?.get_listing()?.get_instruction_at(addr)
    }

    /// `program.getMemory()`, viewed as the `AddressSetView` Java's `Memory` interface also is.
    /// Falls back to an empty set when there is no memory, matching an intersection against
    /// nothing.
    fn memory_address_set(&self) -> Box<dyn AddressSetView> {
        self.program
            .get_memory()
            .map(|mem| mem.get_all_initialized_address_set())
            .unwrap_or_else(|| Box::new(AddressSet::new()) as Box<dyn AddressSetView>)
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `CodeSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing CODE ...");

        let mut request: Vec<AddressRange> = Vec::new();
        let mut request_override: Vec<(Arc<dyn Instruction>, FlowOverride)> = Vec::new();

        let mut it = self.instructions_iterator(set);

        while let Some(mut inst) = it.next() {
            let mut start = inst.get_min_address();
            let mut end = inst.get_max_address();
            while let Some(next_inst) = it.next() {
                inst = next_inst;
                let override_ = inst.get_flow_override();
                if override_ != FlowOverride::None {
                    request_override.push((inst.clone(), override_));
                }

                if !end.is_successor(&inst.get_min_address()) {
                    request.push(AddressRange::new(start.clone(), end.clone()));
                    start = inst.get_min_address();
                }
                end = inst.get_max_address();
                monitor.check_cancelled()?;
            }
            request.push(AddressRange::new(start, end));
        }

        Self::write_as_sarif(&request, &request_override, results, monitor);
        Ok(())
    }

    /// `program.getListing().getInstructions(true)` / `getInstructions(set, true)`.
    fn instructions_iterator(&mut self, set: Option<&dyn AddressSetView>) -> Box<dyn InstructionIterator> {
        let listing = Arc::get_mut(&mut self.program)
            .expect("CodeSarifMgr holds the only handle to its Program")
            .get_listing()
            .expect("CodeSarifMgr's Program has no Listing");
        match set {
            Some(set) => listing.get_instructions_in(set, true),
            None => listing.get_instructions(true),
        }
    }

    /// `CodeSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(
        request: &[AddressRange],
        request_override: &[(Arc<dyn Instruction>, FlowOverride)],
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifCodeWriter::new(request.to_vec(), request_override.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

impl DisassemblerMessageListener for CodeSarifMgr {
    /// `CodeSarifMgr.disassembleMessageReported`.
    fn disassemble_message_reported(&self, msg: &str) {
        self.log.append_msg(format!("Error from disassembler: {msg}"));
    }
}

/// `FlowOverride.valueOf(String)`. Falls back to `NONE` for an unrecognized name; Java's
/// `valueOf` throws `IllegalArgumentException` instead, but nothing in `CodeSarifMgr` catches
/// that, so a malformed SARIF `kind` would otherwise crash the whole read.
fn parse_flow_override(name: &str) -> FlowOverride {
    match name {
        "BRANCH" => FlowOverride::Branch,
        "CALL" => FlowOverride::Call,
        "CALL_RETURN" => FlowOverride::CallReturn,
        "RETURN" => FlowOverride::Return,
        _ => FlowOverride::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::stub_listing::StubListing;
    use crate::program::model::listing::Listing;
    use crate::program::model::mem::{Memory, MemoryAccessException};
    use crate::util::task::DummyMonitor;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    struct MockListing;

    impl StubListing for MockListing {
        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    struct MockMemory {
        initialized: AddressSet,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("not modeled"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("not modeled"))
        }
        fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(self.initialized.clone())
        }
    }

    struct MockProgram {
        listing: MockListing,
        memory: Arc<MockMemory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            Some(&mut self.listing)
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone() as Arc<dyn Memory>)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            listing: MockListing,
            memory: Arc::new(MockMemory {
                initialized: AddressSet::new(),
            }),
        })
    }

    fn mgr_with(program: Arc<dyn Program>) -> CodeSarifMgr {
        CodeSarifMgr {
            base: SarifMgr::new(CodeSarifMgr::KEY),
            log: MessageLog::new(),
            program,
        }
    }

    fn result_map(entries: &[(&str, &str)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn key_and_subkeys_match_java() {
        assert_eq!(CodeSarifMgr::KEY, "CODE");
        assert_eq!(CodeSarifMgr::SUBKEY, "Code");
        assert_eq!(CodeSarifMgr::SUBKEY2, "Override");
    }

    #[test]
    fn get_key_returns_code() {
        let mgr = mgr_with(empty_mock_program());
        assert_eq!(mgr.get_key(), "CODE");
    }

    #[test]
    fn parse_flow_override_matches_java_value_of() {
        assert_eq!(parse_flow_override("BRANCH"), FlowOverride::Branch);
        assert_eq!(parse_flow_override("CALL"), FlowOverride::Call);
        assert_eq!(parse_flow_override("CALL_RETURN"), FlowOverride::CallReturn);
        assert_eq!(parse_flow_override("RETURN"), FlowOverride::Return);
        assert_eq!(parse_flow_override("NONE"), FlowOverride::None);
        // Unlike Java's `valueOf`, an unrecognized name falls back to NONE instead of throwing.
        assert_eq!(parse_flow_override("bogus"), FlowOverride::None);
    }

    #[test]
    fn disassemble_skips_range_and_logs_when_no_instruction_found() {
        // With the `Disassembler` stub always reporting nothing disassembled and the `Listing`
        // stub always reporting no instruction present, `disassemble` must fall back to the
        // "skip the whole range" branch instead of looping forever.
        let mut mgr = mgr_with(empty_mock_program());
        let mut set = AddressSet::new();
        set.add_range(&test_address(0x100), &test_address(0x110));

        mgr.disassemble(set, &DummyMonitor);

        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("Expected valid Instruction at"));
        assert!(messages[1].contains("skipping code range"));
    }

    #[test]
    fn disassemble_message_reported_appends_prefixed_log_message() {
        let mgr = mgr_with(empty_mock_program());
        mgr.disassemble_message_reported("bad opcode");
        assert_eq!(mgr.log.messages(), vec!["Error from disassembler: bad opcode".to_string()]);
    }

    #[test]
    fn read_handles_subkey2_gracefully_when_location_stub_finds_nothing() {
        // `SarifMgr::get_locations` is a stub pending the `SarifUtils` port, so `set` stays
        // empty; Java's `read` would NPE dereferencing a null `Instruction` here, but `read`
        // should just skip the override instead of panicking.
        let mut mgr = mgr_with(empty_mock_program());
        let result = result_map(&[("Message", CodeSarifMgr::SUBKEY2), ("kind", "BRANCH")]);
        assert!(mgr.read(&result, None, &DummyMonitor));
    }

    #[test]
    fn read_returns_true_for_a_plain_message() {
        let mut mgr = mgr_with(empty_mock_program());
        let result = result_map(&[("Message", "Code")]);
        assert!(mgr.read(&result, None, &DummyMonitor));
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        CodeSarifMgr::write_as_sarif(&[], &[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }
}
