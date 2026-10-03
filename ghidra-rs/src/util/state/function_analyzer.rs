use crate::program::model::address::Address;
use crate::program::model::pcode::{PcodeOp, Varnode};
use crate::program::model::symbol::RefType;
use crate::util::exception::CancelledException;
use crate::util::seam_stubs::{ContextState, ResultsState, VarnodeOperation};
use crate::util::task::TaskMonitor;

/// Callback interface used to analyze the pcode/flow state produced while walking a function,
/// invoked for each reference or flow destination discovered during the walk.
pub trait FunctionAnalyzer {
    /// Callback indicating that an absolute stack reference was encountered. A non-load/store
    /// operation will have a -1 for both `storage_space_id` and `size`.
    ///
    /// * `op` - pcode operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `stack_offset` - stack offset
    /// * `size` - access size or -1 if not applicable
    /// * `storage_space_id` - storage space ID or -1 if not applicable
    /// * `ref_type` - read/write/data reference type
    /// * `monitor` - task monitor
    fn stack_reference(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        stack_offset: i32,
        size: i32,
        storage_space_id: i32,
        ref_type: RefType,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Callback indicating that a computed stack reference was encountered. A non-load/store
    /// operation will have a -1 for both `storage_space_id` and `size`.
    ///
    /// * `op` - pcode operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `computed_stack_offset` - stack offset computation (i.e. a [`VarnodeOperation`] with the
    ///   stack pointer)
    /// * `size` - access size or -1 if not applicable
    /// * `storage_space_id` - storage space ID or -1 if not applicable
    /// * `ref_type` - read/write/data reference type
    /// * `monitor` - task monitor
    fn stack_reference_computed(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        computed_stack_offset: &VarnodeOperation,
        size: i32,
        storage_space_id: i32,
        ref_type: RefType,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Callback indicating that an absolute memory reference was encountered.
    ///
    /// * `op` - pcode operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `storage_varnode` - absolute storage varnode
    /// * `ref_type` - read/write/data reference type
    /// * `monitor` - task monitor
    fn data_reference(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        storage_varnode: &Varnode,
        ref_type: RefType,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Callback indicating that an indirect/computed memory reference was encountered using an
    /// indirect/computed offset.
    ///
    /// * `op` - pcode operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `offset_varnode` - indirect/computed offset
    /// * `size` - access size or -1 if not applicable
    /// * `storage_space_id` - storage space ID
    /// * `ref_type` - read/write/data reference type
    /// * `monitor` - task monitor
    fn indirect_data_reference(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        offset_varnode: &Varnode,
        size: i32,
        storage_space_id: i32,
        ref_type: RefType,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Callback indicating that a call/branch destination was identified. The analyzer should
    /// create a reference if appropriate. Keep in mind that there could be other unidentified
    /// destinations.
    ///
    /// * `op` - branch or call flow operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `dest_addr` - destination address
    /// * `current_state` - current state at the branch/call
    /// * `results` - contains previous states leading up to `current_state`
    /// * `monitor` - task monitor
    ///
    /// Returns true if the destination should be disassembled if not already.
    fn resolved_flow(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        dest_addr: &Address,
        current_state: &ContextState,
        results: &ResultsState,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException>;

    /// Callback indicating that a computed call/branch destination was not resolved.
    ///
    /// * `op` - indirect branch or call flow operation
    /// * `instr_op_index` - opIndex associated with reference or -1 if it could not be determined
    /// * `destination` - destination identified as a [`Varnode`] (may be an expression
    ///   represented by a [`VarnodeOperation`])
    /// * `current_state` - current state at the branch/call
    /// * `results` - contains previous states leading up to `current_state`
    /// * `monitor` - task monitor
    ///
    /// Returns the list of resolved destinations which should be used, or `None`. A list of
    /// destination addresses will trigger disassembly where necessary.
    fn unresolved_indirect_flow(
        &mut self,
        op: &PcodeOp,
        instr_op_index: i32,
        destination: &Varnode,
        current_state: &ContextState,
        results: &ResultsState,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Vec<Address>>, CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::pcode::{OpCode, SequenceNumber};
    use crate::util::task::DummyMonitor;

    /// Records every callback it receives, mirroring how `MySwitchAnalyzer` (the sole in-repo
    /// implementor) drives the switch-table analysis off these callbacks.
    struct RecordingAnalyzer {
        resolved_flows: Vec<Address>,
        unresolved_flows: usize,
    }

    impl FunctionAnalyzer for RecordingAnalyzer {
        fn stack_reference(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            _stack_offset: i32,
            _size: i32,
            _storage_space_id: i32,
            _ref_type: RefType,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn stack_reference_computed(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            _computed_stack_offset: &VarnodeOperation,
            _size: i32,
            _storage_space_id: i32,
            _ref_type: RefType,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn data_reference(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            _storage_varnode: &Varnode,
            _ref_type: RefType,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn indirect_data_reference(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            _offset_varnode: &Varnode,
            _size: i32,
            _storage_space_id: i32,
            _ref_type: RefType,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn resolved_flow(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            dest_addr: &Address,
            _current_state: &ContextState,
            _results: &ResultsState,
            monitor: &dyn TaskMonitor,
        ) -> Result<bool, CancelledException> {
            monitor.check_cancelled()?;
            self.resolved_flows.push(dest_addr.clone());
            Ok(true)
        }

        fn unresolved_indirect_flow(
            &mut self,
            _op: &PcodeOp,
            _instr_op_index: i32,
            _destination: &Varnode,
            _current_state: &ContextState,
            _results: &ResultsState,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Vec<Address>>, CancelledException> {
            self.unresolved_flows += 1;
            Ok(None)
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    fn test_op() -> PcodeOp {
        let addr = test_address(0x1000);
        let seqnum = SequenceNumber::new(addr, 0);
        PcodeOp::new(OpCode::CallInd, seqnum, Vec::new(), None)
    }

    #[test]
    fn resolved_flow_records_destination_and_reports_disassemble() {
        let mut analyzer = RecordingAnalyzer {
            resolved_flows: Vec::new(),
            unresolved_flows: 0,
        };
        let op = test_op();
        let dest = test_address(0x2000);
        let current_state = ContextState;
        let results = ResultsState;
        let monitor = DummyMonitor;

        let should_disassemble = analyzer
            .resolved_flow(&op, -1, &dest, &current_state, &results, &monitor)
            .expect("not cancelled");

        assert!(should_disassemble);
        assert_eq!(analyzer.resolved_flows, vec![dest]);
    }

    #[test]
    fn unresolved_indirect_flow_reports_no_destinations_by_default() {
        let mut analyzer = RecordingAnalyzer {
            resolved_flows: Vec::new(),
            unresolved_flows: 0,
        };
        let op = test_op();
        let destination = Varnode::new(test_address(0x3000), 4);
        let current_state = ContextState;
        let results = ResultsState;
        let monitor = DummyMonitor;

        let resolved = analyzer
            .unresolved_indirect_flow(&op, -1, &destination, &current_state, &results, &monitor)
            .expect("not cancelled");

        assert_eq!(resolved, None);
        assert_eq!(analyzer.unresolved_flows, 1);
    }

    #[test]
    fn trait_object_is_usable_behind_a_box() {
        let mut analyzer: Box<dyn FunctionAnalyzer> = Box::new(RecordingAnalyzer {
            resolved_flows: Vec::new(),
            unresolved_flows: 0,
        });
        let op = test_op();
        let storage_varnode = Varnode::new(test_address(0x4000), 4);
        let monitor = DummyMonitor;

        analyzer
            .data_reference(&op, 0, &storage_varnode, RefType::Data, &monitor)
            .expect("not cancelled");
    }
}
