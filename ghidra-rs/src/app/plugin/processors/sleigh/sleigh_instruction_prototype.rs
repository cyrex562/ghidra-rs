//! Port of `ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype`.
//!
//! `SleighInstructionPrototype` was selected as a dependency-cycle cut-point, so instead of a
//! single concrete struct its public API is modeled as the [`SleighInstructionPrototype`] trait.
//! It extends the pre-existing [`InstructionPrototype`] trait, mirroring `implements
//! InstructionPrototype` on the Java class, and adds the two genuinely public members the Java
//! class contributes beyond that interface: `getRootState()` and `dumpConstructorTree()`.
//!
//! Java's constructor and its package-private helpers (`getMnemonicState`, `cacheInfo`,
//! `getContextCache`, `getOperandSymbol`, ...) are dropped, since traits cannot provide
//! constructors and package-private members are not part of the public API being cut across.
//!
//! The public static flow-flag constants, the `FlowRecord`/`FlowSummary` nested classes, and the
//! public static helpers `walkTemplates`/`flowListToFlowType` (plus the private `addExplicitFlow`
//! and `convertFlowFlags` they depend on) *are* fully ported as free functions/types in this
//! module: they only reference types that already exist in the crate (the [`OpTplWalker`] trait,
//! [`OpTpl`], `ConstTpl`, and [`RefType`]), so no placeholder stubs were needed for them.

use std::sync::Arc;

use crate::app::plugin::processors::sleigh::op_tpl_walker::{NextOpTpl, OpTplWalker};
use crate::app::seam_stubs::ConstructState;
use crate::decompiler::opcodes::OpCode;
use crate::program::model::lang::sleigh::template::{ConstTplType, OpTpl};
use crate::program::model::lang::InstructionPrototype;
use crate::program::model::symbol::RefType;

/// Port of `SleighInstructionPrototype.RETURN`.
pub const RETURN: i32 = 0x01;
/// Port of `SleighInstructionPrototype.CALL_INDIRECT`.
pub const CALL_INDIRECT: i32 = 0x02;
/// Port of `SleighInstructionPrototype.BRANCH_INDIRECT`.
pub const BRANCH_INDIRECT: i32 = 0x04;
/// Port of `SleighInstructionPrototype.CALL`.
pub const CALL: i32 = 0x08;
/// Port of `SleighInstructionPrototype.JUMPOUT`.
pub const JUMPOUT: i32 = 0x10;
/// Port of `SleighInstructionPrototype.NO_FALLTHRU`.
pub const NO_FALLTHRU: i32 = 0x20;
/// Port of `SleighInstructionPrototype.BRANCH_TO_END`.
pub const BRANCH_TO_END: i32 = 0x40;
/// Port of `SleighInstructionPrototype.CROSSBUILD`.
pub const CROSSBUILD: i32 = 0x80;
/// Port of `SleighInstructionPrototype.LABEL`.
pub const LABEL: i32 = 0x100;

/// A single flow (branch/call/crossbuild/...) discovered while walking a constructor's p-code
/// templates.
///
/// Port of `SleighInstructionPrototype.FlowRecord`.
#[derive(Clone)]
pub struct FlowRecord {
    /// The constructor state containing the destination address of the flow, if this flow leaves
    /// the instruction and its address is statically resolvable from the parse tree.
    pub addressnode: Option<Arc<dyn ConstructState>>,
    /// The p-code template op producing the flow.
    pub op: OpTpl,
    /// Flags describing this flow; a combination of the flow-flag constants in this module.
    pub flow_flags: i32,
}

/// A summary of the flow information gathered while walking a constructor's p-code templates.
///
/// Port of `SleighInstructionPrototype.FlowSummary`.
#[derive(Clone, Default)]
pub struct FlowSummary {
    /// The largest delay-slot instruction count encoded via a `CPUI_INDIRECT` delay directive.
    pub delay: i32,
    /// True if any `CPUI_PTRSUB` (crossbuild) directive was encountered.
    pub has_cross_builds: bool,
    /// True if any input references `inst_next2`.
    pub has_next2: bool,
    /// The flow records gathered, in traversal order, or `None` if none were gathered.
    pub flow_state: Option<Vec<FlowRecord>>,
    /// The last p-code template op visited.
    pub lastop: Option<OpTpl>,
}

/// Records a single flow discovered during [`walk_templates`], resolving its destination
/// [`ConstructState`] when the flow leaves the instruction and is statically determinable.
///
/// Port of the private `SleighInstructionPrototype.addExplicitFlow`.
fn add_explicit_flow(state: Option<Arc<dyn ConstructState>>, op: OpTpl, flags: i32, summary: &mut FlowSummary) {
    let dest = op.get_in(0).clone();
    let mut record = FlowRecord {
        addressnode: None,
        op,
        flow_flags: flags,
    };

    if (flags & (JUMPOUT | CALL | CROSSBUILD)) != 0 {
        if let Some(state) = state {
            if (flags & CROSSBUILD) != 0 {
                record.addressnode = Some(state);
            } else if dest.offset.tp == ConstTplType::Handle {
                let oper = dest.offset.handle_index as i32;
                if let Some(ct) = state.constructor() {
                    if let Some(sym) = ct.operands.get(oper as usize) {
                        if sym.code_address {
                            record.addressnode = Some(state.sub_state(oper));
                        }
                    }
                }
            }
        }
    }

    summary.flow_state.get_or_insert_with(Vec::new).push(record);
}

/// Walks the p-code templates in the order they would be emitted, collecting flow-flag
/// [`FlowRecord`]s into a [`FlowSummary`].
///
/// Port of `SleighInstructionPrototype.walkTemplates(OpTplWalker)`.
pub fn walk_templates(walker: &mut dyn OpTplWalker) -> FlowSummary {
    let mut res = FlowSummary::default();

    while walker.is_state() {
        let op = match walker.next_op_tpl() {
            None => {
                walker.pop_build();
                continue;
            }
            Some(NextOpTpl::OperandIndex(buildnum)) => {
                walker.push_build(buildnum);
                continue;
            }
            Some(NextOpTpl::Op(op)) => op,
        };
        res.lastop = Some(op.clone());
        match op.get_opcode() {
            OpCode::CpuiPtrsub => {
                // Encoded crossbuild directive.
                res.has_cross_builds = true;
                add_explicit_flow(walker.get_state(), op.clone(), CROSSBUILD, &mut res);
            }
            OpCode::CpuiBranchind => {
                add_explicit_flow(None, op.clone(), BRANCH_INDIRECT | NO_FALLTHRU, &mut res);
            }
            OpCode::CpuiBranch => {
                let dest_type = op.get_in(0).offset.tp;
                let flags = if dest_type == ConstTplType::JNext {
                    BRANCH_TO_END
                } else if dest_type == ConstTplType::JStart {
                    NO_FALLTHRU
                } else if dest_type == ConstTplType::JRelative {
                    NO_FALLTHRU
                } else {
                    JUMPOUT | NO_FALLTHRU
                };
                add_explicit_flow(walker.get_state(), op.clone(), flags, &mut res);
            }
            OpCode::CpuiCbranch => {
                let dest_type = op.get_in(0).offset.tp;
                let flags = if dest_type == ConstTplType::JNext {
                    BRANCH_TO_END
                } else if dest_type == ConstTplType::JNext2 {
                    JUMPOUT
                } else if dest_type != ConstTplType::JStart && dest_type != ConstTplType::JRelative {
                    JUMPOUT
                } else {
                    0
                };
                add_explicit_flow(walker.get_state(), op.clone(), flags, &mut res);
            }
            OpCode::CpuiCall => {
                add_explicit_flow(walker.get_state(), op.clone(), CALL, &mut res);
            }
            OpCode::CpuiCallind => {
                add_explicit_flow(None, op.clone(), CALL_INDIRECT, &mut res);
            }
            OpCode::CpuiReturn => {
                add_explicit_flow(None, op.clone(), RETURN | NO_FALLTHRU, &mut res);
            }
            OpCode::CpuiPtradd => {
                // Encoded label build directive.
                add_explicit_flow(None, op.clone(), LABEL, &mut res);
            }
            OpCode::CpuiIndirect => {
                // Encode delay slot.
                let dest_type = op.get_in(0).offset.value_real as i32;
                if dest_type > res.delay {
                    res.delay = dest_type;
                }
            }
            _ => {}
        }
        for input in &op.input {
            if input.offset.tp == ConstTplType::JNext2 {
                res.has_next2 = true;
            }
        }
    }
    res
}

/// Converts normalized flow flags into a [`RefType`].
///
/// Port of the private `SleighInstructionPrototype.convertFlowFlags(int)`.
fn convert_flow_flags(mut flow_flags: i32) -> RefType {
    if (flow_flags & LABEL) != 0 {
        flow_flags |= BRANCH_TO_END;
    }
    flow_flags &= !(CROSSBUILD | LABEL);
    // NOTE: If prototype has cross-build, flow must be determined dynamically.
    if flow_flags == 0 || flow_flags == BRANCH_TO_END {
        RefType::FallThrough
    } else if flow_flags == CALL {
        RefType::UnconditionalCall
    } else if flow_flags == (CALL | NO_FALLTHRU | RETURN) {
        RefType::CallTerminator
    } else if flow_flags == (CALL_INDIRECT | NO_FALLTHRU | RETURN) {
        RefType::ComputedCallTerminator
    } else if flow_flags == (CALL | BRANCH_TO_END) {
        // This could be wrong but doesn't matter much.
        RefType::ConditionalCall
    } else if flow_flags == (CALL | NO_FALLTHRU | JUMPOUT) {
        RefType::ComputedJump
    } else if flow_flags == (CALL | NO_FALLTHRU | BRANCH_TO_END | RETURN) {
        RefType::UnconditionalCall
    } else if flow_flags == CALL_INDIRECT {
        RefType::ComputedCall
    } else if flow_flags == (BRANCH_INDIRECT | NO_FALLTHRU) {
        RefType::ComputedJump
    } else if flow_flags == (BRANCH_INDIRECT | BRANCH_TO_END)
        || flow_flags == (BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END)
        || flow_flags == (BRANCH_INDIRECT | JUMPOUT | NO_FALLTHRU | BRANCH_TO_END)
    {
        RefType::ConditionalComputedJump
    } else if flow_flags == (CALL_INDIRECT | BRANCH_TO_END)
        || flow_flags == (CALL_INDIRECT | NO_FALLTHRU | BRANCH_TO_END)
    {
        RefType::ConditionalComputedCall
    } else if flow_flags == (RETURN | NO_FALLTHRU) {
        RefType::Terminator
    } else if flow_flags == (RETURN | BRANCH_TO_END) || flow_flags == (RETURN | NO_FALLTHRU | BRANCH_TO_END)
    {
        RefType::ConditionalTerminator
    } else if flow_flags == JUMPOUT {
        RefType::ConditionalJump
    } else if flow_flags == (JUMPOUT | NO_FALLTHRU) {
        RefType::UnconditionalJump
    } else if flow_flags == (JUMPOUT | NO_FALLTHRU | BRANCH_TO_END) {
        RefType::ConditionalJump
    } else if flow_flags == (JUMPOUT | NO_FALLTHRU | RETURN) {
        RefType::JumpTerminator
    } else if flow_flags == (JUMPOUT | NO_FALLTHRU | BRANCH_INDIRECT) {
        // Added for tableswitch in JVM.
        RefType::ComputedJump
    } else if flow_flags == (BRANCH_INDIRECT | NO_FALLTHRU | RETURN) {
        RefType::JumpTerminator
    } else if flow_flags == NO_FALLTHRU {
        RefType::Terminator
    } else if flow_flags == (BRANCH_TO_END | JUMPOUT) {
        RefType::ConditionalJump
    } else if flow_flags == (NO_FALLTHRU | BRANCH_TO_END) {
        RefType::FallThrough
    } else {
        RefType::Invalid
    }
}

/// Reduces a list of [`FlowRecord`]s (as gathered by [`walk_templates`]) to a single overall
/// [`RefType`] for the instruction.
///
/// Port of `SleighInstructionPrototype.flowListToFlowType(List<FlowRecord>)`.
pub fn flow_list_to_flow_type(flowstate: Option<&[FlowRecord]>) -> RefType {
    let Some(flowstate) = flowstate else {
        return RefType::FallThrough;
    };
    let mut flags = 0i32;
    for rec in flowstate {
        flags &= !(NO_FALLTHRU | CROSSBUILD | LABEL);
        flags |= rec.flow_flags;
    }
    convert_flow_flags(flags)
}

/// The `InstructionPrototype` for sleigh languages.
///
/// The prototype is unique up to the tree of Constructors. Variations in the bit pattern that
/// none of the Constructor mask/values care about get lumped under the same prototype.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype`.
pub trait SleighInstructionPrototype: InstructionPrototype {
    /// The root [`ConstructState`] of the resolved constructor tree for this prototype.
    ///
    /// Port of `SleighInstructionPrototype.getRootState()`.
    fn get_root_state(&self) -> Arc<dyn ConstructState>;

    /// Lists the constructor line numbers used to resolve this encoding, including braces
    /// describing the tree structure. Used for testing and diagnostics.
    ///
    /// Port of `SleighInstructionPrototype.dumpConstructorTree()`.
    fn dump_constructor_tree(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::lang::instruction_prototype::GetPseudoParserContextError;
    use crate::program::model::lang::sleigh::template::const_tpl::{ConstTpl, ConstTplType as CTT};
    use crate::program::model::lang::sleigh::template::VarnodeTpl;
    use crate::program::model::lang::InstructionContext;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::instruction::OperandValue;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::{PatchEncoder, PcodeOp, PcodeOverride};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::mem::MemBuffer;
    use std::io;
    use std::sync::Mutex;

    fn real_varnode(offset: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: ConstTpl::new(),
            offset: ConstTpl {
                tp: CTT::Real,
                value_real: offset,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            size: ConstTpl::new(),
        }
    }

    struct MockConstructState {
        parent: Mutex<Option<Arc<dyn ConstructState>>>,
    }

    impl ConstructState for MockConstructState {
        fn constructor(
            &self,
        ) -> Option<Arc<crate::program::model::lang::sleigh::constructor::Constructor>> {
            None
        }
        fn sub_state(&self, _index: i32) -> Arc<dyn ConstructState> {
            unimplemented!("not exercised by these tests")
        }
        fn parent(&self) -> Option<Arc<dyn ConstructState>> {
            self.parent.lock().unwrap().clone()
        }
    }

    struct MockWalker {
        point: Option<Arc<dyn ConstructState>>,
        oparray: Option<Vec<OpTpl>>,
        depth: i32,
        breadcrumb: Vec<i32>,
        maxsize: i32,
    }

    impl MockWalker {
        fn new(point: Arc<dyn ConstructState>, ops: Vec<OpTpl>) -> Self {
            let maxsize = ops.len() as i32;
            Self {
                point: Some(point),
                oparray: Some(ops),
                depth: 0,
                breadcrumb: vec![0],
                maxsize,
            }
        }
    }

    impl OpTplWalker for MockWalker {
        fn point(&self) -> Option<Arc<dyn ConstructState>> {
            self.point.clone()
        }
        fn set_point(&mut self, point: Option<Arc<dyn ConstructState>>) {
            self.point = point;
        }
        fn oparray(&self) -> Option<&Vec<OpTpl>> {
            self.oparray.as_ref()
        }
        fn set_oparray(&mut self, oparray: Option<Vec<OpTpl>>) {
            self.oparray = oparray;
        }
        fn depth(&self) -> i32 {
            self.depth
        }
        fn set_depth(&mut self, depth: i32) {
            self.depth = depth;
        }
        fn breadcrumb(&self) -> &Vec<i32> {
            &self.breadcrumb
        }
        fn breadcrumb_mut(&mut self) -> &mut Vec<i32> {
            &mut self.breadcrumb
        }
        fn maxsize(&self) -> i32 {
            self.maxsize
        }
        fn set_maxsize(&mut self, maxsize: i32) {
            self.maxsize = maxsize;
        }
        fn sectionnum(&self) -> i32 {
            -1
        }
    }

    #[test]
    fn walk_templates_collects_crossbuild_delay_and_call_flow_records() {
        let state: Arc<dyn ConstructState> = Arc::new(MockConstructState {
            parent: Mutex::new(None),
        });

        let mut ptrsub_op = OpTpl::with_opcode(OpCode::CpuiPtrsub);
        ptrsub_op.add_input(real_varnode(0));
        let mut indirect_op = OpTpl::with_opcode(OpCode::CpuiIndirect);
        indirect_op.add_input(real_varnode(2)); // delay slot byte count
        let mut call_op = OpTpl::with_opcode(OpCode::CpuiCall);
        call_op.add_input(real_varnode(0));

        let mut walker = MockWalker::new(state.clone(), vec![ptrsub_op, indirect_op, call_op.clone()]);
        let summary = walk_templates(&mut walker);

        assert!(summary.has_cross_builds);
        assert!(!summary.has_next2);
        assert_eq!(summary.delay, 2);
        assert_eq!(summary.lastop.unwrap().get_opcode(), OpCode::CpuiCall);

        let records = summary.flow_state.expect("expected flow records");
        assert_eq!(records.len(), 2);

        assert_eq!(records[0].flow_flags, CROSSBUILD);
        let addressnode = records[0].addressnode.as_ref().expect("crossbuild address");
        assert!(Arc::ptr_eq(addressnode, &state));

        assert_eq!(records[1].flow_flags, CALL);
        assert!(records[1].addressnode.is_none());
    }

    #[test]
    fn flow_list_to_flow_type_maps_known_flag_combinations() {
        let rec = |flags: i32| FlowRecord {
            addressnode: None,
            op: OpTpl::with_opcode(OpCode::CpuiCall),
            flow_flags: flags,
        };

        assert_eq!(flow_list_to_flow_type(None), RefType::FallThrough);
        assert_eq!(flow_list_to_flow_type(Some(&[rec(CALL)])), RefType::UnconditionalCall);
        assert_eq!(
            flow_list_to_flow_type(Some(&[rec(JUMPOUT | NO_FALLTHRU)])),
            RefType::UnconditionalJump
        );
        assert_eq!(
            flow_list_to_flow_type(Some(&[rec(RETURN | NO_FALLTHRU)])),
            RefType::Terminator
        );
        // LABEL alone folds into BRANCH_TO_END once CROSSBUILD/LABEL bits are stripped.
        assert_eq!(flow_list_to_flow_type(Some(&[rec(LABEL)])), RefType::FallThrough);
    }

    // --- SleighInstructionPrototype trait object-safety smoke test ---

    struct MockPrototype {
        root: Arc<dyn ConstructState>,
    }

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, GetPseudoParserContextError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn InstructionContext) -> String {
            "NOP".to_string()
        }

        fn get_length(&self) -> i32 {
            2
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_operand_value_mask(
            &self,
            _operand_index: i32,
        ) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
            RefType::FallThrough
        }

        fn get_delay_slot_depth(&self, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }

        fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
            2
        }

        fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Vec<OperandValue>> {
            None
        }

        fn get_address(&self, _operand_index: i32, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<RegisterRef> {
            None
        }

        fn get_scalar(&self, _operand_index: i32, _context: &dyn InstructionContext) -> Option<Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn InstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl SleighInstructionPrototype for MockPrototype {
        fn get_root_state(&self) -> Arc<dyn ConstructState> {
            self.root.clone()
        }

        fn dump_constructor_tree(&self) -> String {
            "{1}".to_string()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let root: Arc<dyn ConstructState> = Arc::new(MockConstructState {
            parent: Mutex::new(None),
        });
        let proto: Box<dyn SleighInstructionPrototype> = Box::new(MockPrototype { root: root.clone() });

        assert_eq!(proto.get_length(), 2);
        assert!(Arc::ptr_eq(&proto.get_root_state(), &root));
        assert_eq!(proto.dump_constructor_tree(), "{1}");
    }
}
