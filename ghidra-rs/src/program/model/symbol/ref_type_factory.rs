use crate::program::model::address::Address;
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::listing::instruction_record::{InstructionSnapshot, InstructionView};
use crate::program::model::mem::Memory;
use crate::program::model::pcode::OpCode;
use crate::program::model::symbol::RefType;

/// Reference type factory helpers.
///
/// This ports the static lookup and category lists from Ghidra's `RefTypeFactory`, and its
/// instruction routines (`getDefaultFlowType`, `getDefaultComputedFlowType`,
/// `getDefaultMemoryRefType` for instructions) over an [`InstructionView`]. The register, stack
/// and data-code-unit routines are not ported yet.
pub struct RefTypeFactory;

const MEMORY_REF_TYPES: &[RefType] = &[
    RefType::Indirection,
    RefType::ComputedCall,
    RefType::ComputedJump,
    RefType::ConditionalCall,
    RefType::ConditionalJump,
    RefType::UnconditionalCall,
    RefType::UnconditionalJump,
    RefType::ConditionalComputedCall,
    RefType::ConditionalComputedJump,
    RefType::Param,
    RefType::Data,
    RefType::DataInd,
    RefType::Read,
    RefType::ReadInd,
    RefType::Write,
    RefType::WriteInd,
    RefType::ReadWrite,
    RefType::ReadWriteInd,
    RefType::CallOverrideUnconditional,
    RefType::JumpOverrideUnconditional,
    RefType::CallOtherOverrideCall,
    RefType::CallOtherOverrideJump,
];

const STACK_REF_TYPES: &[RefType] = &[
    RefType::Data,
    RefType::Read,
    RefType::Write,
    RefType::ReadWrite,
];

const DATA_REF_TYPES: &[RefType] = &[
    RefType::Data,
    RefType::Param,
    RefType::Read,
    RefType::Write,
    RefType::ReadWrite,
];

const EXTERNAL_REF_TYPES: &[RefType] = &[
    RefType::ComputedCall,
    RefType::ComputedJump,
    RefType::ConditionalCall,
    RefType::ConditionalJump,
    RefType::UnconditionalCall,
    RefType::UnconditionalJump,
    RefType::ConditionalComputedCall,
    RefType::ConditionalComputedJump,
    RefType::Data,
    RefType::DataInd,
    RefType::Read,
    RefType::ReadInd,
    RefType::Write,
    RefType::WriteInd,
    RefType::ReadWrite,
    RefType::ReadWriteInd,
    RefType::CallOverrideUnconditional,
    RefType::CallOtherOverrideCall,
    RefType::CallOtherOverrideJump,
];

impl RefTypeFactory {
    /// Returns the memory reference types accepted by Ghidra's factory.
    pub fn memory_ref_types() -> &'static [RefType] {
        MEMORY_REF_TYPES
    }

    /// Returns the stack reference types accepted by Ghidra's factory.
    pub fn stack_ref_types() -> &'static [RefType] {
        STACK_REF_TYPES
    }

    /// Returns the data reference types accepted by Ghidra's factory.
    pub fn data_ref_types() -> &'static [RefType] {
        DATA_REF_TYPES
    }

    /// Returns the external reference types accepted by Ghidra's factory.
    pub fn external_ref_types() -> &'static [RefType] {
        EXTERNAL_REF_TYPES
    }

    /// Looks up a static reference type by Java byte value.
    pub fn get(value: i8) -> Result<RefType, String> {
        RefType::from_value(value).ok_or_else(|| format!("RefType not defined: {value}"))
    }

    /// Returns true if the type is valid for memory references.
    pub fn is_valid_memory_ref_type(ref_type: RefType) -> bool {
        MEMORY_REF_TYPES.contains(&ref_type)
    }

    /// Port of `getDefaultFlowType(Instruction, Address, boolean)`: the default flow type of
    /// `instr`'s flow to `to_addr`, or `None` if it cannot be determined. With
    /// `allow_computed_flow_type`, a computed flow type is returned when no absolute one is found
    /// and only one exists.
    ///
    /// Java throws `IllegalArgumentException` for a `to_addr` that is neither a memory nor an
    /// external address; this returns `None` for one.
    pub fn get_default_flow_type<S: InstructionSnapshot + ?Sized>(
        instr: &InstructionView<'_, S>,
        to_addr: &Address,
        allow_computed_flow_type: bool,
    ) -> Option<RefType> {
        if !to_addr.is_memory_address() && !to_addr.is_external_address() {
            return None;
        }
        let simple_flow = Self::is_simple_flow(instr);
        let flow_type = if simple_flow { Self::default_jump_or_call_flow_type(instr.flow_type()) } else { None };
        if let Some(flow_type) = flow_type {
            if !flow_type.is_computed() || allow_computed_flow_type {
                return Some(flow_type);
            }
        }
        if simple_flow || to_addr.is_external_address() {
            // Don't bother looking if not complex flow or address is external
            return None;
        }
        // Assumption - any complex flow type is due to the presence of multiple conditional
        // flows (as in Java).
        for op in instr.pcode(None) {
            let target = op.get_input(0).map(|v| v.get_address() == to_addr).unwrap_or(false);
            match op.get_opcode() {
                OpCode::CBranch | OpCode::Branch if target => return Some(RefType::ConditionalJump),
                OpCode::Call if target => return Some(RefType::ConditionalCall),
                _ => {}
            }
        }
        if allow_computed_flow_type {
            return Self::get_default_computed_flow_type(instr);
        }
        None
    }

    /// Port of `getDefaultComputedFlowType(Instruction)`: assumes every computed flow uses a
    /// register in its destination computation.
    pub fn get_default_computed_flow_type<S: InstructionSnapshot + ?Sized>(
        instr: &InstructionView<'_, S>,
    ) -> Option<RefType> {
        if Self::is_simple_flow(instr) {
            // Don't bother looking if not complex flow
            return Self::default_jump_or_call_flow_type(instr.flow_type());
        }
        let mut flow_type = None;
        for op in instr.pcode(None) {
            match op.get_opcode() {
                OpCode::BranchInd => {
                    if flow_type == Some(RefType::ConditionalComputedCall) {
                        return None; // more than one flow type
                    }
                    flow_type = Some(RefType::ConditionalComputedJump);
                }
                OpCode::CallInd => {
                    if flow_type == Some(RefType::ConditionalComputedJump) {
                        return None; // more than one flow type
                    }
                    flow_type = Some(RefType::ConditionalComputedCall);
                }
                _ => {}
            }
        }
        flow_type
    }

    /// Port of `getDefaultMemoryRefType(CodeUnit, int, Address, boolean)` for an instruction with
    /// `ignoreExistingReferences` true (what `CodeManager` asks when it lays down default
    /// references): the default reference type of `instr`'s operand `op_index` to `to_addr`.
    /// `memory` answers whether `to_addr` is in a mapped block (which rules out a speculative
    /// computed flow type).
    ///
    /// Java throws `IllegalArgumentException` for a `to_addr` that is neither a memory nor an
    /// external address; this returns `None` for one.
    pub fn get_default_memory_ref_type<S: InstructionSnapshot + ?Sized>(
        instr: &InstructionView<'_, S>,
        op_index: i32,
        to_addr: &Address,
        memory: &dyn Memory,
    ) -> Option<RefType> {
        let mut speculative_flow_not_allowed = false;
        if to_addr.is_memory_address() && memory.get_block(to_addr).is_some_and(|b| b.get_type().is_mapped()) {
            speculative_flow_not_allowed = true;
        }
        if !to_addr.is_memory_address() && !to_addr.is_external_address() {
            return None;
        }
        if instr.default_flows().unwrap_or_default().iter().any(|flow| flow == to_addr) {
            // we should always find default flows and INVALID should not happen
            return Some(Self::get_default_flow_type(instr, to_addr, false).unwrap_or(RefType::Invalid));
        }
        let is_to = |obj: &OperandValue| matches!(obj, OperandValue::Address(a) if a == to_addr);
        let mut ref_type = None;
        if instr.result_objects().iter().any(is_to) {
            ref_type = Some(RefType::Write);
        }
        for input in instr.input_objects() {
            if is_to(&input) {
                if ref_type == Some(RefType::Write) {
                    return Some(RefType::ReadWrite);
                }
                let operand_ref_type =
                    instr.record().prototype().get_operand_ref_type(op_index, instr, None);
                ref_type = Some(operand_ref_type);
                if operand_ref_type != RefType::Indirection {
                    return Some(RefType::Read);
                }
            }
        }
        if ref_type.is_some() {
            return ref_type;
        }
        let mut ref_type = Self::get_mem_ref_type(instr, to_addr);
        if ref_type.is_none() && !speculative_flow_not_allowed {
            ref_type = Self::get_default_computed_flow_type(instr);
        }
        Some(ref_type.unwrap_or(RefType::Data))
    }

    fn is_simple_flow<S: InstructionSnapshot + ?Sized>(instr: &InstructionView<'_, S>) -> bool {
        instr.flow_type() != RefType::Invalid && instr.default_flows().map_or(0, |f| f.len()) <= 1
    }

    /// Port of the private `getDefaultJumpOrCallFlowType`: the call/jump flow type of an
    /// instruction flow type, without terminator.
    fn default_jump_or_call_flow_type(flow_type: RefType) -> Option<RefType> {
        let (call, jump) = (flow_type.is_call(), flow_type.is_jump());
        let computed = flow_type.is_computed();
        if flow_type.is_conditional() {
            match (computed, call, jump) {
                (true, true, _) => return Some(RefType::ConditionalComputedCall),
                (true, false, true) => return Some(RefType::ConditionalComputedJump),
                (false, true, _) => return Some(RefType::ConditionalCall),
                (false, false, true) => return Some(RefType::ConditionalJump),
                _ => {}
            }
        }
        match (computed, call, jump) {
            (true, true, _) => Some(RefType::ComputedCall),
            (true, false, true) => Some(RefType::ComputedJump),
            (false, true, _) => Some(RefType::UnconditionalCall),
            (false, false, true) => Some(RefType::UnconditionalJump),
            _ => None,
        }
    }

    /// Port of the private `getMemRefType(Instruction, Address)`: how `instr`'s p-code uses
    /// `mem_addr` -- loaded, stored, used as a constant, or loaded and then flowed through
    /// (`INDIRECTION`).
    fn get_mem_ref_type<S: InstructionSnapshot + ?Sized>(
        instr: &InstructionView<'_, S>,
        mem_addr: &Address,
    ) -> Option<RefType> {
        let mem_offset = mem_addr.addressable_word_offset();
        let mut ref_type: Option<RefType> = None;
        let mut offset_varnode = None;
        let mut value_varnode = None;
        for op in instr.pcode(None) {
            let inputs = op.get_inputs();
            let opcode = op.get_opcode();
            if opcode == OpCode::IntZext || opcode == OpCode::Copy {
                if inputs.first().is_some_and(|v| v.is_constant() && v.get_offset() == mem_offset) {
                    offset_varnode = op.get_output().cloned();
                    ref_type = Some(RefType::Data);
                    continue;
                }
            }
            let is_mem_operand = |vn: Option<&crate::program::model::pcode::Varnode>| {
                vn.is_some_and(|vn| vn.get_offset() == mem_offset || offset_varnode.as_ref() == Some(vn))
            };
            if opcode == OpCode::Store {
                // Java compares the space's unique id with the space varnode's space id
                if inputs.first().is_some_and(|v| mem_addr.space().unique() == v.get_space_id())
                    && is_mem_operand(inputs.get(1))
                {
                    if ref_type.is_some_and(RefType::is_read) {
                        return Some(RefType::ReadWrite);
                    }
                    ref_type = Some(RefType::Write);
                }
            } else if opcode == OpCode::Load {
                if inputs.first().is_some_and(|v| i64::from(mem_addr.space().space_id()) == v.get_offset())
                    && is_mem_operand(inputs.get(1))
                {
                    if ref_type.is_some_and(RefType::is_write) {
                        return Some(RefType::ReadWrite);
                    }
                    ref_type = Some(RefType::Read);
                    value_varnode = op.get_output().cloned();
                }
            } else {
                for input in inputs {
                    if ref_type.is_none() && input.is_constant() && input.get_offset() == mem_offset {
                        ref_type = Some(RefType::Data);
                    } else if input.is_address() && input.get_address().offset() == mem_addr.offset() {
                        // only the offsets are compared, as in Java (overlay spaces)
                        if ref_type.is_some_and(RefType::is_write) {
                            return Some(RefType::ReadWrite);
                        }
                        ref_type = Some(RefType::Read);
                    }
                }
            }
            if let Some(value) = &value_varnode {
                let is_flow_op = matches!(
                    opcode,
                    OpCode::Call | OpCode::CallInd | OpCode::CBranch | OpCode::Branch | OpCode::BranchInd
                );
                if is_flow_op && inputs.first() == Some(value) {
                    return Some(RefType::Indirection);
                }
            }
        }
        ref_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_ref_type_factory_static_map() {
        assert_eq!(RefTypeFactory::get(-2), Ok(RefType::Invalid));
        assert_eq!(RefTypeFactory::get(-1), Ok(RefType::Flow));
        assert_eq!(RefTypeFactory::get(0), Ok(RefType::FallThrough));
        assert_eq!(
            RefTypeFactory::get(16),
            Ok(RefType::CallOverrideUnconditional)
        );
        assert_eq!(RefTypeFactory::get(19), Ok(RefType::CallOtherOverrideJump));
        assert_eq!(RefTypeFactory::get(110), Ok(RefType::Read));
        assert_eq!(RefTypeFactory::get(111), Ok(RefType::Write));
        assert!(RefTypeFactory::get(112)
            .unwrap_err()
            .contains("not defined"));
    }

    #[test]
    fn memory_ref_types_match_java_order() {
        assert_eq!(
            RefTypeFactory::memory_ref_types(),
            &[
                RefType::Indirection,
                RefType::ComputedCall,
                RefType::ComputedJump,
                RefType::ConditionalCall,
                RefType::ConditionalJump,
                RefType::UnconditionalCall,
                RefType::UnconditionalJump,
                RefType::ConditionalComputedCall,
                RefType::ConditionalComputedJump,
                RefType::Param,
                RefType::Data,
                RefType::DataInd,
                RefType::Read,
                RefType::ReadInd,
                RefType::Write,
                RefType::WriteInd,
                RefType::ReadWrite,
                RefType::ReadWriteInd,
                RefType::CallOverrideUnconditional,
                RefType::JumpOverrideUnconditional,
                RefType::CallOtherOverrideCall,
                RefType::CallOtherOverrideJump,
            ]
        );
        assert!(RefTypeFactory::is_valid_memory_ref_type(RefType::Read));
        assert!(!RefTypeFactory::is_valid_memory_ref_type(
            RefType::FallThrough
        ));
    }

    #[test]
    fn stack_data_and_external_ref_type_groups_match_java_order() {
        assert_eq!(
            RefTypeFactory::stack_ref_types(),
            &[
                RefType::Data,
                RefType::Read,
                RefType::Write,
                RefType::ReadWrite
            ]
        );
        assert_eq!(
            RefTypeFactory::data_ref_types(),
            &[
                RefType::Data,
                RefType::Param,
                RefType::Read,
                RefType::Write,
                RefType::ReadWrite
            ]
        );
        assert_eq!(
            RefTypeFactory::external_ref_types().first(),
            Some(&RefType::ComputedCall)
        );
        assert_eq!(
            RefTypeFactory::external_ref_types().last(),
            Some(&RefType::CallOtherOverrideJump)
        );
        assert!(!RefTypeFactory::external_ref_types().contains(&RefType::Param));
        assert!(!RefTypeFactory::external_ref_types().contains(&RefType::JumpOverrideUnconditional));
    }
}
