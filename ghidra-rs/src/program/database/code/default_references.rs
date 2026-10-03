//! The default references `CodeManager` lays down for a new instruction: port of the private
//! `CodeManager.addReferencesForInstruction` with `addDefaultMemoryReferenceIfMissing` and
//! `getOperandMemoryReferenceType`.
//!
//! Every address in an operand's representation (or, when the representation has none and
//! flows remain unaccounted for, the operand's address value) that is not a register becomes a
//! `SourceType::Default` memory reference on that operand, typed by
//! [`RefTypeFactory::get_default_memory_ref_type`]; an operand reference whose type is a flow
//! consumes the matching flow address. The flows left over become mnemonic references, typed by
//! [`RefTypeFactory::get_default_flow_type`] -- except a jump to the next instruction from an
//! instruction that falls through. Fall-through itself is never a reference.
//!
//! Java's re-disassembly mode (reusing the instruction's existing default references) is not
//! ported: instructions are only created where none existed.

use crate::program::database::references::{ReferenceId, ReferenceStore};
use crate::program::model::address::Address;
use crate::program::model::lang::Language;
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::listing::instruction_record::{InstructionSnapshot, InstructionView};
use crate::program::model::mem::Memory;
use crate::program::model::symbol::{RefType, RefTypeFactory, Reference, SourceType};

/// Adds the default references of the instruction `inst` to `refs`. `memory` is the program's
/// (mapped-block checks) and `language` its language (register addresses get no reference).
pub fn add_references_for_instruction<S: InstructionSnapshot + ?Sized>(
    refs: &mut ReferenceStore,
    inst: &InstructionView<'_, S>,
    memory: &dyn Memory,
    language: &dyn Language,
) {
    let prototype = inst.record().prototype();
    let from = inst.record().address().clone();
    let mut flow_addrs: Vec<Option<Address>> =
        prototype.get_flows(inst).unwrap_or_default().into_iter().map(Some).collect();
    let mut remaining_addrs = flow_addrs.len() as i64;

    for op_index in 0..prototype.get_num_operands() {
        // only the addresses reported by the prototype, not any added by the user
        let mut ref_cnt = 0;
        let mut operand_primary_ref = None;
        for obj in prototype.get_op_representation_list(op_index, inst).unwrap_or_default() {
            if let OperandValue::Address(ref_addr) = obj {
                ref_cnt += 1;
                if let Some(ref_type) =
                    operand_memory_reference_type(inst, op_index, &mut flow_addrs, &ref_addr, memory, language)
                {
                    operand_primary_ref =
                        add_default_memory_reference(refs, &from, op_index, ref_addr, ref_type, operand_primary_ref);
                    remaining_addrs -= 1;
                }
            }
        }
        // If there are still more addresses on this operand, see if the whole operand has any
        if ref_cnt == 0 && remaining_addrs > 0 {
            if let Some(ref_addr) = prototype.get_address(op_index, inst) {
                if let Some(ref_type) =
                    operand_memory_reference_type(inst, op_index, &mut flow_addrs, &ref_addr, memory, language)
                {
                    operand_primary_ref =
                        add_default_memory_reference(refs, &from, op_index, ref_addr, ref_type, operand_primary_ref);
                    remaining_addrs -= 1;
                }
            }
        }
        ensure_primary(refs, operand_primary_ref);
    }

    let mut mnemonic_primary_ref = None;
    let next = inst.record().address().add_wrap(i64::from(inst.record().length()) - 1).next().ok();
    for flow_addr in flow_addrs.into_iter().flatten() {
        if !flow_addr.is_memory_address() {
            continue;
        }
        let flow_type = RefTypeFactory::get_default_flow_type(inst, &flow_addr, false).unwrap_or(RefType::Invalid);
        // Only drop a jump to the next address if the instruction falls through: removing the
        // branch to next address of an instruction with no fall-through breaks flow following.
        let is_fallthrough = flow_type.is_jump() && next.as_ref() == Some(&flow_addr) && inst.has_fallthrough();
        if !is_fallthrough {
            mnemonic_primary_ref = add_default_memory_reference(
                refs,
                &from,
                RefType::MNEMONIC,
                flow_addr,
                flow_type,
                mnemonic_primary_ref,
            );
        }
    }
    ensure_primary(refs, mnemonic_primary_ref);
}

/// Port of `getOperandMemoryReferenceType`: `None` for a register address (or one Java would
/// reject); a flow type consumes its address from `flow_addrs`, and a flow type to an address
/// that is not one of the flows becomes `DATA` (unless it is `INDIRECTION`).
fn operand_memory_reference_type<S: InstructionSnapshot + ?Sized>(
    inst: &InstructionView<'_, S>,
    op_index: i32,
    flow_addrs: &mut [Option<Address>],
    ref_addr: &Address,
    memory: &dyn Memory,
    language: &dyn Language,
) -> Option<RefType> {
    if language.get_register_at(ref_addr, 0).is_some() {
        return None;
    }
    let ref_type = RefTypeFactory::get_default_memory_ref_type(inst, op_index, ref_addr, memory)?;
    if ref_type.is_flow() {
        if let Some(slot) = flow_addrs.iter_mut().find(|slot| slot.as_ref() == Some(ref_addr)) {
            *slot = None;
            return Some(ref_type);
        }
        if ref_type != RefType::Indirection {
            return Some(RefType::Data);
        }
    }
    Some(ref_type)
}

/// Port of `addDefaultMemoryReferenceIfMissing` without an old-reference list: adds the
/// reference and returns the operand's preferred primary reference (the first one added).
fn add_default_memory_reference(
    refs: &mut ReferenceStore,
    from: &Address,
    op_index: i32,
    to: Address,
    ref_type: RefType,
    operand_primary_ref: Option<ReferenceId>,
) -> Option<ReferenceId> {
    match refs.add_memory_reference(from.clone(), to, ref_type, SourceType::Default, op_index) {
        Ok(added) => operand_primary_ref.or(Some(added.id())),
        Err(_) => operand_primary_ref,
    }
}

/// Ensures the preferred primary reference of an operand is primary, if there is one.
fn ensure_primary(refs: &mut ReferenceStore, preferred: Option<ReferenceId>) {
    if let Some(id) = preferred {
        if refs.get(id).is_some_and(|r| !r.is_primary()) {
            refs.set_primary(id, true);
        }
    }
}
