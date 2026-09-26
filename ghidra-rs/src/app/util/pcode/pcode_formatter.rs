use std::collections::HashMap;

use crate::decompiler::opcodes::OpCode as SleighOpCode;
use crate::program::model::address::AddressFactory;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, OpTpl, VarnodeTpl};
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};

/// Formats p-code ops into some result `T`.
///
/// Port of `ghidra.app.util.pcode.PcodeFormatter`.
pub trait PcodeFormatter<T> {
    /// Format the p-code ops.
    ///
    /// Mirrors `PcodeFormatter.formatOps(Language, List<PcodeOp>)`, which delegates to the
    /// [`format_ops_with_factory`](Self::format_ops_with_factory) overload using the language's
    /// own address factory.
    fn format_ops(&self, language: &dyn Language, pcode_ops: &[PcodeOp]) -> T {
        let addr_factory = language.get_address_factory();
        self.format_ops_with_factory(language, addr_factory.as_ref(), pcode_ops)
    }

    /// Format the p-code ops with a specified [`AddressFactory`]. For use when the pcode ops can
    /// reference program-specific address spaces.
    ///
    /// Mirrors `PcodeFormatter.formatOps(Language, AddressFactory, List<PcodeOp>)`.
    fn format_ops_with_factory(
        &self,
        language: &dyn Language,
        addr_factory: &dyn AddressFactory,
        pcode_ops: &[PcodeOp],
    ) -> T {
        self.format_templates(language, &get_pcode_op_templates(addr_factory, pcode_ops))
    }

    /// Format the p-code op templates.
    ///
    /// Mirrors `PcodeFormatter.formatTemplates(Language, List<OpTpl>)`.
    fn format_templates(&self, language: &dyn Language, pcode_op_templates: &[OpTpl]) -> T;
}

/// Convert one p-code op into a template, without re-writing relative branches.
///
/// Mirrors `PcodeFormatter.getPcodeOpTemplateLog(AddressFactory, PcodeOp)`. `addr_factory` is
/// unused, matching the Java method (which also never reads it -- `getVarnodeTpl` doesn't need
/// it either).
pub fn get_pcode_op_template_log(_addr_factory: &dyn AddressFactory, pcode_op: &PcodeOp) -> OpTpl {
    let output_tpl = pcode_op.output.as_ref().map(get_varnode_tpl);
    let input_tpls = pcode_op.inputs.iter().map(get_varnode_tpl).collect();
    OpTpl {
        opc: sleigh_opcode(pcode_op.opcode),
        output: output_tpl,
        input: input_tpls,
    }
}

/// Convert flattened p-code ops into templates, without re-writing relative branches.
///
/// Mirrors `PcodeFormatter.getPcodeOpTemplatesLog(AddressFactory, List<PcodeOp>)`.
pub fn get_pcode_op_templates_log(
    addr_factory: &dyn AddressFactory,
    pcode_ops: &[PcodeOp],
) -> Vec<OpTpl> {
    pcode_ops
        .iter()
        .map(|op| get_pcode_op_template_log(addr_factory, op))
        .collect()
}

/// Convert flattened p-code ops into templates.
///
/// Mirrors `PcodeFormatter.getPcodeOpTemplates(AddressFactory, List<PcodeOp>)`.
pub fn get_pcode_op_templates(addr_factory: &dyn AddressFactory, pcode_ops: &[PcodeOp]) -> Vec<OpTpl> {
    let mut list: Vec<OpTpl> = Vec::with_capacity(pcode_ops.len());
    // label offset to index map
    let mut label_map: HashMap<i32, i32> = HashMap::new();

    for (seq, pcode_op) in pcode_ops.iter().enumerate() {
        let opcode = pcode_op.opcode;

        let output_tpl = pcode_op.output.as_ref().map(get_varnode_tpl);

        let mut input_tpls: Vec<VarnodeTpl> = Vec::with_capacity(pcode_op.inputs.len());
        for (i, input) in pcode_op.inputs.iter().enumerate() {
            if i == 0 && (opcode == OpCode::Branch || opcode == OpCode::CBranch) && input.is_constant() {
                // Handle internal branch destination represented by constant destination
                let label_offset = seq as i32 + input.get_offset() as i32;
                let label_index = match label_map.get(&label_offset) {
                    Some(&idx) => idx,
                    None => {
                        let idx = label_map.len() as i32;
                        label_map.insert(label_offset, idx);
                        idx
                    }
                };
                input_tpls.push(VarnodeTpl {
                    space: const_tpl_space(addr_factory),
                    offset: real_const_tpl_typed(ConstTplType::JRelative, label_index as u64),
                    size: real_const_tpl(8),
                });
                continue;
            }
            input_tpls.push(get_varnode_tpl(input));
        }

        list.push(OpTpl {
            opc: sleigh_opcode(opcode),
            output: output_tpl,
            input: input_tpls,
        });
    }

    // Insert label templates from the bottom-up
    let mut offset_list: Vec<i32> = label_map.keys().copied().collect();
    offset_list.sort_unstable();
    for &label_offset in offset_list.iter().rev() {
        if label_offset < 0 || label_offset as usize > pcode_ops.len() {
            // Skip jumps out of this block/program
            continue;
        }
        let label_index = label_map[&label_offset];
        let label_tpl = get_label_op_template(addr_factory, label_index);
        list.insert(label_offset as usize, label_tpl);
    }

    list
}

/// Create label `OpTpl`. Uses overloaded `PcodeOp.PTRADD` with `input[0]` = `labelIndex`.
///
/// Mirrors the private `PcodeFormatter.getLabelOpTemplate(AddressFactory, int)`.
fn get_label_op_template(addr_factory: &dyn AddressFactory, label_index: i32) -> OpTpl {
    let input = VarnodeTpl {
        space: const_tpl_space(addr_factory),
        offset: real_const_tpl(label_index as u64),
        size: real_const_tpl(8),
    };
    OpTpl {
        opc: SleighOpCode::CpuiPtradd,
        output: None,
        input: vec![input],
    }
}

/// Mirrors `PcodeFormatter.getVarnodeTpl(AddressFactory, Varnode)`. The Java method also takes an
/// `AddressFactory` parameter, but never reads it -- the varnode's own address space is used
/// instead -- so it's dropped here.
pub fn get_varnode_tpl(v: &Varnode) -> VarnodeTpl {
    VarnodeTpl {
        space: ConstTpl {
            tp: ConstTplType::SpaceId,
            value_real: 0,
            value_spaceid: Some(v.get_address().space().clone()),
            handle_index: 0,
            select: None,
        },
        offset: real_const_tpl(v.get_offset() as u64),
        size: real_const_tpl(v.get_size() as u64),
    }
}

/// A `ConstTpl` of type `REAL` holding `value`. Mirrors `new ConstTpl(ConstTpl.REAL, value)`.
fn real_const_tpl(value: u64) -> ConstTpl {
    real_const_tpl_typed(ConstTplType::Real, value)
}

/// A `ConstTpl` of the given type holding `value`. Mirrors `new ConstTpl(tp, value)`.
fn real_const_tpl_typed(tp: ConstTplType, value: u64) -> ConstTpl {
    ConstTpl {
        tp,
        value_real: value,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    }
}

/// A `ConstTpl` of type `SPACEID` holding the address factory's constant space. Mirrors
/// `new ConstTpl(addrFactory.getConstantSpace())`.
fn const_tpl_space(addr_factory: &dyn AddressFactory) -> ConstTpl {
    ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: addr_factory.get_constant_space(),
        handle_index: 0,
        select: None,
    }
}

/// Converts a `ghidra.program.model.pcode.PcodeOp` opcode into the corresponding
/// `ghidra.pcodeCPort.opcodes.OpCode`. The two enums share the same opcode numbering (Ghidra's
/// p-code opcode numbers are a crate-wide constant), so this is a plain ordinal round-trip.
fn sleigh_opcode(opcode: OpCode) -> SleighOpCode {
    SleighOpCode::from_ordinal(opcode as usize)
        .unwrap_or_else(|| panic!("unmapped p-code opcode {opcode:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::pcode::SequenceNumber;

    fn factory() -> (DefaultAddressFactory, std::sync::Arc<AddressSpace>, std::sync::Arc<AddressSpace>) {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let constant = AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1);
        let factory = DefaultAddressFactory::new(vec![ram.clone(), constant.clone()]);
        (factory, ram, constant)
    }

    #[test]
    fn get_varnode_tpl_mirrors_varnode_address_offset_and_size() {
        let (_factory, ram, _constant) = factory();
        let vn = Varnode::new(Address::new(ram.clone(), 0x1234), 4);

        let tpl = get_varnode_tpl(&vn);

        assert_eq!(tpl.space.tp, ConstTplType::SpaceId);
        assert_eq!(tpl.space.value_spaceid, Some(ram));
        assert_eq!(tpl.offset.tp, ConstTplType::Real);
        assert_eq!(tpl.offset.value_real, 0x1234);
        assert_eq!(tpl.size.tp, ConstTplType::Real);
        assert_eq!(tpl.size.value_real, 4);
    }

    #[test]
    fn get_pcode_op_templates_passes_through_non_branch_ops() {
        let (factory, ram, _constant) = factory();

        let copy_out = Varnode::new(Address::new(ram.clone(), 0x14), 1);
        let copy_in = Varnode::new(Address::new(ram.clone(), 0x10), 1);
        let copy = PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(Address::new(ram.clone(), 0x1000), 0),
            vec![copy_in],
            Some(copy_out),
        );

        let templates = get_pcode_op_templates(&factory, std::slice::from_ref(&copy));

        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].opc, SleighOpCode::CpuiCopy);
        assert!(templates[0].output.is_some());
        assert_eq!(templates[0].input.len(), 1);
    }

    #[test]
    fn get_pcode_op_templates_rewrites_backward_branch_and_inserts_label() {
        let (factory, ram, constant) = factory();

        // A CBRANCH back to the top of this two-op sequence (offset 0, i.e. seq 0 + 0).
        let cond = Varnode::new(Address::new(ram.clone(), 0x10), 1);
        let target = Varnode::new(Address::new(constant.clone(), 0), 8);
        let branch = PcodeOp::new(
            OpCode::CBranch,
            SequenceNumber::new(Address::new(ram.clone(), 0x1000), 0),
            vec![target, cond],
            None,
        );

        let copy_out = Varnode::new(Address::new(ram.clone(), 0x14), 1);
        let copy_in = Varnode::new(Address::new(ram.clone(), 0x10), 1);
        let copy = PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(Address::new(ram.clone(), 0x1001), 0),
            vec![copy_in],
            Some(copy_out),
        );

        let templates = get_pcode_op_templates(&factory, &[branch, copy]);

        // The label (for offset 0) is inserted before the branch that targets it: [label,
        // cbranch, copy].
        assert_eq!(templates.len(), 3);

        assert_eq!(templates[0].opc, SleighOpCode::CpuiPtradd);
        assert!(templates[0].output.is_none());
        assert_eq!(templates[0].input.len(), 1);
        assert_eq!(templates[0].input[0].offset.value_real, 0);
        assert_eq!(templates[0].input[0].space.value_spaceid, Some(constant.clone()));

        assert_eq!(templates[1].opc, SleighOpCode::CpuiCbranch);
        assert_eq!(templates[1].input[0].offset.tp, ConstTplType::JRelative);
        assert_eq!(templates[1].input[0].offset.value_real, 0);
        assert_eq!(templates[1].input[0].space.value_spaceid, Some(constant));

        assert_eq!(templates[2].opc, SleighOpCode::CpuiCopy);
    }
}
