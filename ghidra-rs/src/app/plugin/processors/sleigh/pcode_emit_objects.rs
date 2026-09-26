//! Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitObjects`.

use super::pcode_emit::{PcodeEmit, PcodeEmitBase, PcodeEmitBuildError, PcodeEmitSink};
use super::sleigh_exception::SleighException;
use super::sleigh_parser_context::SleighParserContext;
use super::varnode_data::VarnodeData;
use crate::decompiler::opcodes::op_code::OpCode as TemplateOpCode;
use crate::program::model::address::Address;
use crate::program::model::lang::instruction_context::InstructionContext;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::ParserWalker;
use crate::program::model::pcode::{OpCode, PcodeOp, PcodeOverride, SequenceNumber, Varnode};
use std::io;

/// The emitted ops and pending label references of a [`PcodeEmitObjects`]: the part of the
/// emitter the [`PcodeEmitBase`] driver writes to.
#[derive(Default)]
pub struct PcodeOpList {
    /// P-code operations generated so far, in emission order (`oplist`).
    pub oplist: Vec<PcodeOp>,
    /// Indices of ops whose first input is a pending relative label reference (`labelref`).
    pub labelref: Vec<i32>,
}

/// Converts a template opcode (the sleigh compiler's numbering, where some ops double as
/// directives) to the p-code opcode with the same number.
fn pcode_opcode(opcode: TemplateOpCode) -> OpCode {
    OpCode::from_ordinal(opcode.ordinal() as i32).unwrap_or(OpCode::Unimplemented)
}

impl PcodeOpList {
    /// Builds a [`PcodeOp`] from resolved inputs/output and appends it. Port of
    /// `PcodeEmitObjects.dump(Address, int, VarnodeData[], int, VarnodeData)`, given the opcode
    /// before and after `checkOverrides`.
    fn push_op(
        &mut self,
        instr_addr: Address,
        opcode: OpCode,
        updated_opcode: OpCode,
        in_: &[VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) {
        let outvn = out.map(|o| Varnode::new(Address::new(o.space.clone(), o.offset), o.size));
        let isize = if opcode == OpCode::CallOther && updated_opcode == OpCode::Call {
            1 // CALLOTHER_CALL_OVERRIDE, ignore inputs other than call dest
        } else {
            isize
        };
        let invn: Vec<Varnode> = in_[..isize]
            .iter()
            .map(|v| Varnode::new(Address::new(v.space.clone(), v.offset), v.size))
            .collect();
        let op_index = self.oplist.len() as i32;
        self.oplist.push(PcodeOp::new(
            updated_opcode,
            SequenceNumber::new(instr_addr, op_index),
            invn,
            outvn,
        ));
    }

    /// Port of `PcodeEmitObjects.resolveRelatives()`: patches each pending relative branch's
    /// first input to its op-relative offset, now that every label definition has been seen.
    ///
    /// # Errors
    /// A [`SleighException`] if a reference names a label with no definition.
    fn resolve_relatives(&mut self, label_def: impl Fn(i32) -> Option<i32>) -> Result<(), SleighException> {
        for &opindex in &self.labelref {
            let op = &mut self.oplist[opindex as usize];
            let vn = op.inputs[0].clone();
            let labelid = vn.get_offset() as i32;
            let Some(def) = label_def(labelid) else {
                return Err(SleighException::with_message(
                    "Reference to non-existant sleigh label",
                ));
            };
            let mut res = (def as i64).wrapping_sub(opindex as i64);
            if vn.get_size() < 8 {
                let shift = ((8 - vn.get_size()) * 8) as u32;
                let mask = (-1i64 as u64).wrapping_shr(shift) as i64;
                res &= mask;
            }
            let spc = vn.get_address().space().clone();
            op.inputs[0] = Varnode::new(Address::new(spc, res), vn.get_size());
        }
        Ok(())
    }
}

impl PcodeEmitSink for PcodeOpList {
    fn add_label_ref(&mut self, num_ops: i32) {
        self.labelref.push(num_ops);
    }

    fn dump(
        &mut self,
        base: &PcodeEmitBase<'_>,
        instr_addr: Address,
        opcode: TemplateOpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()> {
        let updated = base.check_overrides(opcode, in_);
        self.push_op(
            instr_addr,
            pcode_opcode(opcode),
            pcode_opcode(updated),
            in_,
            isize,
            out,
        );
        Ok(())
    }
}

/// Emits p-code operations as [`PcodeOp`] objects.
///
/// Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitObjects` (Java `extends PcodeEmit`):
/// the inherited state and driver are the [`PcodeEmitBase`], the emitted ops the
/// [`PcodeOpList`].
pub struct PcodeEmitObjects<'a> {
    base: PcodeEmitBase<'a>,
    walker: ParserWalker<'a>,
    ops: PcodeOpList,
}

impl<'a> PcodeEmitObjects<'a> {
    /// Port of `PcodeEmitObjects(ParserWalker, InstructionContext, int, PcodeOverride)`:
    /// `ictx` resolves delay-slot and crossbuild directives, `fall_offset` is the default
    /// instruction fall offset (the length including delay-slotted instructions) and
    /// `pcode_override` steers p-code overrides.
    pub fn new(
        walker: ParserWalker<'a>,
        ictx: Option<&'a dyn InstructionContext>,
        fall_offset: i32,
        pcode_override: Option<&'a dyn PcodeOverride>,
    ) -> Self {
        let base = PcodeEmitBase::new(&walker, ictx, fall_offset, pcode_override);
        Self {
            base,
            walker,
            ops: PcodeOpList::default(),
        }
    }

    /// Port of `PcodeEmitObjects(ParserWalker)`, for emitting precompiled p-code templates when
    /// the fall offset will not be used.
    pub fn for_walker(walker: ParserWalker<'a>) -> Self {
        Self::new(walker, None, 0, None)
    }

    /// Port of `PcodeEmitObjects(ParserWalker, int)`.
    pub fn with_fall_offset(walker: ParserWalker<'a>, fall_offset: i32) -> Self {
        Self::new(walker, None, fall_offset, None)
    }

    /// Port of `getPcodeOp()`: every p-code operation generated so far.
    pub fn get_pcode_op(&self) -> Vec<PcodeOp> {
        self.ops.oplist.clone()
    }

    /// Consumes the emitter, returning the generated operations.
    pub fn into_pcode_ops(self) -> Vec<PcodeOp> {
        self.ops.oplist
    }

    /// The pending relative label references (op indices).
    pub fn label_refs(&self) -> &[i32] {
        &self.ops.labelref
    }

    /// The shared emitter state.
    pub fn base(&self) -> &PcodeEmitBase<'a> {
        &self.base
    }
}

impl PcodeEmit for PcodeEmitObjects<'_> {
    fn start_address(&self) -> Address {
        self.base.get_start_address()
    }

    fn fall_offset(&self) -> i32 {
        self.base.get_fall_offset()
    }

    fn walker(&self) -> &ParserWalker<'_> {
        &self.walker
    }

    fn pcode_override(&self) -> Option<&dyn PcodeOverride> {
        self.base.pcode_override()
    }

    fn fall_override(&self) -> Option<Address> {
        self.base.fall_override()
    }

    fn default_fall_address(&self) -> Option<Address> {
        self.base.default_fall_address()
    }

    fn add_label_ref(&mut self) {
        let num_ops = self.ops.oplist.len() as i32;
        self.ops.add_label_ref(num_ops);
    }

    fn resolve_relatives(&mut self) -> Result<(), SleighException> {
        let base = &self.base;
        self.ops.resolve_relatives(|id| base.label_def(id))
    }

    fn dump(
        &mut self,
        instr_addr: Address,
        opcode: TemplateOpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()> {
        self.ops.dump(&self.base, instr_addr, opcode, in_, isize, out)
    }

    fn build(&mut self, construct: &ConstructTpl, secnum: i32) -> Result<(), PcodeEmitBuildError> {
        self.build_template(Some(construct), secnum)
    }

    fn resolve_final_fallthrough(&mut self) -> io::Result<()> {
        self.base.resolve_final_fallthrough(&mut self.ops)
    }
}

impl<'a> PcodeEmitObjects<'a> {
    /// [`PcodeEmit::build`] for a possibly absent template: a constructor with no semantics
    /// reports [`PcodeEmitBuildError::NotYetImplemented`], as Java's `build(null, ...)` throws
    /// `NotYetImplementedException`.
    ///
    /// # Errors
    /// See [`PcodeEmitBase::build`].
    pub fn build_template(
        &mut self,
        construct: Option<&ConstructTpl>,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        let context: &'a SleighParserContext = self.walker.get_parser_context();
        let mut walker = std::mem::replace(&mut self.walker, ParserWalker::new(context));
        let res = self.base.build(&mut self.ops, &mut walker, construct, secnum);
        self.walker = walker;
        res
    }

    /// Builds the main template of the constructor at the walker's position.
    ///
    /// # Errors
    /// See [`PcodeEmitBase::build`].
    pub fn build_current(&mut self) -> Result<(), PcodeEmitBuildError> {
        let ct = self.walker.get_constructor();
        self.build_template(ct.as_ref().and_then(|c| c.get_templ()), -1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0)
    }

    fn instr_addr() -> Address {
        Address::new(ram_space(), 0x1000)
    }

    #[test]
    fn push_op_appends_pcode_op_with_resolved_varnodes() {
        let mut ops = PcodeOpList::default();
        let inputs = [
            VarnodeData::new(ram_space(), 0x2000, 4),
            VarnodeData::new(ram_space(), 0x3000, 4),
        ];
        let out = VarnodeData::new(ram_space(), 0x1000, 4);
        ops.push_op(instr_addr(), OpCode::IntAdd, OpCode::IntAdd, &inputs, 2, Some(&out));

        assert_eq!(ops.oplist.len(), 1);
        let op = &ops.oplist[0];
        assert_eq!(op.opcode, OpCode::IntAdd);
        assert_eq!(op.inputs.len(), 2);
        assert_eq!(op.inputs[0].get_offset(), 0x2000);
        assert_eq!(op.output.as_ref().unwrap().get_offset(), 0x1000);
        assert_eq!(op.seqnum.get_time(), 0);
    }

    #[test]
    fn callother_overridden_to_call_keeps_only_the_destination() {
        let mut ops = PcodeOpList::default();
        let inputs = [
            VarnodeData::new(const_space(), 0, 4),
            VarnodeData::new(ram_space(), 0x4000, 4),
            VarnodeData::new(ram_space(), 0x5000, 4),
        ];
        ops.push_op(instr_addr(), OpCode::CallOther, OpCode::Call, &inputs, 3, None);
        assert_eq!(ops.oplist[0].opcode, OpCode::Call);
        assert_eq!(ops.oplist[0].inputs.len(), 1);

        ops.push_op(instr_addr(), OpCode::CallOther, OpCode::CallOther, &inputs, 3, None);
        assert_eq!(ops.oplist[1].opcode, OpCode::CallOther);
        assert_eq!(ops.oplist[1].inputs.len(), 3);
    }

    /// Label defined at op 5, referenced from op 2: the patched offset is 3.
    #[test]
    fn resolve_relatives_patches_branch_target_to_relative_offset() {
        let mut ops = PcodeOpList::default();
        ops.push_op(instr_addr(), OpCode::Copy, OpCode::Copy, &[], 0, None);
        ops.push_op(instr_addr(), OpCode::Copy, OpCode::Copy, &[], 0, None);
        ops.add_label_ref(2);
        let inputs = [VarnodeData::new(const_space(), 0, 8)];
        ops.push_op(instr_addr(), OpCode::Branch, OpCode::Branch, &inputs, 1, None);

        ops.resolve_relatives(|id| (id == 0).then_some(5)).unwrap();
        assert_eq!(ops.oplist[2].inputs[0].get_offset(), 3);
    }

    /// A backwards reference through a 4-byte varnode is masked to 32 bits.
    #[test]
    fn resolve_relatives_masks_negative_offsets_to_the_varnode_size() {
        let mut ops = PcodeOpList::default();
        ops.push_op(instr_addr(), OpCode::Copy, OpCode::Copy, &[], 0, None);
        ops.add_label_ref(1);
        let inputs = [VarnodeData::new(const_space(), 0, 4)];
        ops.push_op(instr_addr(), OpCode::Branch, OpCode::Branch, &inputs, 1, None);
        ops.resolve_relatives(|_| Some(0)).unwrap();
        assert_eq!(ops.oplist[1].inputs[0].get_offset(), 0xffff_ffff);
    }

    #[test]
    fn resolve_relatives_rejects_undefined_label() {
        let mut ops = PcodeOpList::default();
        ops.add_label_ref(0);
        let inputs = [VarnodeData::new(const_space(), 7, 8)];
        ops.push_op(instr_addr(), OpCode::CBranch, OpCode::CBranch, &inputs, 1, None);
        let err = ops.resolve_relatives(|_| None).unwrap_err();
        assert!(err.message().contains("non-existant"));
    }

    #[test]
    fn template_opcodes_map_by_number() {
        assert_eq!(pcode_opcode(TemplateOpCode::CpuiIntAdd), OpCode::IntAdd);
        assert_eq!(pcode_opcode(TemplateOpCode::CpuiCallother), OpCode::CallOther);
        assert_eq!(pcode_opcode(TemplateOpCode::CpuiReturn), OpCode::Return);
    }
}
