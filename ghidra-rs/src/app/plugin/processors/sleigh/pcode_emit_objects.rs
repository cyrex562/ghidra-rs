use super::sleigh_exception::SleighException;
use super::varnode_data::VarnodeData;
use crate::program::model::address::Address;
use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};

/// Emits p-code operations as live [`PcodeOp`] objects, for use with unimplemented/snippet/empty
/// responses (or any other caller that wants direct `PcodeOp` objects rather than an encoded
/// stream -- see [`PcodeEmitPacked`](super::pcode_emit_packed::PcodeEmitPacked) for that case).
///
/// Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitObjects`. In Java this extends the
/// abstract `PcodeEmit`, which drives parsing of a `ConstructTpl` and owns the `numOps` counter
/// and `labeldef` table that this class's overrides read. That base class is still
/// [`TODO`](crate::program::seam_stubs::PcodeEmit) (and, being a large template-walking driver
/// rather than a single-responsibility interface, is out of scope for this cut), so the one piece
/// of base-class state this type actually needs -- `labeldef` -- is exposed here as an accessor
/// method instead, mirroring [`PcodeEmitPacked`](super::pcode_emit_packed::PcodeEmitPacked).
/// `numOps` is not modeled separately: the base class increments it by exactly one immediately
/// after each call to [`dump`](Self::dump), so it always equals `oplist.size()` at the point
/// [`add_label_ref`](Self::add_label_ref)/[`dump`](Self::dump) read it, and this trait uses
/// [`oplist`](Self::oplist)'s length directly instead. The three Java constructors are dropped, as
/// they only forward to the (unported) base class constructor and initialize `oplist`; a
/// concrete implementor is expected to start with an empty `oplist`/`labelref`.
pub trait PcodeEmitObjects {
    /// P-code operations generated so far, in emission order.
    fn oplist(&self) -> &[PcodeOp];
    /// Mutable access to the p-code operations generated so far, appended to by
    /// [`dump`](Self::dump) and patched in place by [`resolve_relatives`](Self::resolve_relatives).
    fn oplist_mut(&mut self) -> &mut Vec<PcodeOp>;

    /// Indices (into [`oplist`](Self::oplist)) of ops whose first input is a pending relative
    /// sleigh-label reference, accumulated by [`add_label_ref`](Self::add_label_ref).
    fn label_refs(&self) -> &[i32];
    /// Mutable access to the pending relative-label op indices.
    fn label_refs_mut(&mut self) -> &mut Vec<i32>;

    /// Stands in for the base `PcodeEmit.labeldef.get(label_index)`. Returns `None` both when
    /// `label_index` is out of bounds and when the base class's corresponding entry is unset,
    /// matching the Java override's single combined bounds/null check.
    fn label_def(&self, label_index: i32) -> Option<i32>;

    /// Applies opcode-specific call/jump overrides. Stands in for the base
    /// `PcodeEmit.checkOverrides(int, VarnodeData[])`. Defaults to no override support, leaving
    /// `opcode` and `in_` unchanged, since overrides are optional (a `null` `PcodeOverride` in
    /// Java short-circuits the same way).
    fn check_overrides(&self, opcode: OpCode, in_: &mut [VarnodeData]) -> OpCode {
        let _ = in_;
        opcode
    }

    /// Stands in for `PcodeEmitObjects.getPcodeOp()`: a snapshot copy of every p-code operation
    /// generated so far.
    fn get_pcode_op(&self) -> Vec<PcodeOp> {
        self.oplist().to_vec()
    }

    /// Flags the operand about to be built by the next [`dump`](Self::dump) call as a relative
    /// sleigh-label reference, to be patched by [`resolve_relatives`](Self::resolve_relatives)
    /// once every label definition has been seen.
    fn add_label_ref(&mut self) {
        let op_index = self.oplist().len() as i32;
        self.label_refs_mut().push(op_index);
    }

    /// Builds a [`PcodeOp`] from resolved input/output [`VarnodeData`] and appends it to
    /// [`oplist`](Self::oplist).
    fn dump(
        &mut self,
        instr_addr: Address,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) {
        let updated_opcode = self.check_overrides(opcode, in_);
        let outvn = out.map(|o| Varnode::new(Address::new(o.space.clone(), o.offset), o.size));

        let isize = if opcode == OpCode::CallOther && updated_opcode == OpCode::Call {
            // CALLOTHER_CALL_OVERRIDE: ignore inputs other than the call destination.
            1
        } else {
            isize
        };
        let invn: Vec<Varnode> = in_[..isize]
            .iter()
            .map(|v| Varnode::new(Address::new(v.space.clone(), v.offset), v.size))
            .collect();

        let op_index = self.oplist().len() as i32;
        let op = PcodeOp::new(
            updated_opcode,
            SequenceNumber::new(instr_addr, op_index),
            invn,
            outvn,
        );
        self.oplist_mut().push(op);
    }

    /// Now that every label definition and reference has been seen, patches each pending
    /// relative branch/call operand's first input to its resolved op-relative offset.
    ///
    /// # Errors
    /// Returns a [`SleighException`] if a reference names a label index with no definition.
    fn resolve_relatives(&mut self) -> Result<(), SleighException> {
        let op_indices = self.label_refs().to_vec();
        for op_index in op_indices {
            let vn = self.oplist()[op_index as usize].inputs[0].clone();
            let label_id = vn.get_offset() as i32;
            let Some(label_def) = self.label_def(label_id) else {
                return Err(SleighException::with_message(
                    "Reference to non-existant sleigh label",
                ));
            };
            let mut res = (label_def as i64).wrapping_sub(op_index as i64);
            if vn.get_size() < 8 {
                let shift = ((8 - vn.get_size()) * 8) as u32;
                let mask = if shift >= 64 {
                    -1i64
                } else {
                    ((-1i64 as u64) >> shift) as i64
                };
                res &= mask;
            }
            let spc = vn.get_address().space().clone();
            let new_vn = Varnode::new(Address::new(spc, res), vn.get_size());
            self.oplist_mut()[op_index as usize].inputs[0] = new_vn;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockPcodeEmitObjects {
        oplist: Vec<PcodeOp>,
        label_refs: Vec<i32>,
        labeldef: Vec<Option<i32>>,
    }

    impl MockPcodeEmitObjects {
        fn set_label(&mut self, label_index: usize, op_index: i32) {
            while self.labeldef.len() <= label_index {
                self.labeldef.push(None);
            }
            self.labeldef[label_index] = Some(op_index);
        }
    }

    impl PcodeEmitObjects for MockPcodeEmitObjects {
        fn oplist(&self) -> &[PcodeOp] {
            &self.oplist
        }
        fn oplist_mut(&mut self) -> &mut Vec<PcodeOp> {
            &mut self.oplist
        }
        fn label_refs(&self) -> &[i32] {
            &self.label_refs
        }
        fn label_refs_mut(&mut self) -> &mut Vec<i32> {
            &mut self.label_refs
        }
        fn label_def(&self, label_index: i32) -> Option<i32> {
            self.labeldef.get(label_index as usize).copied().flatten()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    fn instr_addr() -> Address {
        Address::new(ram_space(), 0x1000)
    }

    #[test]
    fn dump_appends_pcode_op_with_resolved_varnodes() {
        let mut emit = MockPcodeEmitObjects::default();
        let mut inputs = [
            VarnodeData::new(ram_space(), 0x2000, 4),
            VarnodeData::new(ram_space(), 0x3000, 4),
        ];
        let out = VarnodeData::new(ram_space(), 0x1000, 4);
        emit.dump(instr_addr(), OpCode::IntAdd, &mut inputs, 2, Some(&out));

        assert_eq!(emit.get_pcode_op().len(), 1);
        let op = &emit.oplist()[0];
        assert_eq!(op.opcode, OpCode::IntAdd);
        assert_eq!(op.inputs.len(), 2);
        assert_eq!(op.inputs[0].get_offset(), 0x2000);
        assert_eq!(op.output.as_ref().unwrap().get_offset(), 0x1000);
    }

    #[derive(Default)]
    struct OverrideToCall {
        oplist: Vec<PcodeOp>,
        label_refs: Vec<i32>,
    }

    impl PcodeEmitObjects for OverrideToCall {
        fn oplist(&self) -> &[PcodeOp] {
            &self.oplist
        }
        fn oplist_mut(&mut self) -> &mut Vec<PcodeOp> {
            &mut self.oplist
        }
        fn label_refs(&self) -> &[i32] {
            &self.label_refs
        }
        fn label_refs_mut(&mut self) -> &mut Vec<i32> {
            &mut self.label_refs
        }
        fn label_def(&self, _label_index: i32) -> Option<i32> {
            None
        }
        fn check_overrides(&self, _opcode: OpCode, _in_: &mut [VarnodeData]) -> OpCode {
            OpCode::Call
        }
    }

    #[test]
    fn dump_callother_override_to_call_truncates_inputs_to_one() {
        let mut emit = OverrideToCall::default();
        let mut inputs = [
            VarnodeData::new(const_space(), 0, 4),
            VarnodeData::new(ram_space(), 0x4000, 4),
            VarnodeData::new(ram_space(), 0x5000, 4),
        ];

        emit.dump(instr_addr(), OpCode::CallOther, &mut inputs, 3, None);

        // The CALLOTHER_CALL_OVERRIDE rewrite fired: opcode became CALL and only the first
        // (call destination) input survived, even though 3 inputs were passed in.
        assert_eq!(emit.oplist()[0].opcode, OpCode::Call);
        assert_eq!(emit.oplist()[0].inputs.len(), 1);
        assert_eq!(emit.oplist()[0].inputs[0].get_offset(), 0);
    }

    #[test]
    fn dump_without_override_keeps_callother_and_all_inputs() {
        let mut emit = MockPcodeEmitObjects::default();
        let mut inputs = [
            VarnodeData::new(const_space(), 0, 4),
            VarnodeData::new(ram_space(), 0x4000, 4),
            VarnodeData::new(ram_space(), 0x5000, 4),
        ];

        emit.dump(instr_addr(), OpCode::CallOther, &mut inputs, 3, None);

        assert_eq!(emit.oplist()[0].opcode, OpCode::CallOther);
        assert_eq!(emit.oplist()[0].inputs.len(), 3);
    }

    /// Exercises the whole relative-branch patch cycle: `add_label_ref` records the pending op
    /// index, `dump` appends the op with its placeholder input, and `resolve_relatives` -- once
    /// the label has actually been defined -- rewrites that input's offset to the real
    /// op-relative offset (label defined at op 5, referenced from op 2, so offset 3).
    #[test]
    fn resolve_relatives_patches_branch_target_to_relative_offset() {
        let mut emit = MockPcodeEmitObjects::default();
        emit.set_label(0, 5);
        // Two prior ops so the branch we care about lands at index 2.
        emit.dump(instr_addr(), OpCode::Copy, &mut [], 0, None);
        emit.dump(instr_addr(), OpCode::Copy, &mut [], 0, None);

        let mut inputs = [VarnodeData::new(const_space(), 0, 8)];
        emit.add_label_ref();
        emit.dump(instr_addr(), OpCode::Branch, &mut inputs, 1, None);

        assert_eq!(emit.label_refs(), &[2]);
        assert_eq!(emit.oplist()[2].inputs[0].get_offset(), 0);

        emit.resolve_relatives().unwrap();

        assert_eq!(emit.oplist()[2].inputs[0].get_offset(), 3);
    }

    #[test]
    fn resolve_relatives_rejects_undefined_label() {
        let mut emit = MockPcodeEmitObjects::default();
        let mut inputs = [VarnodeData::new(const_space(), 7, 8)];
        emit.add_label_ref();
        emit.dump(instr_addr(), OpCode::CBranch, &mut inputs, 1, None);

        let err = emit.resolve_relatives().unwrap_err();
        assert!(err.message().contains("non-existant"));
    }

    #[test]
    fn resolve_relatives_with_no_pending_refs_is_a_no_op() {
        let mut emit = MockPcodeEmitObjects::default();
        assert!(emit.resolve_relatives().is_ok());
    }

    /// Proves `dyn PcodeEmitObjects` is object safe and usable through a trait object.
    #[test]
    fn is_object_safe() {
        let mut emit: Box<dyn PcodeEmitObjects> = Box::new(MockPcodeEmitObjects::default());
        emit.dump(instr_addr(), OpCode::Copy, &mut [], 0, None);
        assert_eq!(emit.get_pcode_op().len(), 1);
        assert!(emit.resolve_relatives().is_ok());
    }
}
