use super::sleigh_exception::SleighException;
use super::varnode_data::VarnodeData;
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::Address;
use crate::program::model::pcode::{
    PatchEncoder, ATTRIB_CODE, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_ADDR,
    ELEM_INST, ELEM_OP, ELEM_SPACEID, ELEM_VOID,
};
use std::io;

/// One patch-pending reference to a sleigh label within a `BRANCH`/`CBRANCH` operand, recorded
/// so the operand can be converted from a label index to a relative op offset once every label
/// definition has been seen (by [`PcodeEmitPacked::resolve_relatives`]).
///
/// Mirrors the `LabelRef` nested class of `ghidra.app.plugin.processors.sleigh.PcodeEmitPacked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelRef {
    /// Index of the operation referencing the label.
    pub op_index: i32,
    /// Index of the label being referenced.
    pub label_index: i32,
    /// Number of bytes in the label.
    pub label_size: i32,
    /// Position in the byte stream where the label is getting encoded.
    pub streampos: i32,
}

impl LabelRef {
    pub fn new(op_index: i32, label_index: i32, label_size: i32, streampos: i32) -> Self {
        Self {
            op_index,
            label_index,
            label_size,
            streampos,
        }
    }
}

/// Emits p-code operations in Ghidra's packed binary encoding, deferring relative branch/call
/// operands until every referenced label has been seen so they can be patched to their final
/// op-relative offset.
///
/// Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitPacked`. In Java this extends the
/// abstract `PcodeEmit`, which drives parsing of a `ConstructTpl` and owns the `numOps` counter
/// and `labeldef` table that this class's overrides read. That base class's own template-walking
/// driver (`build` and its private helpers) is still out of scope for a full port -- see
/// [`PcodeEmit::build`](crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit::build)'s
/// docs -- so those fields are exposed here as accessor methods instead. `dump`'s `instrAddr` parameter is
/// dropped: it goes unused in the Java override, existing only to satisfy the base class's
/// abstract signature.
pub trait PcodeEmitPacked {
    /// The stream encoder p-code is packed into.
    fn encoder(&self) -> &dyn PatchEncoder;
    /// Mutable access to the stream encoder p-code is packed into.
    fn encoder_mut(&mut self) -> &mut dyn PatchEncoder;

    /// Stands in for the base `PcodeEmit.getFallOffset()`: the default instruction fall offset
    /// (i.e. instruction length including delay-slotted instructions).
    fn fall_offset(&self) -> i32;

    /// Stands in for the base `PcodeEmit.getStartAddress()`: the address of the instruction
    /// whose p-code is being emitted.
    fn start_address(&self) -> Address;

    /// Stands in for the base `PcodeEmit.numOps` counter of p-code ops generated so far.
    fn num_ops(&self) -> i32;

    /// Stands in for `PcodeEmit.labeldef.get(label_index)`. Returns `None` both when
    /// `label_index` is out of bounds and when the base class's corresponding entry is unset,
    /// matching the Java override's single combined bounds/null check.
    fn label_def(&self, label_index: i32) -> Option<i32>;

    /// Whether [`add_label_ref`](Self::add_label_ref) has flagged the operand about to be
    /// dumped as needing a [`LabelRef`].
    fn has_relative_patch(&self) -> bool;
    /// Sets the flag returned by [`has_relative_patch`](Self::has_relative_patch).
    fn set_has_relative_patch(&mut self, value: bool);

    /// Patch-pending label references accumulated so far.
    fn label_refs(&self) -> &[LabelRef];
    /// Mutable access to the patch-pending label references, appended to by
    /// [`add_label_ref_delayed`](Self::add_label_ref_delayed).
    fn label_refs_mut(&mut self) -> &mut Vec<LabelRef>;

    /// Applies opcode-specific call/jump overrides. Stands in for the base
    /// `PcodeEmit.checkOverrides(int, VarnodeData[])`. Defaults to no override support, leaving
    /// `opcode` and `in_` unchanged, since overrides are optional (a `null` `PcodeOverride` in
    /// Java short-circuits the same way).
    fn check_overrides(&self, opcode: OpCode, in_: &mut [VarnodeData]) -> OpCode {
        let _ = in_;
        opcode
    }

    /// Emits the `<inst>` element opening a packed instruction: its fall offset and start
    /// address.
    fn emit_header(&mut self) -> io::Result<()> {
        self.encoder_mut().open_element(ELEM_INST)?;
        let fall_offset = self.fall_offset();
        self.encoder_mut()
            .write_signed_integer(ATTRIB_OFFSET, fall_offset as i64)?;
        let addr = self.start_address();
        self.encoder_mut().open_element(ELEM_ADDR)?;
        self.encoder_mut().write_space(ATTRIB_SPACE, addr.space())?;
        self.encoder_mut()
            .write_unsigned_integer(ATTRIB_OFFSET, addr.unsigned_offset())?;
        self.encoder_mut().close_element(ELEM_ADDR)?;
        Ok(())
    }

    /// Closes the `<inst>` element opened by [`emit_header`](Self::emit_header).
    fn emit_tail(&mut self) -> io::Result<()> {
        self.encoder_mut().close_element(ELEM_INST)
    }

    /// Marks the operand about to be dumped next as a relative label reference needing a
    /// [`LabelRef`], created lazily once the parameter is actually written (see
    /// [`add_label_ref_delayed`](Self::add_label_ref_delayed)).
    fn add_label_ref(&mut self) {
        self.set_has_relative_patch(true);
    }

    /// Creates the pending [`LabelRef`] now that the next element written will be the operand
    /// needing a patch, and forces its encoding to a maximum-length placeholder (offset `-1`) so
    /// there is room to later overwrite it with the resolved relative offset.
    fn add_label_ref_delayed(&mut self, in_: &mut [VarnodeData]) {
        let label_index = in_[0].offset as i32;
        let label_size = in_[0].size;
        in_[0].offset = -1;

        let num_ops = self.num_ops();
        let streampos = self.encoder().size();
        self.label_refs_mut()
            .push(LabelRef::new(num_ops, label_index, label_size, streampos));
        self.set_has_relative_patch(false);
    }

    /// Encodes a raw address-space id as a `<spaceid>` element, used for the space operand of
    /// `LOAD`/`STORE` ops.
    fn dump_space_id(&mut self, v: &VarnodeData) -> io::Result<()> {
        self.encoder_mut().open_element(ELEM_SPACEID)?;
        self.encoder_mut().write_space_id(ATTRIB_NAME, v.offset)?;
        self.encoder_mut().close_element(ELEM_SPACEID)?;
        Ok(())
    }

    /// Encodes a single p-code operation as an `<op>` element.
    fn dump(
        &mut self,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()> {
        let updated_opcode = self.check_overrides(opcode, in_);
        let isize = if opcode == OpCode::CpuiCallother && updated_opcode == OpCode::CpuiCall {
            // CALLOTHER_CALL_OVERRIDE: ignore inputs other than the call destination.
            1
        } else {
            isize
        };

        self.encoder_mut().open_element(ELEM_OP)?;
        self.encoder_mut().write_opcode(ATTRIB_CODE, updated_opcode)?;
        self.encoder_mut()
            .write_signed_integer(ATTRIB_SIZE, isize as i64)?;
        match out {
            None => {
                self.encoder_mut().open_element(ELEM_VOID)?;
                self.encoder_mut().close_element(ELEM_VOID)?;
            }
            Some(out) => out.encode(self.encoder_mut())?,
        }

        let mut i = 0;
        if updated_opcode == OpCode::CpuiLoad || updated_opcode == OpCode::CpuiStore {
            self.dump_space_id(&in_[0])?;
            i = 1;
        } else if self.has_relative_patch() {
            self.add_label_ref_delayed(in_);
        }
        for varnode in &in_[i..isize] {
            varnode.encode(self.encoder_mut())?;
        }
        self.encoder_mut().close_element(ELEM_OP)?;
        Ok(())
    }

    /// Now that every label definition and reference has been seen, patches each pending
    /// relative branch/call operand to its resolved op-relative offset.
    ///
    /// # Errors
    /// Returns a [`SleighException`] if a reference names a label index with no definition, or
    /// if the encoder rejects the patch.
    fn resolve_relatives(&mut self) -> Result<(), SleighException> {
        let refs = self.label_refs().to_vec();
        for r in refs {
            let Some(label_def) = self.label_def(r.label_index) else {
                return Err(SleighException::with_message(
                    "Reference to non-existant sleigh label",
                ));
            };
            let mut res = (label_def as i64).wrapping_sub(r.op_index as i64);
            if r.label_size < 8 {
                let shift = ((8 - r.label_size) * 8) as u32;
                let mask = if shift >= 64 {
                    -1i64
                } else {
                    ((-1i64 as u64) >> shift) as i64
                };
                res &= mask;
            }
            if !self
                .encoder_mut()
                .patch_integer_attribute(r.streampos, ATTRIB_OFFSET, res)
            {
                return Err(SleighException::with_message(
                    "PcodeEmitPacked: Unable to patch relative offset",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::CachedEncoder;
    use std::sync::Arc;

    /// A minimal record-based encoder: each write is logged as an (attribute, value) pair
    /// (only the attribute kinds `PcodeEmitPacked` actually writes are modeled), and
    /// `patch_integer_attribute` scans forward from a recorded position to find and overwrite
    /// the matching attribute -- mirroring how the real packed encoder locates an attribute
    /// within the element that was open at that position.
    #[derive(Default)]
    struct MockEncoder {
        log: Vec<(crate::program::model::pcode::AttributeId, i64)>,
    }

    impl crate::program::model::pcode::Encoder for MockEncoder {
        fn open_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            Ok(())
        }
        fn close_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.log.push((attrib_id, val));
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::AttributeId,
            val: u64,
        ) -> io::Result<()> {
            self.log.push((attrib_id, val as i64));
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _spc: &AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, attrib_id: crate::program::model::pcode::AttributeId, opcode: OpCode) -> io::Result<()> {
            self.log.push((attrib_id, opcode.ordinal() as i64));
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, attrib_id: crate::program::model::pcode::AttributeId, opcode: i32) -> io::Result<()> {
            self.log.push((attrib_id, opcode as i64));
            Ok(())
        }
    }

    impl CachedEncoder for MockEncoder {
        fn clear(&mut self) {
            self.log.clear();
        }
        fn is_empty(&self) -> bool {
            self.log.is_empty()
        }
        fn write_to(&self, _writer: &mut dyn io::Write) -> io::Result<()> {
            Ok(())
        }
    }

    impl PatchEncoder for MockEncoder {
        fn write_space_id(&mut self, attrib_id: crate::program::model::pcode::AttributeId, space_id: i64) -> io::Result<()> {
            self.log.push((attrib_id, space_id));
            Ok(())
        }
        fn size(&self) -> i32 {
            self.log.len() as i32
        }
        fn patch_integer_attribute(
            &mut self,
            pos: i32,
            attrib_id: crate::program::model::pcode::AttributeId,
            val: i64,
        ) -> bool {
            let pos = pos as usize;
            if pos > self.log.len() {
                return false;
            }
            match self.log[pos..].iter_mut().find(|(id, _)| *id == attrib_id) {
                Some(entry) => {
                    entry.1 = val;
                    true
                }
                None => false,
            }
        }
    }

    struct MockPcodeEmitPacked {
        encoder: MockEncoder,
        fall_offset: i32,
        start_address: Address,
        num_ops: i32,
        labeldef: Vec<Option<i32>>,
        has_relative_patch: bool,
        label_refs: Vec<LabelRef>,
    }

    impl MockPcodeEmitPacked {
        fn new(fall_offset: i32, start_address: Address) -> Self {
            Self {
                encoder: MockEncoder::default(),
                fall_offset,
                start_address,
                num_ops: 0,
                labeldef: Vec::new(),
                has_relative_patch: false,
                label_refs: Vec::new(),
            }
        }

        fn set_label(&mut self, label_index: usize, op_index: i32) {
            while self.labeldef.len() <= label_index {
                self.labeldef.push(None);
            }
            self.labeldef[label_index] = Some(op_index);
        }
    }

    impl PcodeEmitPacked for MockPcodeEmitPacked {
        fn encoder(&self) -> &dyn PatchEncoder {
            &self.encoder
        }
        fn encoder_mut(&mut self) -> &mut dyn PatchEncoder {
            &mut self.encoder
        }
        fn fall_offset(&self) -> i32 {
            self.fall_offset
        }
        fn start_address(&self) -> Address {
            self.start_address.clone()
        }
        fn num_ops(&self) -> i32 {
            self.num_ops
        }
        fn label_def(&self, label_index: i32) -> Option<i32> {
            self.labeldef.get(label_index as usize).copied().flatten()
        }
        fn has_relative_patch(&self) -> bool {
            self.has_relative_patch
        }
        fn set_has_relative_patch(&mut self, value: bool) {
            self.has_relative_patch = value;
        }
        fn label_refs(&self) -> &[LabelRef] {
            &self.label_refs
        }
        fn label_refs_mut(&mut self) -> &mut Vec<LabelRef> {
            &mut self.label_refs
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    #[test]
    fn emit_header_and_tail_bracket_the_instruction() {
        let mut emit = MockPcodeEmitPacked::new(4, Address::new(ram_space(), 0x1000));
        emit.emit_header().unwrap();
        emit.emit_tail().unwrap();

        // write_space is a no-op in this mock (it never needs to be scanned/patched), so only
        // the two `ATTRIB_OFFSET` integer writes show up in the log.
        assert_eq!(
            emit.encoder.log,
            vec![(ATTRIB_OFFSET, 4), (ATTRIB_OFFSET, 0x1000)]
        );
    }

    /// Exercises the whole relative-branch patch cycle: `add_label_ref` flags the next dump as
    /// needing a patch, `dump` captures a `LabelRef` and forces the operand to a placeholder
    /// `-1`, and `resolve_relatives` -- once the label has actually been defined -- rewrites
    /// that placeholder to the real op-relative offset (label defined at op 5, referenced from
    /// op 2, so offset 3).
    #[test]
    fn resolve_relatives_patches_branch_target_to_relative_offset() {
        let mut emit = MockPcodeEmitPacked::new(2, Address::new(ram_space(), 0x2000));
        emit.num_ops = 2;
        emit.set_label(0, 5);

        // A relative branch operand: label index 0, encoded as an 8-byte relative offset.
        let mut inputs = [VarnodeData::new(const_space(), 0, 8)];
        emit.add_label_ref();
        emit.dump(OpCode::CpuiBranch, &mut inputs, 1, None).unwrap();

        // The placeholder was forced in before encoding.
        assert_eq!(inputs[0].offset, -1);
        assert_eq!(emit.label_refs().len(), 1);
        assert_eq!(emit.label_refs()[0].op_index, 2);
        assert_eq!(emit.label_refs()[0].label_index, 0);

        // The encoded placeholder offset is still the sentinel prior to resolution.
        let offset_writes: Vec<i64> = emit
            .encoder
            .log
            .iter()
            .filter(|(id, _)| *id == ATTRIB_OFFSET)
            .map(|(_, v)| *v)
            .collect();
        assert!(offset_writes.contains(&-1));

        emit.resolve_relatives().unwrap();

        let offset_writes: Vec<i64> = emit
            .encoder
            .log
            .iter()
            .filter(|(id, _)| *id == ATTRIB_OFFSET)
            .map(|(_, v)| *v)
            .collect();
        assert!(!offset_writes.contains(&-1));
        assert!(offset_writes.contains(&3));
    }

    #[test]
    fn resolve_relatives_rejects_undefined_label() {
        let mut emit = MockPcodeEmitPacked::new(0, Address::new(ram_space(), 0));
        let mut inputs = [VarnodeData::new(const_space(), 7, 8)];
        emit.add_label_ref();
        emit.dump(OpCode::CpuiCbranch, &mut inputs, 1, None).unwrap();

        let err = emit.resolve_relatives().unwrap_err();
        assert!(err.message().contains("non-existant"));
    }

    #[test]
    fn dump_load_encodes_space_id_before_remaining_inputs() {
        let mut emit = MockPcodeEmitPacked::new(0, Address::new(ram_space(), 0));
        let mut inputs = [
            VarnodeData::new(const_space(), 0x50, 4),
            VarnodeData::new(ram_space(), 0x8000, 4),
        ];
        emit.dump(OpCode::CpuiLoad, &mut inputs, 2, None).unwrap();

        // ATTRIB_NAME is only ever written by dump_space_id.
        assert!(emit.encoder.log.iter().any(|(id, v)| *id == ATTRIB_NAME && *v == 0x50));
    }

    /// Proves `dyn PcodeEmitPacked` is object safe and usable through a trait object.
    #[test]
    fn is_object_safe() {
        let mut emit: Box<dyn PcodeEmitPacked> =
            Box::new(MockPcodeEmitPacked::new(1, Address::new(ram_space(), 0x10)));
        emit.emit_header().unwrap();
        emit.emit_tail().unwrap();
        assert!(emit.resolve_relatives().is_ok());
    }
}
