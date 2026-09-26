//! Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitPacked`.

use super::pcode_emit::{PcodeEmit, PcodeEmitBase, PcodeEmitBuildError, PcodeEmitSink};
use super::sleigh_exception::SleighException;
use super::sleigh_parser_context::SleighParserContext;
use super::varnode_data::VarnodeData;
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::Address;
use crate::program::model::lang::instruction_context::InstructionContext;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::ParserWalker;
use crate::program::model::pcode::{
    encode_addr, PatchEncoder, PcodeOverride, ATTRIB_CODE, ATTRIB_NAME, ATTRIB_OFFSET,
    ATTRIB_SIZE, ELEM_INST, ELEM_OP, ELEM_SPACEID, ELEM_VOID,
};
use std::io;

/// One patch-pending reference to a sleigh label within a `BRANCH`/`CBRANCH` operand, recorded
/// so the operand can be converted from a label index to a relative op offset once every label
/// definition has been seen (by [`PcodeEmit::resolve_relatives`]).
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
    /// Port of `LabelRef(int op, int lab, int size, int stream)`.
    pub fn new(op_index: i32, label_index: i32, label_size: i32, streampos: i32) -> Self {
        Self {
            op_index,
            label_index,
            label_size,
            streampos,
        }
    }
}

/// The encoder and pending label references of a [`PcodeEmitPacked`]: the part of the emitter
/// the [`PcodeEmitBase`] driver writes to.
pub struct PackedOpSink<'e> {
    encoder: &'e mut dyn PatchEncoder,
    /// Pending relative label references (`labelref`).
    labelref: Vec<LabelRef>,
    /// Set by `addLabelRef`: the next op dumped carries a relative label operand
    /// (`hasRelativePatch`).
    has_relative_patch: bool,
}

impl<'e> PackedOpSink<'e> {
    fn new(encoder: &'e mut dyn PatchEncoder) -> Self {
        Self {
            encoder,
            labelref: Vec::new(),
            has_relative_patch: false,
        }
    }

    /// Port of the private `addLabelRefDelayed()`: creates the [`LabelRef`] now that the next
    /// element written will be the parameter needing a patch, and forces the encoder to write a
    /// maximum-length encoding (offset `-1`) so there is room for whatever value is patched in
    /// once the relative is resolved.
    fn add_label_ref_delayed(&mut self, num_ops: i32, in_: &mut [VarnodeData]) {
        let label_index = in_[0].offset as i32;
        let label_size = in_[0].size;
        in_[0].offset = -1;
        let streampos = self.encoder.size();
        self.labelref
            .push(LabelRef::new(num_ops, label_index, label_size, streampos));
        self.has_relative_patch = false; // Mark patch as handled
    }

    /// Port of the private `dumpSpaceId(VarnodeData)`: the raw space id operand of a
    /// `LOAD`/`STORE`.
    fn dump_space_id(&mut self, v: &VarnodeData) -> io::Result<()> {
        self.encoder.open_element(ELEM_SPACEID)?;
        self.encoder.write_space_id(ATTRIB_NAME, v.offset)?;
        self.encoder.close_element(ELEM_SPACEID)
    }

    /// Port of `resolveRelatives()`: patches every pending relative operand to its resolved
    /// op-relative offset.
    ///
    /// # Errors
    /// A [`SleighException`] if a reference names a label with no definition, or the encoder
    /// cannot patch the operand.
    fn resolve_relatives(
        &mut self,
        label_def: impl Fn(i32) -> Option<i32>,
    ) -> Result<(), SleighException> {
        for r in &self.labelref {
            let Some(def) = label_def(r.label_index) else {
                return Err(SleighException::with_message(
                    "Reference to non-existant sleigh label",
                ));
            };
            let mut res = (def as i64).wrapping_sub(r.op_index as i64);
            if r.label_size < 8 {
                let shift = ((8 - r.label_size) * 8) as u32;
                let mask = (-1i64 as u64).wrapping_shr(shift) as i64;
                res &= mask;
            }
            if !self
                .encoder
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

impl PcodeEmitSink for PackedOpSink<'_> {
    fn add_label_ref(&mut self, _num_ops: i32) {
        // Delay putting in the LabelRef until we are ready to emit the parameter
        self.has_relative_patch = true;
    }

    fn dump(
        &mut self,
        base: &PcodeEmitBase<'_>,
        _instr_addr: Address,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()> {
        let updated_opcode = base.check_overrides(opcode, in_);
        let isize = if opcode == OpCode::CpuiCallother && updated_opcode == OpCode::CpuiCall {
            1 // CALLOTHER_CALL_OVERRIDE, ignore inputs other than call dest
        } else {
            isize
        };
        self.encoder.open_element(ELEM_OP)?;
        self.encoder
            .write_signed_integer(ATTRIB_CODE, updated_opcode.ordinal() as i64)?;
        self.encoder.write_signed_integer(ATTRIB_SIZE, isize as i64)?;
        match out {
            None => {
                self.encoder.open_element(ELEM_VOID)?;
                self.encoder.close_element(ELEM_VOID)?;
            }
            Some(out) => out.encode(self.encoder)?,
        }
        let mut i = 0;
        if updated_opcode == OpCode::CpuiLoad || updated_opcode == OpCode::CpuiStore {
            self.dump_space_id(&in_[0])?;
            i = 1;
        } else if self.has_relative_patch {
            self.add_label_ref_delayed(base.num_ops(), in_);
        }
        for v in &in_[i..isize] {
            v.encode(self.encoder)?;
        }
        self.encoder.close_element(ELEM_OP)
    }
}

/// Emits p-code operations in Ghidra's packed binary encoding, patching relative branch
/// operands once every label definition has been seen.
///
/// Port of `ghidra.app.plugin.processors.sleigh.PcodeEmitPacked` (Java `extends PcodeEmit`):
/// the inherited state and driver are the [`PcodeEmitBase`], the encoder and pending label
/// references the [`PackedOpSink`].
pub struct PcodeEmitPacked<'a, 'e> {
    base: PcodeEmitBase<'a>,
    walker: ParserWalker<'a>,
    sink: PackedOpSink<'e>,
}

impl<'a, 'e> PcodeEmitPacked<'a, 'e> {
    /// Port of `PcodeEmitPacked(PatchEncoder, ParserWalker, InstructionContext, int,
    /// PcodeOverride)`: `encoder` receives the packed stream, `ictx` resolves delay-slot and
    /// crossbuild directives, `fall_offset` is the default instruction fall offset (the length
    /// including delay-slotted instructions) and `pcode_override` steers p-code overrides.
    pub fn new(
        encoder: &'e mut dyn PatchEncoder,
        walker: ParserWalker<'a>,
        ictx: Option<&'a dyn InstructionContext>,
        fall_offset: i32,
        pcode_override: Option<&'a dyn PcodeOverride>,
    ) -> Self {
        let base = PcodeEmitBase::new(&walker, ictx, fall_offset, pcode_override);
        Self {
            base,
            walker,
            sink: PackedOpSink::new(encoder),
        }
    }

    /// Port of `emitHeader()`: opens the `<inst>` element with the fall offset and start
    /// address.
    ///
    /// # Errors
    /// Errors from the underlying stream.
    pub fn emit_header(&mut self) -> io::Result<()> {
        let encoder = &mut *self.sink.encoder;
        encoder.open_element(ELEM_INST)?;
        encoder.write_signed_integer(ATTRIB_OFFSET, self.base.get_fall_offset() as i64)?;
        encode_addr(encoder, &self.base.get_start_address())
    }

    /// Port of `emitTail()`: closes the `<inst>` element.
    ///
    /// # Errors
    /// Errors from the underlying stream.
    pub fn emit_tail(&mut self) -> io::Result<()> {
        self.sink.encoder.close_element(ELEM_INST)
    }

    /// The pending relative label references.
    pub fn label_refs(&self) -> &[LabelRef] {
        &self.sink.labelref
    }

    /// The shared emitter state.
    pub fn base(&self) -> &PcodeEmitBase<'a> {
        &self.base
    }

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
        let res = self.base.build(&mut self.sink, &mut walker, construct, secnum);
        self.walker = walker;
        res
    }

    /// Builds the main template of the constructor at the walker's position
    /// (`build(walker.getConstructor().getTempl(), -1)`).
    ///
    /// # Errors
    /// See [`PcodeEmitBase::build`].
    pub fn build_current(&mut self) -> Result<(), PcodeEmitBuildError> {
        let ct = self.walker.get_constructor();
        self.build_template(ct.as_ref().and_then(|c| c.get_templ()), -1)
    }
}

impl PcodeEmit for PcodeEmitPacked<'_, '_> {
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
        let num_ops = self.base.num_ops();
        self.sink.add_label_ref(num_ops);
    }

    fn resolve_relatives(&mut self) -> Result<(), SleighException> {
        let base = &self.base;
        self.sink.resolve_relatives(|id| base.label_def(id))
    }

    fn dump(
        &mut self,
        instr_addr: Address,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()> {
        self.sink.dump(&self.base, instr_addr, opcode, in_, isize, out)
    }

    fn build(&mut self, construct: &ConstructTpl, secnum: i32) -> Result<(), PcodeEmitBuildError> {
        self.build_template(Some(construct), secnum)
    }

    fn resolve_final_fallthrough(&mut self) -> io::Result<()> {
        self.base.resolve_final_fallthrough(&mut self.sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, OpTpl, VarnodeTpl};
    use crate::program::model::pcode::{
        CachedEncoder, Decoder, PackedDecode, PatchPackedEncode, ATTRIB_SPACE, ELEM_ADDR,
    };
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0)
    }

    fn walker_at(addr: Address) -> ParserWalker<'static> {
        // The emitter owns its walker, so the (tiny) snippet context is leaked for the test.
        let context: &'static SleighParserContext = Box::leak(Box::new(
            SleighParserContext::for_snippet(
                addr.clone(),
                Some(addr),
                None,
                None,
                Some(const_space()),
            ),
        ));
        ParserWalker::new(context)
    }

    fn cpl(tp: ConstTplType, value: u64, space: Option<Arc<AddressSpace>>) -> ConstTpl {
        ConstTpl {
            tp,
            value_real: value,
            value_spaceid: space,
            handle_index: 0,
            select: None,
        }
    }

    fn vn(space: Arc<AddressSpace>, offset: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: cpl(ConstTplType::SpaceId, 0, Some(space)),
            offset: cpl(ConstTplType::Real, offset, None),
            size: cpl(ConstTplType::Real, size, None),
        }
    }

    fn relative(label: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: cpl(ConstTplType::SpaceId, 0, Some(const_space())),
            offset: cpl(ConstTplType::JRelative, label, None),
            size: cpl(ConstTplType::Real, size, None),
        }
    }

    fn op(opc: OpCode, out: Option<VarnodeTpl>, inputs: Vec<VarnodeTpl>) -> OpTpl {
        let mut op = OpTpl::with_opcode(opc);
        if let Some(out) = out {
            op.set_output(out);
        }
        for i in inputs {
            op.add_input(i);
        }
        op
    }

    fn bytes_of(enc: &PatchPackedEncode) -> Vec<u8> {
        let mut out = Vec::new();
        enc.write_to(&mut out).unwrap();
        out
    }

    fn decoder(bytes: Vec<u8>) -> PackedDecode {
        let factory: Arc<dyn AddressFactory> =
            Arc::new(DefaultAddressFactory::new(vec![const_space(), ram_space()]));
        PackedDecode::new(factory, bytes)
    }

    /// Decodes an `<addr>` element's space name, offset and size.
    fn read_varnode(d: &PackedDecode) -> (String, u64, i64) {
        let el = d.open_element_with_id(ELEM_ADDR).unwrap();
        let space = d.read_space_with_id(ATTRIB_SPACE).unwrap().name().to_string();
        let offset = d.read_unsigned_integer_with_id(ATTRIB_OFFSET).unwrap();
        let size = d.read_signed_integer_with_id(ATTRIB_SIZE).unwrap();
        d.close_element(el).unwrap();
        (space, offset, size)
    }

    /// `COPY ram:0x100:4 <- const:0x2a:4 ; BRANCH <label 0> ; COPY ... ; label 0:` -- the packed
    /// stream carries the header, both ops, and the branch operand patched from the forced `-1`
    /// placeholder to the op-relative distance 2 (label at op 3, referenced from op 1).
    #[test]
    fn build_encodes_ops_and_patches_relative_branch() {
        let start = Address::new(ram_space(), 0x1000);
        let mut enc = PatchPackedEncode::new();
        {
            let mut emit = PcodeEmitPacked::new(&mut enc, walker_at(start), None, 4, None);
            let mut tpl = ConstructTpl::new();
            tpl.num_labels = 1;
            tpl.vec = vec![
                op(
                    OpCode::CpuiCopy,
                    Some(vn(ram_space(), 0x100, 4)),
                    vec![vn(const_space(), 0x2a, 4)],
                ),
                op(OpCode::CpuiBranch, None, vec![relative(0, 4)]),
                op(
                    OpCode::CpuiCopy,
                    Some(vn(ram_space(), 0x104, 4)),
                    vec![vn(const_space(), 1, 4)],
                ),
                op(OpCode::CpuiPtradd, None, vec![vn(const_space(), 0, 4)]),
                op(
                    OpCode::CpuiCopy,
                    Some(vn(ram_space(), 0x108, 4)),
                    vec![vn(const_space(), 2, 4)],
                ),
            ];
            emit.emit_header().unwrap();
            emit.build(&tpl, -1).unwrap();
            assert_eq!(emit.label_refs().len(), 1);
            assert_eq!(emit.label_refs()[0].op_index, 1);
            assert_eq!(emit.label_refs()[0].label_index, 0);
            emit.resolve_relatives().unwrap();
            emit.resolve_final_fallthrough().unwrap();
            emit.emit_tail().unwrap();
        }

        let d = decoder(bytes_of(&enc));
        let inst = d.open_element_with_id(ELEM_INST).unwrap();
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_OFFSET).unwrap(), 4);
        let addr = d.open_element_with_id(ELEM_ADDR).unwrap();
        assert_eq!(d.read_unsigned_integer_with_id(ATTRIB_OFFSET).unwrap(), 0x1000);
        d.close_element(addr).unwrap();

        // op 0: COPY
        let el = d.open_element_with_id(ELEM_OP).unwrap();
        assert_eq!(
            d.read_signed_integer_with_id(ATTRIB_CODE).unwrap(),
            OpCode::CpuiCopy.ordinal() as i64
        );
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_SIZE).unwrap(), 1);
        assert_eq!(read_varnode(&d), ("ram".to_string(), 0x100, 4));
        assert_eq!(read_varnode(&d), ("const".to_string(), 0x2a, 4));
        d.close_element(el).unwrap();

        // op 1: BRANCH, void output, patched relative operand
        let el = d.open_element_with_id(ELEM_OP).unwrap();
        assert_eq!(
            d.read_signed_integer_with_id(ATTRIB_CODE).unwrap(),
            OpCode::CpuiBranch.ordinal() as i64
        );
        let void = d.open_element_with_id(ELEM_VOID).unwrap();
        d.close_element(void).unwrap();
        assert_eq!(read_varnode(&d), ("const".to_string(), 2, 4));
        d.close_element(el).unwrap();

        // op 2 and op 3 (after the label directive, which emits nothing)
        for expected in [0x104u64, 0x108] {
            let el = d.open_element_with_id(ELEM_OP).unwrap();
            assert_eq!(read_varnode(&d).1, expected);
            d.close_element_skipping(el).unwrap();
        }
        d.close_element(inst).unwrap();
    }

    /// A backwards label reference through a 1-byte operand is masked to 8 bits (Java's
    /// `mask >>>= (8 - labelSize) * 8`).
    #[test]
    fn backward_relative_is_masked_to_the_label_size() {
        let start = Address::new(ram_space(), 0x2000);
        let mut enc = PatchPackedEncode::new();
        {
            let mut emit = PcodeEmitPacked::new(&mut enc, walker_at(start), None, 2, None);
            let mut tpl = ConstructTpl::new();
            tpl.num_labels = 1;
            tpl.vec = vec![
                op(OpCode::CpuiPtradd, None, vec![vn(const_space(), 0, 4)]),
                op(
                    OpCode::CpuiCopy,
                    Some(vn(ram_space(), 0x100, 4)),
                    vec![vn(const_space(), 7, 4)],
                ),
                op(OpCode::CpuiBranch, None, vec![relative(0, 1)]),
            ];
            emit.build(&tpl, -1).unwrap();
            emit.resolve_relatives().unwrap();
        }
        let d = decoder(bytes_of(&enc));
        let el = d.open_element_with_id(ELEM_OP).unwrap();
        d.close_element_skipping(el).unwrap();
        let el = d.open_element_with_id(ELEM_OP).unwrap();
        let void = d.open_element_with_id(ELEM_VOID).unwrap();
        d.close_element(void).unwrap();
        // label at op 0, referenced from op 1: -1 masked to one byte
        assert_eq!(read_varnode(&d).1, 0xff);
        d.close_element(el).unwrap();
    }

    #[test]
    fn resolve_relatives_rejects_undefined_label() {
        let start = Address::new(ram_space(), 0);
        let mut enc = PatchPackedEncode::new();
        let mut emit = PcodeEmitPacked::new(&mut enc, walker_at(start), None, 0, None);
        let mut tpl = ConstructTpl::new();
        tpl.num_labels = 1;
        tpl.vec = vec![op(OpCode::CpuiBranch, None, vec![relative(0, 8)])];
        emit.build(&tpl, -1).unwrap();
        let err = emit.resolve_relatives().unwrap_err();
        assert!(err.message().contains("non-existant"));
    }

    /// `LOAD`'s first operand is written as a raw `<spaceid>`, and a template-less build reports
    /// the missing semantics.
    #[test]
    fn load_space_operand_is_a_spaceid_element() {
        let start = Address::new(ram_space(), 0);
        let mut enc = PatchPackedEncode::new();
        {
            let mut emit = PcodeEmitPacked::new(&mut enc, walker_at(start), None, 0, None);
            let sid = VarnodeData::new(const_space(), ram_space().space_id() as i64, 8);
            let mut inputs = [sid, VarnodeData::new(ram_space(), 0x10, 4)];
            let out = VarnodeData::new(ram_space(), 0x20, 4);
            emit.dump(start_addr(), OpCode::CpuiLoad, &mut inputs, 2, Some(&out)).unwrap();
            assert!(matches!(
                emit.build_template(None, -1),
                Err(PcodeEmitBuildError::NotYetImplemented(_))
            ));
        }
        let d = decoder(bytes_of(&enc));
        let el = d.open_element_with_id(ELEM_OP).unwrap();
        assert_eq!(read_varnode(&d), ("ram".to_string(), 0x20, 4));
        let spc = d.open_element_with_id(ELEM_SPACEID).unwrap();
        assert_eq!(d.read_space_with_id(ATTRIB_NAME).unwrap().name(), "ram");
        d.close_element(spc).unwrap();
        assert_eq!(read_varnode(&d), ("ram".to_string(), 0x10, 4));
        d.close_element(el).unwrap();
    }

    fn start_addr() -> Address {
        Address::new(ram_space(), 0)
    }
}
