//! Port of `ghidra.pcode.emu.jit.decode.DecodedStride`.

use std::sync::Arc;

use crate::pcode::seam_stubs::{AddrCtx, PseudoInstruction};
use crate::program::model::pcode::PcodeOp;

/// A list of contiguous instructions connected by fall through, along with their emitted p-code
/// ops.
///
/// Port of `ghidra.pcode.emu.jit.decode.DecodedStride`, a Java `record` with three components:
/// `start`, `instructions`, and `ops`. A record's components are automatically `private final`
/// fields plus bare-named accessor methods (`start()`, `instructions()`, `ops()`) and a
/// canonical constructor; this port keeps the fields `pub` (matching how
/// [`DecoderForOneStride`](crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride)
/// already constructs and reads this type via field-literal syntax) and additionally supplies the
/// three accessor methods for parity with the Java record's own API surface.
///
/// # Divergence: `instructions: Vec<Arc<dyn PseudoInstruction>>`, not `List<Instruction>`
///
/// Java declares `instructions` as `List<Instruction>`. The only instructions
/// [`DecoderForOneStride`](crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride)
/// actually has on hand when building a stride are the
/// [`PseudoInstruction`](crate::pcode::seam_stubs::PseudoInstruction)s it decodes --
/// `PseudoInstruction` does not yet implement the ported
/// [`Instruction`](crate::program::model::listing::Instruction) trait (see
/// `DecoderForOneStride::step_addr_ctx`'s own `unimplemented!` note, which is blocked on exactly
/// this), so this field uses `PseudoInstruction` instead. `Arc`, not `Box`, because Java hands the
/// very same instruction object to both this list and the
/// [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor) that
/// decoded it. Replace the field's element type with `Instruction` once `PseudoInstruction` (or
/// its eventual real replacement) implements that trait.
///
/// This struct was previously a placeholder living in `pcode::seam_stubs` (see
/// [`crate::pcode::seam_stubs`]'s own module docs on the convention); it is now a real, complete
/// port and the seam-stub location re-exports it so existing call sites keep compiling.
pub struct DecodedStride {
    /// The address and contextreg value that seeded this stride.
    ///
    /// Port of `DecodedStride.start()`.
    pub start: AddrCtx,
    /// The instructions in the order decoded. See the struct's own docs for why this holds
    /// [`PseudoInstruction`] rather than `Instruction`.
    ///
    /// Port of `DecodedStride.instructions()`.
    pub instructions: Vec<Arc<dyn PseudoInstruction>>,
    /// The p-code ops in the order decoded and emitted.
    ///
    /// Port of `DecodedStride.ops()`.
    pub ops: Vec<PcodeOp>,
}

impl DecodedStride {
    /// Construct a stride from its three components.
    ///
    /// Port of the record's canonical constructor `DecodedStride(AddrCtx, List<Instruction>,
    /// List<PcodeOp>)`.
    pub fn new(
        start: AddrCtx,
        instructions: Vec<Arc<dyn PseudoInstruction>>,
        ops: Vec<PcodeOp>,
    ) -> Self {
        Self { start, instructions, ops }
    }

    /// The address and contextreg value that seeded this stride.
    ///
    /// Port of the record accessor `DecodedStride.start()`.
    pub fn start(&self) -> &AddrCtx {
        &self.start
    }

    /// The instructions in the order decoded.
    ///
    /// Port of the record accessor `DecodedStride.instructions()`.
    pub fn instructions(&self) -> &[Arc<dyn PseudoInstruction>] {
        &self.instructions
    }

    /// The p-code ops in the order decoded and emitted.
    ///
    /// Port of the record accessor `DecodedStride.ops()`.
    pub fn ops(&self) -> &[PcodeOp] {
        &self.ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_op(addr: &Address) -> PcodeOp {
        PcodeOp::new(OpCode::Unimplemented, SequenceNumber::new(addr.clone(), 0), Vec::new(), None)
    }

    #[test]
    fn new_and_accessors_round_trip_the_three_components() {
        let addr = mock_address(0x1000);
        let start = AddrCtx::new(None, addr.clone());
        let op = mock_op(&addr);
        let stride = DecodedStride::new(start.clone(), Vec::new(), vec![op.clone()]);

        assert!(stride.start() == &start);
        assert!(stride.instructions().is_empty());
        assert_eq!(stride.ops().len(), 1);
    }

    #[test]
    fn fields_are_directly_accessible_like_the_field_literal_construction_call_sites_use() {
        // Mirrors how `DecoderForOneStride::to_stride` builds this struct via field-literal
        // syntax rather than `DecodedStride::new`.
        let addr = mock_address(0x2000);
        let start = AddrCtx::new(None, addr);
        let stride = DecodedStride { start: start.clone(), instructions: Vec::new(), ops: Vec::new() };
        assert!(stride.start == start);
        assert!(stride.instructions.is_empty());
        assert!(stride.ops.is_empty());
    }
}
