//! Port of `ghidra.pcode.emu.jit.decode.DecoderForOneStride`.
//!
//! The decoder for a single stride.
//!
//! This starts at a given seed and proceeds linearly until it hits an instruction without fall
//! through. It may also stop if it encounters an existing entry point or an erroneous user
//! inject.
//!
//! See [`JitPassageDecoder`].

use std::sync::Arc;

use crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor;
use crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::seam_stubs::{
    cond_pcode_op, exit_pcode_op, nop_pcode_op, AddrCtx, DecodedStride, DecoderForOnePassage,
    PBranch, Reachability, RExtBranch, PseudoInstruction,
};
use crate::program::model::pcode::PcodeOp;

/// The result of decoding an instruction.
///
/// This may also represent an error encountered while trying to decode an instruction.
///
/// Port of the nested `DecoderForOneStride.StepResult` record.
struct StepResult<'d> {
    /// The p-code interpreter, which retains some state. Port of `StepResult.executor()`.
    executor: DecoderExecutor<'d>,
    /// The resulting p-code. Port of `StepResult.program()`.
    #[allow(dead_code)]
    program: PcodeProgram,
}

impl<'d> StepResult<'d> {
    /// Check whether the result falls through, accumulate its instructions and ops, and apply
    /// any control-flow effects.
    ///
    /// Port of `StepResult.checkFallthroughAndAccumulate()`. Java's executor holds the stride it
    /// writes back into; here it is passed in, since the stride owns this result for the duration
    /// of the step.
    fn check_fallthrough_and_accumulate(
        &mut self,
        stride: &mut DecoderForOneStride<'d, '_>,
    ) -> Option<Reachability> {
        self.executor.check_fallthrough_and_accumulate(&self.program, stride)
    }

    /// Compute the fall-through target.
    ///
    /// **NOTE**: This should only be called after checking if the result actually has fall
    /// through; otherwise, this will blindly compute the address and context immediately after
    /// the instruction.
    ///
    /// Port of `StepResult.next()`.
    fn next(&self) -> AddrCtx {
        let advanced = self.executor.get_advanced_address();
        self.executor.take_target_context(&advanced)
    }
}

/// The decoder for a single stride.
///
/// This starts at a given seed and proceeds linearly until it hits an instruction without fall
/// through. It may also stop if it encounters an existing entry point or an erroneous user
/// inject.
///
/// Port of `ghidra.pcode.emu.jit.decode.DecoderForOneStride`.
///
/// `'d` is the lifetime of the passage decoder (shared with the `passage`'s own reference to it);
/// `'p` is the lifetime of the mutable borrow of the passage being built.
pub struct DecoderForOneStride<'d, 'p> {
    decoder: &'d JitPassageDecoder,
    /// Port of `DecoderForOneStride.passage`, which `DecoderExecutor` also writes through.
    pub(crate) passage: &'p mut DecoderForOnePassage<'d>,
    start: AddrCtx,
    /// Port of `DecoderForOneStride.instructions`, package-private in Java and likewise written by
    /// `DecoderExecutor.addInstruction`.
    pub(crate) instructions: Vec<Arc<dyn PseudoInstruction>>,
    /// Port of `DecoderForOneStride.opsForStride`, package-private in Java and likewise written by
    /// `DecoderExecutor.checkFallthroughAndAccumulate`.
    pub(crate) ops_for_stride: Vec<PcodeOp>,
}

impl<'d, 'p> DecoderForOneStride<'d, 'p> {
    /// Construct a stride decoder.
    ///
    /// # Arguments
    /// * `decoder` - the thread's passage decoder
    /// * `passage` - the decoder for this specific passage
    /// * `start` - the seed to start this stride
    ///
    /// Port of `new DecoderForOneStride(JitPassageDecoder, DecoderForOnePassage, AddrCtx)`.
    pub fn new(
        decoder: &'d JitPassageDecoder,
        passage: &'p mut DecoderForOnePassage<'d>,
        start: AddrCtx,
    ) -> Self {
        Self { decoder, passage, start, instructions: Vec::new(), ops_for_stride: Vec::new() }
    }

    /// Finish decoding and create the stride.
    ///
    /// Java aliases the same mutable lists into the returned record; every call site here returns
    /// immediately afterward, so taking ownership of `instructions`/`ops_for_stride` has the same
    /// observable effect without requiring `PseudoInstruction: Clone`.
    ///
    /// Port of `DecoderForOneStride.toStride()`.
    fn to_stride(&mut self) -> DecodedStride {
        DecodedStride {
            start: self.start.clone(),
            instructions: std::mem::take(&mut self.instructions),
            ops: std::mem::take(&mut self.ops_for_stride),
        }
    }

    /// Record a synthetic exit branch: push `exit_op` onto the stride's ops and file an
    /// [`RExtBranch`] for it in the passage's `otherBranches`. Java repeats this
    /// three-statement pattern inline at each of its four call sites; factored out here since
    /// Rust's ownership makes the duplication more awkward than in Java, not because the Java
    /// behavior differs.
    fn push_exit_branch(&mut self, exit_op: PcodeOp, at: AddrCtx, reach: Reachability) {
        self.ops_for_stride.push(exit_op.clone());
        let branch = RExtBranch::new(exit_op.clone(), at, reach);
        self.passage.other_branches.insert(exit_op, PBranch::Ext(branch));
    }

    /// "Step" the decoder an instruction.
    ///
    /// This will attempt to decode the instruction at the given address (and contextreg value).
    /// If the given address is already a known entry point (for the entire emulator), then this
    /// returns `None` and the stride should be terminated. Otherwise, this checks for a user
    /// inject or then decodes an instruction. The resulting p-code (which may represent a decode
    /// error) is interpreted, and the first op is saved, in case it is targeted by a direct
    /// branch. As a special case, if the inject and/or instruction emits no p-code, we synthesize
    /// a nop, so that we can enter something into our books.
    ///
    /// Port of `DecoderForOneStride.stepAddrCtx(AddrCtx)`.
    fn step_addr_ctx(&mut self, at: AddrCtx) -> Option<StepResult<'d>> {
        // Avoid duplicate translation when we encounter an existing entry point. Just encode an
        // exit branch.
        if self.decoder.thread_has_entry(&at) {
            let exit_op = exit_pcode_op(&at);
            self.push_exit_branch(exit_op, at, Reachability::WithoutCtxmod);
            return None;
        }

        let mut executor = DecoderExecutor::new(self.decoder, at.clone());
        let program = match self.decoder.thread_get_inject(&at.address) {
            Some(program) => program,
            None => {
                let instruction = executor.decode_instruction();
                self.instructions.push(instruction);
                // Java: `program = PcodeProgram.fromInstruction(instruction, false)`. Blocked:
                // `PcodeProgram::from_instruction` takes `&dyn Instruction`, and the
                // `PseudoInstruction` stub doesn't implement `Instruction` yet -- see
                // `seam_stubs::DecodedStride`'s doc comment. Nothing reaches this in the current
                // partial port.
                unimplemented!(
                    "DecoderForOneStride::step_addr_ctx: PcodeProgram::from_instruction needs \
                     PseudoInstruction: Instruction"
                )
            }
        };

        executor.execute(&program);
        if executor.ops_for_this_step.is_empty() {
            let nop = nop_pcode_op(&at, 0);
            self.passage.first_ops.insert(at.clone(), nop.clone());
            self.ops_for_stride.push(nop);
        }
        else {
            self.passage.first_ops.insert(at.clone(), executor.ops_for_this_step[0].clone());
        }
        Some(StepResult { executor, program })
    }

    /// Decode the stride.
    ///
    /// Port of `DecoderForOneStride.decode()`.
    pub fn decode(&mut self) -> DecodedStride {
        let mut at = self.start.clone();
        loop {
            if self.passage.first_ops.contains_key(&at) {
                return self.to_stride();
            }

            let Some(mut result) = self.step_addr_ctx(at.clone()) else {
                return self.to_stride();
            };

            let Some(reach) = result.check_fallthrough_and_accumulate(self) else {
                return self.to_stride();
            };

            let next = result.next();
            if at == next {
                // Would happen because of inject without control flow
                let exit_op = exit_pcode_op(&at);
                self.push_exit_branch(exit_op, at, reach);
                return self.to_stride();
            }
            at = next;

            match reach {
                Reachability::WithoutCtxmod => continue,
                Reachability::WithCtxmod => {
                    // Looks like the without-control-flow case, but at has advanced
                    let exit_op = exit_pcode_op(&at);
                    self.push_exit_branch(exit_op, at, reach);
                    return self.to_stride();
                }
                Reachability::MaybeCtxmod => {
                    let exit_op = cond_pcode_op(&at);
                    self.push_exit_branch(exit_op, at.clone(), reach);
                    continue;
                }
            }

            // NOTE: If we impose a max instruction count within the stride, be sure to add the
            // "external branch" that falls-through to the next instruction outside the passage.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::instruction_decoder::InstructionDecoder;
    use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap};
    use crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread;
    use crate::pcode::seam_stubs::RegisterValue;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use std::sync::{Arc, Mutex};

    struct UnusedDecoder;
    impl InstructionDecoder for UnusedDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn branched(&mut self, _address: &Address) {}
        fn get_last_instruction(&self) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            None
        }
        fn get_last_length_with_delays(&self) -> i32 {
            0
        }
    }

    struct MockUseropLibrary {
        userops: UseropMap<Vec<u8>>,
    }
    impl ErasedPcodeUseropLibrary for MockUseropLibrary {}
    impl PcodeUseropLibrary<Vec<u8>> for MockUseropLibrary {
        fn get_userops(&self) -> &UseropMap<Vec<u8>> {
            &self.userops
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_decoder() -> JitPassageDecoder {
        let decoder: Arc<Mutex<dyn InstructionDecoder>> = Arc::new(Mutex::new(UnusedDecoder));
        let userops: Arc<dyn PcodeUseropLibrary<Vec<u8>>> =
            Arc::new(MockUseropLibrary { userops: UseropMap::new() });
        let thread = JitPcodeThread::new(decoder, None, userops);
        JitPassageDecoder::new(thread)
    }

    /// Java: `if (passage.firstOps.containsKey(at)) { return toStride(); }` -- the seed was
    /// already decoded (e.g. by another stride racing to the same address), so this stride is
    /// empty and doesn't touch the decode/interpret path at all.
    #[test]
    fn decode_returns_empty_stride_when_seed_already_decoded() {
        let jit_decoder = mock_decoder();
        let start = AddrCtx::new(None, mock_address(0x1000));
        let mut passage = DecoderForOnePassage::new(&jit_decoder, start.clone(), 100);
        passage.first_ops.insert(start.clone(), nop_pcode_op(&start, 0));

        let mut stride = DecoderForOneStride::new(&jit_decoder, &mut passage, start.clone());
        let decoded = stride.decode();

        // `AddrCtx` isn't `Debug` (its `rv_ctx` is `Option<Arc<dyn RegisterValue>>`), so compare
        // via `PartialEq` instead of `assert_eq!`.
        assert!(decoded.start == start);
        assert!(decoded.instructions.is_empty());
        assert!(decoded.ops.is_empty());
    }

    /// Java: `AddrCtx.equals` (and thus `Map<AddrCtx, _>` lookups) compare `biCtx`/`address` only.
    #[test]
    fn addr_ctx_equality_ignores_context_object_identity() {
        struct FixedValue(i128);
        impl RegisterValue for FixedValue {
            fn get_unsigned_value(&self) -> i128 {
                self.0
            }
        }
        let addr = mock_address(0x2000);
        let a = AddrCtx::new(Some(Arc::new(FixedValue(7))), addr.clone());
        let b = AddrCtx::new(Some(Arc::new(FixedValue(7))), addr);
        assert!(a == b);
    }
}
