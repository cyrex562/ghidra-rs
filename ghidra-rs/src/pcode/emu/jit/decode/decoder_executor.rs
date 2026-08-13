//! Port of `ghidra.pcode.emu.jit.decode.DecoderExecutor`.
//!
//! The p-code interpreter used during passage decode.
//!
//! Aside from branches, this interpreter simply logs each op, so that they get collected into the
//! greater stride and passage. It does "rewrite" the ops, so that we can easily recover the input
//! context, especially when the op is emitted from a user inject. For branches, this interpreter
//! creates the appropriate branch records and notifies the passage decoder of new seeds.
//!
//! This executor also implements [`DisassemblerContext`] to track context changes, namely uses of
//! `globalset`. This is kept in `fut_ctx`.
//!
//! # Implementation notes
//!
//! Java's class *extends* `PcodeExecutor<Object>` and overrides its `protected` control-flow hooks.
//! This crate's [`PcodeExecutor`](crate::pcode::exec::pcode_executor::PcodeExecutor) is a concrete
//! struct with no virtual dispatch, and -- more decisively -- it requires an arithmetic and a state
//! object, where Java passes `super(language, null, null, null)`. So the interpreter loop is
//! reimplemented here rather than inherited: only the branch-relevant arms of `stepOp` are needed,
//! and with no state to read, each is markedly simpler than the base class's. Method names below
//! mirror the base class's so the correspondence stays checkable.
//!
//! **WARNING** (from Java): this executor has no state object. Care must be taken to ensure we
//! don't invoke any method that assumes we have one.
//!
//! Java holds the [`DecoderForOneStride`] it belongs to and reaches through it for the decoder, the
//! passage, and the two output lists. Here the decoder is held directly (the stride reaches it the
//! same way) and the stride is passed to the two methods that write back into it, because the
//! stride owns this executor for the duration of a step and cannot also be borrowed by it.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride;
use crate::pcode::emu::jit::decode::decoder_userop_library::DecoderUseropLibrary;
use crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder;
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::seam_stubs::{
    exit_pcode_op, nop_pcode_op, AddrCtx, BlockSplitter, ErrBranch, JitBlock,
    PBranch, PseudoInstruction, Reachability, RegisterValue, SBranch, SExtBranch, SIndBranch,
    SIntBranch,
};
use crate::program::model::address::{Address, AddressSpaceType};
use crate::program::model::lang::disassembler_context::DisassemblerContext;
use crate::program::model::lang::disassembler_context_adapter::DisassemblerContextAdapter;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::pcode::{OpCode, PcodeOp};
use crate::program::seam_stubs::RegisterValue as LangRegisterValue;
use crate::util::Msg;

/// The name of the address space of Java's `Address.NO_ADDRESS`. Duplicated from
/// [`crate::pcode::exec::pcode_executor`]'s private constant of the same name, which this
/// executor's `check_injected_target` needs but does not inherit.
const NO_ADDRESS_SPACE_NAME: &str = "NO ADDRESS";

/// The p-code interpreter used during passage decode.
///
/// Port of `ghidra.pcode.emu.jit.decode.DecoderExecutor`.
///
/// `'d` is the lifetime of the passage decoder, which outlives every stride and step.
pub struct DecoderExecutor<'d> {
    /// Java reaches the decoder as `stride.decoder`; see the module docs for why the stride itself
    /// isn't held.
    decoder: &'d JitPassageDecoder,
    /// The language, which Java's superclass constructor takes as
    /// `stride.decoder.thread.getLanguage()`.
    language: Arc<dyn Language>,
    /// The address and contextreg value of the instruction. Port of `DecoderExecutor.at`.
    pub(crate) at: AddrCtx,

    /// The instruction being interpreted, or `None` until one is decoded. Port of
    /// `DecoderExecutor.instruction`.
    instruction: Option<Arc<dyn PseudoInstruction>>,
    /// The terminal nop for the frame currently being finished, if one turned out to be needed.
    ///
    /// Port of `DecoderExecutor.termNopsPerFrame`, which is a map because a frame can nest (an
    /// inlined userop feeds a new frame to the same executor). Inlining is the one path
    /// [`execute_callother`](Self::execute_callother) cannot follow yet, so a single slot suffices;
    /// [`PcodeFrame`] is in any case neither hashable nor identity-comparable here.
    term_nop: Option<PcodeOp>,

    /// The input context for the next decoded instruction, not accounting for `globalset`. Port of
    /// `DecoderExecutor.flow`. See [`set_instruction`](Self::set_instruction).
    flow: Option<Arc<dyn RegisterValue>>,
    /// The context changes this instruction's constructors placed at specific addresses via
    /// `globalset`. Port of `DecoderExecutor.futCtx`.
    ///
    /// The values are `program::seam_stubs::RegisterValue`, not the `pcode::seam_stubs` trait
    /// [`flow`](Self::flow) uses: they arrive through [`DisassemblerContext`], which speaks the
    /// former. The two are placeholders for the same unported Java class, and combining across them
    /// is what blocks [`take_target_context`](Self::take_target_context)'s second arm.
    fut_ctx: HashMap<Address, Box<dyn LangRegisterValue>>,

    /// Every op interpreted during this step, in order. Port of `DecoderExecutor.opsForThisStep`.
    pub(crate) ops_for_this_step: Vec<PcodeOp>,
    /// Every branch record produced during this step. Port of
    /// `DecoderExecutor.branchesForThisStep`.
    branches_for_this_step: Vec<SBranch>,
}

impl<'d> DecoderExecutor<'d> {
    /// Construct the interpreter without an instruction.
    ///
    /// The decoder must set the instruction via [`set_instruction`](Self::set_instruction) as soon
    /// as it becomes available, either because the step resulted in a simple instruction, or
    /// because a user inject caused the instruction to be decoded.
    ///
    /// # Arguments
    /// * `decoder` - the passage decoder; Java takes the stride and reads `stride.decoder`
    /// * `at` - the address and contextreg value of the instruction
    ///
    /// Port of `new DecoderExecutor(DecoderForOneStride, AddrCtx)`.
    pub fn new(decoder: &'d JitPassageDecoder, at: AddrCtx) -> Self {
        Self::with_instruction(decoder, at, None)
    }

    /// Construct the interpreter for an already-decoded instruction.
    ///
    /// # Arguments
    /// * `decoder` - the passage decoder
    /// * `at` - the address and contextreg value of the instruction
    /// * `instruction` - the instruction, or `None`
    ///
    /// Port of `new DecoderExecutor(DecoderForOneStride, AddrCtx, PseudoInstruction)`; Rust has no
    /// overloading, so it carries a distinct name.
    pub fn with_instruction(
        decoder: &'d JitPassageDecoder,
        at: AddrCtx,
        instruction: Option<Arc<dyn PseudoInstruction>>,
    ) -> Self {
        let mut executor = Self {
            decoder,
            language: decoder.thread_get_language(),
            at,
            instruction: None,
            term_nop: None,
            flow: None,
            fut_ctx: HashMap::new(),
            ops_for_this_step: Vec::new(),
            branches_for_this_step: Vec::new(),
        };
        executor.set_instruction(instruction);
        executor
    }

    /// Re-write the given op as a `DecodedPcodeOp` with the given address/contextreg value.
    ///
    /// Port of the static `DecoderExecutor.rewriteOp(AddrCtx, PcodeOp)`.
    ///
    /// Java's `DecodedPcodeOp` is a `PcodeOp` subclass carrying the `at` it was decoded at, and
    /// this method either wraps the op or, if it is already decoded, returns it unchanged after
    /// asserting the two agree. This crate models `DecodedPcodeOp` as a plain [`PcodeOp`] -- the
    /// same choice [`nop_pcode_op`]/[`exit_pcode_op`] make for its siblings -- so both arms
    /// collapse into a clone. Nothing is lost at this call site: `at` is fixed for the whole step,
    /// so it is exactly [`DecoderExecutor::at`] for every op this executor rewrites. It *will*
    /// matter to the passage-wide bookkeeping in `JitPassage`, which is not yet ported.
    pub fn rewrite_op(at: &AddrCtx, op: &PcodeOp) -> PcodeOp {
        let _ = at;
        op.clone()
    }

    /// Re-write the given op, capturing this step's address and decode context.
    ///
    /// Port of `DecoderExecutor.rewrite(PcodeOp)`. Java memoizes in a `rewrites` map so that
    /// re-writing the same op twice yields the same object, preserving identity in the re-written
    /// realm; [`PcodeOp`] here has value semantics with structural `Eq`/`Hash`, so a second rewrite
    /// yields an equal op that keys every map identically, and the memo has nothing to preserve.
    pub fn rewrite(&self, op: &PcodeOp) -> PcodeOp {
        Self::rewrite_op(&self.at, op)
    }

    /// Set the current instruction.
    ///
    /// This also pre-computes the resulting "flow" context from the given instruction: the input
    /// context for the next decoded instruction, not accounting for `globalset`. It is computed by
    /// taking the instruction's input context and resetting non-flowing bits to the language's
    /// defaults. When a branch is encountered or fall through is considered,
    /// [`take_target_context`](Self::take_target_context) accounts for `globalset` and derives the
    /// target context for the target address.
    ///
    /// Port of `DecoderExecutor.setInstruction(PseudoInstruction)`.
    ///
    /// # Panics
    ///
    /// When the language has a context register *and* a non-error instruction was decoded: the
    /// flow context is built as `new RegisterValue(contextreg, ZERO).combineValues(...)`, and
    /// `ghidra.program.model.lang.RegisterValue` is not ported -- there is no concrete
    /// implementation of either `RegisterValue` placeholder to construct. Languages without a
    /// context register take the other arm and work.
    pub fn set_instruction(&mut self, instruction: Option<Arc<dyn PseudoInstruction>>) {
        let is_decode_error =
            instruction.as_deref().is_some_and(|i| i.decode_error_message().is_some());
        self.instruction = instruction;
        if self.at.rv_ctx.is_none() || self.instruction.is_none() || is_decode_error {
            self.flow = self.at.rv_ctx.clone();
            return;
        }
        let _ = (self.decoder.contextreg(), self.decoder.default_context());
        unimplemented!(
            "DecoderExecutor::set_instruction: the flow context needs RegisterValue, not yet ported"
        )
    }

    /// Decode the instruction this executor is meant to interpret.
    ///
    /// This can be delayed if there is a user inject at the target address, in which case the
    /// (unported) `DecoderUseropLibrary`'s `emu_exec_decoded`/`emu_skip_decoded` invoke it.
    ///
    /// Port of `DecoderExecutor.decodeInstruction()`. Returns the decoded instruction, which may be
    /// a `DecodeErrorInstruction`.
    pub fn decode_instruction(&mut self) -> Arc<dyn PseudoInstruction> {
        let decoded = self
            .decoder
            .decode_instruction(&self.at.address, self.at.rv_ctx.as_deref())
            .unwrap_or_else(|err| panic!("DecoderExecutor::decode_instruction: {err}"));
        // Java keeps the one instruction object in both this executor and the stride's list; `Arc`
        // is how that aliasing is spelled here.
        let instruction: Arc<dyn PseudoInstruction> = Arc::from(decoded);
        self.set_instruction(Some(Arc::clone(&instruction)));
        instruction
    }

    /// Apply the instruction's `globalset` commits to this executor, which collects them into
    /// [`fut_ctx`](Self::fut_ctx) via [`DisassemblerContext::set_future_register_value`].
    ///
    /// Port of `DecoderExecutor.processContextChanges()`.
    ///
    /// # Panics
    ///
    /// Always: this needs `PseudoInstruction.getParserContext()` and
    /// `SleighParserContext.applyCommits`, and the `PseudoInstruction` placeholder carries no
    /// parser context. Only [`set_instruction`](Self::set_instruction)'s already-panicking arm
    /// calls it.
    #[allow(dead_code)] // Its one caller is the arm of `set_instruction` that panics first.
    fn process_context_changes(&mut self) {
        unimplemented!(
            "DecoderExecutor::process_context_changes needs PseudoInstruction::get_parser_context, \
             not yet ported"
        )
    }

    /// Interpret the given program with the passage decoder's userop library.
    ///
    /// Port of `DecoderExecutor.execute(PcodeProgram)`, which passes `stride.passage.library()` --
    /// the decoder's one wrapped library.
    pub fn execute(&mut self, program: &PcodeProgram) {
        let decoder = self.decoder;
        self.execute_code(program.code().to_vec(), program.userop_names().clone(), decoder.library());
    }

    /// Interpret a list of p-code ops with the given library.
    ///
    /// Port of the inherited `PcodeExecutor.execute(List, Map, PcodeUseropLibrary)`. Java's
    /// `executeCode` wraps anything thrown in a `PcodeExecutionException` carrying the frame;
    /// nothing this executor does throws, so the frame simply stays local.
    fn execute_code(
        &mut self,
        code: Vec<PcodeOp>,
        userop_names: HashMap<i32, String>,
        library: &DecoderUseropLibrary,
    ) {
        let mut frame = PcodeFrame::new(Arc::clone(&self.language), code, userop_names);
        self.finish(&mut frame, library);
    }

    /// Finish execution of a frame.
    ///
    /// Port of `DecoderExecutor.finish(PcodeFrame, PcodeUseropLibrary)`.
    ///
    /// We check here if a "terminal nop" was necessary. Any jump to (should never be past) the end
    /// of the program will require one. Instead of trying to figure out what the op following this
    /// instruction is, so the jumps can target it, we add a special nop, and the jump is made to
    /// target it. Once we reach the end of the p-code program proper, we have to add that nop.
    pub fn finish(&mut self, frame: &mut PcodeFrame, library: &DecoderUseropLibrary) {
        while !frame.is_finished() {
            self.step(frame, library);
        }
        if let Some(term_nop) = self.term_nop.take() {
            self.ops_for_this_step.push(term_nop);
        }
    }

    /// Step a single p-code op of the given frame.
    ///
    /// Port of the inherited `PcodeExecutor.step(PcodeFrame, PcodeUseropLibrary)`.
    fn step(&mut self, frame: &mut PcodeFrame, library: &DecoderUseropLibrary) {
        // Java hands `frame.nextOp()` straight to `stepOp`, which also takes the frame; Rust
        // cannot lend the frame twice when the second lend is mutable, so the op is copied out.
        let op = frame.next_op().clone();
        self.step_op(&op, frame, library);
    }

    /// Step one p-code op.
    ///
    /// Port of `DecoderExecutor.stepOp(PcodeOp, PcodeFrame, PcodeUseropLibrary)`.
    ///
    /// We only really need to interpret branching ops here. We also interpret `callother`, in case
    /// we're able to inline a p-code userop. Note that if we inline the userop, we still retain the
    /// `callother` op, because internal jumps may target it. It is easier to leave it in the books
    /// and nop it out later than to try to substitute the first inlined op. Worse, if the inlined
    /// userop emits no p-code, substitution would get especially difficult.
    ///
    /// We also interpret `unimplemented`, because that will require us to create an `ErrBranch`
    /// record. All other ops must still be added to the decoded passage, but not (yet) interpreted.
    pub fn step_op(
        &mut self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
        library: &DecoderUseropLibrary,
    ) {
        // NOTE: Must log every op, including inlined CALLOTHER's, because an internal jump may
        // refer to that CALLOTHER. It's easier to snuff the op later than to substitute the refs.
        let op = self.rewrite(op);
        self.ops_for_this_step.push(op.clone());
        // Java lists the interpreted opcodes in `stepOp`'s switch and delegates to `super.stepOp`,
        // whose own switch dispatches them; the two switches are fused here.
        match op.opcode {
            OpCode::Branch => self.execute_branch(&op, frame),
            OpCode::CBranch => self.execute_conditional_branch(&op, frame),
            OpCode::Call => self.execute_call(&op, frame),
            OpCode::BranchInd => self.execute_indirect_branch(&op, frame),
            OpCode::CallInd => self.execute_indirect_call(&op, frame),
            OpCode::Return => self.execute_return(&op, frame),
            OpCode::CallOther => self.execute_callother(&op, frame, library),
            OpCode::Unimplemented => self.bad_op(&op),
            _ => {}
        }
    }

    /// Get the target address (input 0's address) of a branch, conditional branch, or call op.
    ///
    /// Port of the inherited `PcodeExecutor.getBranchTarget(PcodeOp)`.
    fn get_branch_target(&self, op: &PcodeOp) -> Address {
        op.inputs[0].get_address().clone()
    }

    /// Check and correct the given target address, if it resides in "NO ADDRESS" space.
    ///
    /// Port of the inherited `PcodeExecutor.checkInjectedTarget(Address)`.
    fn check_injected_target(&self, target: &Address) -> Address {
        let space = target.space();
        let is_no_address =
            space.space_type() == AddressSpaceType::None && space.name() == NO_ADDRESS_SPACE_NAME;
        if !is_no_address {
            return target.clone();
        }
        self.language.get_default_space().address(target.offset())
    }

    /// Perform the actual logic of a branch p-code op.
    ///
    /// Port of the inherited `PcodeExecutor.doExecuteBranch(PcodeOp, PcodeFrame)`. The base class
    /// also calls `branchToOffset`, which this executor overrides to do nothing (there is no state
    /// to write the program counter to), so it is elided rather than called and ignored -- note in
    /// particular that not finishing the frame is what lets decode keep logging the rest of the
    /// step's ops.
    fn do_execute_branch(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        let target = self.get_branch_target(op);
        if target.is_constant_address() {
            self.branch_internal(op, frame, target.offset() as i32);
        } else {
            let target = self.check_injected_target(&target);
            self.branch_to_address(op, &target);
        }
    }

    /// Execute a branch.
    ///
    /// Port of the inherited `PcodeExecutor.executeBranch(PcodeOp, PcodeFrame)`.
    fn execute_branch(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        self.do_execute_branch(op, frame);
    }

    /// Execute a conditional branch.
    ///
    /// Port of `DecoderExecutor.executeConditionalBranch(PcodeOp, PcodeFrame)`: we interpret this
    /// the same as an unconditional branch, because at this point we need only collect branch
    /// targets to seed additional strides. (The base class would read the predicate from the state
    /// this executor does not have.)
    pub fn execute_conditional_branch(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        self.do_execute_branch(op, frame);
    }

    /// Record a branch to an address.
    ///
    /// Port of `DecoderExecutor.branchToAddress(PcodeOp, Address)`: create an `ExtBranch` record
    /// and collect it for this instruction step. The record will first be used to check for fall
    /// through; then the passage decoder is notified, which either adds it to the seed queue or
    /// converts it to an `IntBranch` record.
    ///
    /// See [`check_fallthrough_and_accumulate`](Self::check_fallthrough_and_accumulate).
    fn branch_to_address(&mut self, op: &PcodeOp, target: &Address) {
        let to = self.take_target_context(target);
        self.branches_for_this_step.push(SBranch::Ext(SExtBranch::new(op.clone(), to)));
    }

    /// Record a branch to another op within this step's p-code.
    ///
    /// Port of `DecoderExecutor.branchInternal(PcodeOp, PcodeFrame, int)`: create an `IntBranch`
    /// record and collect it for this instruction step. The record will first be used to check for
    /// fall through; then the passage decoder is notified, which collects the records for later
    /// passage-wide control flow analysis.
    ///
    /// See [`check_fallthrough_and_accumulate`](Self::check_fallthrough_and_accumulate).
    fn branch_internal(&mut self, op: &PcodeOp, frame: &mut PcodeFrame, relative: i32) {
        // Java's `SequenceNumber.getTime()`; this crate names the field `uniq`.
        let tgt_seq = op.seqnum.uniq + relative;
        let to = if tgt_seq as usize == frame.code().len() {
            if self.term_nop.is_none() {
                self.term_nop = Some(nop_pcode_op(&self.at, tgt_seq));
            }
            self.term_nop.clone().expect("just set")
        } else {
            let to = frame.code()[tgt_seq as usize].clone();
            self.rewrite(&to)
        };
        self.branches_for_this_step.push(SBranch::Int(SIntBranch::new(op.clone(), to, false)));
    }

    /// Perform the actual logic of an indirect branch p-code op.
    ///
    /// Port of `DecoderExecutor.doExecuteIndirectBranch(PcodeOp, PcodeFrame)`: create an
    /// `IndBranch` record and collect it for this instruction step. The record will first be used
    /// to check for fall through; then the passage decoder is notified, which collects the records
    /// for later passage-wide control flow analysis.
    ///
    /// See [`check_fallthrough_and_accumulate`](Self::check_fallthrough_and_accumulate).
    fn do_execute_indirect_branch(&mut self, op: &PcodeOp, _frame: &mut PcodeFrame) {
        self.branches_for_this_step
            .push(SBranch::Ind(SIndBranch::new(op.clone(), self.flow.clone())));
    }

    /// Execute an indirect branch.
    ///
    /// Port of the inherited `PcodeExecutor.executeIndirectBranch(PcodeOp, PcodeFrame)`.
    fn execute_indirect_branch(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        self.do_execute_indirect_branch(op, frame);
    }

    /// Execute a call.
    ///
    /// Port of the inherited `PcodeExecutor.executeCall(PcodeOp, PcodeFrame, PcodeUseropLibrary)`.
    /// As with [`do_execute_branch`](Self::do_execute_branch), the overridden-to-nothing
    /// `branchToOffset` is elided.
    fn execute_call(&mut self, op: &PcodeOp, _frame: &mut PcodeFrame) {
        let target = self.get_branch_target(op);
        let target = self.check_injected_target(&target);
        self.branch_to_address(op, &target);
    }

    /// Execute an indirect call.
    ///
    /// Port of the inherited `PcodeExecutor.executeIndirectCall(PcodeOp, PcodeFrame)`.
    fn execute_indirect_call(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        self.do_execute_indirect_branch(op, frame);
    }

    /// Execute a return.
    ///
    /// Port of the inherited `PcodeExecutor.executeReturn(PcodeOp, PcodeFrame)`.
    fn execute_return(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        self.do_execute_indirect_branch(op, frame);
    }

    /// Get the userop number (const input 0) of a `callother` op.
    ///
    /// Port of the inherited `PcodeExecutor.getCallotherOpNumber(PcodeOp)`.
    fn get_callother_op_number(&self, op: &PcodeOp) -> i32 {
        op.inputs[0].get_address().offset() as i32
    }

    /// Get the name of the userop with the given number, or `None` if it is not defined.
    ///
    /// Port of the inherited `PcodeExecutor.getUseropName(int, PcodeFrame)`.
    fn get_userop_name(&self, op_no: i32, frame: &PcodeFrame) -> Option<String> {
        if op_no < self.language.get_number_of_user_defined_op_names() {
            return self.language.get_user_defined_op_name(op_no);
        }
        frame.get_userop_name(op_no).map(str::to_string)
    }

    /// Execute a userop call.
    ///
    /// Port of the inherited
    /// `PcodeExecutor.executeCallother(PcodeOp, PcodeFrame, PcodeUseropLibrary)`, fused with the
    /// `DecoderUseropLibrary.WrappedUseropDefinition.execute` it dispatches to: the wrapper inlines
    /// the runtime userop's p-code when the userop says it may be inlined, and otherwise does
    /// nothing, since the `callother` has already been logged and will be compiled later.
    ///
    /// # Panics
    ///
    /// On the inlining arm: the wrapper re-types the runtime userop's `execute` from `byte[]` to
    /// `Object` by raw-casting the executor, and the ported `PcodeUseropDefinition::execute_raw`
    /// requires a real
    /// [`PcodeExecutor`](crate::pcode::exec::pcode_executor::PcodeExecutor), which this executor is
    /// not (see the module docs). Also on an undefined userop number, where Java throws an
    /// `AssertionError`.
    fn execute_callother(
        &mut self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
        library: &DecoderUseropLibrary,
    ) {
        let op_no = self.get_callother_op_number(op);
        let Some(op_name) = self.get_userop_name(op_no, frame) else {
            panic!("Pcode userop {op_no} is not defined");
        };
        let Some(userop) = library.get_userop(&op_name) else {
            self.on_missing_userop_def(op, &op_name);
            return;
        };
        if userop.can_inline_pcode() {
            unimplemented!(
                "DecoderExecutor::execute_callother cannot inline the p-code of userop \
                 '{op_name}': that needs a PcodeExecutor, which this executor is not"
            )
        }
        // Nothing to do. CALLOTHER is logged and will be compiled later.
    }

    /// Record a call to a userop the library does not define.
    ///
    /// Port of
    /// `DecoderExecutor.onMissingUseropDef(PcodeOp, PcodeFrame, String, PcodeUseropLibrary)`:
    /// create an `ErrBranch` record and collect it for this instruction step. In contrast to
    /// [`bad_op`](Self::bad_op), an instruction that calls a missing userop may still have fall
    /// through.
    fn on_missing_userop_def(&mut self, op: &PcodeOp, op_name: &str) {
        self.branches_for_this_step.push(SBranch::Err(ErrBranch::new(
            op.clone(),
            format!("Sleigh userop '{op_name}' is not in the library"),
        )));
    }

    /// Record an unimplemented or otherwise unrecognized op.
    ///
    /// Port of `DecoderExecutor.badOp(PcodeOp)`: create an `ErrBranch` record and collect it for
    /// this instruction step. In most (all?) cases this is the only op emitted by the instruction
    /// (decode error, unimplemented instruction), and so there is certainly no fall through.
    ///
    /// Java's non-decode-error message also interpolates the whole `AddrCtx` record and the
    /// instruction; neither the placeholder `AddrCtx` (its `rv_ctx` is a non-`Debug` trait object)
    /// nor the placeholder `PseudoInstruction` can render itself here, so the message keeps the
    /// two fields of `AddrCtx` that exist.
    fn bad_op(&mut self, op: &PcodeOp) {
        let message = match self.instruction.as_deref().and_then(|i| i.decode_error_message()) {
            Some(message) => message.to_string(),
            None => format!(
                "Encountered an unimplemented instruction at AddrCtx[biCtx={}, address={}]",
                self.at.bi_ctx, self.at.address
            ),
        };
        self.branches_for_this_step.push(SBranch::Err(ErrBranch::new(op.clone(), message)));
    }

    /// Derive the contextreg value at the given target address (branch or fall through).
    ///
    /// An instruction's constructors may use `globalset` to place context changes at specific
    /// addresses. Those changes are collected by
    /// [`DisassemblerContext::set_future_register_value`] through some chain of method invocations
    /// started by [`set_instruction`](Self::set_instruction). When the interpreter encounters a
    /// branch op, that op will specify the target address. We must also derive the context for that
    /// branch: the pre-computed [`flow`](Self::flow) context, but now accounting for `globalset` at
    /// the target address.
    ///
    /// Port of `DecoderExecutor.takeTargetContext(Address)`.
    ///
    /// # Panics
    ///
    /// When a `globalset` did land on `target`: combining requires the two `RegisterValue`
    /// placeholders to be one type (see [`fut_ctx`](Self::fut_ctx)). Without a `globalset` -- the
    /// case for every instruction that does not modify context -- this is exact.
    pub fn take_target_context(&self, target: &Address) -> AddrCtx {
        if !self.fut_ctx.contains_key(target) {
            return AddrCtx::new(self.flow.clone(), target.clone());
        }
        // Do not remove, in case there are multiple branches to the same target address.
        unimplemented!(
            "DecoderExecutor::take_target_context cannot combine a globalset context: the decode \
             context and the disassembler context are separate RegisterValue placeholders"
        )
    }

    /// After p-code interpretation, check if the instruction has fall through, notify the stride
    /// decoder of the instruction's ops, and notify the passage of the instruction's branches.
    ///
    /// To determine whether there's fall through, this performs a miniature control flow analysis
    /// on just this step's p-code ops. This is required because a user inject can be very complex,
    /// and need not obey all of the usual control flow checks imposed by the Sleigh semantic
    /// compiler. In particular `Instruction.hasFallthrough()` is not sufficient, for at least two
    /// reasons: 1) the aforementioned user inject possibilities, 2) we do not consider a `call` or
    /// `callind` as having fall through.
    ///
    /// To use control flow analysis as a means of checking for fall through, we append a special
    /// "probe" exit op along with an `ExtBranch` record to [`AddrCtx::nowhere`]. The probe thus
    /// serves the secondary purpose of preventing any complaints from the analyzer about
    /// unterminated control flow. We then perform the analysis, borrowing [`BlockSplitter`] from
    /// `JitControlFlowModel`. In practice, this seems fast enough. Because the splitter keeps the
    /// blocks in the original order, the first op will certainly be in the first block, and the
    /// probe op will certainly be in the last block. We perform a simple reachability test between
    /// the two. The step has fall through if and only if a path is found.
    ///
    /// # Arguments
    /// * `from` - the instruction's or inject's p-code
    /// * `stride` - the stride being decoded, which Java reaches as this executor's `stride` field
    ///
    /// Port of `DecoderExecutor.checkFallthroughAndAccumulate(PcodeProgram)`. Returns the
    /// reachability of the fall-through flow, or `None` if the exit is not reachable at all.
    ///
    /// # Panics
    ///
    /// Once past the empty-step shortcut: [`BlockSplitter`] is a placeholder, so the analysis
    /// itself is not yet runnable. See its docs.
    pub fn check_fallthrough_and_accumulate(
        &mut self,
        from: &PcodeProgram,
        stride: &mut DecoderForOneStride<'_, '_>,
    ) -> Option<Reachability> {
        if self.ops_for_this_step.is_empty() {
            return Some(Reachability::WithoutCtxmod);
        }

        let probe_op = exit_pcode_op(&AddrCtx::nowhere());
        self.ops_for_this_step.push(probe_op.clone());
        self.branches_for_this_step
            .push(SBranch::Ext(SExtBranch::new(probe_op.clone(), AddrCtx::nowhere())));

        let program = PcodeProgram::from_program(from, self.ops_for_this_step.clone());
        let mut splitter = BlockSplitter::new(program, |from, to| {
            SIntBranch::new(from.clone(), to.clone(), true)
        });
        // Java hands the live list over; the branches are not `Clone`, and this executor is done
        // with them either way, so they are moved out.
        splitter.add_branches(std::mem::take(&mut self.branches_for_this_step));
        let blocks = splitter.split_blocks();
        let entry = blocks.first().expect("a non-empty step splits into at least one block").1;
        let exit = blocks.last().expect("a non-empty step splits into at least one block").1;

        let mut reachable: HashMap<JitBlock, Reachability> = HashMap::new();
        self.collect_reachable(&mut reachable, entry, Reachability::WithoutCtxmod, stride);

        for (_first_op, block) in &blocks {
            let Some(reach) = reachable.get(block).copied() else {
                continue;
            };
            for op in block.get_code() {
                if *op != probe_op {
                    stride.ops_for_stride.push(op.clone());
                }
            }
            for branch in block.branches_from() {
                if !branch.is_fall {
                    let from = branch.from.clone();
                    stride.passage.internal_branches.insert(from, branch.with_reach(reach));
                }
            }
            for branch in block.branches_out() {
                if branch.from() == &probe_op {
                    continue;
                }
                match branch {
                    SBranch::Ext(eb) => stride.passage.flow_to(eb.with_reach(reach)),
                    SBranch::Ind(ib) => {
                        let from = ib.from.clone();
                        stride.passage.other_branches.insert(from, PBranch::Ind(ib.with_reach(reach)));
                    }
                    SBranch::Err(eb) => {
                        let from = eb.from.clone();
                        stride.passage.other_branches.insert(from, PBranch::Err(eb));
                    }
                    // Java: `default -> throw new AssertionError()`. An internal branch never
                    // leaves its block.
                    SBranch::Int(_) => panic!("an IntBranch cannot be a branch out of a block"),
                }
            }
        }

        reachable.get(&exit).copied()
    }

    /// Check whether any op in the block calls a userop that may modify the decode context.
    ///
    /// Port of `DecoderExecutor.blockModifiesContext(JitBlock)`.
    fn block_modifies_context(
        &self,
        block: &JitBlock,
        stride: &DecoderForOneStride<'_, '_>,
    ) -> bool {
        for op in block.get_code() {
            if op.opcode != OpCode::CallOther {
                continue;
            }
            let Some(name) = block.get_userop_name(self.get_callother_op_number(op)) else {
                continue;
            };
            let Some(userop) = stride.passage.library().get_userop(&name) else {
                continue;
            };
            if userop.modifies_context() {
                return true;
            }
        }
        false
    }

    /// The reachability test mentioned in
    /// [`check_fallthrough_and_accumulate`](Self::check_fallthrough_and_accumulate).
    ///
    /// Collects the reachability of blocks reachable from `cur` into the given mutable map. The
    /// value indicates whether or not context modifications can occur along the paths to the block
    /// (key). If a block is not in the map, it is not reachable.
    ///
    /// Context-modifying userops are all considered hazards, but we shouldn't abort until after the
    /// instruction. If the exit is reachable without passing through a context modification, then
    /// we're good to proceed. Otherwise, no. Additionally, we check all branches, direct or
    /// indirect, to see if they are reachable without context modification. If they are, we treat
    /// them as usual. If not, they will be treated as indirect, and we'll neglect to "retire" the
    /// context, because presumably the userop will already have caused that retirement and modified
    /// it in place. If one branch is reachable by multiple paths where some require context
    /// modification and some do not, we keep a local variable at run time to track whether a
    /// context-modifying userop has actually been executed, check it at the branch site, and treat
    /// it as a hazard if it is set.
    ///
    /// # Arguments
    /// * `into` - a mutable map for collecting reachable blocks
    /// * `cur` - the source block, or an intermediate during recursion
    /// * `how` - the computed reachability of the source block; use
    ///   [`Reachability::WithoutCtxmod`] for the seed
    /// * `stride` - the stride being decoded, for [`block_modifies_context`](Self::block_modifies_context)
    ///
    /// Port of `DecoderExecutor.collectReachable(Map, JitBlock, Reachability)`.
    fn collect_reachable(
        &self,
        into: &mut HashMap<JitBlock, Reachability>,
        cur: JitBlock,
        how: Reachability,
        stride: &DecoderForOneStride<'_, '_>,
    ) {
        let cur_how = into.get(&cur).copied();

        let how = if self.block_modifies_context(&cur, stride) {
            // Not combine. If we're MAYBE here, we still become WITH_CTX.
            Reachability::WithCtxmod
        } else {
            how.combine(cur_how)
        };

        if Some(how) == cur_how {
            return;
        }
        into.insert(cur, how);

        for flow in cur.flows_from() {
            self.collect_reachable(into, flow.to, how, stride);
        }
    }

    /// Compute the fall-through address.
    ///
    /// This computes the "next" address whether or not the instruction actually has fall through.
    /// The caller should check for fall through first.
    ///
    /// If no instruction was actually decoded during this step, and the decoder is asking about
    /// fall through, then the user very likely made an error in specifying an inject's control
    /// flow, in which case the counter will not advance. To get this same effect, we just return
    /// the current address. The decoder and/or translator ought to recognize this and ensure the
    /// resulting infinite loop can be interrupted.
    ///
    /// Port of `DecoderExecutor.getAdvancedAddress()`.
    pub fn get_advanced_address(&self) -> Address {
        let Some(instruction) = self.instruction.as_deref() else {
            Msg::warn("DecoderExecutor", &"An inject may have forgotten control flow.");
            return self.at.address.clone();
        };
        // Java's `Address.next()` yields null at the end of the space; nothing downstream handles
        // that, and an instruction cannot end there in practice.
        instruction
            .get_max_address()
            .next()
            .expect("an instruction cannot end at the last address of its space")
    }

    /// Notify the stride of an instruction.
    ///
    /// For addresses without injects, every decoded instruction ought to be included in the stride.
    /// For an address with an inject, a decoded instruction should only be included if it is
    /// actually interpreted, i.e., its ops are included.
    ///
    /// Port of `DecoderExecutor.addInstruction(PseudoInstruction)`; `stride` is this executor's
    /// `stride` field in Java.
    #[allow(dead_code)] // Java's only caller is `DecoderUseropLibrary`, not yet ported.
    pub(crate) fn add_instruction(
        &self,
        stride: &mut DecoderForOneStride<'_, '_>,
        instruction: Arc<dyn PseudoInstruction>,
    ) {
        stride.instructions.push(instruction);
    }
}

/// Java's `DecoderExecutor implements DisassemblerContextAdapter`. Rust does not let a subtrait's
/// default method satisfy a supertrait's required method, so -- as
/// [`DisassemblerContextAdapter`]'s own docs prescribe -- the supertraits are implemented here by
/// delegating to it.
impl ProcessorContextView for DecoderExecutor<'_> {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_base_context_register(self)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_registers(self)
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_register(self, name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        <Self as DisassemblerContextAdapter>::get_value(self, register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn LangRegisterValue>> {
        <Self as DisassemblerContextAdapter>::get_register_value(self, register)
    }

    fn has_value(&self, register: &Register) -> bool {
        <Self as DisassemblerContextAdapter>::has_value(self, register)
    }
}

impl ProcessorContext for DecoderExecutor<'_> {
    fn set_value(
        &mut self,
        register: &Register,
        value: i128,
    ) -> Result<(), ContextChangeException> {
        <Self as DisassemblerContextAdapter>::set_value(self, register, value)
    }

    fn set_register_value(
        &mut self,
        value: Box<dyn LangRegisterValue>,
    ) -> Result<(), ContextChangeException> {
        <Self as DisassemblerContextAdapter>::set_register_value(self, value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        <Self as DisassemblerContextAdapter>::clear_register(self, register)
    }
}

impl DisassemblerContext for DecoderExecutor<'_> {
    fn set_future_register_value(&mut self, address: Address, value: Box<dyn LangRegisterValue>) {
        <Self as DisassemblerContextAdapter>::set_future_register_value(self, address, value)
    }

    fn set_future_register_value_for_flow(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        value: Box<dyn LangRegisterValue>,
    ) {
        <Self as DisassemblerContextAdapter>::set_future_register_value_for_flow(
            self, from_addr, to_addr, value,
        )
    }
}

impl DisassemblerContextAdapter for DecoderExecutor<'_> {
    /// Collect a `globalset` context change for the given address, ignoring any register that is
    /// not the processor context.
    ///
    /// Port of `DecoderExecutor.setFutureRegisterValue(Address, RegisterValue)`.
    fn set_future_register_value(&mut self, address: Address, value: Box<dyn LangRegisterValue>) {
        if !value.get_register().borrow().is_processor_context() {
            return;
        }
        // Java: `futCtx.compute(address, (a, v) -> v == null ? value : v.combineValues(value))`.
        match self.fut_ctx.remove(&address) {
            Some(existing) => {
                let combined = existing.combine_values(value.as_ref());
                self.fut_ctx.insert(address, combined);
            }
            None => {
                self.fut_ctx.insert(address, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::instruction_decoder::InstructionDecoder;
    use crate::pcode::exec::pcode_userop_library::{
        ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
    };
    use crate::pcode::seam_stubs::JitPcodeThread;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{SequenceNumber, Varnode};
    use std::sync::Mutex;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0)
    }

    fn ram(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    /// An op at sequence `seq` within the step's p-code, targeting `target` via input 0.
    fn op(opcode: OpCode, seq: i32, target: Address) -> PcodeOp {
        PcodeOp::new(
            opcode,
            SequenceNumber::new(ram(0x1000), seq),
            vec![Varnode::new(target, 4)],
            None,
        )
    }

    fn nop(seq: i32) -> PcodeOp {
        PcodeOp::new(OpCode::Copy, SequenceNumber::new(ram(0x1000), seq), Vec::new(), None)
    }

    struct UnusedDecoder;
    impl InstructionDecoder for UnusedDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            mock_language()
        }
        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            unimplemented!("not exercised by these smoke tests")
        }
        fn branched(&mut self, _address: &Address) {}
        fn get_last_instruction(
            &self,
        ) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
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

    fn mock_decoder() -> JitPassageDecoder {
        let decoder: Arc<Mutex<dyn InstructionDecoder>> = Arc::new(Mutex::new(UnusedDecoder));
        let userops: Arc<dyn PcodeUseropLibrary<Vec<u8>>> =
            Arc::new(MockUseropLibrary { userops: UseropMap::new() });
        JitPassageDecoder::new(JitPcodeThread::new(decoder, None, userops))
    }

    fn empty_library() -> DecoderUseropLibrary {
        DecoderUseropLibrary::new(Arc::new(MockUseropLibrary { userops: UseropMap::new() }))
    }

    fn frame_of(code: Vec<PcodeOp>) -> PcodeFrame {
        PcodeFrame::new(mock_language(), code, HashMap::new())
    }

    /// Java: an unconditional branch to an address outside the step produces an `SExtBranch` whose
    /// target context is the flow context (here `null`/`None`, the language having no contextreg),
    /// and the op is still logged for the stride.
    #[test]
    fn branch_to_address_logs_the_op_and_records_an_external_branch() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        let branch = op(OpCode::Branch, 0, ram(0x2000));
        let mut frame = frame_of(vec![branch.clone()]);
        executor.step_op(&branch, &mut frame, &library);

        assert_eq!(executor.ops_for_this_step, vec![branch.clone()]);
        assert_eq!(executor.branches_for_this_step.len(), 1);
        match &executor.branches_for_this_step[0] {
            SBranch::Ext(eb) => {
                assert_eq!(eb.from, branch);
                assert!(eb.to == AddrCtx::new(None, ram(0x2000)));
            }
            _ => panic!("expected an external branch"),
        }
    }

    /// Java: `executeConditionalBranch` is overridden to `doExecuteBranch`, i.e. the predicate is
    /// never read (there is no state to read it from) and the target is always collected as a seed.
    #[test]
    fn conditional_branch_is_collected_like_an_unconditional_one() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        let cbranch = op(OpCode::CBranch, 0, ram(0x2000));
        let mut frame = frame_of(vec![cbranch.clone()]);
        executor.step_op(&cbranch, &mut frame, &library);

        match &executor.branches_for_this_step[0] {
            SBranch::Ext(eb) => assert!(eb.to == AddrCtx::new(None, ram(0x2000))),
            _ => panic!("expected an external branch"),
        }
    }

    /// Java: a branch whose target is in the constant space is internal; the target op is
    /// `frame.getCode().get(op.getSeqnum().getTime() + relative)`.
    #[test]
    fn branch_to_constant_target_records_an_internal_branch_to_that_op() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        // Op 0 branches forward by 2, i.e. to op 2 of the frame.
        let branch = op(OpCode::Branch, 0, Address::new(const_space(), 2));
        let mut frame = frame_of(vec![branch.clone(), nop(1), nop(2)]);
        executor.step_op(&branch, &mut frame, &library);

        match &executor.branches_for_this_step[0] {
            SBranch::Int(ib) => {
                assert_eq!(ib.from, branch);
                assert_eq!(ib.to, nop(2));
                assert!(!ib.is_fall);
            }
            _ => panic!("expected an internal branch"),
        }
        // The target was within the frame, so no terminal nop was needed.
        assert!(executor.term_nop.is_none());
    }

    /// Java: a branch to one past the last op targets a synthesized `NopPcodeOp`, which `finish`
    /// then appends to the step's ops so the jump has something to land on.
    #[test]
    fn branch_past_the_end_synthesizes_a_terminal_nop_appended_by_finish() {
        let decoder = mock_decoder();
        let library = empty_library();
        let at = AddrCtx::new(None, ram(0x1000));
        let mut executor = DecoderExecutor::new(&decoder, at.clone());

        // Op 0 branches forward by 2 in a two-op frame, i.e. to sequence 2 == code.len().
        let branch = op(OpCode::Branch, 0, Address::new(const_space(), 2));
        let mut frame = frame_of(vec![branch.clone(), nop(1)]);
        executor.finish(&mut frame, &library);

        let term_nop = nop_pcode_op(&at, 2);
        match &executor.branches_for_this_step[0] {
            SBranch::Int(ib) => assert_eq!(ib.to, term_nop),
            _ => panic!("expected an internal branch"),
        }
        assert_eq!(executor.ops_for_this_step, vec![branch, nop(1), term_nop]);
        assert!(executor.term_nop.is_none(), "finish removes the nop from the pending slot");
    }

    /// Java: `badOp` turns an `unimplemented` op into an `ErrBranch` rather than throwing, and,
    /// when the instruction is a `DecodeErrorInstruction`, uses that instruction's message.
    #[test]
    fn unimplemented_op_records_an_error_branch() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        let unimpl = op(OpCode::Unimplemented, 0, ram(0x1000));
        let mut frame = frame_of(vec![unimpl.clone()]);
        executor.step_op(&unimpl, &mut frame, &library);

        match &executor.branches_for_this_step[0] {
            SBranch::Err(eb) => {
                assert_eq!(eb.from, unimpl);
                assert_eq!(
                    eb.message,
                    "Encountered an unimplemented instruction at \
                     AddrCtx[biCtx=0, address=ram:0x1000]"
                );
            }
            _ => panic!("expected an error branch"),
        }
    }

    /// Java: when the instruction is a `DecodeErrorInstruction`, `badOp` reports its message
    /// verbatim.
    #[test]
    fn unimplemented_op_of_a_decode_error_reports_the_decode_message() {
        use crate::pcode::seam_stubs::JitPassage;

        let decoder = mock_decoder();
        let library = empty_library();
        let instruction: Arc<dyn PseudoInstruction> = Arc::new(JitPassage::decode_error(
            mock_language(),
            ram(0x1000),
            None,
            "bad opcode",
        ));
        let mut executor = DecoderExecutor::with_instruction(
            &decoder,
            AddrCtx::new(None, ram(0x1000)),
            Some(instruction),
        );

        let unimpl = op(OpCode::Unimplemented, 0, ram(0x1000));
        let mut frame = frame_of(vec![unimpl.clone()]);
        executor.step_op(&unimpl, &mut frame, &library);

        match &executor.branches_for_this_step[0] {
            SBranch::Err(eb) => assert_eq!(eb.message, "bad opcode"),
            _ => panic!("expected an error branch"),
        }
    }

    /// Java: `callother` to a userop the library doesn't define yields an `ErrBranch`, but -- in
    /// contrast to `badOp` -- the op is still logged, since the step may still fall through.
    #[test]
    fn callother_to_a_missing_userop_records_an_error_branch() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        // Input 0 of a CALLOTHER is the userop number, as a constant.
        let callother = op(OpCode::CallOther, 0, Address::new(const_space(), 7));
        let mut frame = PcodeFrame::new(
            mock_language(),
            vec![callother.clone()],
            HashMap::from([(7, "my_userop".to_string())]),
        );
        executor.step_op(&callother, &mut frame, &library);

        assert_eq!(executor.ops_for_this_step, vec![callother]);
        match &executor.branches_for_this_step[0] {
            SBranch::Err(eb) => {
                assert_eq!(eb.message, "Sleigh userop 'my_userop' is not in the library")
            }
            _ => panic!("expected an error branch"),
        }
    }

    /// Java: `branchind`/`callind`/`return` all funnel into `doExecuteIndirectBranch`, which
    /// records an `SIndBranch` carrying the flow context rather than a resolved target.
    #[test]
    fn indirect_branches_record_an_indirect_branch_record() {
        let decoder = mock_decoder();
        let library = empty_library();
        for opcode in [OpCode::BranchInd, OpCode::CallInd, OpCode::Return] {
            let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));
            let indirect = op(opcode, 0, ram(0x1000));
            let mut frame = frame_of(vec![indirect.clone()]);
            executor.step_op(&indirect, &mut frame, &library);

            match &executor.branches_for_this_step[0] {
                SBranch::Ind(ib) => {
                    assert_eq!(ib.from, indirect);
                    assert!(ib.flow_ctx.is_none());
                }
                _ => panic!("expected an indirect branch for {opcode:?}"),
            }
        }
    }

    /// Java: an op with no control-flow meaning is logged and nothing else.
    #[test]
    fn ordinary_ops_are_only_logged() {
        let decoder = mock_decoder();
        let library = empty_library();
        let mut executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        let copy = nop(0);
        let mut frame = frame_of(vec![copy.clone()]);
        executor.step_op(&copy, &mut frame, &library);

        assert_eq!(executor.ops_for_this_step, vec![copy]);
        assert!(executor.branches_for_this_step.is_empty());
    }

    /// Java: `takeTargetContext` pairs the target with the flow context when no `globalset` landed
    /// on that address.
    #[test]
    fn take_target_context_pairs_the_target_with_the_flow_context() {
        let decoder = mock_decoder();
        let executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        let to = executor.take_target_context(&ram(0x2000));
        assert!(to == AddrCtx::new(None, ram(0x2000)));
        assert_eq!(to.bi_ctx, 0);
    }

    /// Java: with no decoded instruction, `getAdvancedAddress` warns and returns the current
    /// address, so the decoder sees no advance.
    #[test]
    fn get_advanced_address_without_an_instruction_returns_the_current_address() {
        let decoder = mock_decoder();
        let executor = DecoderExecutor::new(&decoder, AddrCtx::new(None, ram(0x1000)));

        assert_eq!(executor.get_advanced_address(), ram(0x1000));
    }

    /// A language whose methods are never actually invoked by these tests: nothing here decodes,
    /// branches into "NO ADDRESS" space, or names a language-declared userop. `PcodeFrame` and the
    /// executor only carry it around.
    ///
    /// (`check_fallthrough_and_accumulate`'s empty-step shortcut is the one branch of that method
    /// that is runnable today, but it still takes a `PcodeProgram`, and this crate exposes no way
    /// to build one without a full `Instruction`, so it is left to the `BlockSplitter` port.)
    fn mock_language() -> Arc<dyn Language> {
        use crate::app::plugin::processors::generic::MemoryBlockDefinition;
        use crate::program::model::address::{AddressFactory, AddressSetView};
        use crate::program::model::lang::compiler_spec::CompilerSpec;
        use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
        use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
        use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
        use crate::program::model::lang::instruction_prototype::InstructionPrototype;
        use crate::program::model::lang::language::ParseError;
        use crate::program::model::lang::language_description::LanguageDescription;
        use crate::program::model::lang::language_id::LanguageID;
        use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
        use crate::program::model::listing::default_program_context::DefaultProgramContext;
        use crate::program::model::mem::MemBuffer;
        use crate::program::seam_stubs::{AddressLabelInfo, Processor};
        use crate::util::task::TaskMonitor;
        use std::collections::HashSet;

        struct MockLanguage;
        impl Language for MockLanguage {
            fn get_language_id(&self) -> LanguageID {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_language_description(&self) -> Box<dyn LanguageDescription> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_parallel_instruction_helper(
                &self,
            ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_processor(&self) -> Box<dyn Processor> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_version(&self) -> i32 {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_minor_version(&self) -> i32 {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_address_factory(&self) -> Box<dyn AddressFactory> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_default_space(&self) -> Arc<AddressSpace> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_default_data_space(&self) -> Arc<AddressSpace> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn is_big_endian(&self) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_instruction_alignment(&self) -> i32 {
                unimplemented!("not exercised by these smoke tests")
            }
            fn supports_pcode(&self) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn is_volatile(&self, _addr: &Address) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn parse(
                &self,
                _buf: &dyn MemBuffer,
                _context: &mut dyn ProcessorContext,
                _in_delay_slot: bool,
            ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_number_of_user_defined_op_names(&self) -> i32 {
                // The one method these tests do reach: `getUseropName` consults the language's
                // declared userops before the frame's. This language declares none.
                0
            }
            fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
                None
            }
            fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_register_in_space(
                &self,
                _addrspc: &Arc<AddressSpace>,
                _offset: i64,
                _size: i32,
            ) -> Option<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_register_names(&self) -> Vec<String> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_program_counter(&self) -> Option<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_context_base_register(&self) -> Option<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_context_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_segmented_space(&self) -> String {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {
                unimplemented!("not exercised by these smoke tests")
            }
            fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_compatible_compiler_spec_descriptions(
                &self,
            ) -> Vec<Box<dyn CompilerSpecDescription>> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_compiler_spec_by_id(
                &self,
                _compiler_spec_id: &CompilerSpecID,
            ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn has_property(&self, _key: &str) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_property(&self, _key: &str) -> Option<String> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_property_keys(&self) -> HashSet<String> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn has_manual(&self) -> bool {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_manual_entry(
                &self,
                _instruction_mnemonic: &str,
            ) -> Option<crate::util::manual_entry::ManualEntry> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_manual_exception(
                &self,
            ) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
                unimplemented!("not exercised by these smoke tests")
            }
            fn get_maximum_instruction_length(&self) -> Option<i32> {
                unimplemented!("not exercised by these smoke tests")
            }
        }
        Arc::new(MockLanguage)
    }
}
