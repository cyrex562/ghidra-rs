//! An executor of p-code programs.
//!
//! Port of `ghidra.pcode.exec.PcodeExecutor`.
//!
//! This is the kernel of Sleigh expression evaluation and p-code emulation. For a complete example
//! of a p-code emulator, see [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//!
//! # Divergences from Java
//!
//! * **The bound language.** Java's field is a `SleighLanguage`, from which it uses exactly five
//!   members: `getProgramCounter`, `getDefaultSpace`, `getAddressFactory`,
//!   `getNumberOfUserDefinedOpNames`, and `getUserDefinedOpName`. This crate's
//!   [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) is a partial,
//!   `.sla`-only port: it does not implement [`Language`] and exposes none of those five. All five
//!   *are* on [`Language`], so the executor binds to `Arc<dyn Language>`, which is also exactly
//!   what [`PcodeFrame::new`] wants. Only `execute_sleigh` genuinely needs the Sleigh-specific
//!   language, and it is blocked on `SleighProgramCompiler` regardless.
//! * **Op behavior dispatch.** Java asks `OpBehaviorFactory` for an `OpBehavior` and then switches
//!   on its *class* to decide unary vs. binary vs. special. There is no factory in this crate's
//!   [`opbehavior`](crate::pcode::opbehavior) module (the behaviors carry no per-op instances), so
//!   the same three-way classification is made directly from the opcode by [`op_behavior_kind`],
//!   which mirrors `OpBehaviorFactory`'s table entry for entry. Consequently `execute_unary_op`
//!   and `execute_binary_op` do not take the behavior argument that Java's counterparts accept and
//!   ignore.
//! * **Exceptions.** Java throws `LowlevelError` from the individual op executions and wraps
//!   anything escaping a step in a `PcodeExecutionException`. Here the op executions return
//!   `Result<_, LowlevelError>` and [`step`](PcodeExecutor::step) performs the same wrap. Java's
//!   `SleighLinkException` (a `PcodeExecutionException` subclass) is not ported; the missing-userop
//!   error carries Java's message as a [`LowlevelError`], which `step` then wraps identically.
//! * **Extension points.** Java's `protected` hooks (`beforeLoad`, `afterStore`,
//!   `branchToAddress`, ...) exist for subclasses to override. Rust cannot override an inherent
//!   method, so they are no-op inherent methods here, faithful to the base class's own behavior.
//!   The subclasses that override them are not yet ported; when they land they will need an
//!   explicit hook seam.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::seam_stubs::PcodeProgram;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};

/// The name of the address space of Java's `Address.NO_ADDRESS`.
///
/// `Address.NO_ADDRESS` is a `SpecialAddress("NO ADDRESS")`, i.e., an address in a nameless-typed
/// space of that name. Neither `SpecialAddress` nor the constant is ported, so
/// [`PcodeExecutor::check_injected_target`] recognizes the space by name and type instead of by
/// identity.
const NO_ADDRESS_SPACE_NAME: &str = "NO ADDRESS";

/// How the executor must handle an op, as determined by the class of `OpBehavior` that Java's
/// `OpBehaviorFactory` maps the opcode to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpBehaviorKind {
    /// Java maps the opcode to a `UnaryOpBehavior`.
    Unary,
    /// Java maps the opcode to a `BinaryOpBehavior`.
    Binary,
    /// Java maps the opcode to a `SpecialOpBehavior`: the executor itself implements it.
    Special,
    /// Java's factory has no entry for the opcode, i.e., `getOpBehavior` returns `null`.
    Undefined,
}

/// Classify an opcode the way `OpBehaviorFactory.getOpBehavior(int)` plus Java's
/// `switch (b) { case UnaryOpBehavior ... }` would.
pub fn op_behavior_kind(opcode: OpCode) -> OpBehaviorKind {
    use OpCode::*;
    match opcode {
        Copy | IntZext | IntSext | Int2Comp | IntNegate | BoolNegate | FloatNan | FloatNeg
        | FloatAbs | FloatSqrt | FloatInt2Float | FloatFloat2Float | FloatTrunc | FloatCeil
        | FloatFloor | FloatRound | Popcount | Lzcount => OpBehaviorKind::Unary,

        Piece | Subpiece | IntEqual | IntNotEqual | IntSless | IntSlessEqual | IntLess
        | IntLessEqual | IntAdd | IntSub | IntCarry | IntScarry | IntSborrow | IntXor | IntAnd
        | IntOr | IntLeft | IntRight | IntSright | IntMult | IntDiv | IntSdiv | IntRem | IntSrem
        | BoolXor | BoolAnd | BoolOr | FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual
        | FloatAdd | FloatDiv | FloatMult | FloatSub => OpBehaviorKind::Binary,

        Load | Store | Branch | CBranch | BranchInd | Call | CallInd | CallOther | Return
        | MultiEqual | Indirect | Cast | PtrAdd | PtrSub | SegmentOp | CpoolRef | New | Insert
        | Zpull | Spull => OpBehaviorKind::Special,

        // Java's factory has no entry for UNIMPLEMENTED, so `getOpBehavior` returns null.
        Unimplemented => OpBehaviorKind::Undefined,
    }
}

/// An executor of p-code programs.
///
/// `T` is the type of values processed by the executor.
pub struct PcodeExecutor<T: 'static> {
    language: Arc<dyn Language>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    /// Java hands the state back from `getState()` and lets callers both read and write it (a
    /// userop, for example, reads its inputs and writes its output through it). Writing needs
    /// `&mut`, which a `&PcodeExecutor` cannot produce, so the state is shared behind a `Mutex`:
    /// the executor and the userops it runs genuinely share mutable access to it.
    state: Arc<Mutex<dyn PcodeExecutorState<T>>>,
    reason: Reason,
    pc: Option<RegisterRef>,
    pc_size: i32,
}

impl<T: 'static> PcodeExecutor<T> {
    /// Construct an executor with the given bindings.
    ///
    /// `language` is the processor language, `arithmetic` an implementation of the arithmetic
    /// p-code ops, `state` an implementation of the load/store p-code ops, and `reason` the reason
    /// for reading the state with this executor.
    pub fn new(
        language: Arc<dyn Language>,
        arithmetic: Arc<dyn PcodeArithmetic<T>>,
        state: Arc<Mutex<dyn PcodeExecutorState<T>>>,
        reason: Reason,
    ) -> Self {
        let pc = language.get_program_counter();
        let pc_size = match &pc {
            Some(pc) => pc.borrow().num_bytes(),
            None => language.get_default_space().pointer_size(),
        };
        PcodeExecutor { language, arithmetic, state, reason, pc, pc_size }
    }

    /// Get the executor's language (processor model).
    pub fn get_language(&self) -> &Arc<dyn Language> {
        &self.language
    }

    /// Get the arithmetic applied by the executor.
    ///
    /// Returns an owned `Arc` rather than a borrow, matching
    /// [`PcodeExecutorStatePiece::get_arithmetic`].
    pub fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    /// Get the state bound to this executor.
    pub fn get_state(&self) -> &Mutex<dyn PcodeExecutorState<T>> {
        &self.state
    }

    /// Get the reason for reading state with this executor.
    pub fn get_reason(&self) -> Reason {
        self.reason
    }

    /// Get the program counter register, if the language declares one.
    ///
    /// Java's field is `protected final Register pc`, read by subclasses.
    pub fn get_program_counter(&self) -> Option<&RegisterRef> {
        self.pc.as_ref()
    }

    /// Get the size, in bytes, of the program counter.
    ///
    /// This is the program counter register's size, or, if the language declares no program
    /// counter, the default space's pointer size.
    pub fn get_pc_size(&self) -> i32 {
        self.pc_size
    }

    /// Compile and execute a block of Sleigh.
    ///
    /// # Panics
    ///
    /// Always: `SleighProgramCompiler` is not yet ported.
    pub fn execute_sleigh(&self, _source: &str) -> PcodeFrame {
        unimplemented!("PcodeExecutor::execute_sleigh needs SleighProgramCompiler, not yet ported")
    }

    /// Begin execution of the given program, e.g., from an injection or a decoded instruction.
    pub fn begin(&self, program: &dyn PcodeProgram) -> PcodeFrame {
        self.begin_code(program.code(), program.userop_names())
    }

    /// Execute a program using the given library.
    ///
    /// Port of `execute(PcodeProgram, PcodeUseropLibrary)`.
    pub fn execute(
        &self,
        program: &dyn PcodeProgram,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<PcodeFrame, PcodeExecutionException> {
        self.execute_code(program.code(), program.userop_names(), library)
    }

    /// Begin execution of a list of p-code ops.
    ///
    /// Port of `begin(List<PcodeOp>, Map<Integer, String>)`; Rust has no overloading, so this
    /// carries a distinct name from [`begin`](Self::begin).
    pub fn begin_code(&self, code: Vec<PcodeOp>, userop_names: HashMap<i32, String>) -> PcodeFrame {
        PcodeFrame::new(Arc::clone(&self.language), code, userop_names)
    }

    /// Execute a list of p-code ops with the given library.
    ///
    /// Port of `execute(List<PcodeOp>, Map<Integer, String>, PcodeUseropLibrary)`.
    ///
    /// On error, the frame is moved into the returned exception (as Java's `finish` does), so the
    /// caller can still recover what the executor was doing.
    pub fn execute_code(
        &self,
        code: Vec<PcodeOp>,
        userop_names: HashMap<i32, String>,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<PcodeFrame, PcodeExecutionException> {
        let mut frame = self.begin_code(code, userop_names);
        match self.finish(&mut frame, library) {
            Ok(()) => Ok(frame),
            Err(mut e) => {
                e.set_frame_if_absent(frame);
                Err(e)
            }
        }
    }

    /// Finish execution of a frame.
    ///
    /// Java catches the `PcodeExecutionException` here only to attach the frame to it; the frame
    /// stays with its (borrowing) owner in Rust, so nothing needs to be attached. See
    /// [`execute_code`](Self::execute_code), which owns the frame and does move it in.
    ///
    /// TODO (from Java): This is not really sufficient for continuation after a break, esp. if
    /// that break occurs within a nested call back into the executor.
    pub fn finish(
        &self,
        frame: &mut PcodeFrame,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), PcodeExecutionException> {
        while !frame.is_finished() {
            self.step(frame, library)?;
        }
        Ok(())
    }

    /// Handle an unrecognized or unimplemented p-code op.
    ///
    /// Java throws the error; here it is returned for the caller to propagate.
    fn bad_op(&self, op: &PcodeOp) -> LowlevelError {
        match op.opcode {
            OpCode::Unimplemented => LowlevelError::with_message(format!(
                "Encountered an unimplemented instruction at {}",
                op.seqnum.pc
            )),
            _ => LowlevelError::with_message(format!(
                "Unsupported p-code op at {}: {}",
                op.seqnum.pc, op
            )),
        }
    }

    /// Step one p-code op.
    ///
    /// `library` is invoked in case of [`OpCode::CallOther`].
    pub fn step_op(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        match op_behavior_kind(op.opcode) {
            OpBehaviorKind::Unary => {
                self.execute_unary_op(op);
                Ok(())
            }
            OpBehaviorKind::Binary => {
                self.execute_binary_op(op);
                Ok(())
            }
            OpBehaviorKind::Special => match op.opcode {
                OpCode::Load => {
                    self.execute_load(op);
                    Ok(())
                }
                OpCode::Store => {
                    self.execute_store(op);
                    Ok(())
                }
                OpCode::Branch => self.execute_branch(op, frame),
                OpCode::CBranch => self.execute_conditional_branch(op, frame),
                OpCode::BranchInd => self.execute_indirect_branch(op, frame),
                OpCode::Call => self.execute_call(op, frame, library),
                OpCode::CallInd => self.execute_indirect_call(op, frame),
                OpCode::CallOther => self.execute_callother(op, frame, library),
                OpCode::Return => self.execute_return(op, frame),
                _ => Err(self.bad_op(op)),
            },
            OpBehaviorKind::Undefined => Err(self.bad_op(op)),
        }
    }

    /// Step a single p-code op of the given frame.
    ///
    /// Anything escaping the op is wrapped in a [`PcodeExecutionException`], as in Java.
    pub fn step(
        &self,
        frame: &mut PcodeFrame,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), PcodeExecutionException> {
        // Java reads `frame.nextOp()` and hands the op straight to `stepOp`, which also takes the
        // frame; Rust cannot lend the frame twice when the second lend is mutable, so the op --
        // which the frame owns -- is copied out first.
        let op = frame.next_op().clone();
        self.step_op(&op, frame, library)
            .map_err(|e| PcodeExecutionException::with_cause(e.message().to_string(), e))
    }

    /// Skip a single p-code op.
    pub fn skip(&self, frame: &mut PcodeFrame) {
        frame.next_op();
    }

    /// Assert that a varnode is constant and get its value as an integer.
    ///
    /// Here "constant" means a literal or immediate value. It does not read from the state.
    fn get_int_const(&self, vn: &Varnode) -> i32 {
        debug_assert!(
            vn.get_address().space().space_type() == AddressSpaceType::Constant,
            "expected a constant varnode, got {vn:?}"
        );
        vn.get_address().offset() as i32
    }

    /// Execute the given unary op.
    pub fn execute_unary_op(&self, op: &PcodeOp) {
        let in1_var = &op.inputs[0];
        let out_var = op.output.as_ref().expect("unary op has no output");
        let in1 = self.state.lock().unwrap().get_var_varnode(in1_var, self.reason);
        let out = self.arithmetic.unary_op_from_pcode_op(op, &in1);
        self.state.lock().unwrap().set_var_varnode(out_var, &out);
    }

    /// Execute the given binary op.
    pub fn execute_binary_op(&self, op: &PcodeOp) {
        let in1_var = &op.inputs[0];
        let in2_var = &op.inputs[1];
        let out_var = op.output.as_ref().expect("binary op has no output");
        let (in1, in2) = {
            let state = self.state.lock().unwrap();
            (
                state.get_var_varnode(in1_var, self.reason),
                state.get_var_varnode(in2_var, self.reason),
            )
        };
        let out = self.arithmetic.binary_op_from_pcode_op(op, &in1, &in2);
        self.state.lock().unwrap().set_var_varnode(out_var, &out);
    }

    /// Extension point: logic preceding a load.
    fn before_load(&self, _op: &PcodeOp, _space: &Arc<AddressSpace>, _offset: &T, _size: i32) {}

    /// Extension point: logic proceeding a load.
    fn after_load(
        &self,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// Get the address space for a [`OpCode::Load`] or [`OpCode::Store`] op, derived from const
    /// input 0.
    fn get_load_store_space(&self, op: &PcodeOp) -> Arc<AddressSpace> {
        let space_id = self.get_int_const(&op.inputs[0]);
        self.language
            .get_address_factory()
            .get_address_space_by_id(space_id)
            .unwrap_or_else(|| panic!("No address space with id {space_id}"))
    }

    /// Get the offset varnode (input 1) for a [`OpCode::Load`] or [`OpCode::Store`] op.
    fn get_load_store_offset<'a>(&self, op: &'a PcodeOp) -> &'a Varnode {
        &op.inputs[1]
    }

    /// Execute a load.
    pub fn execute_load(&self, op: &PcodeOp) {
        let space = self.get_load_store_space(op);
        let in_offset = self.get_load_store_offset(op);
        let offset = self.state.lock().unwrap().get_var_varnode(in_offset, self.reason);
        let out_var = op.output.as_ref().expect("LOAD has no output");
        self.before_load(op, &space, &offset, out_var.get_size());

        let out = self.state.lock().unwrap().get_var_abstract(
            &space,
            &offset,
            out_var.get_size(),
            true,
            self.reason,
        );
        let modified = self.arithmetic.mod_after_load_from_pcode_op(op, &space, &offset, &out);
        self.state.lock().unwrap().set_var_varnode(out_var, &modified);
        self.after_load(op, &space, &offset, out_var.get_size(), &modified);
    }

    /// Extension point: logic preceding a store.
    fn before_store(
        &self,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// Extension point: logic proceeding a store.
    fn after_store(
        &self,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// Get the value varnode (input 2) for a [`OpCode::Store`] op.
    fn get_store_value<'a>(&self, op: &'a PcodeOp) -> &'a Varnode {
        &op.inputs[2]
    }

    /// Execute a store.
    pub fn execute_store(&self, op: &PcodeOp) {
        let space = self.get_load_store_space(op);
        let in_offset = self.get_load_store_offset(op);
        let val_var = self.get_store_value(op);
        let (offset, val) = {
            let state = self.state.lock().unwrap();
            (
                state.get_var_varnode(in_offset, self.reason),
                state.get_var_varnode(val_var, self.reason),
            )
        };
        let modified = self.arithmetic.mod_before_store_from_pcode_op(op, &space, &offset, &val);
        self.before_store(op, &space, &offset, val_var.get_size(), &modified);

        self.state.lock().unwrap().set_var_abstract(
            &space,
            &offset,
            val_var.get_size(),
            true,
            &modified,
        );
        self.after_store(op, &space, &offset, val_var.get_size(), &modified);
    }

    /// Extension point: called when execution branches to a target address.
    ///
    /// NOTE: This is *not* called for the fall-through case.
    fn branch_to_address(&self, _op: &PcodeOp, _target: &Address) {}

    /// Convert the given offset to the machine's type and delegate to
    /// [`branch_to_offset`](Self::branch_to_offset).
    ///
    /// Port of `branchToOffset(PcodeOp, long, PcodeFrame)`.
    fn branch_to_offset_long(&self, op: &PcodeOp, offset: i64, frame: &mut PcodeFrame) {
        let offset = self.arithmetic.from_const_u64(offset as u64, self.pc_size);
        self.branch_to_offset(op, &offset, frame);
    }

    /// Set the state's pc to the given offset and finish the frame.
    ///
    /// This implements only part of the p-code control flow semantics. An emulator must also hook
    /// [`branch_to_address`](Self::branch_to_address), so that it can update its internal program
    /// counter.
    ///
    /// # Panics
    ///
    /// If the language declares no program counter. Java dereferences the same null field.
    fn branch_to_offset(&self, _op: &PcodeOp, offset: &T, frame: &mut PcodeFrame) {
        let pc = self
            .pc
            .as_ref()
            .expect("cannot branch: the language declares no program counter");
        let out_size = pc.borrow().minimum_byte_size();
        let trunc_off = self.arithmetic.unary_op(
            OpCode::Copy,
            out_size,
            self.arithmetic.size_of(offset) as i32,
            offset,
        );
        self.state.lock().unwrap().set_var_register(pc, &trunc_off);
        frame.finish_as_branch();
    }

    /// Branch internally, by the given offset relative to the current op.
    fn branch_internal(
        &self,
        _op: &PcodeOp,
        frame: &mut PcodeFrame,
        relative: i32,
    ) -> Result<(), LowlevelError> {
        frame.branch(relative)
    }

    /// Get the target address (input 0's address) of a [`OpCode::Branch`], [`OpCode::CBranch`], or
    /// [`OpCode::Call`] op.
    fn get_branch_target(&self, op: &PcodeOp) -> Address {
        op.inputs[0].get_address().clone()
    }

    /// Perform the actual logic of a branch p-code op.
    ///
    /// This is a separate method, so that instrumenting [`execute_branch`](Self::execute_branch)
    /// does not implicitly modify
    /// [`execute_conditional_branch`](Self::execute_conditional_branch).
    fn do_execute_branch(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        let target = self.get_branch_target(op);
        if target.is_constant_address() {
            self.branch_internal(op, frame, target.offset() as i32)
        } else {
            self.branch_to_offset_long(op, target.offset(), frame);
            self.branch_to_address(op, &self.check_injected_target(&target));
            Ok(())
        }
    }

    /// Execute a branch.
    pub fn execute_branch(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.do_execute_branch(op, frame)
    }

    /// Get the predicate varnode (input 1) of a [`OpCode::CBranch`] op.
    fn get_conditional_branch_predicate<'a>(&self, op: &'a PcodeOp) -> &'a Varnode {
        &op.inputs[1]
    }

    /// Execute a conditional branch.
    pub fn execute_conditional_branch(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        let cond_var = self.get_conditional_branch_predicate(op);
        let cond = self.state.lock().unwrap().get_var_varnode(cond_var, self.reason);
        let taken = self
            .arithmetic
            .is_true(&cond, Purpose::Condition)
            .map_err(|e| LowlevelError::with_cause(e.message().to_string(), e))?;
        if taken {
            return self.do_execute_branch(op, frame);
        }
        Ok(())
    }

    /// Get the target varnode (input 0) of a [`OpCode::BranchInd`], [`OpCode::CallInd`], or
    /// [`OpCode::Return`] op.
    fn get_indirect_branch_target<'a>(&self, op: &'a PcodeOp) -> &'a Varnode {
        &op.inputs[0]
    }

    /// Check and correct the given target address, if it resides in "NO ADDRESS" space.
    ///
    /// The p-code compiler sets the target address of any branch to be in the same space, which
    /// for injects winds up in "NO ADDRESS". Target addresses are not expected anywhere but the
    /// default space, so if one lands in "NO ADDRESS", assume it was an inject whose intended
    /// target was the default space.
    fn check_injected_target(&self, target: &Address) -> Address {
        let space = target.space();
        let is_no_address =
            space.space_type() == AddressSpaceType::None && space.name() == NO_ADDRESS_SPACE_NAME;
        if !is_no_address {
            return target.clone();
        }
        self.language.get_default_space().address(target.offset())
    }

    /// Perform the actual logic of an indirect branch p-code op.
    ///
    /// This is a separate method, so that instrumenting
    /// [`execute_indirect_branch`](Self::execute_indirect_branch) does not implicitly modify
    /// [`execute_indirect_call`](Self::execute_indirect_call) and
    /// [`execute_return`](Self::execute_return).
    fn do_execute_indirect_branch(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        let offset = self
            .state
            .lock()
            .unwrap()
            .get_var_varnode(self.get_indirect_branch_target(op), self.reason);
        self.branch_to_offset(op, &offset, frame);

        let concrete = self
            .arithmetic
            .to_long(&offset, Purpose::Branch)
            .map_err(|e| LowlevelError::with_cause(e.message().to_string(), e))?;
        // Java: `op.getSeqnum().getTarget().getNewAddress(concrete, true)`, i.e., the offset is an
        // addressable word offset in the op's own space.
        let target = op
            .seqnum
            .pc
            .space()
            .address_from_word_offset(concrete)
            .map_err(|e| LowlevelError::with_message(e.to_string()))?;
        self.branch_to_address(op, &self.check_injected_target(&target));
        Ok(())
    }

    /// Execute an indirect branch.
    pub fn execute_indirect_branch(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.do_execute_indirect_branch(op, frame)
    }

    /// Execute a call.
    pub fn execute_call(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
        _library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        let target = self.get_branch_target(op);
        self.branch_to_offset_long(op, target.offset(), frame);
        self.branch_to_address(op, &self.check_injected_target(&target));
        Ok(())
    }

    /// Execute an indirect call.
    pub fn execute_indirect_call(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.do_execute_indirect_branch(op, frame)
    }

    /// Get the name of the userop with the given number, or `None` if it is not defined.
    ///
    /// Java reads the language's declared userop names via
    /// `SleighLanguage.getNumberOfUserDefinedOpNames()`/`getUserDefinedOpName(int)`; those same
    /// accessors are on [`Language`] here.
    pub fn get_userop_name(&self, op_no: i32, frame: &PcodeFrame) -> Option<String> {
        if op_no < self.language.get_number_of_user_defined_op_names() {
            return self.language.get_user_defined_op_name(op_no);
        }
        frame.get_userop_name(op_no).map(str::to_string)
    }

    /// Get the userop number (const input 0) of a [`OpCode::CallOther`] op.
    fn get_callother_op_number(&self, op: &PcodeOp) -> i32 {
        self.get_int_const(&op.inputs[0])
    }

    /// Execute a userop call.
    pub fn execute_callother(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        let op_no = self.get_callother_op_number(op);
        let Some(op_name) = self.get_userop_name(op_no, frame) else {
            // Java throws an AssertionError here.
            return Err(LowlevelError::with_message(format!(
                "Pcode userop {op_no} is not defined"
            )));
        };
        let op_def = library.get_userops().get(&op_name).cloned();
        if let Some(op_def) = op_def {
            op_def.execute_raw(self, library, op);
            return Ok(());
        }
        self.on_missing_userop_def(op, frame, &op_name, library)
    }

    /// Extension point: behavior when a userop definition was not found in the library.
    ///
    /// The default behavior is Java's `SleighLinkException`, which is not ported; the message is
    /// carried by a [`LowlevelError`], which [`step`](Self::step) wraps in a
    /// [`PcodeExecutionException`] exactly as it would the Java exception.
    fn on_missing_userop_def(
        &self,
        _op: &PcodeOp,
        _frame: &PcodeFrame,
        op_name: &str,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        // Java interpolates the library itself; `type_name_of_val` stands in for its `toString`,
        // as it does in `PcodeUseropLibrary::get_symbols`.
        Err(LowlevelError::with_message(format!(
            "Sleigh userop '{}' is not in the library {}",
            op_name,
            std::any::type_name_of_val(library)
        )))
    }

    /// Execute a return.
    pub fn execute_return(
        &self,
        op: &PcodeOp,
        frame: &mut PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.do_execute_indirect_branch(op, frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece,
    };
    use crate::pcode::exec::pcode_userop_library::{
        nil, ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
    };
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::{
        AddressFactory, AddressSet, AddressSetView, DefaultAddressFactory,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::pcode::SequenceNumber;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;

    struct Spaces {
        ram: Arc<AddressSpace>,
        constant: Arc<AddressSpace>,
        register: Arc<AddressSpace>,
    }

    fn spaces() -> Spaces {
        Spaces {
            ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            constant: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1),
            register: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2),
        }
    }

    /// A language just complete enough for the executor: an address factory, a default space, a
    /// program counter, and one language-declared userop name.
    struct MockLanguage {
        factory: DefaultAddressFactory,
        pc: Option<RegisterRef>,
    }

    impl MockLanguage {
        fn new(spaces: &Spaces, with_pc: bool) -> Self {
            let pc = with_pc.then(|| {
                Register::new(
                    "pc",
                    "program counter",
                    Address::new(spaces.register.clone(), 0),
                    4,
                    false,
                    0,
                )
            });
            MockLanguage {
                factory: DefaultAddressFactory::new(vec![
                    spaces.ram.clone(),
                    spaces.constant.clone(),
                    spaces.register.clone(),
                ]),
                pc,
            }
        }
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.factory.get_default_address_space().unwrap()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.get_default_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            1
        }
        fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
            // Only op 0 is known to the language; the frame supplies the rest.
            if index == 0 {
                Some("lang_op".to_string())
            } else {
                None
            }
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            self.pc.clone()
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// Little-endian `i64` arithmetic that really evaluates the handful of ops these tests use.
    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            let masked = |v: i64| {
                if sizeout >= 8 {
                    v
                } else {
                    v & ((1i64 << (sizeout * 8)) - 1)
                }
            };
            match opcode {
                OpCode::Copy | OpCode::IntZext => masked(*in1),
                OpCode::Int2Comp => masked(-*in1),
                other => unimplemented!("unary {other:?} not exercised by these tests"),
            }
        }
        fn binary_op(
            &self,
            opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            in2: &i64,
        ) -> i64 {
            match opcode {
                OpCode::IntAdd => in1.wrapping_add(*in2),
                OpCode::IntSub => in1.wrapping_sub(*in2),
                other => unimplemented!("binary {other:?} not exercised by these tests"),
            }
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A state backed by an in-memory map keyed by (space name, offset).
    #[derive(Default)]
    struct MapState {
        cells: HashMap<(String, i64), i64>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            val: &i64,
        ) {
            self.cells.insert((space.name().to_string(), *offset), *val);
        }
        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            val: &i64,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            if space.space_type() == AddressSpaceType::Constant {
                return *offset;
            }
            *self.cells.get(&(space.name().to_string(), *offset)).unwrap_or(&0)
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            reason: Reason,
        ) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    fn executor_with(spaces: &Spaces, with_pc: bool) -> PcodeExecutor<i64> {
        PcodeExecutor::new(
            Arc::new(MockLanguage::new(spaces, with_pc)),
            Arc::new(I64Arithmetic),
            Arc::new(Mutex::new(MapState::default())),
            Reason::ExecuteRead,
        )
    }

    fn executor(spaces: &Spaces) -> PcodeExecutor<i64> {
        executor_with(spaces, true)
    }

    fn ram(s: &Spaces, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(s.ram.clone(), offset), size)
    }

    fn constant(s: &Spaces, value: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(s.constant.clone(), value), size)
    }

    fn op(s: &Spaces, opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        PcodeOp::new(
            opcode,
            SequenceNumber::new(Address::new(s.ram.clone(), 0x1000), 0),
            inputs,
            output,
        )
    }

    fn poke(exec: &PcodeExecutor<i64>, var: &Varnode, value: i64) {
        exec.get_state().lock().unwrap().set_var_varnode(var, &value);
    }

    fn peek(exec: &PcodeExecutor<i64>, var: &Varnode) -> i64 {
        exec.get_state().lock().unwrap().get_var_varnode(var, Reason::Inspect)
    }

    /// `Result::expect_err` wants the `Ok` type to be `Debug`, and [`PcodeFrame`] is not.
    fn expect_err(
        result: Result<PcodeFrame, PcodeExecutionException>,
        what: &str,
    ) -> PcodeExecutionException {
        match result {
            Ok(_) => panic!("expected an error: {what}"),
            Err(e) => e,
        }
    }

    #[test]
    fn pc_size_comes_from_the_program_counter_or_the_default_space() {
        let s = spaces();

        // Java: `pcSize = pc != null ? pc.getNumBytes() : ...`. The mock's pc is 4 bytes.
        let exec = executor_with(&s, true);
        assert_eq!(exec.get_pc_size(), 4);
        assert_eq!(exec.get_program_counter().unwrap().borrow().name(), "pc");

        // Java: `... : language.getDefaultSpace().getPointerSize()`. "ram" is 32 bits => 4 bytes.
        let exec = executor_with(&s, false);
        assert!(exec.get_program_counter().is_none());
        assert_eq!(exec.get_pc_size(), s.ram.pointer_size());
    }

    #[test]
    fn accessors_return_the_constructor_bindings() {
        let s = spaces();
        let exec = executor(&s);

        assert_eq!(exec.get_reason(), Reason::ExecuteRead);
        assert_eq!(exec.get_arithmetic().get_endian(), Some(Endian::Little));
        assert_eq!(exec.get_language().get_default_space().name(), "ram");
    }

    #[test]
    fn unary_and_binary_ops_read_inputs_and_write_the_output() {
        let s = spaces();
        let exec = executor(&s);
        poke(&exec, &ram(&s, 0x10, 4), 7);
        poke(&exec, &ram(&s, 0x14, 4), 5);

        // out = COPY in1
        let frame = exec
            .execute_code(
                vec![op(&s, OpCode::Copy, vec![ram(&s, 0x10, 4)], Some(ram(&s, 0x20, 4)))],
                HashMap::new(),
                &nil(),
            )
            .expect("copy executes");
        assert!(frame.is_fall_through());
        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 7);

        // out = INT_ADD in1, in2
        exec.execute_code(
            vec![op(
                &s,
                OpCode::IntAdd,
                vec![ram(&s, 0x10, 4), ram(&s, 0x14, 4)],
                Some(ram(&s, 0x24, 4)),
            )],
            HashMap::new(),
            &nil(),
        )
        .expect("add executes");
        assert_eq!(peek(&exec, &ram(&s, 0x24, 4)), 12);
    }

    #[test]
    fn load_and_store_use_the_space_named_by_const_input_0() {
        let s = spaces();
        let exec = executor(&s);
        // The value to load lives at ram:0x40; the offset varnode holds that address.
        poke(&exec, &ram(&s, 0x40, 4), 0xbeef);
        poke(&exec, &ram(&s, 0x10, 4), 0x40);

        let space_id = constant(&s, s.ram.space_id() as i64, 4);
        exec.execute_code(
            vec![op(
                &s,
                OpCode::Load,
                vec![space_id.clone(), ram(&s, 0x10, 4)],
                Some(ram(&s, 0x20, 4)),
            )],
            HashMap::new(),
            &nil(),
        )
        .expect("load executes");
        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 0xbeef);

        // STORE space, offset, value -- writes ram:0x50 = 0x1234
        poke(&exec, &ram(&s, 0x18, 4), 0x50);
        poke(&exec, &ram(&s, 0x1c, 4), 0x1234);
        exec.execute_code(
            vec![op(
                &s,
                OpCode::Store,
                vec![space_id, ram(&s, 0x18, 4), ram(&s, 0x1c, 4)],
                None,
            )],
            HashMap::new(),
            &nil(),
        )
        .expect("store executes");
        assert_eq!(peek(&exec, &ram(&s, 0x50, 4)), 0x1234);
    }

    #[test]
    fn branch_to_a_constant_target_is_an_internal_branch() {
        let s = spaces();
        let exec = executor(&s);
        let code = vec![
            // 0: BRANCH const:2 -- skips op 1
            op(&s, OpCode::Branch, vec![constant(&s, 2, 4)], None),
            // 1: would set ram:0x20, but is skipped
            op(&s, OpCode::Copy, vec![ram(&s, 0x10, 4)], Some(ram(&s, 0x20, 4))),
            // 2: out = COPY in1
            op(&s, OpCode::Copy, vec![ram(&s, 0x14, 4)], Some(ram(&s, 0x24, 4))),
        ];
        poke(&exec, &ram(&s, 0x10, 4), 1);
        poke(&exec, &ram(&s, 0x14, 4), 2);

        let frame = exec.execute_code(code, HashMap::new(), &nil()).expect("branch executes");

        // An internal branch is *not* an external branch: the frame falls through the end.
        assert!(frame.is_fall_through());
        assert!(!frame.is_branch());
        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 0, "op 1 was skipped");
        assert_eq!(peek(&exec, &ram(&s, 0x24, 4)), 2);
        // The pc is untouched by an internal branch.
        assert_eq!(peek(&exec, &Varnode::new(Address::new(s.register.clone(), 0), 4)), 0);
    }

    #[test]
    fn branch_to_an_address_sets_the_pc_and_finishes_the_frame() {
        let s = spaces();
        let exec = executor(&s);
        let code = vec![
            op(&s, OpCode::Branch, vec![ram(&s, 0xdead, 1)], None),
            op(&s, OpCode::Copy, vec![ram(&s, 0x10, 4)], Some(ram(&s, 0x20, 4))),
        ];
        poke(&exec, &ram(&s, 0x10, 4), 9);

        let frame = exec.execute_code(code, HashMap::new(), &nil()).expect("branch executes");

        assert!(frame.is_branch());
        assert_eq!(frame.branched(), 0);
        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 0, "the frame ended before op 1");
        // branchToOffset truncates to the pc's size and writes it through the state.
        assert_eq!(peek(&exec, &Varnode::new(Address::new(s.register.clone(), 0), 4)), 0xdead);
    }

    #[test]
    fn conditional_branch_is_taken_only_when_the_predicate_is_true() {
        let s = spaces();
        let pc = Varnode::new(Address::new(s.register.clone(), 0), 4);
        let cbranch =
            |s: &Spaces| op(s, OpCode::CBranch, vec![ram(s, 0xbeef, 1), ram(s, 0x30, 1)], None);

        // Predicate false: falls through.
        let exec = executor(&s);
        poke(&exec, &ram(&s, 0x30, 1), 0);
        let frame = exec
            .execute_code(vec![cbranch(&s)], HashMap::new(), &nil())
            .expect("cbranch executes");
        assert!(frame.is_fall_through());
        assert_eq!(peek(&exec, &pc), 0);

        // Predicate true: branches.
        let exec = executor(&s);
        poke(&exec, &ram(&s, 0x30, 1), 1);
        let frame = exec
            .execute_code(vec![cbranch(&s)], HashMap::new(), &nil())
            .expect("cbranch executes");
        assert!(frame.is_branch());
        assert_eq!(peek(&exec, &pc), 0xbeef);
    }

    #[test]
    fn indirect_branch_reads_its_target_from_the_state() {
        let s = spaces();
        let exec = executor(&s);
        poke(&exec, &ram(&s, 0x10, 4), 0x2000);

        let frame = exec
            .execute_code(
                vec![op(&s, OpCode::BranchInd, vec![ram(&s, 0x10, 4)], None)],
                HashMap::new(),
                &nil(),
            )
            .expect("branchind executes");

        assert!(frame.is_branch());
        assert_eq!(peek(&exec, &Varnode::new(Address::new(s.register.clone(), 0), 4)), 0x2000);
    }

    #[test]
    fn unimplemented_and_unsupported_ops_are_bad_ops() {
        let s = spaces();
        let exec = executor(&s);

        let err = expect_err(
            exec.execute_code(vec![op(&s, OpCode::Unimplemented, vec![], None)], HashMap::new(), &nil()),
            "UNIMPLEMENTED is not in OpBehaviorFactory's map",
        );
        assert_eq!(err.message(), "Encountered an unimplemented instruction at ram:0x1000");

        // MULTIEQUAL maps to a SpecialOpBehavior the executor does not implement.
        let err = expect_err(
            exec.execute_code(
                vec![op(&s, OpCode::MultiEqual, vec![ram(&s, 0x10, 4)], Some(ram(&s, 0x20, 4)))],
                HashMap::new(),
                &nil(),
            ),
            "MULTIEQUAL is unsupported",
        );
        assert!(
            err.message().starts_with("Unsupported p-code op at ram:0x1000: "),
            "unexpected message: {}",
            err.message()
        );
        // Java's `finish` attaches the frame to the exception; so does `execute_code`.
        assert!(err.frame().is_some());
    }

    #[test]
    fn userop_names_come_from_the_language_then_the_frame() {
        let s = spaces();
        let exec = executor(&s);
        let frame = exec.begin_code(vec![], HashMap::from([(1, "frame_op".to_string())]));

        // Op 0 is declared by the language (which declares exactly one).
        assert_eq!(exec.get_userop_name(0, &frame).as_deref(), Some("lang_op"));
        // Op 1 is beyond the language's count, so the frame's map answers.
        assert_eq!(exec.get_userop_name(1, &frame).as_deref(), Some("frame_op"));
        assert_eq!(exec.get_userop_name(2, &frame), None);
    }

    /// A userop that records that it ran and writes a fixed value to its output varnode.
    struct MarkerUserop;

    impl PcodeUseropDefinition<i64> for MarkerUserop {
        fn get_name(&self) -> &str {
            "frame_op"
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            executor: &PcodeExecutor<i64>,
            _library: &dyn PcodeUseropLibrary<i64>,
            _op: &PcodeOp,
            out_var: Option<&Varnode>,
            _in_vars: &[Varnode],
        ) {
            let out_var = out_var.expect("invoked as an rval");
            executor.get_state().lock().unwrap().set_var_varnode(out_var, &0x99);
        }
        fn is_functional(&self) -> bool {
            true
        }
        fn has_side_effects(&self) -> bool {
            false
        }
        fn modifies_context(&self) -> bool {
            false
        }
        fn can_inline_pcode(&self) -> bool {
            false
        }
        fn get_output_type(&self) -> Option<std::any::TypeId> {
            None
        }
        fn get_java_method(&self) -> Option<()> {
            None
        }
        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    struct MarkerLibrary {
        userops: UseropMap<i64>,
    }

    impl MarkerLibrary {
        fn new() -> Self {
            let mut userops: UseropMap<i64> = HashMap::new();
            userops.insert("frame_op".to_string(), Arc::new(MarkerUserop));
            Self { userops }
        }
    }

    impl ErasedPcodeUseropLibrary for MarkerLibrary {}

    impl PcodeUseropLibrary<i64> for MarkerLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            &self.userops
        }
    }

    #[test]
    fn callother_dispatches_to_the_library_by_name() {
        let s = spaces();
        let exec = executor(&s);
        let library = MarkerLibrary::new();

        exec.execute_code(
            vec![op(&s, OpCode::CallOther, vec![constant(&s, 1, 4)], Some(ram(&s, 0x20, 4)))],
            HashMap::from([(1, "frame_op".to_string())]),
            &library,
        )
        .expect("callother executes");

        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 0x99);
    }

    #[test]
    fn callother_without_a_definition_is_a_link_error() {
        let s = spaces();
        let exec = executor(&s);

        let err = expect_err(
            exec.execute_code(
                vec![op(&s, OpCode::CallOther, vec![constant(&s, 1, 4)], None)],
                HashMap::from([(1, "frame_op".to_string())]),
                &nil::<i64>(),
            ),
            "the empty library defines no userop",
        );
        assert!(
            err.message().starts_with("Sleigh userop 'frame_op' is not in the library "),
            "unexpected message: {}",
            err.message()
        );

        // An entirely unnamed userop number is a different error.
        let err = expect_err(
            exec.execute_code(
                vec![op(&s, OpCode::CallOther, vec![constant(&s, 7, 4)], None)],
                HashMap::new(),
                &nil::<i64>(),
            ),
            "userop 7 has no name at all",
        );
        assert_eq!(err.message(), "Pcode userop 7 is not defined");
    }

    #[test]
    fn skip_advances_the_frame_without_executing() {
        let s = spaces();
        let exec = executor(&s);
        poke(&exec, &ram(&s, 0x10, 4), 3);
        let mut frame = exec.begin_code(
            vec![op(&s, OpCode::Copy, vec![ram(&s, 0x10, 4)], Some(ram(&s, 0x20, 4)))],
            HashMap::new(),
        );

        exec.skip(&mut frame);

        assert!(frame.is_finished());
        assert_eq!(peek(&exec, &ram(&s, 0x20, 4)), 0, "the op was skipped, not executed");
    }

    #[test]
    fn op_behavior_kind_matches_the_java_factory_table() {
        // Spot checks against OpBehaviorFactory's map: a unary, a binary, two specials, and the
        // one opcode it has no entry for.
        assert_eq!(op_behavior_kind(OpCode::Copy), OpBehaviorKind::Unary);
        assert_eq!(op_behavior_kind(OpCode::Popcount), OpBehaviorKind::Unary);
        assert_eq!(op_behavior_kind(OpCode::Subpiece), OpBehaviorKind::Binary);
        assert_eq!(op_behavior_kind(OpCode::BoolAnd), OpBehaviorKind::Binary);
        assert_eq!(op_behavior_kind(OpCode::Load), OpBehaviorKind::Special);
        assert_eq!(op_behavior_kind(OpCode::PtrAdd), OpBehaviorKind::Special);
        assert_eq!(op_behavior_kind(OpCode::Unimplemented), OpBehaviorKind::Undefined);
    }
}
