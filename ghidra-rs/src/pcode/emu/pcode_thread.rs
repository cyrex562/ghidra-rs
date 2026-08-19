//! An emulated thread of execution.
//!
//! Corresponds to `ghidra.pcode.emu.PcodeThread`.

use std::sync::{Arc, MutexGuard};

use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::seam_stubs::RegisterValue;
use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Instruction;

/// A thread whose value type has been erased: the Rust rendering of Java's wildcard
/// `PcodeThread<?>`.
///
/// This mirrors
/// [`ErasedPcodeMachine`](crate::pcode::emu::pcode_machine::ErasedPcodeMachine): a bare,
/// object-safe marker that every thread also implements, and a supertrait of [`PcodeThread`], so a
/// generic `impl PcodeThread<T>` satisfies it without an explicit conversion.
///
/// It stands in at two kinds of call site:
///
/// * Java's *generic method* parameters over an unknown `T`, e.g.
///   `PcodeStateInitializer.initializeThread(PcodeThread<T>)`. Making those methods generic in Rust
///   would cost their enclosing traits object safety, which an extension point cannot afford.
/// * Java parameterizations that the Rust port cannot yet spell or does not need, e.g.
///   `AuxEmulatorPartsFactory`'s `PcodeThread<Pair<byte[], U>>`, and the machine-side thread
///   handles (`PcodeMachine::new_thread` and friends) whose concrete implementations
///   (`BytesPcodeThread`, `DefaultPcodeThread`) are not ported yet. Those signatures can be
///   tightened to `dyn PcodeThread<T>` once a real thread implementation exists to satisfy them.
///
/// Unlike the placeholder it replaces, this is not bound `Send + Sync`: a thread owns its current
/// [`PcodeFrame`], which holds an `Arc<dyn Language>` and is therefore neither, so no faithful
/// implementation could satisfy such a bound. Java's threads are not safe to share across host
/// threads either -- `run()` is documented as "donating the current Java thread" to one emulated
/// thread.
pub trait ErasedPcodeThread {}

/// An emulated thread of execution.
///
/// `T` is the type of values in the emulated machine state.
pub trait PcodeThread<T: 'static>: ErasedPcodeThread {
    /// The concrete type of this thread's shared (memory) state delegate.
    ///
    /// [`ThreadPcodeExecutorState`] takes its shared and local delegates as generic parameters
    /// rather than trait objects (see its module docs), so a thread implementation must name its
    /// delegates' concrete types here.
    type SharedState: PcodeExecutorState<T>;

    /// The concrete type of this thread's thread-local (register/unique) state delegate.
    type LocalState: PcodeExecutorState<T>;

    /// Get the name of this thread.
    fn get_name(&self) -> &str;

    /// Get the machine within which this thread executes.
    fn get_machine(&self) -> &dyn PcodeMachine<T>;

    /// Set the thread's program counter without writing to its executor state.
    ///
    /// See [`override_counter`](Self::override_counter).
    fn set_counter(&mut self, counter: &Address);

    /// Get the value of the program counter of this thread.
    fn get_counter(&self) -> Address;

    /// Set the thread's program counter and write the pc register of its executor state.
    ///
    /// **Warning:** Setting the counter into the middle of group constructs, e.g., parallel
    /// instructions or delay-slotted instructions, may cause undefined behavior.
    ///
    /// See [`set_counter`](Self::set_counter).
    fn override_counter(&mut self, counter: &Address);

    /// Adjust the thread's decoding context without writing to its executor state.
    ///
    /// As in Java's `RegisterValue.assign(Register, RegisterValue)`, only those bits having a
    /// value in the given context are applied to the current context.
    ///
    /// See [`override_context`](Self::override_context).
    fn assign_context(&mut self, context: &dyn RegisterValue);

    /// Get the thread's decoding context.
    ///
    /// `None` where Java returns `null`, i.e. for a language with no context register.
    /// `RegisterValue` is not clonable here (it is still a bare seam stub), so this hands back a
    /// borrow rather than the owned value Java's reference amounts to.
    fn get_context(&self) -> Option<&dyn RegisterValue>;

    /// Adjust the thread's decoding context and write the contextreg of its executor state.
    ///
    /// See [`assign_context`](Self::assign_context).
    fn override_context(&mut self, context: &dyn RegisterValue);

    /// Set the context at the current counter to the default given by the language.
    ///
    /// This also writes the context to the thread's state. For languages without context, this
    /// call does nothing.
    fn override_context_with_default(&mut self);

    /// Re-sync the decode context and counter address from the machine state.
    fn re_initialize(&mut self);

    /// Step emulation a single instruction.
    ///
    /// Note because of the way Ghidra and Sleigh handle delay slots, the execution of an
    /// instruction with delay slots cannot be separated from the instructions filling those slots.
    /// It and its slotted instructions are executed in a single "step." However, stepping the
    /// individual p-code ops is still possible using [`step_pcode_op`](Self::step_pcode_op).
    fn step_instruction(&mut self);

    /// Repeat [`step_instruction`](Self::step_instruction) `count` times.
    ///
    /// Java overloads `stepInstruction(long)`; Rust traits cannot overload on arity, so the
    /// counted form gets a distinct name.
    fn step_instruction_count(&mut self, count: i64) {
        for _ in 0..count {
            self.step_instruction();
        }
    }

    /// Step emulation a single p-code operation.
    ///
    /// Execution of the current instruction begins if there is no current frame: a new frame is
    /// constructed and its counter is initialized. If a frame is present, and it has not been
    /// completed, its next operation is executed and its counter is stepped. If the current frame
    /// is completed, the machine's program counter is advanced and the current frame is removed.
    ///
    /// Consider the case of a fall-through instruction: the first p-code step decodes the
    /// instruction and sets up the p-code frame. The second p-code step executes the first p-code
    /// op of the frame. Each subsequent p-code step executes the next p-code op until no ops
    /// remain. The final p-code step detects the fall-through result, advances the counter, and
    /// disposes the frame. The next p-code step is actually the first p-code step of the next
    /// instruction.
    ///
    /// Consider the case of a branching instruction: the first p-code step decodes the instruction
    /// and sets up the p-code frame. The second p-code step executes the first p-code op of the
    /// frame. Each subsequent p-code step executes the next p-code op until an (external) branch
    /// is executed. That branch itself sets the program counter appropriately. The final p-code
    /// step detects the branch result and simply disposes the frame.
    ///
    /// The decode step in both examples is subject to p-code injections. In order to provide the
    /// most flexibility, there is no enforcement of various emulation state on this method. Expect
    /// strange behavior for strange call sequences.
    ///
    /// While this method heeds injects, such injects will obscure the p-code of the instruction
    /// itself. If the inject executes the instruction, the entire instruction will be executed
    /// when stepping the `PcodeEmulationLibrary.emu_exec_decoded()` userop, since there is not
    /// (currently) any way to "step into" a userop.
    fn step_pcode_op(&mut self);

    /// Repeat [`step_pcode_op`](Self::step_pcode_op) `count` times.
    ///
    /// Java overloads `stepPcodeOp(long)`; see [`step_instruction_count`](Self::step_instruction_count).
    fn step_pcode_op_count(&mut self, count: i64) {
        for _ in 0..count {
            self.step_pcode_op();
        }
    }

    /// Skip emulation of a single p-code operation.
    ///
    /// If there is no current frame, this behaves as in [`step_pcode_op`](Self::step_pcode_op).
    /// Otherwise, this skips the current p-code op, advancing as if a fall-through op. If no ops
    /// remain in the frame, this behaves as in [`step_pcode_op`](Self::step_pcode_op). Note that
    /// to skip an external branch, the op itself must be skipped: "skipping" the following op,
    /// which disposes the frame, cannot prevent the branch.
    fn skip_pcode_op(&mut self);

    /// Apply a patch to the emulator.
    ///
    /// `sleigh` is a line of Sleigh semantic source to execute (excluding the final semicolon).
    fn step_patch(&mut self, sleigh: &str);

    /// Get the current frame, if present.
    ///
    /// If the client only calls [`step_instruction`](Self::step_instruction) and execution
    /// completes normally, this method will always return `None` (Java's `null`). If interrupted,
    /// the frame marks where execution of an instruction or inject should resume. Depending on the
    /// case, the frame may need to be stepped back in order to retry the failed p-code operation.
    /// If a frame is present, it means the instruction has not completed execution, even if the
    /// frame reports [`PcodeFrame::is_finished`].
    fn get_frame(&self) -> Option<&PcodeFrame>;

    /// Get the current decoded instruction, if applicable.
    fn get_instruction(&self) -> Option<Arc<dyn Instruction>>;

    /// Execute the next instruction, ignoring injects.
    ///
    /// **WARNING:** This method should likely only be used internally. It steps the current
    /// instruction, but without any consideration for user injects, e.g., breakpoints. Most
    /// clients should call [`step_instruction`](Self::step_instruction) instead.
    ///
    /// Java throws `IllegalStateException` if the emulator is still in the middle of an
    /// instruction; implementations here panic. That can happen if the machine is interrupted, or
    /// if the client has called [`step_pcode_op`](Self::step_pcode_op).
    fn execute_instruction(&mut self);

    /// Finish execution of the current instruction or inject.
    ///
    /// In general, this method is only used after an interrupt or fault in order to complete the
    /// p-code of the faulting instruction. Depending on the nature of the interrupt, this behavior
    /// may not be desired.
    ///
    /// Java throws `IllegalStateException` if there is no current instruction, i.e., the emulator
    /// has not started executing the next instruction yet; implementations here panic.
    fn finish_instruction(&mut self);

    /// Decode, but skip the next instruction.
    fn skip_instruction(&mut self);

    /// If there is a current instruction, drop its frame of execution.
    ///
    /// **WARNING:** This does not revert any state changes caused by a partially-executed
    /// instruction. It is up to the client to revert the underlying machine state if desired. Note
    /// the thread's program counter will not be advanced. Likely, the next call to
    /// [`step_instruction`](Self::step_instruction) will re-start the same instruction. If there
    /// is no current instruction, this method has no effect.
    fn drop_instruction(&mut self);

    /// Emulate indefinitely.
    ///
    /// This begins or resumes execution of the emulator. If there is a current instruction, that
    /// instruction is finished. This method will not likely return, but instead only terminates
    /// via a panic, e.g., hitting a user breakpoint or becoming suspended (Java terminates via
    /// exception). Depending on the use case, this method might be invoked from a thread dedicated
    /// to this emulated thread.
    fn run(&mut self);

    /// Set the suspension state of the thread's executor.
    ///
    /// When [`run`](Self::run) is invoked by a dedicated thread, suspending the p-code thread is
    /// the most reliable way to halt execution. Note the emulator may halt mid instruction. If
    /// this is not desired, then upon catching the interruption, un-suspend the p-code thread and
    /// call [`finish_instruction`](Self::finish_instruction) or
    /// [`drop_instruction`](Self::drop_instruction).
    ///
    /// See [`PcodeMachine::set_suspended`].
    fn set_suspended(&mut self, suspended: bool);

    /// Check the suspension state of the thread's executor.
    fn is_suspended(&self) -> bool;

    /// Get the thread's Sleigh language (processor model).
    fn get_language(&self) -> &SleighLanguage;

    /// Get the thread's p-code arithmetic.
    ///
    /// Returns an owned handle rather than a borrow, matching
    /// [`PcodeMachine::get_arithmetic`]: the arithmetic outlives any single borrow of the thread.
    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>>;

    /// Get the thread's p-code executor.
    ///
    /// This can be used to execute injected p-code, e.g., as part of implementing a userop, or as
    /// part of testing, outside the thread's usual control flow. Any new frame generated by the
    /// executor is ignored by the thread. It retains the instruction frame, if any. Note that
    /// suspension is implemented by the executor, so if this p-code thread is suspended, the
    /// executor cannot execute any code.
    fn get_executor(&self) -> &PcodeExecutor<T>;

    /// Get the complete userop library for this thread.
    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T>;

    /// Get the thread's memory and register state.
    ///
    /// The memory part of this state is shared among all threads in the same machine. See
    /// [`PcodeMachine::get_shared_state`].
    ///
    /// Java hands back the state itself and lets callers both read and write it. A thread shares
    /// that one state with its [`PcodeExecutor`], which holds it behind a `Mutex` (see
    /// [`PcodeExecutor::get_state`]) precisely because writing needs `&mut` where a `&self` method
    /// is all that is available; so this hands back a guard, which serves for both reading and
    /// writing.
    fn get_state(&self) -> MutexGuard<'_, ThreadPcodeExecutorState<T, Self::SharedState, Self::LocalState>>;

    /// Override the p-code at the given address with the given Sleigh source for only this thread.
    ///
    /// This works the same as [`PcodeMachine::inject`] but on a per-thread basis. Where there is
    /// both a machine-level and thread-level inject, the thread inject takes precedence.
    /// Furthermore, the machine-level inject cannot be accessed by the thread-level inject.
    fn inject(&mut self, address: &Address, source: &str);

    /// Remove the per-thread inject, if present, at the given address.
    ///
    /// This has no effect on machine-level injects. If there is one present, it will still
    /// override this thread's p-code if execution reaches the address.
    fn clear_inject(&mut self, address: &Address);

    /// Remove all per-thread injects from this thread.
    ///
    /// All machine-level injects are still effective after this call.
    fn clear_all_injects(&mut self);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece};
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::mem_buffer::MemBuffer;

    /// A state that is never actually exercised, only named as
    /// [`CountingThread`]'s [`PcodeThread::SharedState`]/[`PcodeThread::LocalState`], since
    /// `get_state` is itself unreachable in these tests.
    struct UnimplementedState;

    impl ErasedPcodeExecutorStatePiece for UnimplementedState {}

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for UnimplementedState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("test should not call this")
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("test should not call this")
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("test should not call this")
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            unimplemented!("test should not call this")
        }

        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self
        where
            Self: Sized,
        {
            unimplemented!("test should not call this")
        }

        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _val: &Vec<u8>) {
            unimplemented!("test should not call this")
        }

        fn set_var_internal_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _val: &Vec<u8>) {
            unimplemented!("test should not call this")
        }

        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _reason: crate::pcode::exec::pcode_executor_state_piece::Reason) -> Vec<u8> {
            unimplemented!("test should not call this")
        }

        fn get_var_internal_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _reason: crate::pcode::exec::pcode_executor_state_piece::Reason) -> Vec<u8> {
            unimplemented!("test should not call this")
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            unimplemented!("test should not call this")
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: crate::pcode::exec::pcode_arithmetic::Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("test should not call this")
        }

        fn clear(&mut self) {
            unimplemented!("test should not call this")
        }
    }

    impl PcodeExecutorState<Vec<u8>> for UnimplementedState {}

    /// A thread that models only what the tests exercise: the name, the counter, the suspension
    /// flag, the per-thread injects, and a decode/execute cycle over fixed-length "instructions".
    /// Everything needing a real language, state, or executor is out of reach here.
    struct CountingThread {
        name: String,
        counter: Address,
        suspended: bool,
        frame: Option<PcodeFrame>,
        injects: HashMap<i64, String>,
        /// Number of `step_instruction` calls, to check the default counted overloads.
        steps: i64,
        pcode_steps: i64,
    }

    /// Every instruction in this toy machine is this long.
    const INSN_LEN: i64 = 4;

    impl CountingThread {
        fn new(name: &str, counter: Address) -> Self {
            Self {
                name: name.to_string(),
                counter,
                suspended: false,
                frame: None,
                injects: HashMap::new(),
                steps: 0,
                pcode_steps: 0,
            }
        }
    }

    impl ErasedPcodeThread for CountingThread {}

    impl PcodeThread<Vec<u8>> for CountingThread {
        type SharedState = UnimplementedState;
        type LocalState = UnimplementedState;

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_machine(&self) -> &dyn PcodeMachine<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn set_counter(&mut self, counter: &Address) {
            self.counter = counter.clone();
        }

        fn get_counter(&self) -> Address {
            self.counter.clone()
        }

        fn override_counter(&mut self, counter: &Address) {
            // Java also writes the pc register of the executor state; there is none here.
            self.set_counter(counter);
        }

        fn assign_context(&mut self, _context: &dyn RegisterValue) {}

        fn get_context(&self) -> Option<&dyn RegisterValue> {
            None
        }

        fn override_context(&mut self, _context: &dyn RegisterValue) {}

        fn override_context_with_default(&mut self) {}

        fn re_initialize(&mut self) {}

        fn step_instruction(&mut self) {
            // Java's DefaultPcodeThread refuses to step while suspended.
            assert!(!self.suspended, "Thread is suspended");
            self.steps += 1;
            self.counter = self.counter.add_wrap(INSN_LEN);
        }

        fn step_pcode_op(&mut self) {
            self.pcode_steps += 1;
        }

        fn skip_pcode_op(&mut self) {
            self.pcode_steps += 1;
        }

        fn step_patch(&mut self, _sleigh: &str) {}

        fn get_frame(&self) -> Option<&PcodeFrame> {
            self.frame.as_ref()
        }

        fn get_instruction(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn execute_instruction(&mut self) {
            self.step_instruction();
        }

        fn finish_instruction(&mut self) {
            assert!(self.frame.is_some(), "There is no current instruction to finish");
        }

        fn skip_instruction(&mut self) {
            self.counter = self.counter.add_wrap(INSN_LEN);
        }

        fn drop_instruction(&mut self) {
            // "the thread's program counter will not be advanced"
            self.frame = None;
        }

        fn run(&mut self) {
            while !self.suspended {
                self.step_instruction();
            }
        }

        fn set_suspended(&mut self, suspended: bool) {
            self.suspended = suspended;
        }

        fn is_suspended(&self) -> bool {
            self.suspended
        }

        fn get_language(&self) -> &SleighLanguage {
            unimplemented!("test should not call this")
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("test should not call this")
        }

        fn get_executor(&self) -> &PcodeExecutor<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn get_state(
            &self,
        ) -> MutexGuard<'_, ThreadPcodeExecutorState<Vec<u8>, UnimplementedState, UnimplementedState>>
        {
            unimplemented!("test should not call this")
        }

        fn inject(&mut self, address: &Address, source: &str) {
            self.injects.insert(address.offset(), source.to_string());
        }

        fn clear_inject(&mut self, address: &Address) {
            self.injects.remove(&address.offset());
        }

        fn clear_all_injects(&mut self) {
            self.injects.clear();
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn counted_step_repeats_the_single_step() {
        let space = ram();
        let mut thread = CountingThread::new("Thread-0", space.address(0x400000));
        assert_eq!("Thread-0", thread.get_name());

        // Java: `for (long i = 0; i < count; i++) stepInstruction();`
        thread.step_instruction_count(3);
        assert_eq!(3, thread.steps);
        assert_eq!(0x400000 + 3 * INSN_LEN, thread.get_counter().offset());

        // A zero (or negative) count is a no-op, as the Java loop never runs.
        thread.step_instruction_count(0);
        thread.step_instruction_count(-1);
        assert_eq!(3, thread.steps);

        thread.step_pcode_op_count(5);
        assert_eq!(5, thread.pcode_steps);
    }

    #[test]
    fn set_counter_does_not_advance_and_override_agrees() {
        let space = ram();
        let mut thread = CountingThread::new("Thread-0", space.address(0));

        let target = space.address(0x1234);
        thread.set_counter(&target);
        assert_eq!(target, thread.get_counter());

        thread.override_counter(&space.address(0x5678));
        assert_eq!(0x5678, thread.get_counter().offset());
    }

    #[test]
    fn suspension_halts_run() {
        let space = ram();
        let mut thread = CountingThread::new("Thread-0", space.address(0x1000));
        assert!(!thread.is_suspended());

        // Java: run() "will not likely return, but instead only terminates via exception, e.g.,
        // ... becoming suspended." Pre-suspending makes the loop exit immediately here.
        thread.set_suspended(true);
        assert!(thread.is_suspended());
        thread.run();
        assert_eq!(0, thread.steps);
        assert_eq!(0x1000, thread.get_counter().offset());
    }

    #[test]
    fn injects_are_per_thread_and_replaced() {
        let space = ram();
        let mut thread = CountingThread::new("Thread-0", space.address(0));
        let addr = space.address(0x400000);

        thread.inject(&addr, "emu_exec_decoded();");
        thread.inject(&addr, "emu_swi();");
        assert_eq!(1, thread.injects.len());
        assert_eq!("emu_swi();", thread.injects[&addr.offset()]);

        thread.clear_inject(&addr);
        assert!(thread.injects.is_empty());

        thread.inject(&addr, "emu_swi();");
        thread.inject(&space.address(0x400010), "emu_swi();");
        thread.clear_all_injects();
        assert!(thread.injects.is_empty());
    }

    #[test]
    fn no_frame_until_interrupted() {
        let space = ram();
        let mut thread = CountingThread::new("Thread-0", space.address(0));
        // "If the client only calls stepInstruction() and execution completes normally, this
        // method will always return null."
        assert!(thread.get_frame().is_none());
        thread.step_instruction();
        assert!(thread.get_frame().is_none());

        // dropInstruction with no current instruction "has no effect".
        thread.drop_instruction();
        assert!(thread.get_frame().is_none());
        assert_eq!(INSN_LEN, thread.get_counter().offset());
    }

    #[test]
    fn thread_is_usable_erased() {
        let space = ram();
        let thread = CountingThread::new("Thread-0", space.address(0));
        let erased: &dyn ErasedPcodeThread = &thread;
        let _ = erased;
    }
}
