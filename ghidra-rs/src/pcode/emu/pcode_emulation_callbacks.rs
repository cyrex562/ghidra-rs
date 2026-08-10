//! A set of callbacks available for p-code emulation.
//!
//! Corresponds to `ghidra.pcode.emu.PcodeEmulationCallbacks`.
//!
//! Note that some emulator extensions (notably the JIT-accelerated emulator) may disable and/or
//! slightly change the specification of these callbacks. Read an emulator's documentation
//! carefully. That said, an extension should strive to adhere to this specification as closely as
//! possible.
//!
//! See [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) for advice regarding
//! extending the emulator versus integrating with an emulator. Use of these callbacks is favored
//! over extending an emulator when possible, as this favors composition of such integrations.
//!
//! Deviations from the Java source:
//!
//! * Java overloads `dataWritten`/`delegateDataWritten`/`readUninitialized`/
//!   `delegateReadUninitialized` by parameter type (abstract addressing via `AddressSpace` plus an
//!   offset of domain `A`, vs. concrete addressing via `Address`). Rust has no overloading, so the
//!   abstract-addressing methods carry an `_abstract` suffix, exactly as in
//!   [`PcodeStateCallbacks`].
//! * Those same eight methods are generic in the state piece's domains (`<A, U>`), which would
//!   make the trait dyn-incompatible. A machine stores its callbacks as
//!   `Arc<dyn PcodeEmulationCallbacks<T>>` -- it genuinely is polymorphic over unknown
//!   implementors -- so they are declared `where Self: Sized` instead: every statically-known
//!   implementor (and hence [`Wrapper`], which is generic over one) can call and override them,
//!   while the notification callbacks, which are the whole of what a machine invokes, remain
//!   dispatchable through a trait object.
//! * Java's `PcodeThread<T>` arrives here value-erased, as
//!   [`ErasedPcodeThread`](crate::pcode::emu::pcode_thread::ErasedPcodeThread), and Java's `null` thread
//!   (documented for the state-piece callbacks, where the piece may belong to the machine's
//!   *shared* state rather than to a thread) is an `Option`.
//! * `readUninitialized` returns an owned [`AddressSet`] rather than an `AddressSetView`, and its
//!   default returns a copy of `set` rather than `set` itself. Callers therefore compare with
//!   [`AddressSetView::has_same_addresses`] where Java compares by reference identity. This
//!   follows the already-ported [`PcodeStateCallbacks`].

use std::marker::PhantomData;
use std::sync::Arc;

use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
use crate::pcode::exec::pcode_arithmetic::Purpose;
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_state_callbacks::{rng_set, PcodeStateCallbacks};
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::seam_stubs::RegisterValue;
use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::PcodeOp;

/// A set of callbacks available for p-code emulation.
///
/// `T` is the type of values in the emulator.
pub trait PcodeEmulationCallbacks<T: 'static>: Send + Sync {
    /// The emulator has been created, but not yet finished construction.
    ///
    /// **WARNING:** At this point, the emulator has not been fully constructed. The most the
    /// callback ought to do is save a pointer to the machine. Use
    /// [`shared_state_created`](Self::shared_state_created) to access the machine after it has
    /// been constructed.
    ///
    /// Java passes the machine as `PcodeMachine<T>`; taking it generically would cost this trait
    /// its dyn compatibility, so the machine arrives type-erased, following
    /// [`PcodeStateInitializer`](crate::pcode::emu::pcode_state_initializer::PcodeStateInitializer).
    fn emulator_created(&self, _machine: &dyn ErasedPcodeMachine) {}

    /// The emulator's shared state has been created.
    ///
    /// **NOTE:** It is possible for clients to interact with other parts of the machine, e.g., to
    /// create a thread, before this callback gets invoked. The shared state is created lazily,
    /// i.e., the first time
    /// [`PcodeMachine::get_shared_state`](crate::pcode::emu::pcode_machine::PcodeMachine::get_shared_state)
    /// gets called, whether by the client or the machine's internals. If a pointer to the machine
    /// is needed early, consider [`emulator_created`](Self::emulator_created).
    fn shared_state_created(&self, _machine: &dyn ErasedPcodeMachine) {}

    /// A new thread has just been created.
    ///
    /// The thread is fully constructed. This callback may access it.
    fn thread_created(&self, _thread: &Arc<dyn ErasedPcodeThread>) {}

    /// The emulator is preparing to decode an instruction, but is checking for injected overrides
    /// first.
    ///
    /// Returns `None`, or a p-code program to override the instruction. Java hands back a
    /// reference the emulator neither owns nor copies; the shared handle is the Rust equivalent.
    ///
    /// See [`PcodeMachine::inject`](crate::pcode::emu::pcode_machine::PcodeMachine::inject).
    fn get_inject(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _address: &Address,
    ) -> Option<Arc<PcodeProgram>> {
        None
    }

    /// The emulator is preparing to execute an injected program.
    fn before_execute_inject(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _address: &Address,
        _program: &PcodeProgram,
    ) {
    }

    /// The emulator has just finished executing an injected p-code program.
    ///
    /// If the program executed a branch, then `address` will be the target address. Note that any
    /// sane inject ought to execute a branch, even to effect fall-through, otherwise the program
    /// counter cannot advance.
    fn after_execute_inject(&self, _thread: &dyn ErasedPcodeThread, _address: &Address) {}

    /// The emulator, having found no injects, is preparing to decode an instruction.
    ///
    /// `context` is the decode contextreg value.
    fn before_decode_instruction(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _counter: &Address,
        _context: &dyn RegisterValue,
    ) {
    }

    /// The emulator is preparing to execute a decoded instruction.
    fn before_execute_instruction(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _instruction: &dyn Instruction,
        _program: &PcodeProgram,
    ) {
    }

    /// The emulator has finished executing an instruction.
    fn after_execute_instruction(&self, _thread: &dyn ErasedPcodeThread, _instruction: &dyn Instruction) {}

    /// The emulator is preparing to execute a p-code op.
    fn before_step_op(&self, _thread: &dyn ErasedPcodeThread, _op: &PcodeOp, _frame: &PcodeFrame) {}

    /// The emulator has just executed a p-code op.
    fn after_step_op(&self, _thread: &dyn ErasedPcodeThread, _op: &PcodeOp, _frame: &PcodeFrame) {}

    /// The emulator is preparing to load a value from its execution state.
    ///
    /// `op` is the [`OpCode::Load`](crate::program::model::pcode::OpCode::Load) op; `space`,
    /// `offset`, and `size` describe the operand.
    fn before_load(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
    ) {
    }

    /// The emulator has just loaded a value from its execution state.
    fn after_load(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// The emulator is preparing to store a value into its execution state.
    fn before_store(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// The emulator has just stored a value into its execution state.
    fn after_store(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _op: &PcodeOp,
        _space: &Arc<AddressSpace>,
        _offset: &T,
        _size: i32,
        _value: &T,
    ) {
    }

    /// The emulator has just branched to an address.
    fn after_branch(&self, _thread: &dyn ErasedPcodeThread, _op: &PcodeOp, _target: &Address) {}

    /// The emulator has encountered a userop for which it has no definition.
    ///
    /// Emulation has not yet been interrupted at this point. If a callback returns true,
    /// indicating the fault has been handled, then the emulator will proceed. If not, then
    /// emulation for this thread will be interrupted.
    fn handle_missing_userop(
        &self,
        _thread: &dyn ErasedPcodeThread,
        _op: &PcodeOp,
        _frame: &PcodeFrame,
        _op_name: &str,
        _library: &dyn PcodeUseropLibrary<T>,
    ) -> bool {
        false
    }

    /// Data was written into the given state piece (abstract addressing).
    ///
    /// **NOTE:** In contrast to the operation-driven callbacks, e.g.
    /// [`before_store`](Self::before_store), `thread` here may be `None`. It is not necessarily
    /// the thread executing the op, but the thread associated to the state being accessed. In
    /// particular, when this is the *shared* state, `thread` will be `None`. When this is the
    /// *local* state, `thread` will be the thread of execution.
    fn data_written_abstract<A, U>(
        &self,
        _thread: Option<&dyn ErasedPcodeThread>,
        _piece: &dyn PcodeExecutorStatePiece<A, U>,
        _space: &Arc<AddressSpace>,
        _offset: &A,
        _length: i32,
        _value: &U,
    ) where
        Self: Sized,
    {
    }

    /// Typically used from within [`data_written_abstract`](Self::data_written_abstract) to
    /// forward the call to the callback for concrete addressing,
    /// [`data_written`](Self::data_written).
    fn delegate_data_written_abstract<A, U>(
        &self,
        thread: Option<&dyn ErasedPcodeThread>,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        value: &U,
    ) where
        Self: Sized,
    {
        let address = piece
            .get_address_arithmetic()
            .to_address(offset, space, Purpose::Store)
            .expect("offset could not be made concrete to delegate dataWritten");
        self.data_written(thread, piece, &address, length, value);
    }

    /// Data was written into the given state piece (concrete addressing).
    ///
    /// `thread` may be `None`; see [`data_written_abstract`](Self::data_written_abstract).
    fn data_written<A, U>(
        &self,
        _thread: Option<&dyn ErasedPcodeThread>,
        _piece: &dyn PcodeExecutorStatePiece<A, U>,
        _address: &Address,
        _length: i32,
        _value: &U,
    ) where
        Self: Sized,
    {
    }

    /// Typically used from within [`data_written`](Self::data_written) to forward the call to the
    /// callback for abstract addressing,
    /// [`data_written_abstract`](Self::data_written_abstract).
    fn delegate_data_written<A, U>(
        &self,
        thread: Option<&dyn ErasedPcodeThread>,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        address: &Address,
        length: i32,
        value: &U,
    ) where
        Self: Sized,
    {
        let offset = piece.get_address_arithmetic().from_const_address(address);
        self.data_written_abstract(thread, piece, address.space(), &offset, length, value);
    }

    /// The emulator is preparing to read from uninitialized portions of the given state piece
    /// (abstract addressing).
    ///
    /// This callback provides an opportunity for something to initialize the required portion
    /// lazily. In most cases, this should either return 0 indicating the requested portion remains
    /// uninitialized, or the full `length` indicating the full requested portion is now
    /// initialized. If, for some reason, the requested portion could only be partially
    /// initialized, this can return a smaller length. Partial initializations are only recognized
    /// from the starting offset. Other parts could be initialized; however, there is no mechanism
    /// for communicating that result to the emulator.
    fn read_uninitialized_abstract<A, U>(
        &self,
        _thread: Option<&dyn ErasedPcodeThread>,
        _piece: &dyn PcodeExecutorStatePiece<A, U>,
        _space: &Arc<AddressSpace>,
        _offset: &A,
        _length: i32,
        _reason: Reason,
    ) -> i32
    where
        Self: Sized,
    {
        0
    }

    /// Typically used from within
    /// [`read_uninitialized_abstract`](Self::read_uninitialized_abstract) to forward to the
    /// callback for concrete addressing, [`read_uninitialized`](Self::read_uninitialized).
    fn delegate_read_uninitialized_abstract<A, U>(
        &self,
        thread: Option<&dyn ErasedPcodeThread>,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        reason: Reason,
    ) -> i32
    where
        Self: Sized,
    {
        let l_offset = piece
            .get_address_arithmetic()
            .to_long(offset, Purpose::Load)
            .expect("offset could not be made concrete to delegate readUninitialized");
        let mut set = rng_set(space, l_offset, length);
        let remains = self.read_uninitialized(thread, piece, &set, reason);
        if remains.has_same_addresses(&set) {
            return 0;
        }
        set.delete_set(&remains);
        match set.first_range() {
            Some(first) => first.length() as i32,
            None => 0,
        }
    }

    /// The emulator is preparing to read from uninitialized portions of the given state piece
    /// (concrete addressing).
    ///
    /// This callback provides an opportunity for something to initialize the required portion
    /// lazily. This method must return the address set that remains uninitialized. If no part of
    /// the required portion was initialized, this should return a set with the same addresses as
    /// `set`, so that the caller can recognize that nothing has changed. Otherwise, this should
    /// copy `set`, remove those parts it was able to initialize, and return the copy.
    fn read_uninitialized<A, U>(
        &self,
        _thread: Option<&dyn ErasedPcodeThread>,
        _piece: &dyn PcodeExecutorStatePiece<A, U>,
        set: &dyn AddressSetView,
        _reason: Reason,
    ) -> AddressSet
    where
        Self: Sized,
    {
        AddressSet::from_set(set)
    }

    /// Typically used from within [`read_uninitialized`](Self::read_uninitialized) to forward to
    /// the callback for abstract addressing,
    /// [`read_uninitialized_abstract`](Self::read_uninitialized_abstract).
    fn delegate_read_uninitialized<A, U>(
        &self,
        thread: Option<&dyn ErasedPcodeThread>,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        set: &dyn AddressSetView,
        reason: Reason,
    ) -> AddressSet
    where
        Self: Sized,
    {
        if set.is_empty() {
            return AddressSet::from_set(set);
        }
        let mut remains = AddressSet::from_set(set);
        for range in set.address_ranges() {
            let offset = piece
                .get_address_arithmetic()
                .from_const_address(range.min_address());
            let l = self.read_uninitialized_abstract(
                thread,
                piece,
                range.space(),
                &offset,
                range.length() as i32,
                reason,
            );
            if l == 0 {
                continue;
            }
            let end = range
                .min_address()
                .add(l as i64 - 1)
                .expect("initialized length overflowed the address range");
            remains.delete_range(range.min_address(), &end);
        }
        remains
    }

    /// Obtain a callback wrapper suitable for passing into an emulator's execution states.
    ///
    /// This will forward the calls from the state's pieces to this set of emulator callbacks,
    /// passing the given thread. Port of `wrapFor(PcodeThread)`; `thread` is `None` for the
    /// machine's shared state, which is Java's `null`.
    fn wrap_for<'a>(&'a self, thread: Option<&'a dyn ErasedPcodeThread>) -> Wrapper<'a, T, Self>
    where
        Self: Sized,
    {
        Wrapper::new(thread, self)
    }
}

/// A wrapper that can forward callbacks from state pieces to callbacks for the emulator, for a
/// given thread.
///
/// Port of the nested record `PcodeEmulationCallbacks.Wrapper<T>`. Java's record holds two
/// references; this holds two borrows, since a wrapper only ever lives as long as the call that
/// hands it to a state.
pub struct Wrapper<'a, T: 'static, CB: PcodeEmulationCallbacks<T>> {
    thread: Option<&'a dyn ErasedPcodeThread>,
    cb: &'a CB,
    /// `T` appears only in `CB`'s bound, which does not constrain it on its own.
    domain: PhantomData<fn() -> T>,
}

impl<'a, T: 'static, CB: PcodeEmulationCallbacks<T>> Wrapper<'a, T, CB> {
    /// Construct a wrapper forwarding to `cb` on behalf of `thread`.
    pub fn new(thread: Option<&'a dyn ErasedPcodeThread>, cb: &'a CB) -> Self {
        Self { thread, cb, domain: PhantomData }
    }

    /// The thread included in forwarded callbacks. Port of the record component `thread()`.
    pub fn thread(&self) -> Option<&'a dyn ErasedPcodeThread> {
        self.thread
    }

    /// The emulator callbacks receiving forwarded calls. Port of the record component `cb()`.
    pub fn cb(&self) -> &'a CB {
        self.cb
    }
}

impl<T: 'static, CB: PcodeEmulationCallbacks<T>> PcodeStateCallbacks for Wrapper<'_, T, CB> {
    fn data_written<A, U>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        address: &Address,
        length: i32,
        value: &U,
    ) {
        self.cb.data_written(self.thread, piece, address, length, value);
    }

    fn data_written_abstract<A, U>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        value: &U,
    ) {
        self.cb
            .data_written_abstract(self.thread, piece, space, offset, length, value);
    }

    fn read_uninitialized_abstract<A, U>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        reason: Reason,
    ) -> i32 {
        self.cb
            .read_uninitialized_abstract(self.thread, piece, space, offset, length, reason)
    }

    fn read_uninitialized<A, U>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, U>,
        set: &dyn AddressSetView,
        reason: Reason,
    ) -> AddressSet {
        self.cb.read_uninitialized(self.thread, piece, set, reason)
    }
}

/// Port of the nested singleton `PcodeEmulationCallbacks.NoPcodeEmulationCallbacks`: an
/// implementation of the callbacks that does nothing, i.e. every method left at its default.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoPcodeEmulationCallbacks;

impl<T: 'static> PcodeEmulationCallbacks<T> for NoPcodeEmulationCallbacks {}

/// Obtain callbacks that do nothing. Port of the static `none()`.
///
/// Java casts its single `NoPcodeEmulationCallbacks<Object>` instance to the caller's domain;
/// Rust's `NoPcodeEmulationCallbacks` implements the trait for every domain, so no cast is needed.
pub fn no_pcode_emulation_callbacks<T: 'static>() -> Arc<dyn PcodeEmulationCallbacks<T>> {
    Arc::new(NoPcodeEmulationCallbacks)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
    use crate::pcode::exec::pcode_state_callbacks::rng_set;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;

    /// Arithmetic over `i64`, used for both the address domain `A` and the value domain `U` in
    /// these tests. Only the members the trait's default delegation methods reach
    /// (`to_address`/`from_const_address`/`to_long`, all derived from
    /// `from_const_bytes`/`to_concrete`) need to behave correctly. Mirrors the fixture in
    /// [`crate::pcode::exec::pcode_state_callbacks`].
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Big)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by PcodeEmulationCallbacks tests")
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            unimplemented!("not exercised by PcodeEmulationCallbacks tests")
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
            bytes_to_long(value, value.len(), true)
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, true))
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A minimal arithmetic-only piece; only the two arithmetic accessors are reached here.
    struct TestPiece;

    impl PcodeExecutorStatePiece<i64, i64> for TestPiece {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by PcodeEmulationCallbacks tests")
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
            vec![]
        }

        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _val: &i64,
        ) {
        }

        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _val: &i64,
        ) {
        }

        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            0
        }

        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _reason: Reason,
        ) -> i64 {
            0
        }

        fn get_register_values(
            &self,
        ) -> Vec<(crate::program::model::lang::register::RegisterRef, i64)> {
            vec![]
        }

        fn get_concrete_buffer(
            &self,
            _address: &Address,
            _purpose: Purpose,
        ) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
            unimplemented!("not exercised by PcodeEmulationCallbacks tests")
        }

        fn clear(&mut self) {}
    }

    /// A thread carrying only its name, which is all these tests observe of one.
    struct NamedThread(&'static str);

    impl ErasedPcodeThread for NamedThread {}

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn none_leaves_every_callback_at_its_java_default() {
        let cb = NoPcodeEmulationCallbacks;
        let piece = TestPiece;
        let space = ram();
        let thread = NamedThread("Thread 0");

        // getInject returns null; handleMissingUserop returns false.
        assert!(
            PcodeEmulationCallbacks::<i64>::get_inject(&cb, &thread, &space.address(0x400000))
                .is_none()
        );
        // readUninitialized (abstract) returns 0: nothing was initialized.
        assert_eq!(
            0,
            PcodeEmulationCallbacks::<i64>::read_uninitialized_abstract(
                &cb,
                Some(&thread),
                &piece,
                &space,
                &0x1000i64,
                8,
                Reason::ExecuteRead,
            )
        );
        // readUninitialized (concrete) returns the requested set unchanged.
        let set = rng_set(&space, 0x1000, 8);
        let remains = PcodeEmulationCallbacks::<i64>::read_uninitialized(
            &cb,
            None,
            &piece,
            &set,
            Reason::ExecuteRead,
        );
        assert!(remains.has_same_addresses(&set));
    }

    /// Records the parameters of the callbacks it overrides. Only the concretely-typed ones are
    /// stored, since `A`/`U` are generic per call and cannot be fields of a non-generic struct.
    #[derive(Default)]
    struct RecordingCallbacks {
        /// `(thread name or "" for the shared state, address, length)`
        concrete_writes: Mutex<Vec<(String, Address, i32)>>,
        /// `(thread name or "", space, length)`
        abstract_writes: Mutex<Vec<(String, Arc<AddressSpace>, i32)>>,
    }

    fn thread_name(thread: Option<&dyn ErasedPcodeThread>) -> String {
        match thread {
            Some(_) => "thread".to_string(),
            None => String::new(),
        }
    }

    impl PcodeEmulationCallbacks<i64> for RecordingCallbacks {
        fn data_written<A, U>(
            &self,
            thread: Option<&dyn ErasedPcodeThread>,
            _piece: &dyn PcodeExecutorStatePiece<A, U>,
            address: &Address,
            length: i32,
            _value: &U,
        ) {
            self.concrete_writes
                .lock()
                .unwrap()
                .push((thread_name(thread), address.clone(), length));
        }

        fn data_written_abstract<A, U>(
            &self,
            thread: Option<&dyn ErasedPcodeThread>,
            _piece: &dyn PcodeExecutorStatePiece<A, U>,
            space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _value: &U,
        ) {
            self.abstract_writes
                .lock()
                .unwrap()
                .push((thread_name(thread), Arc::clone(space), length));
        }
    }

    #[test]
    fn delegate_data_written_converts_between_addressing_modes() {
        let cb = RecordingCallbacks::default();
        let piece = TestPiece;
        let space = ram();
        let thread = NamedThread("Thread 0");

        // abstract -> concrete: the offset is concretized through the piece's arithmetic.
        cb.delegate_data_written_abstract(Some(&thread), &piece, &space, &0x2000i64, 4, &99i64);
        assert_eq!(
            vec![("thread".to_string(), space.address(0x2000), 4)],
            *cb.concrete_writes.lock().unwrap()
        );

        // concrete -> abstract: the address supplies both the space and the offset.
        cb.delegate_data_written(None, &piece, &space.address(0x3000), 8, &42i64);
        let writes = cb.abstract_writes.lock().unwrap();
        assert_eq!(1, writes.len());
        assert_eq!("", writes[0].0);
        assert!(Arc::ptr_eq(&writes[0].1, &space));
        assert_eq!(8, writes[0].2);
    }

    /// Callbacks that lazily initialize the first four bytes of any range they are asked about.
    struct PartialInitCallbacks;

    impl PcodeEmulationCallbacks<i64> for PartialInitCallbacks {
        fn read_uninitialized<A, U>(
            &self,
            _thread: Option<&dyn ErasedPcodeThread>,
            _piece: &dyn PcodeExecutorStatePiece<A, U>,
            set: &dyn AddressSetView,
            _reason: Reason,
        ) -> AddressSet {
            let mut remains = AddressSet::from_set(set);
            if let Some(first) = set.first_range() {
                let end = first.min_address().add(3).expect("test range in bounds");
                remains.delete_range(first.min_address(), &end);
            }
            remains
        }
    }

    #[test]
    fn delegate_read_uninitialized_abstract_reports_the_partial_length() {
        let cb = PartialInitCallbacks;
        let piece = TestPiece;
        let space = ram();

        // Java: copy the requested set, subtract what remains, and report the first range's
        // length -- 4 of the 16 requested bytes.
        assert_eq!(
            4,
            cb.delegate_read_uninitialized_abstract(
                None,
                &piece,
                &space,
                &0x4000i64,
                16,
                Reason::ExecuteRead,
            )
        );
    }

    /// Callbacks that fully initialize whatever they are asked about.
    struct FullInitCallbacks;

    impl PcodeEmulationCallbacks<i64> for FullInitCallbacks {
        fn read_uninitialized_abstract<A, U>(
            &self,
            _thread: Option<&dyn ErasedPcodeThread>,
            _piece: &dyn PcodeExecutorStatePiece<A, U>,
            _space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _reason: Reason,
        ) -> i32 {
            length
        }
    }

    #[test]
    fn delegate_read_uninitialized_consumes_fully_initialized_ranges() {
        let cb = FullInitCallbacks;
        let piece = TestPiece;
        let space = ram();
        let set = rng_set(&space, 0x5000, 8);

        let remains = cb.delegate_read_uninitialized(None, &piece, &set, Reason::ExecuteRead);
        assert!(remains.is_empty());
    }

    #[test]
    fn wrapper_forwards_state_callbacks_with_its_thread() {
        let cb = RecordingCallbacks::default();
        let piece = TestPiece;
        let space = ram();
        let thread = NamedThread("Thread 0");

        // A local state's piece reports through a wrapper bound to its thread...
        let local: Wrapper<'_, i64, _> = cb.wrap_for(Some(&thread));
        PcodeStateCallbacks::data_written(&local, &piece, &space.address(0x1000), 2, &1i64);
        // ... and the shared state's through one bound to no thread, Java's null.
        let shared: Wrapper<'_, i64, _> = cb.wrap_for(None);
        PcodeStateCallbacks::data_written(&shared, &piece, &space.address(0x2000), 3, &2i64);

        assert_eq!(
            vec![
                ("thread".to_string(), space.address(0x1000), 2),
                (String::new(), space.address(0x2000), 3),
            ],
            *cb.concrete_writes.lock().unwrap()
        );

        // The wrapper's own components are readable, as the Java record's are.
        assert!(shared.thread().is_none());
        assert!(local.thread().is_some());
    }

    #[test]
    fn wrapper_forwards_read_uninitialized_to_the_emulator_callbacks() {
        let cb = PartialInitCallbacks;
        let piece = TestPiece;
        let space = ram();
        let wrapper: Wrapper<'_, i64, _> = cb.wrap_for(None);
        let set = rng_set(&space, 0x6000, 16);

        // PartialInitCallbacks initializes 4 bytes, so 12 remain: 0x6004..=0x600f.
        let remains =
            PcodeStateCallbacks::read_uninitialized(&wrapper, &piece, &set, Reason::ExecuteRead);
        assert_eq!(12, remains.num_addresses());
        let range = remains.first_range().expect("some addresses remain");
        assert_eq!(&space.address(0x6004), range.min_address());
        assert_eq!(&space.address(0x600f), range.max_address());
    }
}
