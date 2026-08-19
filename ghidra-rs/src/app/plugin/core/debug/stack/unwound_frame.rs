//! A frame that has been unwound through analysis or annotated in the listing.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.UnwoundFrame<T>`.
//!
//! An unwound frame is obtained either from
//! [`StackUnwinder`](crate::app::plugin::core::debug::stack::stack_unwinder::StackUnwinder), when
//! stack-unwind analysis has not yet been applied to the current trace snapshot, or from
//! `ListingUnwoundFrame`, when those annotations are already present. The former actually hands
//! back an
//! [`AnalysisUnwoundFrame`](crate::app::plugin::core::debug::stack::analysis_unwound_frame::AnalysisUnwoundFrame),
//! which can apply the resulting analysis to the snapshot.
//!
//! # Deviations from the Java interface
//!
//! * Java overloads `getValue`, `evaluate` and `setValue` on parameter type. Rust cannot, so each
//!   overload gets a distinct name; the `VariableStorage` form keeps the base name, matching the
//!   convention in [`DebuggerControlService`](crate::app::services::debugger_control_service).
//! * Every implementation of `getProgramCounter`, `getFunction`, `getBasePointer` and
//!   `getReturnAddress` returns `null` when the value could not be recovered (despite the Java
//!   doc's talk of throwing), so all four return [`Option`] here.
//! * `CompletableFuture<Void>` becomes
//!   [`StateEditFuture`](crate::app::services::debugger_control_service::StateEditFuture), the type
//!   `StateEditor` already uses for the same Java type.
//! * `BigInteger` becomes `i128`, the crate-wide stand-in.
//! * The two `Variable`-taking convenience methods return [`Option`]: this crate's
//!   [`Variable::get_variable_storage`] is itself optional, where Java's is documented non-null.

use std::sync::Arc;

use crate::app::seam_stubs::StackUnwindWarningSet;
use crate::app::services::debugger_control_service::{StateEditFuture, StateEditor};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::lang::register::Register;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable::Variable;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// A frame that has been unwound through analysis or annotated in the listing.
///
/// `T` is the type of values retrievable from the unwound frame.
///
/// Port of `ghidra.app.plugin.core.debug.stack.UnwoundFrame<T>`.
pub trait UnwoundFrame<T> {
    /// Checks whether this is an actual frame, as opposed to the fake frame used to evaluate
    /// variables that need no frame at all.
    ///
    /// Port of `UnwoundFrame.isFake()`.
    fn is_fake(&self) -> bool;

    /// Returns the level of this frame, 0 being the innermost.
    ///
    /// Port of `UnwoundFrame.getLevel()`. The fake frame has no level; Java throws
    /// `UnsupportedOperationException` there, so implementations without a level should panic.
    fn get_level(&self) -> i32;

    /// Returns a description of this frame, for display purposes.
    ///
    /// Port of `UnwoundFrame.getDescription()`.
    fn get_description(&self) -> String;

    /// Returns the frame's program counter, or `None` if it could not be recovered.
    ///
    /// For the innermost frame this is the next instruction to be executed. Otherwise it is the
    /// return address of the next inner frame, i.e., the instruction to be executed once control
    /// returns to the function that allocated this frame.
    ///
    /// Port of `UnwoundFrame.getProgramCounter()`.
    fn get_program_counter(&self) -> Option<Address>;

    /// Returns the function that allocated this frame, i.e. the one whose body contains the
    /// program counter, or `None` if it could not be identified.
    ///
    /// Port of `UnwoundFrame.getFunction()`.
    fn get_function(&self) -> Option<Arc<dyn Function>>;

    /// Returns the base pointer for this frame, or `None` if it could not be recovered.
    ///
    /// This is the value of the stack pointer at entry of the allocating function. While related,
    /// it is a separate thing from the "base pointer" register: not all architectures offer one,
    /// not all functions use it, and a function that does use it may place some other value in
    /// it. The value here is recovered by examining stack operations from the function's entry to
    /// the program counter, so that a varnode with a stack offset can be located in this frame by
    /// adding that offset to this base pointer.
    ///
    /// Port of `UnwoundFrame.getBasePointer()`.
    fn get_base_pointer(&self) -> Option<Address>;

    /// Returns the frame's return address, or `None` if it could not be recovered.
    ///
    /// The location of the return address is determined by examining stack and register
    /// operations from the program counter to a return of the allocating function. Three cases
    /// are known: the return address is on the stack (either because the caller pushed it, or
    /// because a callee with a link register saved it); the return address is still in a link
    /// register; or the return address cannot be recovered at all, because the function appears
    /// non-returning or the analysis otherwise failed, which is the `None` case.
    ///
    /// Port of `UnwoundFrame.getReturnAddress()`.
    fn get_return_address(&self) -> Option<Address>;

    /// Returns the warnings generated during analysis.
    ///
    /// Port of `UnwoundFrame.getWarnings()`.
    fn get_warnings(&self) -> StackUnwindWarningSet;

    /// Returns the error explaining why the unwind is in error or incomplete, if it is.
    ///
    /// When analysis is incomplete, the frame may still be partially unwound, meaning only
    /// certain variables can be evaluated and the return address may be unavailable. Typically a
    /// partially unwound frame is the last frame recoverable in the stack. If the base pointer
    /// could not be recovered, then only register and static variables can be evaluated.
    ///
    /// Port of `UnwoundFrame.getError()`.
    fn get_error(&self) -> Option<Arc<dyn std::error::Error + Send + Sync>>;

    /// Returns the value of the given storage, as read from the frame.
    ///
    /// Each varnode in the storage is retrieved and concatenated together, the lower-indexed
    /// varnodes being the more significant -- like big endian. A varnode is retrieved from the
    /// state, with register accesses potentially redirected to the location where that register's
    /// value was saved to the stack.
    ///
    /// Each varnode's value is simply read from the state, in contrast to [`Self::evaluate`],
    /// which ascends to the varnodes' defining p-code ops.
    ///
    /// **Warning:** never invoke this from the UI thread. The state may be associated with a live
    /// session, and this may block to retrieve live state.
    ///
    /// Port of `UnwoundFrame.getValue(Program, VariableStorage)`.
    fn get_value(&self, program: &dyn Program, storage: &dyn VariableStorage) -> T;

    /// Returns the value of the given variable, as read from the frame.
    ///
    /// `None` when the variable has no storage; Java, whose `Variable.getVariableStorage()` is
    /// documented non-null, has no such case.
    ///
    /// **Warning:** never invoke this from the UI thread. See [`Self::get_value`].
    ///
    /// Port of `UnwoundFrame.getValue(Variable)`.
    fn get_variable_value(&self, variable: &dyn Variable) -> Option<T> {
        let storage = variable.get_variable_storage()?;
        let program = variable.get_program();
        Some(self.get_value(program.as_ref(), storage.as_ref()))
    }

    /// Returns the value of the given register, relative to this frame, reading it from wherever
    /// this frame saved it if it was saved to the stack.
    ///
    /// **Warning:** never invoke this from the UI thread. See [`Self::get_value`].
    ///
    /// Port of `UnwoundFrame.getValue(Register)`.
    fn get_register_value(&self, register: &Register) -> T;

    /// Evaluates the given storage, following defining p-code ops until symbol storage is reached.
    ///
    /// This behaves like [`Self::get_value`], except it ascends recursively to each varnode's
    /// defining p-code op. The recursion terminates when a varnode is contained in
    /// `symbol_storage`, which is usually collected by examining the tokens on the same decompiled
    /// line, searching for ones that represent "high symbols" (Java's
    /// `VariableValueUtils.collectSymbolStorage(ClangLine)`). That way, temporary storage the
    /// original program used to evaluate, e.g., a field access is not read from the current state
    /// but re-evaluated in terms of the symbols' current values.
    ///
    /// **Warning:** never invoke this from the UI thread. See [`Self::get_value`].
    ///
    /// Port of `UnwoundFrame.evaluate(Program, VariableStorage, AddressSetView)`.
    fn evaluate(
        &self,
        program: &dyn Program,
        storage: &dyn VariableStorage,
        symbol_storage: &dyn AddressSetView,
    ) -> T;

    /// Evaluates the given varnode, following defining p-code ops until symbol storage is reached.
    ///
    /// **Warning:** never invoke this from the UI thread. See [`Self::get_value`].
    ///
    /// Port of `UnwoundFrame.evaluate(Program, Varnode, AddressSetView)`.
    fn evaluate_varnode(
        &self,
        program: &dyn Program,
        varnode: &Varnode,
        symbol_storage: &dyn AddressSetView,
    ) -> T;

    /// Evaluates the output of the given p-code op, ascending until symbol storage is reached.
    ///
    /// **Warning:** never invoke this from the UI thread. See [`Self::get_value`].
    ///
    /// Port of `UnwoundFrame.evaluate(Program, PcodeOp, AddressSetView)`.
    fn evaluate_op(
        &self,
        program: &dyn Program,
        op: &PcodeOp,
        symbol_storage: &dyn AddressSetView,
    ) -> T;

    /// Sets the value of the given storage, redirecting register accesses to the location where
    /// the register's current value was saved to the stack, if it was.
    ///
    /// The returned future completes once the necessary commands have all completed.
    ///
    /// Port of `UnwoundFrame.setValue(StateEditor, Program, VariableStorage, BigInteger)`.
    fn set_value(
        &self,
        editor: &dyn StateEditor,
        program: &dyn Program,
        storage: &dyn VariableStorage,
        value: i128,
    ) -> StateEditFuture;

    /// Sets the value of the given variable.
    ///
    /// `None` when the variable has no storage; see [`Self::get_variable_value`].
    ///
    /// Port of `UnwoundFrame.setValue(StateEditor, Variable, BigInteger)`.
    fn set_variable_value(
        &self,
        editor: &dyn StateEditor,
        variable: &dyn Variable,
        value: i128,
    ) -> Option<StateEditFuture> {
        let storage = variable.get_variable_storage()?;
        let program = variable.get_program();
        Some(self.set_value(editor, program.as_ref(), storage.as_ref(), value))
    }

    /// Sets the return address of this frame.
    ///
    /// This is typically used to set up a mechanism in pure emulation that traps execution once
    /// the entry function has returned. For example, to emulate a target function in isolation, a
    /// script could load or map the target program into a trace, initialize a thread at the
    /// function's entry, allocate a stack, and "unwind" that stack. Then it can initialize the
    /// function's parameters and return address. The return address is usually a fake but
    /// recognizable address, such as `0xdeadbeef`. The script would then place a breakpoint there
    /// and let the emulator run; once it breaks, the script can read the return value.
    ///
    /// The returned future completes once the necessary commands have all completed.
    ///
    /// Port of `UnwoundFrame.setReturnAddress(StateEditor, Address)`.
    fn set_return_address(&self, editor: &dyn StateEditor, address: &Address) -> StateEditFuture;

    /// Matches `value`'s length to `length` by zero extension or truncation.
    ///
    /// This copes with a small imperfection in field-expression evaluation: fields are evaluated
    /// using the high p-code from the decompiled function that yielded the expression. That code
    /// likely loads the value into a register, which is likely a machine word in size, even if the
    /// field being accessed is smaller. Thus the type of a token's high variable may disagree in
    /// size with the output varnode of the token's associated high p-code op. The type's size is
    /// assumed correct, and the output value is resized to match.
    ///
    /// Port of `UnwoundFrame.zext(T, int)`.
    fn zext(&self, value: T, length: i32) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::plugin::core::debug::stack::stack_unwind_warning::CustomStackUnwindWarning;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::VarnodeListStorage;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    /// A frame modeled on Java's `FakeUnwoundFrame<T>`: it can only evaluate static/global
    /// variables, so it reports itself fake and recovers no frame details at all. Values are
    /// stood in for by the byte width of the storage being read, which is enough to exercise the
    /// value-returning methods and `zext`.
    ///
    /// The warnings are a field so the set-returning accessor can be exercised too; Java's fake
    /// frame always returns an empty one.
    #[derive(Default)]
    struct FakeFrame {
        warnings: Vec<String>,
    }

    impl UnwoundFrame<i64> for FakeFrame {
        fn is_fake(&self) -> bool {
            true
        }

        fn get_level(&self) -> i32 {
            panic!("FakeUnwoundFrame.getLevel() throws UnsupportedOperationException")
        }

        fn get_description(&self) -> String {
            "(No frame required)".to_string()
        }

        fn get_program_counter(&self) -> Option<Address> {
            None
        }

        fn get_function(&self) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_base_pointer(&self) -> Option<Address> {
            None
        }

        fn get_return_address(&self) -> Option<Address> {
            None
        }

        fn get_warnings(&self) -> StackUnwindWarningSet {
            let mut set = StackUnwindWarningSet::new();
            for message in &self.warnings {
                set.add(Arc::new(CustomStackUnwindWarning { message: message.clone() }));
            }
            set
        }

        fn get_error(&self) -> Option<Arc<dyn std::error::Error + Send + Sync>> {
            None
        }

        fn get_value(&self, _program: &dyn Program, storage: &dyn VariableStorage) -> i64 {
            storage.get_varnodes().iter().map(|vn| vn.get_size() as i64).sum()
        }

        fn get_register_value(&self, register: &Register) -> i64 {
            register.num_bytes() as i64
        }

        fn evaluate(
            &self,
            program: &dyn Program,
            storage: &dyn VariableStorage,
            _symbol_storage: &dyn AddressSetView,
        ) -> i64 {
            self.get_value(program, storage)
        }

        fn evaluate_varnode(
            &self,
            _program: &dyn Program,
            varnode: &Varnode,
            _symbol_storage: &dyn AddressSetView,
        ) -> i64 {
            varnode.get_size() as i64
        }

        fn evaluate_op(
            &self,
            _program: &dyn Program,
            op: &PcodeOp,
            _symbol_storage: &dyn AddressSetView,
        ) -> i64 {
            op.output.as_ref().map_or(0, |vn| vn.get_size() as i64)
        }

        fn set_value(
            &self,
            _editor: &dyn StateEditor,
            _program: &dyn Program,
            _storage: &dyn VariableStorage,
            _value: i128,
        ) -> StateEditFuture {
            Box::pin(async {})
        }

        fn set_return_address(
            &self,
            _editor: &dyn StateEditor,
            _address: &Address,
        ) -> StateEditFuture {
            Box::pin(async {})
        }

        fn zext(&self, value: i64, length: i32) -> i64 {
            match length {
                l if l >= 8 => value,
                l if l <= 0 => 0,
                l => value & ((1i64 << (l * 8)) - 1),
            }
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn fake_frame_recovers_nothing() {
        let frame = FakeFrame::default();

        // Java's FakeUnwoundFrame reports itself fake, describes itself as needing no frame, and
        // returns null from every frame-detail accessor.
        assert!(frame.is_fake());
        assert_eq!(frame.get_description(), "(No frame required)");
        assert!(frame.get_program_counter().is_none());
        assert!(frame.get_function().is_none());
        assert!(frame.get_base_pointer().is_none());
        assert!(frame.get_return_address().is_none());
        assert!(frame.get_error().is_none());
        // `new StackUnwindWarningSet()`: empty, not null.
        assert_eq!(frame.get_warnings().size(), 0);
    }

    #[test]
    fn warnings_are_returned_by_value() {
        // ListingUnwoundFrame.getWarnings() rebuilds a set from the frame's warning bookmarks,
        // one warning per line of the bookmark comment, and hands the caller that new set.
        let frame = FakeFrame {
            warnings: vec!["Cannot unwind".to_string(), "Non-returning function".to_string()],
        };

        let returned = frame.get_warnings();
        assert_eq!(returned.size(), 2);
        assert!(!returned.is_empty());
        assert_eq!(returned.warnings()[0].get_message(), "Cannot unwind");
    }

    #[test]
    fn storage_value_visits_every_varnode() {
        let frame = FakeFrame::default();
        let space = ram();
        let storage = VarnodeListStorage(vec![
            Varnode::new(space.address(0x1000), 4),
            Varnode::new(space.address(0x2000), 2),
        ]);

        // getValue(Program, VariableStorage) retrieves every varnode of the storage and
        // concatenates them, so this mock -- which sums their sizes -- sees both, and the
        // symbol-storage-terminated `evaluate` reaches the same varnodes.
        assert_eq!(frame.get_value(&MockProgram, &storage), 6);
        assert_eq!(
            frame.evaluate(&MockProgram, &storage, &AddressSet::new()),
            6
        );
    }

    #[test]
    fn zext_truncates_to_the_types_size() {
        let frame = FakeFrame::default();

        // INT_ZEXT to a wider size leaves the value alone; the narrowing direction, which is the
        // one the field-expression fix-up actually needs, drops the high bytes.
        assert_eq!(frame.zext(0x1122_3344, 8), 0x1122_3344);
        assert_eq!(frame.zext(0x1122_3344, 2), 0x3344);
        assert_eq!(frame.zext(0x1122_3344, 1), 0x44);
    }
}
