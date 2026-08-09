use thiserror::Error;

use crate::app::seam_stubs::{FilteredMemoryState, MemoryAccessFilter};
use crate::pcode::emulate::emulate_execution_state::EmulateExecutionState;
use crate::pcode::emulate::instruction_decode_exception::InstructionDecodeException;
use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::memstate::memory_state::MemoryState;
use crate::pcode::seam_stubs::BreakTableCallBack;
use crate::program::model::address::Address;
use crate::program::seam_stubs::RegisterValue;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The error conditions [`Emulator::execute_instruction`] may report.
///
/// Corresponds to the `CancelledException, LowlevelError, InstructionDecodeException` combination
/// declared on `Emulator.executeInstruction`'s `throws` clause; Rust has no multi-exception
/// `throws`, so this enum carries whichever of the three actually occurred.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal, matching [`Emulator`] itself.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[derive(Debug, Error)]
pub enum ExecuteInstructionError {
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Lowlevel(#[from] LowlevelError),
    #[error(transparent)]
    Decode(#[from] InstructionDecodeException),
}

/// The emulator interface.
///
/// Corresponds to `ghidra.app.emulator.Emulator`.
///
/// # Deprecation
///
/// This interface was extracted from what has now been renamed `DefaultEmulator` and is also
/// deprecated. Please use [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator)
/// instead.
#[deprecated(since = "12.1", note = "use PcodeEmulator instead")]
pub trait Emulator {
    /// Get the name of the program counter register.
    ///
    /// Corresponds to `Emulator.getPCRegisterName()`.
    fn get_pc_register_name(&self) -> String;

    /// Set the value of the program counter.
    ///
    /// `addressable_word_offset` is the *word* offset of the instruction to execute next.
    ///
    /// Corresponds to `Emulator.setExecuteAddress(long)`.
    fn set_execute_address(&mut self, addressable_word_offset: i64);

    /// Get current execution address (or the address of the next instruction to be executed).
    ///
    /// Corresponds to `Emulator.getExecuteAddress()`.
    fn get_execute_address(&self) -> Address;

    /// Get the address of the last instruction executed (or the instruction currently being
    /// executed).
    ///
    /// Corresponds to `Emulator.getLastExecuteAddress()`.
    fn get_last_execute_address(&self) -> Address;

    /// Get the value of the program counter, i.e., offset in code space.
    ///
    /// Corresponds to `Emulator.getPC()`.
    fn get_pc(&self) -> i64;

    /// Execute instruction at current address.
    ///
    /// If `stop_at_breakpoint` is true and a breakpoint hits at the current execution address,
    /// execution halts without executing the instruction.
    ///
    /// Corresponds to `Emulator.executeInstruction(boolean, TaskMonitor)`.
    fn execute_instruction(
        &mut self,
        stop_at_breakpoint: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ExecuteInstructionError>;

    /// Returns true if the emulator is busy executing an instruction.
    ///
    /// Corresponds to `Emulator.isExecuting()`.
    fn is_executing(&self) -> bool;

    /// Get the low-level execution state.
    ///
    /// This can be useful within a memory fault handler to determine if a memory read was
    /// associated with instruction parsing (i.e., [`EmulateExecutionState::InstructionDecode`])
    /// or an actual emulated read (i.e., [`EmulateExecutionState::Execute`]).
    ///
    /// Corresponds to `Emulator.getEmulateExecutionState()`.
    fn get_emulate_execution_state(&self) -> EmulateExecutionState;

    /// Get the memory state.
    ///
    /// Corresponds to `Emulator.getMemState()`.
    fn get_mem_state(&mut self) -> &mut dyn MemoryState;

    /// Add a filter on memory access.
    ///
    /// Corresponds to `Emulator.addMemoryAccessFilter(MemoryAccessFilter)`.
    fn add_memory_access_filter(&mut self, filter: Box<dyn MemoryAccessFilter>);

    /// Get the memory state, modified by all installed access filters.
    ///
    /// Corresponds to `Emulator.getFilteredMemState()`.
    fn get_filtered_mem_state(&mut self) -> &mut dyn FilteredMemoryState;

    /// Sets the context register value at the current execute address.
    ///
    /// The emulator should not be running when this method is invoked. Only flowing context bits
    /// should be set, as non-flowing bits will be cleared prior to parsing an instruction. In
    /// addition, any future context state set by the pcode emitter will take precedence over
    /// context set using this method. This method is primarily intended to be used to establish
    /// the initial context state.
    ///
    /// Corresponds to `Emulator.setContextRegisterValue(RegisterValue)`.
    fn set_context_register_value(&mut self, reg_value: &dyn RegisterValue);

    /// Returns the current context register value.
    ///
    /// The context value returned reflects its state when the previously executed instruction
    /// was parsed/executed. The context value returned will feed into the next instruction to be
    /// parsed with its non-flowing bits cleared and any future context state merged in.
    ///
    /// Corresponds to `Emulator.getContextRegisterValue()`.
    fn get_context_register_value(&self) -> Box<dyn RegisterValue>;

    /// Get the breakpoint table.
    ///
    /// Corresponds to `Emulator.getBreakTable()`.
    fn get_break_table(&self) -> &dyn BreakTableCallBack;

    /// Returns true if halted at a breakpoint.
    ///
    /// Corresponds to `Emulator.isAtBreakpoint()`.
    fn is_at_breakpoint(&self) -> bool;

    /// Halt or un-halt the emulator.
    ///
    /// Corresponds to `Emulator.setHalt(boolean)`.
    fn set_halt(&mut self, halt: bool);

    /// Check if the emulator has been halted.
    ///
    /// Corresponds to `Emulator.getHalt()`.
    fn get_halt(&self) -> bool;

    /// Clean up resources used by the emulator.
    ///
    /// Corresponds to `Emulator.dispose()`.
    fn dispose(&mut self);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::pcode::memstate::memory_bank::MemoryBankImpl;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::pcode::Varnode;
    use std::sync::Arc;

    struct NullMemoryState;

    impl MemoryState for NullMemoryState {
        fn set_memory_bank(&mut self, _bank: Box<dyn MemoryBankImpl>) {}
        fn get_memory_bank(&self, _spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
            None
        }
        fn set_value_varnode(&mut self, _vn: &Varnode, _cval: i64) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_value_register(
            &mut self,
            _reg: &crate::program::model::lang::register::Register,
            _cval: i64,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_value_by_name(&mut self, _nm: &str, _cval: i64) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_value(
            &mut self,
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
            _cval: i64,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn get_value_varnode(&mut self, _vn: &Varnode) -> Result<i64, LowlevelError> {
            Ok(0)
        }
        fn get_value_register(
            &mut self,
            _reg: &crate::program::model::lang::register::Register,
        ) -> Result<i64, LowlevelError> {
            Ok(0)
        }
        fn get_value_by_name(&mut self, _nm: &str) -> Result<i64, LowlevelError> {
            Ok(0)
        }
        fn get_value(&mut self, _spc: &Arc<AddressSpace>, _off: i64, _size: i32) -> Result<i64, LowlevelError> {
            Ok(0)
        }
        fn set_big_value_varnode(&mut self, _vn: &Varnode, _cval: i128) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_big_value_register(
            &mut self,
            _reg: &crate::program::model::lang::register::Register,
            _cval: i128,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_big_value_by_name(&mut self, _nm: &str, _cval: i128) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_big_value(
            &mut self,
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
            _cval: i128,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn get_big_integer_varnode(&mut self, _vn: &Varnode, _signed: bool) -> Result<i128, LowlevelError> {
            Ok(0)
        }
        fn get_big_integer_register(
            &mut self,
            _reg: &crate::program::model::lang::register::Register,
        ) -> Result<i128, LowlevelError> {
            Ok(0)
        }
        fn get_big_integer_by_name(&mut self, _nm: &str) -> Result<i128, LowlevelError> {
            Ok(0)
        }
        fn get_big_integer(
            &mut self,
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
            _signed: bool,
        ) -> Result<i128, LowlevelError> {
            Ok(0)
        }
        fn get_chunk(
            &mut self,
            _res: &mut [u8],
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
            _stop_on_uninitialized: bool,
        ) -> Result<i32, LowlevelError> {
            Ok(0)
        }
        fn set_chunk(
            &mut self,
            _val: &[u8],
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
        fn set_initialized(
            &mut self,
            _initialized: bool,
            _spc: &Arc<AddressSpace>,
            _off: i64,
            _size: i32,
        ) -> Result<(), LowlevelError> {
            Ok(())
        }
    }

    impl FilteredMemoryState for NullMemoryState {}

    struct NullBreakTable;

    impl crate::pcode::emulate::break_table::BreakTable for NullBreakTable {
        fn set_emulate(&mut self, _emu: &dyn crate::pcode::seam_stubs::Emulate) {}
        fn do_pcode_op_break(&self, _curop: &dyn crate::pcode::seam_stubs::PcodeOpRaw) -> bool {
            false
        }
        fn do_address_break(&self, _addr: &Address) -> bool {
            false
        }
    }

    impl BreakTableCallBack for NullBreakTable {}

    struct TestRegisterValue {
        register: RegisterRef,
    }

    impl RegisterValue for TestRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }
        fn get_register_value(&self, _register: &crate::program::model::lang::register::Register) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by these tests")
        }
        fn has_any_value(&self) -> bool {
            true
        }
        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            0
        }
        fn has_value(&self) -> bool {
            true
        }
        fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// A minimal in-memory implementor of [`Emulator`], exercised only to confirm the trait's
    /// getters/setters round-trip like the corresponding `DefaultEmulator` fields would.
    struct TestEmulator {
        pc_register_name: String,
        execute_address: Address,
        last_execute_address: Address,
        halted: bool,
        at_breakpoint: bool,
        mem_state: NullMemoryState,
        filtered_mem_state: NullMemoryState,
        break_table: NullBreakTable,
        context: Option<RegisterRef>,
        filter_count: usize,
    }

    impl Emulator for TestEmulator {
        fn get_pc_register_name(&self) -> String {
            self.pc_register_name.clone()
        }

        fn set_execute_address(&mut self, addressable_word_offset: i64) {
            self.last_execute_address = self.execute_address.clone();
            self.execute_address = ram_space().address(addressable_word_offset);
        }

        fn get_execute_address(&self) -> Address {
            self.execute_address.clone()
        }

        fn get_last_execute_address(&self) -> Address {
            self.last_execute_address.clone()
        }

        fn get_pc(&self) -> i64 {
            self.execute_address.offset()
        }

        fn execute_instruction(
            &mut self,
            stop_at_breakpoint: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), ExecuteInstructionError> {
            if stop_at_breakpoint && self.at_breakpoint {
                return Err(CancelledException::new("halted at breakpoint").into());
            }
            Ok(())
        }

        fn is_executing(&self) -> bool {
            false
        }

        fn get_emulate_execution_state(&self) -> EmulateExecutionState {
            EmulateExecutionState::Stopped
        }

        fn get_mem_state(&mut self) -> &mut dyn MemoryState {
            &mut self.mem_state
        }

        fn add_memory_access_filter(&mut self, _filter: Box<dyn MemoryAccessFilter>) {
            self.filter_count += 1;
        }

        fn get_filtered_mem_state(&mut self) -> &mut dyn FilteredMemoryState {
            &mut self.filtered_mem_state
        }

        fn set_context_register_value(&mut self, reg_value: &dyn RegisterValue) {
            self.context = Some(reg_value.get_register());
        }

        fn get_context_register_value(&self) -> Box<dyn RegisterValue> {
            Box::new(TestRegisterValue {
                register: self.context.clone().expect("context register value not set"),
            })
        }

        fn get_break_table(&self) -> &dyn BreakTableCallBack {
            &self.break_table
        }

        fn is_at_breakpoint(&self) -> bool {
            self.at_breakpoint
        }

        fn set_halt(&mut self, halt: bool) {
            self.halted = halt;
        }

        fn get_halt(&self) -> bool {
            self.halted
        }

        fn dispose(&mut self) {
            self.filter_count = 0;
        }
    }

    fn test_emulator() -> TestEmulator {
        let space = ram_space();
        TestEmulator {
            pc_register_name: "pc".to_string(),
            execute_address: space.address(0),
            last_execute_address: space.address(0),
            halted: false,
            at_breakpoint: false,
            mem_state: NullMemoryState,
            filtered_mem_state: NullMemoryState,
            break_table: NullBreakTable,
            context: None,
            filter_count: 0,
        }
    }

    #[test]
    fn set_execute_address_then_get_execute_address_round_trips() {
        // Java: setExecuteAddress(long) sets the word offset of the next instruction, reflected
        // by getExecuteAddress()/getPC().
        let mut emu = test_emulator();
        emu.set_execute_address(0x1000);
        assert_eq!(emu.get_execute_address().offset(), 0x1000);
        assert_eq!(emu.get_pc(), 0x1000);
    }

    #[test]
    fn set_execute_address_tracks_last_execute_address() {
        let mut emu = test_emulator();
        emu.set_execute_address(0x1000);
        emu.set_execute_address(0x1004);
        assert_eq!(emu.get_last_execute_address().offset(), 0x1000);
        assert_eq!(emu.get_execute_address().offset(), 0x1004);
    }

    #[test]
    fn set_halt_then_get_halt_round_trips() {
        let mut emu = test_emulator();
        assert!(!emu.get_halt());
        emu.set_halt(true);
        assert!(emu.get_halt());
    }

    #[test]
    fn execute_instruction_stops_at_breakpoint() {
        // Java: executeInstruction(stopAtBreakpoint=true) does not execute if halted at a
        // breakpoint; here that surfaces as a CancelledException, one of the three declared
        // `throws` types.
        let mut emu = test_emulator();
        emu.at_breakpoint = true;
        let monitor = crate::util::task::DummyMonitor;
        let err = emu.execute_instruction(true, &monitor).unwrap_err();
        assert!(matches!(err, ExecuteInstructionError::Cancelled(_)));
    }

    #[test]
    fn execute_instruction_ignores_breakpoint_when_not_requested() {
        let mut emu = test_emulator();
        emu.at_breakpoint = true;
        let monitor = crate::util::task::DummyMonitor;
        assert!(emu.execute_instruction(false, &monitor).is_ok());
    }

    #[test]
    fn set_context_register_value_then_get_context_register_value_round_trips() {
        let space = ram_space();
        let register = crate::program::model::lang::register::Register::new(
            "ctx",
            "context register",
            Address::new(space, 0x0),
            4,
            false,
            0,
        );
        let mut emu = test_emulator();
        emu.set_context_register_value(&TestRegisterValue { register: register.clone() });
        assert_eq!(
            emu.get_context_register_value().get_register().borrow().name(),
            "ctx"
        );
    }

    #[test]
    fn add_memory_access_filter_is_tracked() {
        struct NullFilter;
        impl MemoryAccessFilter for NullFilter {}

        let mut emu = test_emulator();
        assert_eq!(emu.filter_count, 0);
        emu.add_memory_access_filter(Box::new(NullFilter));
        assert_eq!(emu.filter_count, 1);
    }

    #[test]
    fn dispose_resets_filter_count() {
        struct NullFilter;
        impl MemoryAccessFilter for NullFilter {}

        let mut emu = test_emulator();
        emu.add_memory_access_filter(Box::new(NullFilter));
        emu.dispose();
        assert_eq!(emu.filter_count, 0);
    }

    #[test]
    fn execute_instruction_error_display_is_transparent() {
        let cancelled: ExecuteInstructionError = CancelledException::new("stop").into();
        assert_eq!(cancelled.to_string(), CancelledException::new("stop").to_string());

        let lowlevel: ExecuteInstructionError = LowlevelError::with_message("bad op").into();
        assert_eq!(lowlevel.to_string(), "bad op");
    }
}
