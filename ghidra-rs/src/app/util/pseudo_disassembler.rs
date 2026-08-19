//! Port of `ghidra.app.util.PseudoDisassembler`.
//!
//! Useful for disassembling and getting an `Instruction` or creating `Data` at a location in
//! memory when you don't want the program to be changed. The instructions or data that are
//! created are `PseudoInstruction`s and `PseudoData`s: they act like regular instructions in
//! most respects, but they don't exist in the program. No references or symbols are created,
//! and nothing is saved when the program is saved.
//!
//! The Java class also acts as a probable-subroutine checker: [`PseudoDisassembler::is_valid_subroutine`]
//! and friends follow flow from a candidate entry point to decide whether it looks like a
//! well-behaved subroutine.
//!
//! This type was selected as a dependency-cycle cut-point, so it is ported here as a trait
//! rather than a struct. Every Java overload set becomes one Rust method with a disambiguating
//! suffix (Rust has no overloading), e.g. `disassemble`/`disassemble_with_context`/
//! `disassemble_bytes`/`disassemble_bytes_with_context`. Overloads whose Java bodies just forward
//! to a sibling overload with literal extra arguments (no access to the private `programContext`/
//! `pseudoDisassembler`/`lastPseudoInstructionBlock` fields the concrete class carries) keep that
//! forwarding as a default trait method; overloads that build a *new* internal
//! `PseudoDisassemblerContext` from those private fields, or that touch the disassembly engine
//! directly, are left abstract for the eventual concrete port to implement.
//!
//! `ghidra.app.util.PseudoDisassemblerContext` (the concrete context class Java passes to several
//! overloads) is not ported here -- it directly `implements DisassemblerContext` and adds no
//! methods of its own, so `&mut dyn `[`DisassemblerContext`]` already stands in for it without
//! needing a placeholder stub. Likewise `PseudoInstruction` (the return type of the `disassemble`
//! methods) reuses the existing [`PseudoInstructionLike`] placeholder that
//! [`PseudoFlowProcessor`] already established.
//!
//! Java's static helper methods (the block at the bottom of the class, `getNormalizedDisassemblyAddress`,
//! `getTargetContextRegisterValueForDisassembly`, `hasLowBitCodeModeInAddrValues`, and the two
//! `setTargetContextForDisassembly` overloads) don't operate on instance state, so -- mirroring
//! how `Loader`'s static `isLoadingDisabled`/`setLoadingDisabled` became free functions in
//! [`loader`](crate::app::util::opinion::loader) -- they become free functions in this module
//! instead of trait methods.

use std::any::Any;

use thiserror::Error;

use crate::app::seam_stubs::PseudoInstructionLike;
use crate::app::util::pseudo_data::PseudoData;
use crate::app::util::pseudo_flow_processor::PseudoFlowProcessor;
use crate::program::model::address::{Address, AddressSet};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::{
    DisassemblerContext, InsufficientBytesException, ProcessorContextView, Register, RegisterRef,
    UnknownContextException, UnknownInstructionException,
};
use crate::program::model::listing::Program;
use crate::program::seam_stubs::RegisterValue;
use crate::util::Msg;

/// Name of the register used by processors that use the lower bit of addresses to switch into an
/// alternate code mode, such as ARM -> Thumb.
///
/// Port of `PseudoDisassembler.LOW_BIT_CODE_MODE_REGISTER_NAME`.
const LOW_BIT_CODE_MODE_REGISTER_NAME: &str = "LowBitCodeMode";

/// Default maximum number of instructions checked by [`PseudoDisassembler::check_valid_subroutine`]
/// and friends.
///
/// Port of `PseudoDisassembler.DEFAULT_MAX_INSTRUCTIONS`.
pub const DEFAULT_MAX_INSTRUCTIONS: i32 = 4000;

/// Only let this many consecutive instructions with the same repeated bytes through.
///
/// Port of `PseudoDisassembler.MAX_REPEAT_BYTES_LIMIT`.
pub const MAX_REPEAT_BYTES_LIMIT: i32 = 4;

/// Combines the checked exceptions declared on `PseudoDisassembler.disassemble`'s overloads.
#[derive(Debug, Error)]
pub enum DisassembleError {
    #[error(transparent)]
    InsufficientBytes(#[from] InsufficientBytesException),
    #[error(transparent)]
    UnknownInstruction(#[from] UnknownInstructionException),
    #[error(transparent)]
    UnknownContext(#[from] UnknownContextException),
}

/// Disassembles and analyzes code without altering the underlying program.
///
/// Port of `ghidra.app.util.PseudoDisassembler`.
pub trait PseudoDisassembler {
    /// Set the maximum number of instructions to check.
    ///
    /// Port of `PseudoDisassembler.setMaxInstructions(int)`.
    fn set_max_instructions(&mut self, max_num_instructions: i32);

    /// Get the last number of disassembled instructions (or the number of initial contiguous
    /// instructions if `require_contiguous` was requested) after a call to a
    /// `check_valid_subroutine`/`is_valid_subroutine` method.
    ///
    /// Port of `PseudoDisassembler.getLastCheckValidInstructionCount()`.
    fn get_last_check_valid_instruction_count(&self) -> i32;

    /// Set whether to respect the Execute bit on memory, if present on any memory block.
    ///
    /// Port of `PseudoDisassembler.setRespectExecuteFlag(boolean)`.
    fn set_respect_execute_flag(&mut self, respect: bool);

    /// Disassemble a single instruction. The program is not affected.
    ///
    /// Port of `PseudoDisassembler.disassemble(Address)`.
    fn disassemble(
        &mut self,
        addr: Address,
    ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError>;

    /// Disassemble a single instruction. The program is not affected.
    ///
    /// Port of `PseudoDisassembler.disassemble(Address, PseudoDisassemblerContext, boolean)`.
    fn disassemble_with_context(
        &mut self,
        addr: Address,
        disassembler_context: &mut dyn DisassemblerContext,
        is_in_delay_slot: bool,
    ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError>;

    /// Disassemble a location in memory using the given bytes instead of whatever is currently
    /// defined in the program at that address.
    ///
    /// Port of `PseudoDisassembler.disassemble(Address, byte[])`.
    fn disassemble_bytes(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError>;

    /// Disassemble a location in memory using the given bytes and disassembler context.
    ///
    /// Port of `PseudoDisassembler.disassemble(Address, byte[], PseudoDisassemblerContext)`.
    fn disassemble_bytes_with_context(
        &mut self,
        addr: Address,
        bytes: &[u8],
        disassembler_context: &mut dyn DisassemblerContext,
    ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError>;

    /// Apply a datatype to the program at the given address without affecting the program.
    /// Returns a [`PseudoData`] that acts like `Data` retrieved from a program.
    ///
    /// Port of `PseudoDisassembler.applyDataType(Address, DataType)`.
    fn apply_data_type(&self, addr: Address, dt: &dyn DataType) -> Option<Box<dyn PseudoData>>;

    /// Interpret the bytes at a location in memory as a pointer-sized address and return the
    /// address it points at.
    ///
    /// Port of `PseudoDisassembler.getIndirectAddr(Address)`.
    fn get_indirect_addr(&self, to_addr: Address) -> Option<Address> {
        let pointer_size = to_addr.space().pointer_size();
        let pointer_data_type = PointerSizedDataType { length: pointer_size };
        let data = self.apply_data_type(to_addr, &pointer_data_type)?;
        let value = crate::program::model::listing::data::Data::get_value(data.as_ref())?;
        value.downcast::<Address>().ok().map(|addr| *addr)
    }

    /// Check that this entry point leads to a well behaved subroutine: it should return, hit no
    /// bad instructions, have only one entry point, and not overlap any existing data or
    /// instructions.
    ///
    /// Port of `PseudoDisassembler.isValidSubroutine(Address)`.
    fn is_valid_subroutine(&mut self, entry_point: Address) -> bool {
        self.is_valid_subroutine_allow_existing(entry_point, false)
    }

    /// Check that this entry point leads to a well behaved subroutine, optionally allowing it to
    /// fall into existing code.
    ///
    /// Port of `PseudoDisassembler.isValidSubroutine(Address, boolean)`.
    fn is_valid_subroutine_allow_existing(
        &mut self,
        entry_point: Address,
        allow_existing_code: bool,
    ) -> bool {
        self.check_valid_subroutine(entry_point, allow_existing_code, true, false)
    }

    /// Check that this entry point leads to a well behaved subroutine, optionally allowing it to
    /// fall into existing code and optionally requiring it to terminate.
    ///
    /// Port of `PseudoDisassembler.isValidSubroutine(Address, boolean, boolean)`.
    fn is_valid_subroutine_full(
        &mut self,
        entry_point: Address,
        allow_existing_code: bool,
        must_terminate: bool,
    ) -> bool {
        self.check_valid_subroutine(entry_point, allow_existing_code, must_terminate, false)
    }

    /// Check that this entry point leads to valid code: it may have multiple entries into the
    /// body, the intent is that it be valid code (not necessarily nice code), and it hits no bad
    /// instructions.
    ///
    /// Port of `PseudoDisassembler.isValidCode(Address)`.
    fn is_valid_code(&mut self, entry_point: Address) -> bool {
        self.check_valid_subroutine(entry_point, true, false, false)
    }

    /// Check that this entry point leads to valid code, using the given disassembly context.
    ///
    /// Port of `PseudoDisassembler.isValidCode(Address, PseudoDisassemblerContext)`.
    fn is_valid_code_with_context(
        &mut self,
        entry_point: Address,
        context: &mut dyn DisassemblerContext,
    ) -> bool {
        self.check_valid_subroutine_with_context(entry_point, context, true, false)
    }

    /// Process a subroutine using the given processor. The processor controls what flows are
    /// followed and when to stop.
    ///
    /// Port of `PseudoDisassembler.followSubFlows(Address, int, PseudoFlowProcessor)`.
    fn follow_sub_flows(
        &mut self,
        entry_point: Address,
        max_instr: i32,
        processor: &mut dyn PseudoFlowProcessor,
    ) -> AddressSet;

    /// Process a subroutine using the given processor and initial disassembly context.
    ///
    /// Port of
    /// `PseudoDisassembler.followSubFlows(Address, PseudoDisassemblerContext, int, PseudoFlowProcessor)`.
    fn follow_sub_flows_with_context(
        &mut self,
        entry_point: Address,
        proc_context: &mut dyn DisassemblerContext,
        max_instr: i32,
        processor: &mut dyn PseudoFlowProcessor,
    ) -> AddressSet;

    /// Check if there is a valid subroutine at the target address.
    ///
    /// Port of `PseudoDisassembler.checkValidSubroutine(Address, boolean, boolean, boolean)`.
    fn check_valid_subroutine(
        &mut self,
        entry_point: Address,
        allow_existing_instructions: bool,
        must_terminate: bool,
        require_contiguous: bool,
    ) -> bool;

    /// Check if there is a valid subroutine at the target address, using the given disassembly
    /// context.
    ///
    /// Port of
    /// `PseudoDisassembler.checkValidSubroutine(Address, PseudoDisassemblerContext, boolean, boolean)`.
    fn check_valid_subroutine_with_context(
        &mut self,
        entry_point: Address,
        proc_context: &mut dyn DisassemblerContext,
        allow_existing_instructions: bool,
        must_terminate: bool,
    ) -> bool {
        self.check_valid_subroutine_with_context_full(
            entry_point,
            proc_context,
            allow_existing_instructions,
            must_terminate,
            false,
        )
    }

    /// Check if there is a valid subroutine at the target address, using the given disassembly
    /// context, and optionally requiring the initial run of instructions to be contiguous.
    ///
    /// Port of
    /// `PseudoDisassembler.checkValidSubroutine(Address, PseudoDisassemblerContext, boolean, boolean, boolean)`.
    fn check_valid_subroutine_with_context_full(
        &mut self,
        entry_point: Address,
        proc_context: &mut dyn DisassemblerContext,
        allow_existing_instructions: bool,
        must_terminate: bool,
        require_contiguous: bool,
    ) -> bool;
}

/// Minimal stand-in for `PointerDataType.getPointer(null, size)`, used by
/// [`PseudoDisassembler::get_indirect_addr`]'s default implementation. `DataType`'s trait methods
/// are all defaulted (see `data_type.rs`), so only the two members that matter for a bare pointer
/// -- its length and the fact that it *is* a pointer -- need overriding.
struct PointerSizedDataType {
    length: i32,
}

impl DataType for PointerSizedDataType {
    fn get_length(&self) -> i32 {
        self.length
    }

    fn is_pointer(&self) -> bool {
        true
    }
}

/// Minimal stand-in for `new RegisterValue(register, BigInteger.ONE)`, used by the free functions
/// below to build the low-bit-code-mode context value. A full port of
/// `ghidra.program.model.lang.RegisterValue` (currently only a placeholder trait, see
/// [`RegisterValue`]) would replace this.
struct LowBitCodeModeValue {
    register: RegisterRef,
}

impl RegisterValue for LowBitCodeModeValue {
    fn get_register(&self) -> RegisterRef {
        self.register.clone()
    }

    fn get_register_value(&self, _register: &Register) -> Box<dyn RegisterValue> {
        Box::new(LowBitCodeModeValue {
            register: self.register.clone(),
        })
    }

    fn has_any_value(&self) -> bool {
        true
    }

    fn get_unsigned_value_ignore_mask(&self) -> u128 {
        1
    }

    fn has_value(&self) -> bool {
        // Constructed as `new RegisterValue(register, BigInteger.ONE)`, whose mask is always full.
        true
    }

    fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        Box::new(LowBitCodeModeValue {
            register: self.register.clone(),
        })
    }
}

/// Get an address that can be used for disassembly. Useful for some processors where pointers to
/// code have 1 added to them for different modes such as Thumb mode for ARM.
///
/// Port of `PseudoDisassembler.getNormalizedDisassemblyAddress(Program, Address)`.
pub fn get_normalized_disassembly_address(program: &dyn Program, addr: Address) -> Address {
    if !addr.is_memory_address() {
        return addr;
    }
    if program.get_register(LOW_BIT_CODE_MODE_REGISTER_NAME).is_none() {
        return addr;
    }
    if addr.offset() & 1 == 0 {
        return addr;
    }
    Address::new(addr.space().clone(), addr.offset() & !0x1)
}

/// The `RegisterValue` setting for the context register to disassemble correctly at the given
/// address, or `None` if no setting is needed.
///
/// Port of `PseudoDisassembler.getTargetContextRegisterValueForDisassembly(Program, Address)`.
pub fn get_target_context_register_value_for_disassembly(
    program: &dyn Program,
    addr: &Address,
) -> Option<Box<dyn RegisterValue>> {
    let low_bit_code_mode = program.get_register(LOW_BIT_CODE_MODE_REGISTER_NAME)?;
    if addr.offset() & 1 == 1 {
        Some(Box::new(LowBitCodeModeValue {
            register: low_bit_code_mode,
        }))
    } else {
        None
    }
}

/// True if `program` uses the low bit of an address to change Instruction Set mode.
///
/// Port of `PseudoDisassembler.hasLowBitCodeModeInAddrValues(Program)`.
pub fn has_low_bit_code_mode_in_addr_values(program: &dyn Program) -> bool {
    program
        .get_register(LOW_BIT_CODE_MODE_REGISTER_NAME)
        .is_some()
}

/// If `program`'s processor uses the low bit of an address to change to a new Instruction Set
/// mode, check the low bit and change the instruction state at the address.
///
/// Port of `PseudoDisassembler.setTargetContextForDisassembly(Program, Address)`.
pub fn set_target_context_for_disassembly(program: &mut dyn Program, addr: Address) -> Address {
    if !addr.is_memory_address() {
        Msg::error(
            "PseudoDisassembler",
            &format!("Invalid attempt to adjust disassembler context at {addr}"),
        );
        return addr;
    }

    if addr.offset() & 1 == 0 {
        return addr;
    }

    let Some(low_bit_code_mode) = program.get_register(LOW_BIT_CODE_MODE_REGISTER_NAME) else {
        return addr;
    };

    let new_addr = Address::new(addr.space().clone(), addr.offset() & !0x1);
    if let Some(program_context) = program.get_program_context() {
        let register = low_bit_code_mode.borrow();
        let _ = program_context.set_value(&register, &new_addr, &new_addr, Some(1));
    }
    new_addr
}

/// In order to check a location to see if it disassembles from an address reference, the address
/// is checked for low-bit code switch behavior. If it does switch, the context is changed.
///
/// Port of `PseudoDisassembler.setTargetContextForDisassembly(DisassemblerContext, Address)`.
pub fn set_target_context_for_disassembly_with_context(
    proc_context: &mut dyn DisassemblerContext,
    addr: Address,
) -> Address {
    if !addr.is_memory_address() {
        Msg::error(
            "PseudoDisassembler",
            &format!("Invalid attempt to adjust disassembler context at {addr}"),
        );
        return addr;
    }

    if addr.offset() & 1 == 0 {
        return addr;
    }

    let Some(low_bit_code_mode) = proc_context.get_register(LOW_BIT_CODE_MODE_REGISTER_NAME)
    else {
        return addr;
    };

    let new_addr = Address::new(addr.space().clone(), addr.offset() & !0x1);
    proc_context.set_future_register_value(
        new_addr.clone(),
        Box::new(LowBitCodeModeValue {
            register: low_bit_code_mode,
        }),
    );
    new_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressRangeIterator, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::listing::ProgramContext;
    use std::cell::RefCell;

    fn mock_space() -> std::sync::Arc<AddressSpace> {
        // 32-bit address space => `AddressSpace::pointer_size()` == 4.
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn mock_address(offset: i64) -> Address {
        Address::new(mock_space(), offset)
    }

    fn mock_register(name: &str) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(name, "mock register", Address::new(space, 0), 1, false, 0)
    }

    /// Records calls and lets the test control every abstract member; proves the trait is
    /// object-safe and that the default methods forward the right arguments.
    struct MockPseudoDisassembler {
        check_valid_calls: RefCell<Vec<(bool, bool, bool)>>,
        check_valid_result: bool,
        apply_data_type_calls: RefCell<Vec<(i32, bool)>>,
        apply_data_type_result: bool,
    }

    impl PseudoDisassembler for MockPseudoDisassembler {
        fn set_max_instructions(&mut self, _max_num_instructions: i32) {}

        fn get_last_check_valid_instruction_count(&self) -> i32 {
            0
        }

        fn set_respect_execute_flag(&mut self, _respect: bool) {}

        fn disassemble(
            &mut self,
            _addr: Address,
        ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError> {
            Ok(None)
        }

        fn disassemble_with_context(
            &mut self,
            _addr: Address,
            _disassembler_context: &mut dyn DisassemblerContext,
            _is_in_delay_slot: bool,
        ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError> {
            Ok(None)
        }

        fn disassemble_bytes(
            &mut self,
            _addr: Address,
            _bytes: &[u8],
        ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError> {
            Ok(None)
        }

        fn disassemble_bytes_with_context(
            &mut self,
            _addr: Address,
            _bytes: &[u8],
            _disassembler_context: &mut dyn DisassemblerContext,
        ) -> Result<Option<Box<dyn PseudoInstructionLike>>, DisassembleError> {
            Ok(None)
        }

        fn apply_data_type(&self, _addr: Address, dt: &dyn DataType) -> Option<Box<dyn PseudoData>> {
            self.apply_data_type_calls
                .borrow_mut()
                .push((dt.get_length(), dt.is_pointer()));
            if self.apply_data_type_result {
                unreachable!("test doubles never need to return Some here")
            } else {
                None
            }
        }

        fn follow_sub_flows(
            &mut self,
            _entry_point: Address,
            _max_instr: i32,
            _processor: &mut dyn PseudoFlowProcessor,
        ) -> AddressSet {
            AddressSet::new()
        }

        fn follow_sub_flows_with_context(
            &mut self,
            _entry_point: Address,
            _proc_context: &mut dyn DisassemblerContext,
            _max_instr: i32,
            _processor: &mut dyn PseudoFlowProcessor,
        ) -> AddressSet {
            AddressSet::new()
        }

        fn check_valid_subroutine(
            &mut self,
            _entry_point: Address,
            allow_existing_instructions: bool,
            must_terminate: bool,
            require_contiguous: bool,
        ) -> bool {
            self.check_valid_calls.borrow_mut().push((
                allow_existing_instructions,
                must_terminate,
                require_contiguous,
            ));
            self.check_valid_result
        }

        fn check_valid_subroutine_with_context_full(
            &mut self,
            _entry_point: Address,
            _proc_context: &mut dyn DisassemblerContext,
            allow_existing_instructions: bool,
            must_terminate: bool,
            require_contiguous: bool,
        ) -> bool {
            self.check_valid_calls.borrow_mut().push((
                allow_existing_instructions,
                must_terminate,
                require_contiguous,
            ));
            self.check_valid_result
        }
    }

    fn mock_disassembler(result: bool) -> MockPseudoDisassembler {
        MockPseudoDisassembler {
            check_valid_calls: RefCell::new(Vec::new()),
            check_valid_result: result,
            apply_data_type_calls: RefCell::new(Vec::new()),
            apply_data_type_result: false,
        }
    }

    #[test]
    fn is_valid_subroutine_default_chain_forwards_literal_arguments() {
        let mut mock = mock_disassembler(true);
        let dyn_disasm: &mut dyn PseudoDisassembler = &mut mock;

        assert!(dyn_disasm.is_valid_subroutine(mock_address(0x1000)));
        assert!(dyn_disasm.is_valid_subroutine_allow_existing(mock_address(0x1000), true));
        assert!(dyn_disasm.is_valid_code(mock_address(0x1000)));

        assert_eq!(
            mock.check_valid_calls.into_inner(),
            vec![
                (false, true, false),  // is_valid_subroutine(entry) -> allow=false, must_terminate=true
                (true, true, false),   // is_valid_subroutine_allow_existing(entry, true)
                (true, false, false),  // is_valid_code(entry) -> allow=true, must_terminate=false
            ]
        );
    }

    #[test]
    fn is_valid_subroutine_full_and_check_valid_subroutine_share_require_contiguous_false() {
        let mut mock = mock_disassembler(false);
        let dyn_disasm: &mut dyn PseudoDisassembler = &mut mock;

        assert!(!dyn_disasm.is_valid_subroutine_full(mock_address(0x2000), true, true));

        assert_eq!(
            mock.check_valid_calls.into_inner(),
            vec![(true, true, false)]
        );
    }

    #[test]
    fn get_indirect_addr_forwards_pointer_sized_data_type_and_short_circuits_on_none() {
        let mock = mock_disassembler(true);
        let to_addr = mock_address(0x4000);

        let result = mock.get_indirect_addr(to_addr);

        assert_eq!(result, None);
        assert_eq!(mock.apply_data_type_calls.into_inner(), vec![(4, true)]);
    }

    // `RegisterRef` (`Rc<RefCell<Register>>`) is not `Send + Sync`, so it can't be stored as a
    // field on a `Program` implementor (`Program: Send + Sync`); build it fresh on each call
    // instead.
    struct MockProgram {
        has_low_bit_register: bool,
        program_context: Option<MockProgramContext>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            if self.has_low_bit_register && name == LOW_BIT_CODE_MODE_REGISTER_NAME {
                Some(mock_register(LOW_BIT_CODE_MODE_REGISTER_NAME))
            } else {
                None
            }
        }

        fn get_program_context(&mut self) -> Option<&mut dyn ProgramContext> {
            self.program_context
                .as_mut()
                .map(|ctx| ctx as &mut dyn ProgramContext)
        }
    }

    struct MockProgramContext {
        set_value_calls: Vec<(String, i64, i64, Option<i128>)>,
    }

    impl ProgramContext for MockProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            false
        }
        fn get_flow_value(&self, value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue> {
            value
        }
        fn get_non_flow_value(
            &self,
            _value: Box<dyn RegisterValue>,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_non_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_value(
            &mut self,
            register: &Register,
            start: &Address,
            end: &Address,
            value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            self.set_value_calls.push((
                register.name().to_string(),
                start.offset(),
                end.offset(),
                value,
            ));
            Ok(())
        }
        fn get_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn get_register_value_range_containing(
            &self,
            _register: &Register,
            addr: &Address,
        ) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }
        fn get_default_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn remove(
            &mut self,
            _start: &Address,
            _end: &Address,
            _register: &Register,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn has_value_over_range(
            &self,
            _reg: &Register,
            _value: i128,
            _addr_set: &dyn AddressSetView,
        ) -> bool {
            false
        }
        fn get_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_base_context_register(&self) -> RegisterRef {
            panic!("no base context register in mock")
        }
        fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
            Box::new(LowBitCodeModeValue {
                register: mock_register("context"),
            })
        }
        fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValue>) {}
        fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValue> {
            Box::new(LowBitCodeModeValue {
                register: mock_register("context"),
            })
        }
    }

    #[test]
    fn get_normalized_disassembly_address_clears_low_bit_only_when_register_present() {
        let with_register = MockProgram {
            has_low_bit_register: true,
            program_context: None,
        };
        let without_register = MockProgram {
            has_low_bit_register: false,
            program_context: None,
        };

        assert_eq!(
            get_normalized_disassembly_address(&with_register, mock_address(0x1001)).offset(),
            0x1000
        );
        assert_eq!(
            get_normalized_disassembly_address(&with_register, mock_address(0x1000)).offset(),
            0x1000
        );
        assert_eq!(
            get_normalized_disassembly_address(&without_register, mock_address(0x1001)).offset(),
            0x1001
        );
    }

    #[test]
    fn has_low_bit_code_mode_in_addr_values_reflects_register_presence() {
        let with_register = MockProgram {
            has_low_bit_register: true,
            program_context: None,
        };
        let without_register = MockProgram {
            has_low_bit_register: false,
            program_context: None,
        };

        assert!(has_low_bit_code_mode_in_addr_values(&with_register));
        assert!(!has_low_bit_code_mode_in_addr_values(&without_register));
    }

    #[test]
    fn get_target_context_register_value_for_disassembly_only_odd_offsets() {
        let program = MockProgram {
            has_low_bit_register: true,
            program_context: None,
        };

        let odd = get_target_context_register_value_for_disassembly(&program, &mock_address(0x1001));
        assert!(odd.is_some());
        assert_eq!(odd.unwrap().get_unsigned_value_ignore_mask(), 1);

        let even = get_target_context_register_value_for_disassembly(&program, &mock_address(0x1000));
        assert!(even.is_none());
    }

    #[test]
    fn set_target_context_for_disassembly_clears_bit_and_records_context_write() {
        let mut program = MockProgram {
            has_low_bit_register: true,
            program_context: Some(MockProgramContext {
                set_value_calls: Vec::new(),
            }),
        };

        let result = set_target_context_for_disassembly(&mut program, mock_address(0x2001));
        assert_eq!(result.offset(), 0x2000);
        assert_eq!(
            program.program_context.unwrap().set_value_calls,
            vec![(
                LOW_BIT_CODE_MODE_REGISTER_NAME.to_string(),
                0x2000,
                0x2000,
                Some(1)
            )]
        );
    }

    struct MockDisassemblerContext {
        base_register: RegisterRef,
        future_values: RefCell<Vec<Address>>,
    }

    impl ProcessorContextView for MockDisassemblerContext {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            Some(self.base_register.clone())
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![self.base_register.clone()]
        }
        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            if self.base_register.borrow().name() == name {
                Some(self.base_register.clone())
            } else {
                None
            }
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl crate::program::model::lang::ProcessorContext for MockDisassemblerContext {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl DisassemblerContext for MockDisassemblerContext {
        fn set_future_register_value(&mut self, address: Address, _value: Box<dyn RegisterValue>) {
            self.future_values.borrow_mut().push(address);
        }
        fn set_future_register_value_for_flow(
            &mut self,
            from_addr: Address,
            _to_addr: Address,
            _value: Box<dyn RegisterValue>,
        ) {
            self.future_values.borrow_mut().push(from_addr);
        }
    }

    #[test]
    fn set_target_context_for_disassembly_with_context_records_future_value_on_odd_offset() {
        let mut ctx = MockDisassemblerContext {
            base_register: mock_register(LOW_BIT_CODE_MODE_REGISTER_NAME),
            future_values: RefCell::new(Vec::new()),
        };

        let result = set_target_context_for_disassembly_with_context(&mut ctx, mock_address(0x3001));

        assert_eq!(result.offset(), 0x3000);
        assert_eq!(
            ctx.future_values.into_inner(),
            vec![mock_address(0x3000)]
        );
    }
}
