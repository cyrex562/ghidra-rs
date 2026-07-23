//! Port of `ghidra.program.util.SymbolicPropogator`.
//!
//! Simulates the flow of constants (and register-relative values) through a subroutine's
//! p-code, creating references and recording register values along the way. The Java class is a
//! large, deeply stateful engine (an `applyPcode` interpreter loop, per-address instruction/pcode
//! caches, a saved-flow-state stack, etc.) built directly on top of two other unported classes:
//! `VarnodeContext` (the register/memory value store the interpreter reads and writes) and
//! `ContextEvaluator` (a caller-supplied callback interface). Both are modeled here with the
//! minimal opaque placeholders
//! [`VarnodeContext`](crate::program::seam_stubs::VarnodeContext) and
//! [`ContextEvaluator`](crate::program::seam_stubs::ContextEvaluator) in
//! [`crate::program::seam_stubs`], since this type's own trait methods only ever pass them
//! through (never call a method on them) -- the real interpreter body that *would* call into
//! them belongs to the eventual concrete implementation, not to this trait's default methods.
//!
//! This type was selected as a dependency-cycle cut-point, so it is ported here as a trait
//! rather than a struct. Every Java overload set becomes one Rust method with a disambiguating
//! suffix (Rust has no overloading): the three `flowConstants` overloads become
//! `flow_constants`/`flow_constants_with_context`/`flow_constants_from`, and the two
//! `makeReference` overloads become `make_reference`/`make_reference_full`. All trait methods are
//! left abstract (no default body) except `flow_constants_with_context`, which mirrors the Java
//! overload that just forwards to the five-argument form with `Address.NO_ADDRESS` as the
//! `fromAddr` -- that forwarding needs no access to private interpreter state, so it is kept as a
//! genuine default method.
//!
//! The `SymbolicPropogator(Program)`/`SymbolicPropogator(Program, boolean)` constructors are not
//! modeled as trait methods: a Rust trait describes behavior on an existing value, not how to
//! build one, and a future concrete implementation is free to define its own `new`/`with_options`
//! associated functions.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressSet, AddressSetView, SpecialAddress};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::{Function, Instruction};
use crate::program::model::pcode::{PcodeOp, Varnode};
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::{ContextEvaluator, VarnodeContext};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A constant value or register-relative value produced by constant propagation.
///
/// Port of `SymbolicPropogator.Value`.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolicValue {
    relative_register: Option<RegisterRef>,
    value: i64,
}

impl SymbolicValue {
    /// Construct a plain constant value.
    pub fn new_constant(value: i64) -> Self {
        SymbolicValue {
            relative_register: None,
            value,
        }
    }

    /// Construct a value relative to the given register.
    pub fn new_relative(relative_register: RegisterRef, value: i64) -> Self {
        SymbolicValue {
            relative_register: Some(relative_register),
            value,
        }
    }

    /// Constant value. This value is register-relative if
    /// [`SymbolicValue::is_register_relative_value`] returns true.
    ///
    /// Port of `SymbolicPropogator.Value.getValue()`.
    pub fn get_value(&self) -> i64 {
        match &self.relative_register {
            Some(reg) => {
                let size = reg.borrow().bit_length();
                let shift = (64 - size) as u32;
                (self.value << shift) >> shift
            }
            None => self.value,
        }
    }

    /// True if this value is relative to a particular input register.
    ///
    /// Port of `SymbolicPropogator.Value.isRegisterRelativeValue()`.
    pub fn is_register_relative_value(&self) -> bool {
        self.relative_register.is_some()
    }

    /// The relative register, or `None` if this value is a simple constant.
    ///
    /// Port of `SymbolicPropogator.Value.getRelativeRegister()`.
    pub fn get_relative_register(&self) -> Option<RegisterRef> {
        self.relative_register.clone()
    }
}

/// Simulates the flow of constants through a subroutine, creating references and recording
/// register values along the way.
///
/// Port of `ghidra.program.util.SymbolicPropogator`.
pub trait SymbolicPropogator {
    /// Enable/disable verbose debug logging of each instruction/pcode-op as it is evaluated.
    ///
    /// Port of `SymbolicPropogator.setDebug(boolean)`.
    fn set_debug(&mut self, debug: bool);

    /// Process a subroutine using the processor function. The process function can control what
    /// flows are followed and when to stop.
    ///
    /// Port of
    /// `SymbolicPropogator.flowConstants(Address, AddressSetView, ContextEvaluator, boolean, TaskMonitor)`.
    fn flow_constants(
        &mut self,
        start_addr: Address,
        restrict_set: Option<&dyn AddressSetView>,
        eval: &mut dyn ContextEvaluator,
        save_context: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledException>;

    /// Process a subroutine starting at `start_addr` using an existing varnode context.
    ///
    /// Port of
    /// `SymbolicPropogator.flowConstants(Address, AddressSetView, ContextEvaluator, VarnodeContext, TaskMonitor)`,
    /// which just forwards to the five-argument overload with `Address.NO_ADDRESS` as the source
    /// address.
    fn flow_constants_with_context(
        &mut self,
        start_addr: Address,
        restrict_set: Option<&dyn AddressSetView>,
        eval: &mut dyn ContextEvaluator,
        v_context: &mut dyn VarnodeContext,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledException> {
        self.flow_constants_from(
            SpecialAddress::no_address(),
            start_addr,
            restrict_set,
            eval,
            v_context,
            monitor,
        )
    }

    /// Process a subroutine using the processor function, flowing from `from_addr` into
    /// `start_addr` using an existing varnode context. Returns the address set of instructions
    /// that were followed.
    ///
    /// Port of
    /// `SymbolicPropogator.flowConstants(Address, Address, AddressSetView, ContextEvaluator, VarnodeContext, TaskMonitor)`.
    fn flow_constants_from(
        &mut self,
        from_addr: Address,
        start_addr: Address,
        restrict_set: Option<&dyn AddressSetView>,
        eval: &mut dyn ContextEvaluator,
        v_context: &mut dyn VarnodeContext,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledException>;

    /// Get the constant or register-relative value assigned to the specified register at the
    /// specified address. Only valid if the propagator was created with `recordStartEndState`.
    ///
    /// Port of `SymbolicPropogator.getRegisterValue(Address, Register)`.
    fn get_register_value(&self, to_addr: &Address, reg: &Register) -> Option<SymbolicValue>;

    /// Get the constant or register-relative value assigned to the specified register at the
    /// specified address after the instruction has executed. Only valid if the propagator was
    /// created with `recordStartEndState`.
    ///
    /// Port of `SymbolicPropogator.getEndRegisterValue(Address, Register)`.
    fn get_end_register_value(&self, to_addr: &Address, reg: &Register) -> Option<SymbolicValue>;

    /// Get a display-debugging representation of the value assigned to `reg` at `addr`.
    ///
    /// Port of `SymbolicPropogator.getRegisterValueRepresentation(Address, Register)`.
    fn get_register_value_representation(&self, addr: &Address, reg: &Register) -> String;

    /// Directly set the value of a register (typically a stack pointer) at the given address to
    /// point at offset zero of its own space, without running the flow-constants interpreter.
    ///
    /// Port of `SymbolicPropogator.setRegister(Address, Register)`.
    fn set_register(&mut self, addr: &Address, stack_reg: &Register);

    /// Get the p-code for an instruction, using (and populating) the propagator's internal cache.
    ///
    /// Port of `SymbolicPropogator.getInstructionPcode(Instruction)`.
    fn get_instruction_pcode(&mut self, instruction: &dyn Instruction) -> Vec<PcodeOp>;

    /// Get the instruction at the given address, using (and populating) the propagator's
    /// internal cache.
    ///
    /// Port of `SymbolicPropogator.getInstructionAt(Address)`.
    fn get_instruction_at(&mut self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Get the function at the given address, using (and populating) the propagator's internal
    /// cache.
    ///
    /// Port of `SymbolicPropogator.getFunctionAt(Address)`.
    fn get_function_at(&mut self, addr: &Address) -> Option<Arc<dyn Function>>;

    /// Get the instruction containing the given address, using (and populating) the propagator's
    /// internal caches.
    ///
    /// Port of `SymbolicPropogator.getInstructionContaining(Address)`.
    fn get_instruction_containing(&mut self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Make a reference from `instruction` based on the varnode passed in, which could be a full
    /// address or just a constant offset.
    ///
    /// Port of
    /// `SymbolicPropogator.makeReference(VarnodeContext, Instruction, int, Varnode, DataType, RefType, int, boolean, TaskMonitor)`.
    #[allow(clippy::too_many_arguments)]
    fn make_reference(
        &mut self,
        varnode_context: &mut dyn VarnodeContext,
        instruction: &dyn Instruction,
        op_index: i32,
        vt: &Varnode,
        data_type: Option<&dyn DataType>,
        ref_type: RefType,
        pcodeop: i32,
        known_reference: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>;

    /// Make a reference from `instruction` to the address described by `known_space_id`/
    /// `word_offset`, which could resolve into an overlay, into memory, or to an external
    /// address.
    ///
    /// Port of
    /// `SymbolicPropogator.makeReference(VarnodeContext, Instruction, int, long, long, int, DataType, RefType, int, boolean, boolean, TaskMonitor)`.
    #[allow(clippy::too_many_arguments)]
    fn make_reference_full(
        &mut self,
        v_context: &mut dyn VarnodeContext,
        instruction: &dyn Instruction,
        op_index: i32,
        known_space_id: i64,
        word_offset: i64,
        size: i32,
        data_type: Option<&dyn DataType>,
        ref_type: RefType,
        pcodeop: i32,
        known_reference: bool,
        pre_existing: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>;

    /// True if any branching flow (call, jump, or non-fallthrough) was encountered while flowing
    /// constants.
    ///
    /// Port of `SymbolicPropogator.encounteredBranch()`.
    fn encountered_branch(&self) -> bool;

    /// True if any executable address was read as data while flowing constants.
    ///
    /// Port of `SymbolicPropogator.readExecutable()`.
    fn read_executable(&self) -> bool;

    /// Set whether parameters to called functions should be checked for references.
    ///
    /// Port of `SymbolicPropogator.setParamRefCheck(boolean)`.
    fn set_param_ref_check(&mut self, check_param_refs_option: bool);

    /// Set whether a parameter must be a marked pointer data type to be checked for references.
    ///
    /// Port of `SymbolicPropogator.setParamPointerRefCheck(boolean)`.
    fn set_param_pointer_ref_check(&mut self, check_param_refs_option: bool);

    /// Set whether return values from functions should be checked for references.
    ///
    /// Port of `SymbolicPropogator.setReturnRefCheck(boolean)`.
    fn set_return_ref_check(&mut self, check_return_refs_option: bool);

    /// Set whether stored values should be checked for references.
    ///
    /// Port of `SymbolicPropogator.setStoredRefCheck(boolean)`.
    fn set_stored_ref_check(&mut self, check_stored_refs_option: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn mock_register(name: &str, bit_length: i32) -> RegisterRef {
        Register::new(
            name.to_string(),
            "",
            SpecialAddress::no_address(),
            (bit_length + 7) / 8,
            false,
            0,
        )
    }

    #[test]
    fn symbolic_value_sign_extends_register_relative_offset() {
        // A 32-bit register holding offset -1 (0xFFFFFFFF) should sign-extend to a full -1 when
        // read back as an i64, mirroring `Value.getValue()`'s shift-based sign extension.
        let esp = mock_register("ESP", 32);
        let value = SymbolicValue::new_relative(esp.clone(), 0xFFFF_FFFFi64);

        assert!(value.is_register_relative_value());
        assert_eq!(value.get_relative_register(), Some(esp));
        assert_eq!(value.get_value(), -1);
    }

    #[test]
    fn symbolic_value_plain_constant_is_not_relative() {
        let value = SymbolicValue::new_constant(0x1234);

        assert!(!value.is_register_relative_value());
        assert_eq!(value.get_relative_register(), None);
        assert_eq!(value.get_value(), 0x1234);
    }

    struct MockPropagator {
        debug: bool,
        branch_seen: bool,
    }

    impl SymbolicPropogator for MockPropagator {
        fn set_debug(&mut self, debug: bool) {
            self.debug = debug;
        }

        fn flow_constants(
            &mut self,
            start_addr: Address,
            _restrict_set: Option<&dyn AddressSetView>,
            _eval: &mut dyn ContextEvaluator,
            _save_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<AddressSet, CancelledException> {
            self.branch_seen = true;
            let mut set = AddressSet::new();
            set.add_address(&start_addr);
            Ok(set)
        }

        fn flow_constants_from(
            &mut self,
            _from_addr: Address,
            start_addr: Address,
            restrict_set: Option<&dyn AddressSetView>,
            eval: &mut dyn ContextEvaluator,
            _v_context: &mut dyn VarnodeContext,
            monitor: &dyn TaskMonitor,
        ) -> Result<AddressSet, CancelledException> {
            self.flow_constants(start_addr, restrict_set, eval, true, monitor)
        }

        fn get_register_value(&self, _to_addr: &Address, _reg: &Register) -> Option<SymbolicValue> {
            None
        }

        fn get_end_register_value(
            &self,
            _to_addr: &Address,
            _reg: &Register,
        ) -> Option<SymbolicValue> {
            None
        }

        fn get_register_value_representation(&self, _addr: &Address, _reg: &Register) -> String {
            "-".to_string()
        }

        fn set_register(&mut self, _addr: &Address, _stack_reg: &Register) {}

        fn get_instruction_pcode(&mut self, _instruction: &dyn Instruction) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_instruction_at(&mut self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_function_at(&mut self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_instruction_containing(&mut self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn make_reference(
            &mut self,
            _varnode_context: &mut dyn VarnodeContext,
            _instruction: &dyn Instruction,
            _op_index: i32,
            _vt: &Varnode,
            _data_type: Option<&dyn DataType>,
            _ref_type: RefType,
            _pcodeop: i32,
            _known_reference: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Address> {
            None
        }

        fn make_reference_full(
            &mut self,
            _v_context: &mut dyn VarnodeContext,
            _instruction: &dyn Instruction,
            _op_index: i32,
            _known_space_id: i64,
            _word_offset: i64,
            _size: i32,
            _data_type: Option<&dyn DataType>,
            _ref_type: RefType,
            _pcodeop: i32,
            _known_reference: bool,
            _pre_existing: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Address> {
            None
        }

        fn encountered_branch(&self) -> bool {
            self.branch_seen
        }

        fn read_executable(&self) -> bool {
            false
        }

        fn set_param_ref_check(&mut self, _check_param_refs_option: bool) {}
        fn set_param_pointer_ref_check(&mut self, _check_param_refs_option: bool) {}
        fn set_return_ref_check(&mut self, _check_return_refs_option: bool) {}
        fn set_stored_ref_check(&mut self, _check_stored_refs_option: bool) {}
    }

    struct StubEvaluator;
    impl ContextEvaluator for StubEvaluator {}

    struct StubVarnodeContext;
    impl VarnodeContext for StubVarnodeContext {}

    #[test]
    fn flow_constants_with_context_forwards_through_default_method_and_is_object_safe() {
        let mut propagator = MockPropagator {
            debug: false,
            branch_seen: false,
        };
        let dyn_propagator: &mut dyn SymbolicPropogator = &mut propagator;

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0x1000);

        let mut evaluator = StubEvaluator;
        let mut v_context = StubVarnodeContext;
        let monitor = crate::util::task::DummyMonitor;

        assert!(!dyn_propagator.encountered_branch());

        let result = dyn_propagator
            .flow_constants_with_context(
                start.clone(),
                None,
                &mut evaluator,
                &mut v_context,
                &monitor,
            )
            .expect("flow_constants_with_context should succeed");

        assert!(result.contains(&start));
        assert!(dyn_propagator.encountered_branch());
    }
}
