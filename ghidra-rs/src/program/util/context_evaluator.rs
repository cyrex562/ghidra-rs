//! Port of `ghidra.program.util.ContextEvaluator`.
//!
//! A callback interface implemented by callers of
//! [`SymbolicPropogator`](crate::program::util::symbolic_propogator::SymbolicPropogator) so they
//! can observe (and influence) constant/context propagation as it happens: veto or stop
//! evaluation, decide whether a computed constant should become a reference, or supply an
//! assumed value for an otherwise-unknown register.
//!
//! This type was itself selected as a dependency-cycle cut-point, so it is ported as a trait. Its
//! `VarnodeContext` parameter is still only an opaque placeholder
//! ([`crate::program::seam_stubs::VarnodeContext`]) since that type has not been ported yet.

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::VarnodeContext;

/// Callback mechanism for [`SymbolicPropogator`](crate::program::util::symbolic_propogator::SymbolicPropogator)
/// as code is evaluated.
///
/// Port of `ghidra.program.util.ContextEvaluator`.
pub trait ContextEvaluator {
    /// Evaluate the current instruction given the context before the instruction is evaluated.
    ///
    /// Port of `ContextEvaluator.evaluateContextBefore(VarnodeContext, Instruction)`.
    ///
    /// Returns true if evaluation should stop.
    fn evaluate_context_before(
        &mut self,
        context: &mut dyn VarnodeContext,
        instr: &dyn Instruction,
    ) -> bool;

    /// Evaluate the current instruction given the final context for the instruction.
    ///
    /// Port of `ContextEvaluator.evaluateContext(VarnodeContext, Instruction)`.
    ///
    /// Returns true if evaluation should stop, false to continue evaluation.
    fn evaluate_context(&mut self, context: &mut dyn VarnodeContext, instr: &dyn Instruction) -> bool;

    /// Evaluate the reference that has been found on this instruction. Computed values that are
    /// used as an address will be passed to this function -- for example a value passed to a
    /// function, or a stored constant value.
    ///
    /// Port of
    /// `ContextEvaluator.evaluateReference(VarnodeContext, Instruction, int, Address, int, DataType, RefType)`.
    ///
    /// Returns false if the reference should be ignored (or has been taken care of by this
    /// routine).
    #[allow(clippy::too_many_arguments)]
    fn evaluate_reference(
        &mut self,
        context: &mut dyn VarnodeContext,
        instr: &dyn Instruction,
        pcodeop: i32,
        address: &Address,
        size: i32,
        data_type: Option<&dyn DataType>,
        ref_type: RefType,
    ) -> bool;

    /// Evaluate a potential constant to be used as an address or an interesting constant that
    /// should have a reference created for it. Computed values that are not known to be used as
    /// an address will be passed to this function -- for example a value passed to a function, or
    /// a stored constant value.
    ///
    /// Port of
    /// `ContextEvaluator.evaluateConstant(VarnodeContext, Instruction, int, Address, int, DataType, RefType)`.
    ///
    /// Returns `Some(constant)` unchanged if it should be a reference, `None` if the constant
    /// reference should not be created, or `Some(other_address)` if the value should be a
    /// different address or address space.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_constant(
        &mut self,
        context: &mut dyn VarnodeContext,
        instr: &dyn Instruction,
        pcodeop: i32,
        constant: &Address,
        size: i32,
        data_type: Option<&dyn DataType>,
        ref_type: RefType,
    ) -> Option<Address>;

    /// Evaluate the instruction for an unknown destination.
    ///
    /// Port of `ContextEvaluator.evaluateDestination(VarnodeContext, Instruction)`.
    ///
    /// Returns true if the evaluation should stop, false to continue evaluation.
    fn evaluate_destination(
        &mut self,
        context: &mut dyn VarnodeContext,
        instruction: &dyn Instruction,
    ) -> bool;

    /// Evaluate the target of a return.
    ///
    /// Port of `ContextEvaluator.evaluateReturn(Varnode, VarnodeContext, Instruction)`.
    ///
    /// Returns true if the evaluation should stop, false to continue evaluation.
    fn evaluate_return(
        &mut self,
        ret_vn: &Varnode,
        context: &mut dyn VarnodeContext,
        instruction: &dyn Instruction,
    ) -> bool;

    /// Called when a value is needed for a register that is unknown.
    ///
    /// Port of `ContextEvaluator.unknownValue(VarnodeContext, Instruction, Varnode)`.
    ///
    /// Returns `None` if the varnode should not have an assumed value, or `Some(value)` if the
    /// varnode (such as a global register) should have an assumed constant value.
    fn unknown_value(
        &mut self,
        context: &mut dyn VarnodeContext,
        instruction: &dyn Instruction,
        node: &Varnode,
    ) -> Option<i64>;

    /// Follow all branches, even if the condition evaluates to false, indicating it shouldn't be
    /// followed.
    ///
    /// Port of `ContextEvaluator.followFalseConditionalBranches()`.
    ///
    /// Returns true if false-evaluated conditional branches should be followed.
    fn follow_false_conditional_branches(&self) -> bool;

    /// Evaluate the reference that has been found on this instruction that points into an
    /// unknown space that has been designated as tracked.
    ///
    /// Port of `ContextEvaluator.evaluateSymbolicReference(VarnodeContext, Instruction, Address)`.
    ///
    /// Returns false if the reference should be ignored (or has been taken care of by this
    /// routine), true to allow the reference to be created.
    fn evaluate_symbolic_reference(
        &mut self,
        context: &mut dyn VarnodeContext,
        instr: &dyn Instruction,
        address: &Address,
    ) -> bool;

    /// Evaluate the address and check if access to the value in the memory location to be read
    /// should be allowed. The address is read-only and is not close to this address.
    ///
    /// Port of `ContextEvaluator.allowAccess(VarnodeContext, Address)`.
    ///
    /// Returns true if the access should be allowed.
    fn allow_access(&mut self, context: &mut dyn VarnodeContext, addr: &Address) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::instruction::tests::mock_instruction;

    struct StubVarnodeContext;
    impl VarnodeContext for StubVarnodeContext {}

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// An evaluator that stops as soon as it sees a reference into a "forbidden" address range,
    /// and otherwise assumes a fixed value for unknown registers -- exercising the veto/assumed
    /// -value behavior real implementations rely on, not just default-returning stubs.
    struct GuardedEvaluator {
        forbidden_offset: i64,
        assumed_register_value: i64,
        stopped: bool,
        allowed_access_count: u32,
    }

    impl ContextEvaluator for GuardedEvaluator {
        fn evaluate_context_before(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instr: &dyn Instruction,
        ) -> bool {
            false
        }

        fn evaluate_context(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instr: &dyn Instruction,
        ) -> bool {
            false
        }

        fn evaluate_reference(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instr: &dyn Instruction,
            _pcodeop: i32,
            address: &Address,
            _size: i32,
            _data_type: Option<&dyn DataType>,
            _ref_type: RefType,
        ) -> bool {
            if address.offset() == self.forbidden_offset {
                self.stopped = true;
                return false;
            }
            true
        }

        fn evaluate_constant(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instr: &dyn Instruction,
            _pcodeop: i32,
            constant: &Address,
            _size: i32,
            _data_type: Option<&dyn DataType>,
            _ref_type: RefType,
        ) -> Option<Address> {
            if constant.offset() == self.forbidden_offset {
                None
            } else {
                Some(constant.clone())
            }
        }

        fn evaluate_destination(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instruction: &dyn Instruction,
        ) -> bool {
            self.stopped
        }

        fn evaluate_return(
            &mut self,
            _ret_vn: &Varnode,
            _context: &mut dyn VarnodeContext,
            _instruction: &dyn Instruction,
        ) -> bool {
            self.stopped
        }

        fn unknown_value(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instruction: &dyn Instruction,
            _node: &Varnode,
        ) -> Option<i64> {
            Some(self.assumed_register_value)
        }

        fn follow_false_conditional_branches(&self) -> bool {
            false
        }

        fn evaluate_symbolic_reference(
            &mut self,
            _context: &mut dyn VarnodeContext,
            _instr: &dyn Instruction,
            address: &Address,
        ) -> bool {
            address.offset() != self.forbidden_offset
        }

        fn allow_access(&mut self, _context: &mut dyn VarnodeContext, addr: &Address) -> bool {
            self.allowed_access_count += 1;
            addr.offset() != self.forbidden_offset
        }
    }

    #[test]
    fn guarded_evaluator_is_object_safe_and_vetoes_forbidden_addresses() {
        let mut evaluator = GuardedEvaluator {
            forbidden_offset: 0xdead,
            assumed_register_value: 42,
            stopped: false,
            allowed_access_count: 0,
        };
        let dyn_eval: &mut dyn ContextEvaluator = &mut evaluator;

        let mut v_context = StubVarnodeContext;
        let instr = mock_instruction(mock_address(0x1000), mock_address(0x1000));
        let forbidden = mock_address(0xdead);
        let ok = mock_address(0x2000);

        assert!(!dyn_eval.follow_false_conditional_branches());

        // A normal address flows through evaluate_reference/evaluate_constant unchanged.
        assert!(dyn_eval.evaluate_reference(
            &mut v_context,
            instr.as_ref(),
            0,
            &ok,
            4,
            None,
            RefType::Data,
        ));
        assert_eq!(
            dyn_eval.evaluate_constant(&mut v_context, instr.as_ref(), 0, &ok, 4, None, RefType::Data),
            Some(ok.clone())
        );

        // Hitting the forbidden address vetoes the reference and latches "stopped".
        assert!(!dyn_eval.evaluate_reference(
            &mut v_context,
            instr.as_ref(),
            0,
            &forbidden,
            4,
            None,
            RefType::Data,
        ));
        assert_eq!(
            dyn_eval.evaluate_constant(
                &mut v_context,
                instr.as_ref(),
                0,
                &forbidden,
                4,
                None,
                RefType::Data
            ),
            None
        );
        assert!(dyn_eval.evaluate_destination(&mut v_context, instr.as_ref()));

        let node = Varnode::new(mock_address(0), 4);
        assert_eq!(
            dyn_eval.unknown_value(&mut v_context, instr.as_ref(), &node),
            Some(42)
        );

        assert!(dyn_eval.allow_access(&mut v_context, &ok));
        assert!(!dyn_eval.allow_access(&mut v_context, &forbidden));
        assert_eq!(evaluator.allowed_access_count, 2);
    }
}
