//! Port of `ghidra.lisa.pcode.contexts.InstructionContext`.
//!
//! # Shape
//!
//! Java's `InstructionContext` is a concrete class that is also subclassed
//! (`HighInstructionContext`), and it carries instance state (`function`, `inst`, `ops`, `loc`).
//! Per `scripts/shape_rules.py` (R11) that splits into a shared-state struct,
//! [`InstructionContextBase`], which holds the fields and the concrete accessors, plus the
//! [`InstructionContext`] trait, which declares only the behaviour a subclass overrides (`next`).
//! [`InstructionContextBase`] is itself the port of the plain Java class and implements the trait.
//!
//! # Deviations from Java
//!
//! * [`InstructionContext::next`] takes the [`Listing`] to search as a parameter. Java reads it
//!   through `inst.getProgram().getListing()`; in this crate `Program::get_listing` needs
//!   `&mut self`, which a shared `Arc<dyn Program>` obtained from an instruction cannot provide.
//!   The p-code visitor that walks these contexts already holds the unit's listing (Java's
//!   `PcodeCodeMemberVisitor` is constructed with `ctx.getListing()`), so the caller supplies it.
//! * When the address following the instruction overflows its address space, Java's
//!   `Address.add` throws `AddressOutOfBoundsException`. No instruction can follow in that case,
//!   so [`InstructionContext::next`] returns `None` instead.

use std::sync::Arc;

use crate::feature::lisa::pcode::contexts::statement_context::StatementContext;
use crate::feature::lisa::pcode::locations::{CodeLocation, InstLocation};
use crate::program::model::listing::{Function, Instruction, Listing};
use crate::program::model::mem::MemBuffer;

/// Shared state of a LiSA instruction context: the p-code statements of one machine instruction,
/// together with the function and instruction they came from.
///
/// Port of the concrete Java class `ghidra.lisa.pcode.contexts.InstructionContext` (its fields and
/// non-overridden methods). See the module docs for the struct/trait split.
pub struct InstructionContextBase {
    function: Option<Arc<dyn Function>>,
    inst: Option<Arc<dyn Instruction>>,
    ops: Vec<StatementContext>,
    loc: Option<InstLocation>,
}

impl InstructionContextBase {
    /// Builds the context for `inst` inside `function`: one [`StatementContext`] per p-code op of
    /// the instruction, and an [`InstLocation`] at the instruction's address.
    ///
    /// Port of `InstructionContext(Function, Instruction)`.
    pub fn new(function: Arc<dyn Function>, inst: Arc<dyn Instruction>) -> Self {
        let ops = inst
            .get_pcode()
            .into_iter()
            .map(|op| StatementContext::new(inst.clone(), op))
            .collect();
        let loc = InstLocation::new(function.clone(), MemBuffer::get_address(inst.as_ref()));
        Self { function: Some(function), inst: Some(inst), ops, loc: Some(loc) }
    }

    /// Builds a context with no function, instruction or location, holding only `ops`.
    ///
    /// Port of the no-arg `InstructionContext()` constructor ("For HighInstructionContext"),
    /// fused with the subclass constructor's assignment of the protected `ops` field.
    pub fn from_ops(ops: Vec<StatementContext>) -> Self {
        Self { function: None, inst: None, ops, loc: None }
    }

    /// The function this instruction belongs to, if any (Java's protected `function` field).
    pub fn function(&self) -> Option<&Arc<dyn Function>> {
        self.function.as_ref()
    }

    /// The instruction this context was built from, if any (Java's protected `inst` field).
    pub fn inst(&self) -> Option<&Arc<dyn Instruction>> {
        self.inst.as_ref()
    }

    /// The p-code statements of this instruction.
    ///
    /// Port of `getPcodeOps()`.
    pub fn get_pcode_ops(&self) -> &[StatementContext] {
        &self.ops
    }

    /// The `i`-th p-code statement of this instruction.
    ///
    /// Port of `getPcodeOp(int)`.
    ///
    /// # Panics
    ///
    /// If `i` is out of range, as Java's `List.get` throws `IndexOutOfBoundsException`.
    pub fn get_pcode_op(&self, i: usize) -> &StatementContext {
        &self.ops[i]
    }

    /// The code location of this instruction, or `None` for a context built by
    /// [`from_ops`](Self::from_ops) (Java leaves `loc` null there).
    ///
    /// Port of `location()`.
    pub fn location(&self) -> Option<&dyn CodeLocation> {
        self.loc.as_ref().map(|loc| loc as &dyn CodeLocation)
    }
}

/// Overridable behaviour of a LiSA instruction context.
///
/// Port of the methods of `ghidra.lisa.pcode.contexts.InstructionContext` that its subclasses
/// override. The shared state and the remaining accessors live on [`InstructionContextBase`],
/// reached through [`base`](Self::base).
pub trait InstructionContext {
    /// The shared state of this context.
    fn base(&self) -> &InstructionContextBase;

    /// The context for the instruction immediately following this one in `listing`, or `None`
    /// when this context has no instruction or no instruction starts right after it.
    ///
    /// Port of `next()`. See the module docs for why `listing` is a parameter.
    fn next(&self, listing: &dyn Listing) -> Option<InstructionContextBase>;
}

impl InstructionContext for InstructionContextBase {
    fn base(&self) -> &InstructionContextBase {
        self
    }

    fn next(&self, listing: &dyn Listing) -> Option<InstructionContextBase> {
        let inst = self.inst.as_ref()?;
        let next_address = MemBuffer::get_address(inst.as_ref())
            .add(i64::from(inst.get_length()))
            .ok()?;
        let next = listing.get_instruction_at(&next_address)?;
        let function = self
            .function
            .clone()
            .expect("an InstructionContext with an instruction always has a function");
        Some(InstructionContextBase::new(function, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::lisa::pcode::locations::inst_location::tests::MockFunction;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::{InstructionStub, StubListing};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn copy_op(addr: &Address, out: i64) -> PcodeOp {
        let space = ram();
        PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(addr.clone(), 0),
            vec![Varnode::new(Address::new(space.clone(), 0x20), 4)],
            Some(Varnode::new(Address::new(space, out), 4)),
        )
    }

    struct FakeInstruction {
        addr: Address,
        length: i32,
        pcode: Vec<PcodeOp>,
    }

    impl InstructionStub for FakeInstruction {
        fn get_membuffer_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_pcode(&self) -> Vec<PcodeOp> {
            self.pcode.clone()
        }
    }

    fn instruction(offset: i64, length: i32, n_ops: usize) -> Arc<dyn Instruction> {
        let addr = Address::new(ram(), offset);
        let pcode = (0..n_ops).map(|i| copy_op(&addr, 0x100 + i as i64)).collect();
        Arc::new(FakeInstruction { addr, length, pcode })
    }

    /// A listing holding a fixed set of instructions, keyed by start address.
    struct FakeListing(Vec<Arc<dyn Instruction>>);

    impl StubListing for FakeListing {
        fn get_instruction_at(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
            self.0.iter().find(|i| &MemBuffer::get_address(i.as_ref()) == addr).cloned()
        }
    }

    #[test]
    fn new_builds_one_statement_per_pcode_op_and_location_at_instruction() {
        let ctx = InstructionContextBase::new(Arc::new(MockFunction), instruction(0x1000, 4, 3));

        assert_eq!(ctx.get_pcode_ops().len(), 3);
        assert_eq!(
            ctx.get_pcode_op(1).get_op().get_output().unwrap().get_address(),
            &Address::new(ram(), 0x101)
        );
        let loc = ctx.location().expect("location");
        assert_eq!(loc.get_code_location(), Address::new(ram(), 0x1000).to_string());
        assert!(ctx.inst().is_some());
        assert!(ctx.function().is_some());
    }

    #[test]
    fn next_finds_the_instruction_at_address_plus_length() {
        let first = instruction(0x1000, 4, 1);
        let second = instruction(0x1004, 2, 2);
        let listing = FakeListing(vec![first.clone(), second]);
        let ctx = InstructionContextBase::new(Arc::new(MockFunction), first);

        let next = ctx.next(&listing).expect("next instruction");
        assert_eq!(next.get_pcode_ops().len(), 2);
        assert_eq!(
            next.location().unwrap().get_code_location(),
            Address::new(ram(), 0x1004).to_string()
        );
        // 0x1004 + 2 has no instruction.
        assert!(next.next(&listing).is_none());
    }

    #[test]
    fn from_ops_context_has_no_location_and_no_next() {
        let ctx = InstructionContextBase::from_ops(vec![StatementContext::from_op(copy_op(
            &Address::new(ram(), 0x2000),
            0x10,
        ))]);
        assert_eq!(ctx.get_pcode_ops().len(), 1);
        assert!(ctx.location().is_none());
        assert!(ctx.next(&FakeListing(vec![])).is_none());
    }

    #[test]
    #[should_panic]
    fn get_pcode_op_out_of_range_panics() {
        let ctx = InstructionContextBase::new(Arc::new(MockFunction), instruction(0x1000, 4, 0));
        let _ = ctx.get_pcode_op(0);
    }

    #[test]
    fn works_through_the_trait_object() {
        let ctx = InstructionContextBase::new(Arc::new(MockFunction), instruction(0x3000, 1, 2));
        let dyn_ctx: &dyn InstructionContext = &ctx;
        assert_eq!(dyn_ctx.base().get_pcode_ops().len(), 2);
    }
}
