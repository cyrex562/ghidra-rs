//! Port of `ghidra.pcode.pcoderaw.PcodeOpRaw`.
//!
//! Java's `PcodeOpRaw extends PcodeOp` purely for reuse: it adds a cached `OpBehavior` and an
//! address convenience accessor. Rust has no implementation inheritance, so the struct embeds the
//! base [`PcodeOp`] and exposes its read-only API through [`Deref`].
//!
//! `OpBehaviorFactory.getOpBehavior(int)` is not ported as a type in this crate: the behaviors in
//! [`opbehavior`](crate::pcode::opbehavior) carry no per-op instance state beyond the opcode, so
//! an [`OpBehavior`] is fully determined by the opcode. Whether the factory has an entry at all
//! (it returns `null` for `UNIMPLEMENTED`) is decided by
//! [`op_behavior_kind`](crate::pcode::exec::pcode_executor::op_behavior_kind), which mirrors the
//! factory's table entry for entry. Java's `null` becomes `None`.

use std::ops::Deref;

use crate::pcode::exec::pcode_executor::{op_behavior_kind, OpBehaviorKind};
use crate::pcode::opbehavior::op_behavior::OpBehavior;
use crate::program::model::address::Address;
use crate::program::model::pcode::PcodeOp;

/// A p-code operation paired with the behavior object that evaluates it.
///
/// Port of `ghidra.pcode.pcoderaw.PcodeOpRaw`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcodeOpRaw {
    op: PcodeOp,
    behave: Option<OpBehavior>,
}

impl PcodeOpRaw {
    /// Port of `PcodeOpRaw(PcodeOp op)`: copies the op's sequence number, opcode, inputs and
    /// output, and looks up the behavior for its opcode.
    pub fn new(op: &PcodeOp) -> Self {
        Self::from(op.clone())
    }

    /// Get the underlying behavior object for this p-code operation. From this object you can
    /// determine how the operation evaluates its inputs to get the output.
    ///
    /// Port of `PcodeOpRaw.getBehavior()`. Returns `None` where Java's factory has no entry for
    /// the opcode (i.e., `UNIMPLEMENTED`), where Java would return `null`.
    pub fn get_behavior(&self) -> Option<OpBehavior> {
        self.behave
    }

    /// Get the address of the machine instruction of which this p-code op is a translation.
    ///
    /// Port of `PcodeOpRaw.getAddress()`, i.e. `getSeqnum().getTarget()`.
    pub fn get_address(&self) -> &Address {
        self.op.get_seqnum().get_target()
    }

    /// The embedded base [`PcodeOp`].
    pub fn pcode_op(&self) -> &PcodeOp {
        &self.op
    }
}

impl From<PcodeOp> for PcodeOpRaw {
    fn from(op: PcodeOp) -> Self {
        let opcode = op.get_opcode();
        let behave = match op_behavior_kind(opcode) {
            OpBehaviorKind::Undefined => None,
            OpBehaviorKind::Unary | OpBehaviorKind::Binary | OpBehaviorKind::Special => {
                Some(OpBehavior::new(opcode as i32))
            }
        };
        Self { op, behave }
    }
}

impl Deref for PcodeOpRaw {
    type Target = PcodeOp;

    fn deref(&self) -> &PcodeOp {
        &self.op
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, Varnode};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn int_add_op() -> PcodeOp {
        let space = ram();
        let a = Varnode::new(Address::new(space.clone(), 0x100), 4);
        let b = Varnode::new(Address::new(space.clone(), 0x104), 4);
        let out = Varnode::new(Address::new(space.clone(), 0x108), 4);
        PcodeOp::with_address(Address::new(space, 0x401000), 3, OpCode::IntAdd, vec![a, b], Some(out))
    }

    #[test]
    fn copies_base_op_fields() {
        let op = int_add_op();
        let raw = PcodeOpRaw::new(&op);
        assert_eq!(raw.get_opcode(), OpCode::IntAdd);
        assert_eq!(raw.get_num_inputs(), 2);
        assert_eq!(raw.get_input(0).unwrap().get_offset(), 0x100);
        assert_eq!(raw.get_input(1).unwrap().get_offset(), 0x104);
        assert_eq!(raw.get_output().unwrap().get_offset(), 0x108);
        assert_eq!(raw.get_seqnum(), op.get_seqnum());
        assert_eq!(raw.pcode_op(), &op);
    }

    #[test]
    fn address_is_seqnum_target() {
        let raw = PcodeOpRaw::new(&int_add_op());
        assert_eq!(raw.get_address().offset(), 0x401000);
        assert_eq!(raw.get_seqnum().uniq, 3);
    }

    #[test]
    fn behavior_matches_opcode_for_mapped_ops() {
        // INT_ADD = 19, COPY = 1, LOAD = 2 (a SpecialOpBehavior), LZCOUNT = 73.
        let raw = PcodeOpRaw::new(&int_add_op());
        assert_eq!(raw.get_behavior(), Some(OpBehavior::new(19)));

        let space = ram();
        for (opcode, value) in [(OpCode::Copy, 1), (OpCode::Load, 2), (OpCode::Lzcount, 73)] {
            let op = PcodeOp::with_address_no_inputs(Address::new(space.clone(), 0), 0, opcode);
            let raw = PcodeOpRaw::from(op);
            assert_eq!(raw.get_behavior().map(|b| b.opcode()), Some(value));
        }
    }

    #[test]
    fn unimplemented_has_no_behavior() {
        // OpBehaviorFactory has no entry for UNIMPLEMENTED, so Java's getBehavior() is null.
        let op = PcodeOp::with_address_no_inputs(Address::new(ram(), 0), 0, OpCode::Unimplemented);
        assert_eq!(PcodeOpRaw::new(&op).get_behavior(), None);
    }
}
