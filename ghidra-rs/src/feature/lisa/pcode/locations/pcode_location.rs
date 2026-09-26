use std::any::Any;
use std::cmp::Ordering;
use std::fmt;

use crate::program::model::address::Address;
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::CodeLocation;

/// A code location identified by a p-code operation's sequence number.
///
/// `PcodeLocation` wraps a single [`PcodeOp`] and identifies a program point by that op's
/// [`SequenceNumber`](crate::program::model::pcode::SequenceNumber), used by the LiSA analysis
/// framework to track program points at p-code granularity (as opposed to
/// [`InstLocation`](super::InstLocation), which tracks at instruction granularity).
///
/// Corresponds to `ghidra.lisa.pcode.locations.PcodeLocation` in the Java source.
#[derive(Debug, Clone)]
pub struct PcodeLocation {
    /// The wrapped p-code operation. Mirrors the Java class's public `op` field.
    pub op: PcodeOp,
}

impl PcodeLocation {
    /// Creates a new p-code location wrapping the given operation.
    ///
    /// Mirrors `PcodeLocation(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Returns the p-code opcode of the wrapped operation.
    ///
    /// Mirrors `PcodeLocation.getOpcode()`. Returns this crate's [`OpCode`] enum rather than
    /// Java's raw `int` opcode, matching [`PcodeOp::get_opcode`] (which already made the same
    /// adaptation).
    pub fn get_opcode(&self) -> OpCode {
        self.op.get_opcode()
    }

    /// Returns the target address of the wrapped operation's sequence number.
    ///
    /// Mirrors `PcodeLocation.getAddress()`.
    pub fn get_address(&self) -> Address {
        self.op.get_seqnum().get_target().clone()
    }
}

impl CodeLocation for PcodeLocation {
    fn compare_to(&self, other: &dyn CodeLocation) -> Ordering {
        if let Some(other_loc) = other.as_any().downcast_ref::<PcodeLocation>() {
            self.op.get_seqnum().cmp(other_loc.op.get_seqnum())
        }
        else {
            Ordering::Less
        }
    }

    fn get_code_location(&self) -> String {
        self.op.get_seqnum().to_string()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for PcodeLocation {
    fn eq(&self, other: &Self) -> bool {
        self.op.get_seqnum() == other.op.get_seqnum()
    }
}

impl Eq for PcodeLocation {}

impl std::hash::Hash for PcodeLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.op.get_seqnum().hash(state);
    }
}

impl fmt::Display for PcodeLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_code_location())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn make_op(space: &std::sync::Arc<AddressSpace>, offset: i64, order: i32, opcode: OpCode) -> PcodeOp {
        let addr = Address::new(space.clone(), offset);
        let seq = SequenceNumber::new(addr, order);
        PcodeOp::new(opcode, seq, Vec::new(), None)
    }

    #[test]
    fn stores_and_returns_wrapped_op_fields() {
        let space = ram_space();
        let op = make_op(&space, 0x1000, 0, OpCode::Copy);
        let loc = PcodeLocation::new(op.clone());

        assert_eq!(loc.get_opcode(), op.get_opcode());
        assert_eq!(loc.get_address(), Address::new(space, 0x1000));
    }

    #[test]
    fn code_location_returns_seqnum_string() {
        let space = ram_space();
        let op = make_op(&space, 0x2000, 0, OpCode::Copy);
        let loc = PcodeLocation::new(op.clone());

        assert_eq!(loc.get_code_location(), op.get_seqnum().to_string());
        assert_eq!(loc.to_string(), loc.get_code_location());
    }

    #[test]
    fn locations_compare_by_seqnum() {
        let space = ram_space();
        let op1 = make_op(&space, 0x1000, 0, OpCode::Copy);
        let op2 = make_op(&space, 0x2000, 0, OpCode::Copy);

        let loc1 = PcodeLocation::new(op1.clone());
        let loc2 = PcodeLocation::new(op2.clone());

        assert_eq!(
            CodeLocation::compare_to(&loc1, &loc2 as &dyn CodeLocation),
            op1.get_seqnum().cmp(op2.get_seqnum())
        );
    }

    /// Java quirk: `PcodeLocation.compareTo(CodeLocation)` returns `-1` for ANY `CodeLocation`
    /// that isn't itself a `PcodeLocation` (see `PcodeLocation.java` lines 31-36: the
    /// `instanceof` check falls through to a bare `return -1`), rather than throwing
    /// `ClassCastException` or otherwise signalling "incomparable". This means a `PcodeLocation`
    /// always sorts as "less than" any foreign `CodeLocation` implementation, which is an
    /// asymmetric, not-quite-total ordering. Reproduced faithfully here rather than fixed.
    #[test]
    fn compare_to_foreign_code_location_is_always_less() {
        struct OtherLocation;
        impl CodeLocation for OtherLocation {
            fn compare_to(&self, _other: &dyn CodeLocation) -> Ordering {
                Ordering::Equal
            }
            fn get_code_location(&self) -> String {
                "other".to_string()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let space = ram_space();
        let op = make_op(&space, 0x3000, 0, OpCode::Copy);
        let loc = PcodeLocation::new(op);
        let other = OtherLocation;

        assert_eq!(
            CodeLocation::compare_to(&loc, &other as &dyn CodeLocation),
            Ordering::Less
        );
    }

    #[test]
    fn locations_with_same_seqnum_are_equal_and_hash_equal() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let space = ram_space();
        let op1 = make_op(&space, 0x4000, 3, OpCode::Copy);
        let op2 = make_op(&space, 0x4000, 3, OpCode::IntAdd);

        let loc1 = PcodeLocation::new(op1);
        let loc2 = PcodeLocation::new(op2);

        // Equality is defined solely by SeqNum, mirroring PcodeLocation.equals(): two ops that
        // differ only in opcode but share a seqnum are equal.
        assert_eq!(loc1, loc2);

        let mut h1 = DefaultHasher::new();
        loc1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        loc2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn locations_with_different_seqnum_are_not_equal() {
        let space = ram_space();
        let op1 = make_op(&space, 0x5000, 0, OpCode::Copy);
        let op2 = make_op(&space, 0x6000, 0, OpCode::Copy);

        let loc1 = PcodeLocation::new(op1);
        let loc2 = PcodeLocation::new(op2);

        assert_ne!(loc1, loc2);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let space = ram_space();
        let op = make_op(&space, 0x7000, 0, OpCode::Copy);
        let loc1 = PcodeLocation::new(op);
        let loc2 = loc1.clone();
        assert_eq!(loc1, loc2);
    }
}
