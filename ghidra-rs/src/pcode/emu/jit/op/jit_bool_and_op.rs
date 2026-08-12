//! A use-def node for a boolean AND p-code operation.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitBoolAndOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{JitBinOp, JitTypeBehavior, JitConstVal, JitMissingVar};
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::{JitBoolBinOp};

/// Wrapper to convert Arc<dyn JitVal> to Box<dyn JitVal> for JitBinOp trait.
struct JitValWrapper(Arc<dyn JitVal>);

impl JitVal for JitValWrapper {
    fn size(&self) -> i32 {
        self.0.size()
    }

    fn uses(&self) -> Vec<crate::pcode::emu::jit::var::ValUse> {
        self.0.uses()
    }

    fn add_use(&self, op: &dyn JitOp, position: i32) {
        self.0.add_use(op, position)
    }

    fn remove_use(&self, op: &dyn JitOp, position: i32) {
        self.0.remove_use(op, position)
    }

    fn is_input_var(&self) -> bool {
        self.0.is_input_var()
    }

    fn as_const_val(&self) -> Option<&JitConstVal> {
        self.0.as_const_val()
    }

    fn as_varnode_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitVarnodeVar> {
        self.0.as_varnode_var()
    }

    fn as_out_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitOutVar> {
        self.0.as_out_var()
    }

    fn as_missing_var(&self) -> Option<&JitMissingVar> {
        self.0.as_missing_var()
    }

    fn accept_val(&self, visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor) {
        self.0.accept_val(visitor)
    }
}

/// A use-def node for the [`PcodeOp::BOOL_AND`] p-code operation.
///
/// This struct represents a binary p-code operation that performs a boolean AND
/// between two input operands. It provides the use-def relationship between the
/// left and right input values, the operation itself, and the output value in the
/// data-flow graph.
#[derive(Clone)]
pub struct JitBoolAndOp {
    op: PcodeOp,
    out: Arc<dyn JitOutVar>,
    l: Arc<dyn JitVal>,
    r: Arc<dyn JitVal>,
}

impl JitBoolAndOp {
    /// Creates a new boolean AND operation node.
    ///
    /// # Arguments
    ///
    /// * `op` - The p-code operation
    /// * `out` - The output variable node
    /// * `l` - The left input operand value node
    /// * `r` - The right input operand value node
    pub fn new(op: PcodeOp, out: Arc<dyn JitOutVar>, l: Arc<dyn JitVal>, r: Arc<dyn JitVal>) -> Self {
        Self { op, out, l, r }
    }

    /// Returns a reference to the underlying p-code operation.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Returns a reference to the output variable.
    pub fn out_ref(&self) -> &Arc<dyn JitOutVar> {
        &self.out
    }

    /// Returns a reference to the left input operand.
    pub fn l_ref(&self) -> &Arc<dyn JitVal> {
        &self.l
    }

    /// Returns a reference to the right input operand.
    pub fn r_ref(&self) -> &Arc<dyn JitVal> {
        &self.r
    }
}

impl JitOp for JitBoolAndOp {
    fn type_for(&self, position: i32) -> JitTypeBehavior {
        // Both input positions return Integer type
        if position == 0 || position == 1 {
            JitTypeBehavior::Integer
        } else {
            JitTypeBehavior::Integer
        }
    }

    fn link(&self) {}

    fn unlink(&self) {}
}

impl JitDefOp for JitBoolAndOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

impl JitBinOp for JitBoolAndOp {
    fn l(&self) -> Box<dyn JitVal> {
        Box::new(JitValWrapper(Arc::clone(&self.l)))
    }

    fn r(&self) -> Box<dyn JitVal> {
        Box::new(JitValWrapper(Arc::clone(&self.r)))
    }

    fn l_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    fn r_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

impl JitBoolBinOp for JitBoolAndOp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitDefOp as JitDefOpTrait;
    use crate::pcode::emu::jit::var::JitVar;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;

    #[test]
    fn bool_and_op_has_fields() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op.clone(), out, l, r);

        assert_eq!(and_op.op().opcode, OpCode::BoolAnd);
    }

    #[test]
    fn bool_and_op_implements_jit_bool_bin_op() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op, out, l, r);

        // Verify trait implementations
        let _: &dyn JitBoolBinOp = &and_op;
        let _: &dyn JitBinOp = &and_op;
        let _: &dyn JitDefOp = &and_op;
        let _: &dyn JitOp = &and_op;
    }

    #[test]
    fn bool_and_op_type_methods_return_integer() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op, out, l, r);

        assert_eq!(JitBinOp::l_type(&and_op), JitTypeBehavior::Integer);
        assert_eq!(JitBinOp::r_type(&and_op), JitTypeBehavior::Integer);
        assert_eq!(JitDefOpTrait::type_(&and_op), JitTypeBehavior::Integer);
    }

    #[test]
    fn bool_and_op_l_type_bool_returns_integer() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op, out, l, r);

        assert_eq!(and_op.l_type_bool(), JitTypeBehavior::Integer);
    }

    #[test]
    fn bool_and_op_r_type_bool_returns_integer() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op, out, l, r);

        assert_eq!(and_op.r_type_bool(), JitTypeBehavior::Integer);
    }

    #[test]
    fn bool_and_op_type_bool_returns_integer() {
        let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolAnd, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;

        let and_op = JitBoolAndOp::new(op, out, l, r);

        assert_eq!(and_op.type_bool(), JitTypeBehavior::Integer);
    }

    struct MockOutVar;

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            1
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<AddressSpace> {
            Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0))
        }
    }

    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0));
            let addr = Address::new(space, 0);
            Varnode::new(addr, 1)
        }
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    struct MockVal;

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            1
        }
        fn uses(&self) -> Vec<crate::pcode::emu::jit::var::ValUse> {
            vec![]
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn is_input_var(&self) -> bool {
            false
        }
        fn accept_val(
            &self,
            _visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
        ) {
        }
    }
}
