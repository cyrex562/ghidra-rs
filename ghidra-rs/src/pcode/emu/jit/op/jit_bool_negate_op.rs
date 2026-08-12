//! A use-def node for a boolean negation p-code operation.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitBoolNegateOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{JitDefOp, JitOutVar, JitTypeBehavior};
use crate::pcode::emu::jit::op::JitOp;
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::{JitBoolUnOp, JitUnOp};

/// A use-def node for the [`PcodeOp::BOOL_NEGATE`] p-code operation.
///
/// This struct represents a unary p-code operation that negates a boolean value.
/// It provides the use-def relationship between the input value, the operation itself,
/// and the output value in the data-flow graph.
#[derive(Clone)]
pub struct JitBoolNegateOp {
    op: PcodeOp,
    out: Arc<dyn JitOutVar>,
    u: Arc<dyn JitVal>,
}

impl JitBoolNegateOp {
    /// Creates a new boolean negate operation node.
    ///
    /// # Arguments
    ///
    /// * `op` - The p-code operation
    /// * `out` - The output variable node
    /// * `u` - The input operand value node
    pub fn new(op: PcodeOp, out: Arc<dyn JitOutVar>, u: Arc<dyn JitVal>) -> Self {
        Self { op, out, u }
    }

    /// Returns a reference to the underlying p-code operation.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Returns a reference to the output variable.
    pub fn out_ref(&self) -> &Arc<dyn JitOutVar> {
        &self.out
    }

    /// Returns a reference to the input operand.
    pub fn u_ref(&self) -> &Arc<dyn JitVal> {
        &self.u
    }
}

impl JitOp for JitBoolNegateOp {
    fn type_for(&self, position: i32) -> JitTypeBehavior {
        if position == 0 {
            JitTypeBehavior::Integer
        } else {
            JitTypeBehavior::Integer
        }
    }

    fn link(&self) {}

    fn unlink(&self) {}
}

impl JitDefOp for JitBoolNegateOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

impl JitUnOp for JitBoolNegateOp {
    fn u(&self) -> Arc<dyn JitVal> {
        Arc::clone(&self.u)
    }

    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

impl JitBoolUnOp for JitBoolNegateOp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::JitDefOp as JitDefOpTrait;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;

    #[test]
    fn bool_negate_op_has_fields() {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolNegate, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;

        let negate_op = JitBoolNegateOp::new(op.clone(), out, u);

        assert_eq!(negate_op.op().opcode, OpCode::BoolNegate);
    }

    #[test]
    fn bool_negate_op_implements_jit_bool_un_op() {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolNegate, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;

        let negate_op = JitBoolNegateOp::new(op, out, u);

        // Verify trait implementations
        let _: &dyn JitBoolUnOp = &negate_op;
        let _: &dyn JitUnOp = &negate_op;
        let _: &dyn JitDefOp = &negate_op;
        let _: &dyn JitOp = &negate_op;
    }

    #[test]
    fn bool_negate_op_type_methods_return_integer() {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0);
        let seqnum = SequenceNumber::new(addr, 0);
        let op = PcodeOp::new(OpCode::BoolNegate, seqnum, vec![], None);

        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;

        let negate_op = JitBoolNegateOp::new(op, out, u);

        assert_eq!(JitUnOp::u_type(&negate_op), JitTypeBehavior::Integer);
        assert_eq!(JitDefOpTrait::type_(&negate_op), JitTypeBehavior::Integer);
    }

    struct MockOutVar;

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            8
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(space.clone(), 0);
            Varnode::new(addr, 8)
        }
    }

    struct MockVal;

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            8
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
