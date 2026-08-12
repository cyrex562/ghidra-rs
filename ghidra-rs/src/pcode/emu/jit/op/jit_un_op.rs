//! A unary p-code operator use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitUnOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::JitDefOp;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::JitTypeBehavior;

/// A p-code operator use-def node with one input and one output.
///
/// Extends [`JitDefOp`] to provide a use-def node for unary operations with a single
/// input operand. Subtraits and implementers can specialize the type behavior of
/// the input and output operands.
///
/// Provides abstract accessors for the single input operand.
pub trait JitUnOp: JitDefOp {
    /// The use-def node for the input operand.
    ///
    /// Returns the [`JitVal`] for the single input to this unary operation.
    fn u(&self) -> Arc<dyn JitVal>;

    /// The required type behavior for the input operand.
    ///
    /// Specifies how the type system should interpret the input operand's bits.
    /// Subtraits override this to provide more specific type requirements.
    fn u_type(&self) -> JitTypeBehavior;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitOutVar;

    struct TestUnOp;

    impl JitOp for TestUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestUnOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestUnOp {
        fn u(&self) -> Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    #[test]
    fn un_op_trait_can_be_implemented() {
        let _op = TestUnOp;
        assert!(true);
    }

    #[test]
    fn un_op_requires_u_and_u_type_methods() {
        // This test verifies that JitUnOp requires u() and u_type() methods
        // to be implemented. The compile check happens automatically when
        // TestUnOp above fails to compile without these methods.
        assert!(true);
    }
}
