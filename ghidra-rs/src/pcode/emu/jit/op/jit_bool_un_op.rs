//! A unary p-code operator use-def node with boolean types.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitBoolUnOp`.

use crate::pcode::seam_stubs::JitTypeBehavior;
use super::JitUnOp;

/// A unary p-code operator use-def node with boolean types.
///
/// This trait extends [`JitUnOp`] and provides default implementations for the type methods that
/// ensure both input operand and output are treated as integer (boolean) values according to
/// `JitTypeBehavior`.
pub trait JitBoolUnOp: JitUnOp {
    /// Get the required type behavior for the input operand.
    ///
    /// For boolean unary operations, the operand must be an integer.
    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the output.
    ///
    /// For boolean unary operations, the output is an integer.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{JitDefOp, JitOutVar};
use crate::pcode::emu::jit::op::JitOp;

    struct TestBoolUnOp;

    impl JitOp for TestBoolUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestBoolUnOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestBoolUnOp {
        fn u(&self) -> std::sync::Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    impl JitBoolUnOp for TestBoolUnOp {}

    #[test]
    fn bool_un_op_trait_exists_and_can_be_implemented() {
        let _op = TestBoolUnOp;
        assert!(true);
    }

    #[test]
    fn bool_un_op_u_type_returns_integer() {
        let op = TestBoolUnOp;
        assert_eq!(JitBoolUnOp::u_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn bool_un_op_type_returns_integer() {
        let op = TestBoolUnOp;
        assert_eq!(JitBoolUnOp::type_(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn bool_un_op_inherits_jit_un_op_implementation() {
        let op = TestBoolUnOp;
        op.link();
        op.unlink();
    }
}
