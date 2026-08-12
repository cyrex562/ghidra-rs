//! A unary p-code operator use-def node with floating-point types.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitFloatUnOp`.

use crate::pcode::seam_stubs::JitTypeBehavior;
use super::JitUnOp;

/// A unary p-code operator use-def node with floating-point types.
///
/// This trait extends [`JitUnOp`] and provides default implementations for the type methods that
/// ensure both input operand and output are treated as floating-point values according to
/// `JitTypeBehavior`.
pub trait JitFloatUnOp: JitUnOp {
    /// Get the required type behavior for the input operand.
    ///
    /// For floating-point unary operations, the operand must be a float.
    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }

    /// Get the required type behavior for the output.
    ///
    /// For floating-point unary operations, the output is a float.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::{JitVal, JitOutVar};

    struct TestFloatUnOp;

    impl JitOp for TestFloatUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatUnOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestFloatUnOp {
        fn u(&self) -> std::sync::Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    impl JitFloatUnOp for TestFloatUnOp {}

    #[test]
    fn float_un_op_trait_exists_and_can_be_implemented() {
        let _op = TestFloatUnOp;
        assert!(true);
    }

    #[test]
    fn float_un_op_u_type_returns_float() {
        let op = TestFloatUnOp;
        assert_eq!(JitFloatUnOp::u_type(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_un_op_type_returns_float() {
        let op = TestFloatUnOp;
        assert_eq!(JitFloatUnOp::type_(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_un_op_inherits_jit_un_op_implementation() {
        let op = TestFloatUnOp;
        op.link();
        op.unlink();
    }
}
