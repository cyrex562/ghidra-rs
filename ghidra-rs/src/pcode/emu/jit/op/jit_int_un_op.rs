//! A unary p-code operator use-def node with integer types.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitIntUnOp`.

use crate::pcode::seam_stubs::JitTypeBehavior;
use super::JitUnOp;

/// A unary p-code operator use-def node with integer types.
///
/// This trait extends [`JitUnOp`] and provides default implementations for the type methods that
/// ensure both input operand and output are treated as integer values according to
/// `JitTypeBehavior`.
pub trait JitIntUnOp: JitUnOp {
    /// Get the required type behavior for the input operand.
    ///
    /// For integer unary operations, the operand must be an integer.
    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the output.
    ///
    /// For integer unary operations, the output is an integer.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::JitOutVar;

    struct TestIntUnOp;

    impl JitOp for TestIntUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestIntUnOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestIntUnOp {
        fn u(&self) -> std::sync::Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    impl JitIntUnOp for TestIntUnOp {}

    #[test]
    fn int_un_op_trait_exists_and_can_be_implemented() {
        let _op = TestIntUnOp;
        assert!(true);
    }

    #[test]
    fn int_un_op_u_type_returns_integer() {
        let op = TestIntUnOp;
        assert_eq!(JitIntUnOp::u_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_un_op_type_returns_integer() {
        let op = TestIntUnOp;
        assert_eq!(JitIntUnOp::type_(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_un_op_inherits_jit_un_op_implementation() {
        let op = TestIntUnOp;
        op.link();
        op.unlink();
    }
}
