//! A binary p-code operator use-def node with integer types.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitIntBinOp`.

use crate::pcode::seam_stubs::{JitBinOp, JitTypeBehavior};

/// A binary p-code operator use-def node with integer types.
///
/// This trait extends [`JitBinOp`] and provides default implementations for the type methods that
/// ensure both input operands and output are treated as integer values according to
/// `JitTypeBehavior`.
pub trait JitIntBinOp: JitBinOp {
    /// Get the required type behavior for the left operand.
    ///
    /// For integer binary operations, the left operand must be an integer.
    fn l_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the right operand.
    ///
    /// For integer binary operations, the right operand must be an integer.
    fn r_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the output.
    ///
    /// For integer binary operations, the output is an integer.
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

    struct TestIntBinOp;

    impl JitOp for TestIntBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestIntBinOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestIntBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn r(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    impl JitIntBinOp for TestIntBinOp {}

    #[test]
    fn int_bin_op_trait_exists_and_can_be_implemented() {
        let _op = TestIntBinOp;
        assert!(true);
    }

    #[test]
    fn int_bin_op_l_type_returns_integer() {
        let op = TestIntBinOp;
        assert_eq!(JitIntBinOp::l_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_bin_op_r_type_returns_integer() {
        let op = TestIntBinOp;
        assert_eq!(JitIntBinOp::r_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_bin_op_type_returns_integer() {
        let op = TestIntBinOp;
        assert_eq!(JitIntBinOp::type_(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_bin_op_inherits_jit_bin_op_methods() {
        let op = TestIntBinOp;
        assert_eq!(JitIntBinOp::l_type(&op), JitTypeBehavior::Integer);
        assert_eq!(JitIntBinOp::r_type(&op), JitTypeBehavior::Integer);
    }
}
