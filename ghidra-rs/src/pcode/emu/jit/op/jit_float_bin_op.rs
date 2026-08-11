//! A binary p-code operator use-def node with floating-point types.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitFloatBinOp`.

use crate::pcode::seam_stubs::{JitBinOp, JitTypeBehavior};

/// A binary p-code operator use-def node with floating-point types.
///
/// This trait extends [`JitBinOp`] and provides default implementations for the type methods that
/// ensure both input operands and output are treated as floating-point values according to
/// `JitTypeBehavior`.
pub trait JitFloatBinOp: JitBinOp {
    /// Get the required type behavior for the left operand.
    ///
    /// For floating-point binary operations, the left operand must be a float.
    fn l_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }

    /// Get the required type behavior for the right operand.
    ///
    /// For floating-point binary operations, the right operand must be a float.
    fn r_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }

    /// Get the required type behavior for the output.
    ///
    /// For floating-point binary operations, the output is a float.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::{JitDefOp, JitOp, JitOutVar, JitVal};

    struct TestFloatBinOp;

    impl JitOp for TestFloatBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatBinOp {
        fn out(&self) -> Box<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestFloatBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn r(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    impl JitFloatBinOp for TestFloatBinOp {}

    #[test]
    fn float_bin_op_trait_exists_and_can_be_implemented() {
        let _op = TestFloatBinOp;
        assert!(true);
    }

    #[test]
    fn float_bin_op_l_type_returns_float() {
        let op = TestFloatBinOp;
        assert_eq!(JitFloatBinOp::l_type(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_bin_op_r_type_returns_float() {
        let op = TestFloatBinOp;
        assert_eq!(JitFloatBinOp::r_type(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_bin_op_type_returns_float() {
        let op = TestFloatBinOp;
        assert_eq!(JitFloatBinOp::type_(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_bin_op_inherits_jit_bin_op_methods() {
        let op = TestFloatBinOp;
        assert_eq!(JitFloatBinOp::l_type(&op), JitTypeBehavior::Float);
        assert_eq!(JitFloatBinOp::r_type(&op), JitTypeBehavior::Float);
    }
}
