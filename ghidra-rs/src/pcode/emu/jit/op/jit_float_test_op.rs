//! A binary p-code operator use-def node with floating-point inputs and boolean output.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitFloatTestOp`.

use crate::pcode::emu::jit::op::JitFloatBinOp;
use crate::pcode::seam_stubs::JitTypeBehavior;

/// A binary p-code operator use-def node with floating-point inputs and a boolean output.
///
/// This trait extends [`JitFloatBinOp`] and provides a default implementation for the type method
/// that ensures the output is treated as an integer (boolean) value, even though both inputs
/// are floating-point.
pub trait JitFloatTestOp: JitFloatBinOp {
    /// Get the required type behavior for the output.
    ///
    /// For floating-point test operations, the output is a boolean (integer) value, not a float.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::{JitBinOp, JitDefOp, JitOp, JitOutVar, JitVal};

    struct TestFloatTestOp;

    impl JitOp for TestFloatTestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatTestOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestFloatTestOp {
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

    impl JitFloatBinOp for TestFloatTestOp {}

    impl JitFloatTestOp for TestFloatTestOp {}

    #[test]
    fn float_test_op_trait_exists_and_can_be_implemented() {
        let _op = TestFloatTestOp;
        assert!(true);
    }

    #[test]
    fn float_test_op_l_type_returns_float() {
        let op = TestFloatTestOp;
        assert_eq!(JitFloatBinOp::l_type(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_test_op_r_type_returns_float() {
        let op = TestFloatTestOp;
        assert_eq!(JitFloatBinOp::r_type(&op), JitTypeBehavior::Float);
    }

    #[test]
    fn float_test_op_type_returns_integer() {
        let op = TestFloatTestOp;
        assert_eq!(JitFloatTestOp::type_(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn float_test_op_inherits_jit_float_bin_op_methods() {
        let op = TestFloatTestOp;
        assert_eq!(JitFloatBinOp::l_type(&op), JitTypeBehavior::Float);
        assert_eq!(JitFloatBinOp::r_type(&op), JitTypeBehavior::Float);
        assert_eq!(JitFloatTestOp::type_(&op), JitTypeBehavior::Integer);
    }
}
