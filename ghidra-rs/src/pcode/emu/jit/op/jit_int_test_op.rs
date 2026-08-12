//! A binary p-code operator use-def node with integer inputs and boolean output.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitIntTestOp`.

use crate::pcode::emu::jit::op::JitIntBinOp;
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;

/// A binary p-code operator use-def node with integer inputs and a boolean output.
///
/// This trait extends [`JitIntBinOp`] and provides a default implementation for the type method
/// that ensures the output is treated as an integer (boolean) value. This forms a useful category
/// of p-code operations, even though boolean is implemented as int in the current system.
pub trait JitIntTestOp: JitIntBinOp {
    /// Get the required type behavior for the output.
    ///
    /// For integer test operations, the output is a boolean (integer) value.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{JitBinOp};

    struct TestIntTestOp;

    impl JitOp for TestIntTestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestIntTestOp {
        fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestIntTestOp {
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

    impl JitIntBinOp for TestIntTestOp {}

    impl JitIntTestOp for TestIntTestOp {}

    #[test]
    fn int_test_op_trait_exists_and_can_be_implemented() {
        let _op = TestIntTestOp;
        assert!(true);
    }

    #[test]
    fn int_test_op_l_type_returns_integer() {
        let op = TestIntTestOp;
        assert_eq!(JitIntBinOp::l_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_test_op_r_type_returns_integer() {
        let op = TestIntTestOp;
        assert_eq!(JitIntBinOp::r_type(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_test_op_type_returns_integer() {
        let op = TestIntTestOp;
        assert_eq!(JitIntTestOp::type_(&op), JitTypeBehavior::Integer);
    }

    #[test]
    fn int_test_op_inherits_jit_int_bin_op_methods() {
        let op = TestIntTestOp;
        assert_eq!(JitIntBinOp::l_type(&op), JitTypeBehavior::Integer);
        assert_eq!(JitIntBinOp::r_type(&op), JitTypeBehavior::Integer);
        assert_eq!(JitIntTestOp::type_(&op), JitTypeBehavior::Integer);
    }
}
