//! A binary p-code operator use-def node with boolean (integer) types.
//!
//! This module provides the trait for representing binary p-code operations that work with boolean
//! (integer) types, as defined by the Ghidra emulator. All operands and results are typed as
//! integers according to JitTypeBehavior.

use crate::pcode::seam_stubs::{JitBinOp, JitTypeBehavior};

/// A binary p-code operator use-def node with boolean (integer) types.
///
/// This trait extends [`JitBinOp`] and provides default implementations for the type methods that
/// ensure both input operands and the output are treated as integers. This is useful for boolean
/// operations that operate on integer-typed values.
pub trait JitBoolBinOp: JitBinOp {
    /// Get the required type behavior for the left operand.
    ///
    /// For boolean binary operations, both operands must be integers.
    fn l_type_bool(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the right operand.
    ///
    /// For boolean binary operations, both operands must be integers.
    fn r_type_bool(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Get the required type behavior for the output.
    ///
    /// For boolean binary operations, the output is an integer.
    fn type_bool(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOp;

    impl JitBinOp for TestOp {
        fn l(&self) -> Box<dyn crate::pcode::emu::jit::var::JitVal> {
            unimplemented!()
        }
        fn r(&self) -> Box<dyn crate::pcode::emu::jit::var::JitVal> {
            unimplemented!()
        }
        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    impl crate::pcode::seam_stubs::JitDefOp for TestOp {
        fn out(&self) -> std::sync::Arc<dyn crate::pcode::seam_stubs::JitOutVar> {
            unimplemented!()
        }
    }

    impl crate::pcode::seam_stubs::JitOp for TestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn link(&self) {
            unimplemented!()
        }
        fn unlink(&self) {
            unimplemented!()
        }
    }

    impl JitBoolBinOp for TestOp {}

    #[test]
    fn test_jit_bool_bin_op_l_type() {
        let op = TestOp;
        assert_eq!(op.l_type_bool(), JitTypeBehavior::Integer);
    }

    #[test]
    fn test_jit_bool_bin_op_r_type() {
        let op = TestOp;
        assert_eq!(op.r_type_bool(), JitTypeBehavior::Integer);
    }

    #[test]
    fn test_jit_bool_bin_op_type() {
        let op = TestOp;
        assert_eq!(op.type_bool(), JitTypeBehavior::Integer);
    }
}
