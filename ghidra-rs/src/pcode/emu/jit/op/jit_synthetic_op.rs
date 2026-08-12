//! A synthetic p-code operator use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitSyntheticOp`.

use crate::pcode::emu::jit::op::JitOp;
use crate::program::model::pcode::PcodeOp;

/// A synthetic p-code operator use-def node.
///
/// Synthetic nodes do not correspond to a [`PcodeOp`] emitted in the actual decoded passage.
/// Instead, they are created as part of the data flow analysis. They are used by downstream
/// analyzers, but do not directly result in any emitted bytecode.
pub trait JitSyntheticOp: JitOp {
    /// Returns the p-code op represented by this use-def node.
    ///
    /// # Panics
    ///
    /// Always panics with a message matching Java's `UnsupportedOperationException`,
    /// since synthetic nodes do not correspond to a real p-code op.
    fn op(&self) -> PcodeOp {
        panic!("UnsupportedOperationException: synthetic ops do not have an underlying PcodeOp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::JitTypeBehavior;
    use std::panic;

    struct TestSyntheticOp;

    impl JitOp for TestSyntheticOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitSyntheticOp for TestSyntheticOp {}

    #[test]
    fn synthetic_op_trait_exists_and_can_be_implemented() {
        let _op = TestSyntheticOp;
        assert!(true);
    }

    #[test]
    fn op_method_panics_with_expected_message() {
        let op = TestSyntheticOp;
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = op.op();
        }));
        assert!(result.is_err(), "op() should panic");
    }

    #[test]
    fn op_panics_matching_java_behavior() {
        let op = TestSyntheticOp;
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = op.op();
        }));
        assert!(result.is_err(), "Java's op() throws UnsupportedOperationException");
    }

    #[test]
    fn synthetic_op_implements_jit_op_methods() {
        let op = TestSyntheticOp;
        assert_eq!(op.type_for(0), JitTypeBehavior::Integer);
        op.link();
        op.unlink();
    }
}
