//! Conveniences and common implementations for bytecode generators of unary p-code operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.UnOpGen`.

use crate::pcode::seam_stubs::{Ext, OpGen};
use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;

/// An extension that provides conveniences and common implementations for unary p-code
/// operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.UnOpGen`.
pub trait UnOpGen<T: JitUnOp>: OpGen<T> {
    /// Whether this operator is signed.
    ///
    /// Port of `UnOpGen.isSigned`.
    ///
    /// In many cases, the operator itself is not affected by the signedness of the operands;
    /// however, if size adjustments to the operands are needed, this can determine how those
    /// operands are extended.
    fn is_signed(&self) -> bool;

    /// When loading and storing variables, the kind of extension to apply.
    ///
    /// Port of `UnOpGen.ext`.
    fn ext(&self) -> Ext {
        Ext::for_signed(self.is_signed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::seam_stubs::{JitOutVar, JitTypeBehavior};
    use std::sync::Arc;

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
        fn u(&self) -> Arc<dyn crate::pcode::emu::jit::var::JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    struct SignedGen;
    impl OpGen<TestUnOp> for SignedGen {}
    impl UnOpGen<TestUnOp> for SignedGen {
        fn is_signed(&self) -> bool {
            true
        }
    }

    struct UnsignedGen;
    impl OpGen<TestUnOp> for UnsignedGen {}
    impl UnOpGen<TestUnOp> for UnsignedGen {
        fn is_signed(&self) -> bool {
            false
        }
    }

    #[test]
    fn ext_matches_is_signed_like_java_default_method() {
        // Java: default Ext ext() { return Ext.forSigned(isSigned()); }
        assert_eq!(SignedGen.ext(), Ext::Sign);
        assert_eq!(UnsignedGen.ext(), Ext::Zero);
    }

    #[test]
    fn un_op_gen_trait_can_be_implemented() {
        let _signed = SignedGen;
        let _unsigned = UnsignedGen;
        assert!(true);
    }
}
