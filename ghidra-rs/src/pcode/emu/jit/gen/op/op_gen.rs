//! The bytecode generator for a specific p-code op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.OpGen`.
//!
//! Notes on what is/isn't modeled here, following the precedent set by the sibling generator
//! traits in this module (`BinOpGen`, `IntOpUnOpGen`, `IntPredBinOpGen`, `FloatOpBinOpGen`, ...):
//! - Java's abstract `genRun(Emitter<Bot>, Local<TRef<THIS>>, Local<TInt>,
//!   Methods.RetReq<TRef<EntryPoint>>, JitCodeGenerator<THIS>, T, JitBlock, Scope) -> OpResult`
//!   is NOT modeled. Its signature is built entirely from `JitCompiledPassage`, `OpResult`
//!   (`LiveOpResult`/`DeadOpResult`), and `Methods.RetReq` -- none of which are ported in this
//!   crate (see the sibling doc comments in `bin_op_gen.rs`, `float_op_bin_op_gen.rs`,
//!   `int_pred_bin_op_gen.rs`, `int_op_un_op_gen.rs`). No default method on any sibling trait
//!   calls it, so this trait remains a marker bound, exactly as it was as a placeholder.
//! - The static `lookup(JitOp) -> OpGen<T>` dispatch table is likewise not modeled: it match-arms
//!   over singleton `GEN` constants of ~35 concrete `*OpGen` implementors, most of which
//!   (`BranchOpGen`, `LoadOpGen`, `StoreOpGen`, `IntAddOpGen`, `PhiOpGen`, etc.) are still TODO in
//!   the port order, so a faithful `lookup` cannot be written yet. Port it alongside those
//!   generators once they exist.
//! - The static `generateSyserrInts` debugging helper (dumps operand legs to stderr via
//!   `System.err.printf`) is a debug-only utility with no callers among already-ported types; it
//!   is omitted for the same reason.
//! - The `sealed interface OpResult` (with `LiveOpResult`/`DeadOpResult` records) is part of the
//!   unported `genRun` signature above and is likewise not modeled here.
//!
//! This mirrors the shape decided by `scripts/shape_rules.py` (Rust `trait`: a genuine open
//! extension point -- a Java `interface` with one abstract method and 15 in-repo implementors)
//! and is the cycle cut-point that `OpGen` sits on: every `*OpGen` implementor in this directory
//! bounds its type parameter on `OpGen<T>` without requiring `genRun`/`lookup` to compile.

use crate::pcode::emu::jit::op::JitOp;

/// The bytecode generator for a specific p-code op.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.OpGen<T extends JitOp>`.
///
/// See the module docs for what of Java's `OpGen` is (and is not) modeled.
pub trait OpGen<T: JitOp>: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitOutVar;
    use std::sync::Arc;

    struct TestOp;

    impl JitOp for TestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    struct DummyGen;
    impl OpGen<TestOp> for DummyGen {}

    #[test]
    fn op_gen_trait_can_be_implemented_as_a_marker_bound() {
        // Java's OpGen<T extends JitOp> is a genuine interface with an abstract genRun and a
        // static lookup, neither of which is modeled here (see module docs) -- this smoke test
        // just confirms the marker bound is implementable and object-parametric like the Java
        // generic interface is.
        let _gen = DummyGen;
        fn accepts_op_gen<G: OpGen<TestOp>>(_g: &G) {}
        accepts_op_gen(&DummyGen);
    }
}
