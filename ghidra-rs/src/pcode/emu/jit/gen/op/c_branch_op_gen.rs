//! The generator for a `cbranch` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.CBranchOpGen`.
//!
//! # Differences from Java
//!
//! Java's `CBranchOpGen` is a singleton enum (`GEN`) implementing `OpGen<JitCBranchOp>`. Its
//! entire content -- the nested `CBranchGen`/`IntCBranchGen`/`ExtCBranchGen` classes and the
//! `genRun` override -- is bytecode-emission logic that dispatches on:
//! - `RBranch`'s `Reachability` (`WITH_CTXMOD`/`WITHOUT_CTXMOD`/`MAYBE_CTXMOD`),
//! - the sealed `RIntBranch`/`RExtBranch` branch-target hierarchy, and
//! - `BranchOpGen`'s (unported) `IntBranchGen`/`ExtBranchGen` singletons and
//!   `VarGen.computeBlockTransition`,
//!
//! none of which exist in this crate yet: they come from `ghidra.pcode.emu.jit.JitPassage`'s
//! nested types (`JitPassage.java` itself is not yet ported) and from
//! `ghidra.pcode.emu.jit.gen.op.BranchOpGen`/`ghidra.pcode.emu.jit.gen.var.VarGen`, both also not
//! yet ported. Following the precedent set by [`OpGen`](crate::pcode::seam_stubs::OpGen) itself --
//! whose Rust port already omits `genRun` because no current implementor's *own* logic calls it,
//! only the (also unported) JIT driver would -- this port keeps only the one piece of real,
//! checkable content: the singleton enum shape and its `OpGen<JitCBranchOp>` implementation.
//! `genRun`'s bytecode-emission dispatch is left unmodeled until `JitPassage`, `BranchOpGen`, and
//! `VarGen` land.

use crate::pcode::seam_stubs::{JitCBranchOp, OpGen};

/// The generator for a [`JitCBranchOp`] (`cbranch`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.CBranchOpGen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CBranchOpGen {
    /// The generator singleton.
    ///
    /// Port of the sole enum constant `GEN`.
    Gen,
}

impl OpGen<JitCBranchOp> for CBranchOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::JitOp;

    fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}

    #[test]
    fn gen_implements_op_gen_for_jit_c_branch_op() {
        // Java: `enum CBranchOpGen implements OpGen<JitCBranchOp> { GEN; }`
        assert_is_op_gen::<JitCBranchOp>(&CBranchOpGen::Gen);
    }

    #[test]
    fn gen_is_the_sole_variant_and_carries_no_state() {
        // Java: an enum with exactly one constant is a zero-field singleton; every reference to
        // `GEN` observes the same instance.
        assert_eq!(std::mem::size_of::<CBranchOpGen>(), 0);
        assert_eq!(CBranchOpGen::Gen, CBranchOpGen::Gen);
    }
}
