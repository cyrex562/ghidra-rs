//! Models `ghidra.pcodeCPort.slghpatexpress.PatternExpression`.

use crate::decompiler::slghpatexpress::PatternValue;
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::pcode::encoder::Encoder;
use std::io;

/// The abstract base of every pattern-matching expression used by the SLEIGH compiler: token/
/// context field references, constants, instruction addresses, operand references, and the
/// arithmetic/bitwise/comparison operators that combine them.
///
/// Models the abstract class `ghidra.pcodeCPort.slghpatexpress.PatternExpression`. Java's
/// reference-counted `layClaim`/`release`/`dispose` lifetime management has no Rust equivalent
/// (ownership is tracked by the type system instead, via `Box<dyn PatternExpression>`), so only
/// the four behavioral abstract methods are ported. `genMinPattern` is also not part of this
/// trait: Java's uniform `genMinPattern(VectorSTL<TokenPattern> ops)` signature covers both
/// "build a brand new pattern" (every operator) and "borrow an entry out of `ops`"
/// ([`crate::decompiler::slghpatexpress::OperandValue`]), which return owned vs. borrowed
/// `TokenPattern`s respectively -- a distinction each concrete type's own already-ported
/// `gen_min_pattern` inherent method (with its own fitting signature) already captures correctly.
/// Unifying that into one object-safe trait method would need a `TokenPattern` clone-box
/// mechanism that doesn't exist yet and isn't needed by anything calling `gen_min_pattern` today
/// (only same-type test code and one documented future caller,
/// [`crate::decompiler::slghpatexpress::UnconstrainedEquation::gen_pattern`], do).
pub trait PatternExpression: Send + Sync {
    /// Collects every `PatternValue` leaf reachable from this expression into `list` (leaves
    /// push themselves; composite operators recurse into their operands).
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>);

    /// Appends this expression's min/max bounds, one entry per `PatternValue` leaf, to
    /// `minlist`/`maxlist`.
    fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>);

    /// Evaluates this expression given per-leaf replacement values, consuming entries from
    /// `replace` starting at `listpos`.
    fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64;

    /// Encodes this expression to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;
}
