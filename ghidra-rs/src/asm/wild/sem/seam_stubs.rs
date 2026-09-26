//! Minimal placeholder types for Java classes not yet ported that
//! [`WildAssemblyResolvedPatterns`](super::WildAssemblyResolvedPatterns) references. See
//! `STUBS.tsv` for provenance.

use std::sync::Arc;

use crate::app::seam_stubs::{AssemblyConstructorSemantic, AssemblyPatternBlock};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// Placeholder for the unported Java type `ghidra.asm.wild.WildOperandInfo`, referenced by
/// [`WildAssemblyResolvedPatterns`](super::WildAssemblyResolvedPatterns). `WildOperandInfo` is a
/// Java `record` (an immutable data holder plus one derived method, `shift`); modeled here as a
/// plain struct with the same fields.
///
/// The record's `choice` field is a bare `Object` in Java (used to stash arbitrary erased data);
/// here it is `Arc<dyn Any + Send + Sync>` so it can still be cloned cheaply by [`Self::shift`]
/// without knowing what it actually holds. Java's auto-generated `equals`/`hashCode` (used when
/// this type sits in a `Set<WildOperandInfo>`) are not reproduced, since `Any` has no meaningful
/// equality; [`WildAssemblyResolvedPatterns::get_operand_info`] therefore returns a `Vec` rather
/// than a `HashSet` (this type has no `Eq`/`Hash` impl to require).
#[derive(Clone)]
pub struct WildOperandInfo {
    /// The name of the wildcard that matched the operand.
    pub wildcard: String,
    /// The hierarchy of Sleigh constructors leading to the operand.
    pub path: Vec<Arc<dyn AssemblyConstructorSemantic>>,
    /// The bit pattern giving the location of the operand's field(s) in the machine instruction.
    pub location: Arc<dyn AssemblyPatternBlock>,
    /// The expression describing how to encode the operand in the field(s).
    pub expression: PatternExpression,
    /// If applicable, the value encoded in the result containing this information.
    pub choice: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl WildOperandInfo {
    /// Mirrors the record's canonical constructor
    /// `WildOperandInfo(String, List, AssemblyPatternBlock, PatternExpression, Object)`.
    pub fn new(
        wildcard: impl Into<String>,
        path: Vec<Arc<dyn AssemblyConstructorSemantic>>,
        location: Arc<dyn AssemblyPatternBlock>,
        expression: PatternExpression,
        choice: Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) -> Self {
        Self { wildcard: wildcard.into(), path, location, expression, choice }
    }

    /// Copy this wildcard info, but with an increased shift amount.
    ///
    /// Mirrors `WildOperandInfo.shift(int)`.
    pub fn shift(&self, amt: i32) -> Self {
        Self {
            wildcard: self.wildcard.clone(),
            path: self.path.clone(),
            location: Arc::from(self.location.shift(amt)),
            expression: self.expression.clone(),
            choice: self.choice.clone(),
        }
    }
}
