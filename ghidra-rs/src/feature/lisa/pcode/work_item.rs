//! Port of `ghidra.lisa.pcode.WorkItem`.

use crate::feature::lisa::pcode::contexts::statement_context::StatementContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::feature::lisa::pcode::locations::CodeLocation;
use crate::program::model::pcode::OpCode;

/// Mirrors Java's nested `WorkItem.PredType` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredType {
    True,
    False,
    Seq,
}

/// Stand-in for the subset of LiSA's `it.unive.lisa.program.cfg.statement.Statement` interface
/// [`WorkItem`] actually needs: its own [`CodeLocation`] (Java: `Statement.getLocation()`).
///
/// The full LiSA CFG/analysis framework `Statement`/`Edge`/`TrueEdge`/`FalseEdge`/
/// `SequentialEdge` are part of has no Rust port in this crate (the same situation
/// [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)'s
/// docs describe for the sibling `expressions` package), so [`WorkItem`] is generic over `P`, the
/// caller's chosen stand-in for `Statement`, bounded by this trait.
pub trait WorkItemStatement {
    /// Java: `getLocation()`.
    fn location(&self) -> Box<dyn CodeLocation>;
}

/// Stand-in for the three LiSA `Edge` subclasses [`WorkItem::compute_branch`] may construct
/// (`TrueEdge`, `FalseEdge`, `SequentialEdge`), all of which simply pair a predecessor and
/// successor `Statement`. Generic over `P`, the same [`WorkItemStatement`] stand-in
/// [`WorkItem<P>`] is generic over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkItemEdge<P> {
    /// Java: `new TrueEdge(pred, succ)`.
    True(P, P),
    /// Java: `new FalseEdge(pred, succ)`.
    False(P, P),
    /// Java: `new SequentialEdge(pred, succ)`.
    Sequential(P, P),
}

/// One pending unit of work in a p-code-to-LiSA-CFG translation: a to-be-processed
/// [`StatementContext`], plus the predecessor statement (if any) that will connect to it and how
/// (per [`WorkItem::pred_type`]).
///
/// Corresponds to `ghidra.lisa.pcode.WorkItem` in the Java source. See [`WorkItemStatement`]'s
/// docs for why this is generic over `P` rather than depending on LiSA's own `Statement` type.
///
/// # Deviations from Java
///
/// Java's `pred` field is a plain (nullable) `Statement pred;`, and real call sites in this same
/// package do pass `null` for it (`PcodeCodeMemberVisitor`'s `new WorkItem(null,
/// entry.getPcodeOp(0))`, used for a CFG's entry statements, which have no predecessor) -- an
/// ordinary, common input shape, not just malformed input. This port therefore models `pred` as
/// `Option<P>`, and only panics at the point Java would actually dereference a `null` there
/// ([`WorkItem::compute_branch`]), matching Java's deferred-`NullPointerException` timing rather
/// than rejecting `None` eagerly at construction.
pub struct WorkItem<P> {
    pred: Option<P>,
    pred_type: PredType,
    context: StatementContext,
}

impl<P: WorkItemStatement> WorkItem<P> {
    /// Java: `WorkItem(Statement pred, StatementContext ctx)`. `type` always starts `SEQ`,
    /// matching Java's `this.type = PredType.SEQ;`.
    pub fn new(pred: Option<P>, context: StatementContext) -> Self {
        Self { pred, pred_type: PredType::Seq, context }
    }

    /// Java: `getContext()`.
    pub fn get_context(&self) -> &StatementContext {
        &self.context
    }

    /// Java: `getPred()`.
    pub fn get_pred(&self) -> Option<&P> {
        self.pred.as_ref()
    }

    /// Java: `setType(boolean val)`.
    pub fn set_type(&mut self, val: bool) {
        self.pred_type = if val { PredType::True } else { PredType::False };
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> PredType {
        self.pred_type
    }

    /// Java: `computeBranch(Statement succ)`.
    ///
    /// # Panics
    ///
    /// If `pred` is `None` -- the `NullPointerException` Java's `pred.getLocation()` would throw
    /// on a `null` `pred`. See the struct docs for why `pred` can legitimately be absent here
    /// (real callers do construct a `WorkItem` with no predecessor), so this only panics when
    /// `compute_branch` is actually called on one, mirroring Java's own deferred failure point.
    ///
    /// Also panics if `pred`'s location is not a [`PcodeLocation`] -- the `ClassCastException`
    /// Java's `(PcodeLocation) pred.getLocation()` would throw for a `Statement` whose location
    /// isn't a `PcodeLocation`. Every `Statement` reachable from this codebase's p-code-to-CFG
    /// translation carries a `PcodeLocation`, so this is not expected to trigger in practice.
    pub fn compute_branch(&self, succ: P) -> Option<WorkItemEdge<P>>
    where
        P: Clone,
    {
        let pred = self
            .pred
            .clone()
            .expect("WorkItem::compute_branch: pred is None (Java NullPointerException)");
        let loc = pred.location();
        let pcode_loc = loc
            .as_any()
            .downcast_ref::<PcodeLocation>()
            .expect(
                "WorkItem::compute_branch: pred's location is not a PcodeLocation \
                 (Java ClassCastException)",
            )
            .clone();

        if pcode_loc.get_opcode() == OpCode::Return {
            return None;
        }

        Some(match self.pred_type {
            PredType::True => WorkItemEdge::True(pred, succ),
            PredType::False => WorkItemEdge::False(pred, succ),
            PredType::Seq => WorkItemEdge::Sequential(pred, succ),
        })
    }

    /// Java: `getKey()`.
    pub fn get_key(&self) -> String {
        let key = self.context.get_op().get_seqnum().to_string();
        match &self.pred {
            Some(pred) => format!("{}=>{}", pred.location().get_code_location(), key),
            None => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{PcodeOp, SequenceNumber, Varnode};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn op_at(opcode: OpCode, offset: i64, order: i32) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space.clone(), offset), order);
        let output = Varnode::new(Address::new(space, 0x10), 4);
        PcodeOp::new(opcode, seq, vec![], Some(output))
    }

    /// A minimal `WorkItemStatement` implementation wrapping a `PcodeLocation`, standing in for a
    /// LiSA `Statement` in this codebase's p-code translation path.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockStatement(PcodeLocation);

    impl WorkItemStatement for MockStatement {
        fn location(&self) -> Box<dyn CodeLocation> {
            Box::new(self.0.clone())
        }
    }

    #[test]
    fn new_defaults_to_seq_type() {
        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 0));
        let item: WorkItem<MockStatement> = WorkItem::new(None, ctx);
        assert_eq!(item.get_type(), PredType::Seq);
        assert!(item.get_pred().is_none());
    }

    #[test]
    fn set_type_maps_bool_to_true_or_false() {
        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 0));
        let mut item: WorkItem<MockStatement> = WorkItem::new(None, ctx);

        item.set_type(true);
        assert_eq!(item.get_type(), PredType::True);

        item.set_type(false);
        assert_eq!(item.get_type(), PredType::False);
    }

    #[test]
    fn get_key_with_no_pred_is_just_the_contexts_seqnum() {
        let op = op_at(OpCode::Copy, 0x1000, 0);
        let expected = op.get_seqnum().to_string();
        let ctx = StatementContext::from_op(op);
        let item: WorkItem<MockStatement> = WorkItem::new(None, ctx);
        assert_eq!(item.get_key(), expected);
    }

    #[test]
    fn get_key_with_pred_prefixes_the_preds_code_location() {
        let pred_op = op_at(OpCode::Copy, 0x2000, 0);
        let pred_loc = PcodeLocation::new(pred_op.clone());
        let pred = MockStatement(pred_loc.clone());

        let ctx_op = op_at(OpCode::Copy, 0x1000, 1);
        let ctx = StatementContext::from_op(ctx_op.clone());

        let item = WorkItem::new(Some(pred), ctx);

        let expected = format!("{}=>{}", pred_loc.get_code_location(), ctx_op.get_seqnum());
        assert_eq!(item.get_key(), expected);
    }

    #[test]
    fn compute_branch_returns_none_for_a_return_op_predecessor() {
        let pred_op = op_at(OpCode::Return, 0x2000, 0);
        let pred = MockStatement(PcodeLocation::new(pred_op));
        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 1));
        let item = WorkItem::new(Some(pred.clone()), ctx);

        assert!(item.compute_branch(pred).is_none());
    }

    #[test]
    fn compute_branch_builds_sequential_true_or_false_edges_per_pred_type() {
        let pred_op = op_at(OpCode::CBranch, 0x2000, 0);
        let pred = MockStatement(PcodeLocation::new(pred_op));
        let succ_op = op_at(OpCode::Copy, 0x3000, 0);
        let succ = MockStatement(PcodeLocation::new(succ_op));

        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 1));
        let mut item = WorkItem::new(Some(pred.clone()), ctx);

        assert_eq!(
            item.compute_branch(succ.clone()),
            Some(WorkItemEdge::Sequential(pred.clone(), succ.clone()))
        );

        item.set_type(true);
        assert_eq!(
            item.compute_branch(succ.clone()),
            Some(WorkItemEdge::True(pred.clone(), succ.clone()))
        );

        item.set_type(false);
        assert_eq!(item.compute_branch(succ.clone()), Some(WorkItemEdge::False(pred, succ)));
    }

    #[test]
    #[should_panic(expected = "pred is None")]
    fn compute_branch_panics_when_there_is_no_pred() {
        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 0));
        let item: WorkItem<MockStatement> = WorkItem::new(None, ctx);
        let succ = MockStatement(PcodeLocation::new(op_at(OpCode::Copy, 0x3000, 0)));
        let _ = item.compute_branch(succ);
    }

    #[test]
    #[should_panic(expected = "pred's location is not a PcodeLocation")]
    fn compute_branch_panics_when_the_preds_location_is_not_a_pcode_location() {
        #[derive(Clone)]
        struct ForeignStatement;
        impl WorkItemStatement for ForeignStatement {
            fn location(&self) -> Box<dyn CodeLocation> {
                struct ForeignLocation;
                impl CodeLocation for ForeignLocation {
                    fn compare_to(&self, _other: &dyn CodeLocation) -> std::cmp::Ordering {
                        std::cmp::Ordering::Equal
                    }
                    fn get_code_location(&self) -> String {
                        "foreign".to_string()
                    }
                    fn as_any(&self) -> &dyn std::any::Any {
                        self
                    }
                }
                Box::new(ForeignLocation)
            }
        }

        let ctx = StatementContext::from_op(op_at(OpCode::Copy, 0x1000, 0));
        let item = WorkItem::new(Some(ForeignStatement), ctx);
        let succ = ForeignStatement;
        let _ = item.compute_branch(succ);
    }
}
