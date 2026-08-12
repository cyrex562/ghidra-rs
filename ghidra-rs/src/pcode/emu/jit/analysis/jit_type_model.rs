//! The type analysis for JIT-accelerated emulation.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitTypeModel`.
//!
//! This implements the Type Assignment phase of the JIT compiler using a very basic "voting"
//! algorithm. The result is an assignment of a type to each
//! [`JitVal`](crate::pcode::emu::jit::var::JitVal) in the use-def graph -- to variables and
//! constants, not to varnodes.
//!
//! # Types in p-code and the JVM
//!
//! P-code is a relatively type-free language: aside from size, variables are just bit vectors, and
//! the operators cast the bits as required. JVM variables, in contrast, have a type, and
//! conversions between JVM types must be explicit. Only two aspects of a p-code type require such
//! a conversion -- its [behavior](JitTypeBehavior) (integral vs. floating-point) and its size --
//! so signedness is omitted from [`JitType`](super::jit_type::JitType) entirely: it is just a
//! behavior applied to a size, e.g. [`IntJitType::I3`](super::jit_type::IntJitType::I3).
//!
//! # Type assignment
//!
//! The type of an *operand* is trivially determined: the p-code opcode specifies each operand's
//! behavior, and the op instance's varnode specifies its size. So `$U00:4 = FLOAT_ADD r0, r1`
//! casts a vote that `$U00:4` be `float4`, while a subsequent `r2 = INT_2COMP $U00` casts a vote
//! for `int4`. Ties favor integers, so `$U00:4` here is assigned `int4`.
//!
//! This becomes complicated in the face of the typeless ops, namely `JitCopyOp` and
//! [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp). For `r1 = COPY r0`, the JVM
//! requires the source and destination locals to have the same type, or else a cast; so the votes
//! regarding `r0` must incorporate the votes regarding `r1` and vice versa.
//!
//! The algorithm is a queued traversal of the use-def graph until convergence. Every value starts
//! assigned [`JitTypeBehavior::Any`] and queued. Processing a value tallies the votes of its uses
//! and of its defining op: [`Integer`](JitTypeBehavior::Integer) and
//! [`Float`](JitTypeBehavior::Float) each count as one vote, [`Any`](JitTypeBehavior::Any)
//! contributes none, and [`Copy`](JitTypeBehavior::Copy) means the use is a copy or phi, so the
//! vote goes to the *tentative* assignment of that op's output instead. The defining op, if it is
//! a copy or phi, runs a sub-contest among its inputs' tentative assignments and votes for the
//! winner. When a value's tentative assignment changes, its neighbors -- the values connected to
//! it through a copy or phi -- are re-queued, since their votes may change too. Whatever remains
//! [`Any`](JitTypeBehavior::Any) at the end is treated as an integer, which is exactly what
//! [`JitTypeBehavior::type_of`] does for that variant.
//!
//! # Differences from Java
//!
//! - Java's `assignments` is an identity-keyed `Map<JitVal, JitTypeBehavior>` and its `queue` a
//!   `SequencedSet<JitVal>`. Neither has a direct Rust counterpart over `dyn JitVal`, which is
//!   neither `Hash` nor `Eq`. Instead, the values reported by the data flow model are numbered
//!   once, and both the assignment table and the queue work in those indices; [`ValIndex`] maps a
//!   value back to its number by object identity, which is what Java's maps compare on. This also
//!   keeps the queue local to [`JitTypeModel::analyze`], since it is scratch state that is always
//!   empty once construction returns.
//! - Java holds the `JitDataFlowModel` in a field, but only reads it in `analyze()`, so this port
//!   takes it as a constructor parameter and keeps the values it reported rather than the model.
//!   The values must be kept: the assignment table is keyed by their addresses.
//! - `out.definition()` is `Option` here, and Java would throw a `NullPointerException` on a value
//!   whose definition is unset. This port instead leaves `defType` at
//!   [`Any`](JitTypeBehavior::Any) -- the value Java's `computeNewAssignment` initializes it to
//!   before overwriting it unconditionally.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::pcode::emu::jit::analysis::jit_type::AnyJitType;
use crate::pcode::emu::jit::var::{JitOutVar, JitVal};
use crate::pcode::seam_stubs::{JitDataFlowModel, JitTypeBehavior};

/// The identity of a value node, i.e. the address of the node itself.
///
/// This is what Java's `HashMap<JitVal, ..>` keys on: no `JitVal` implementation overrides
/// `equals`, so its maps compare references. Only the thin part of the pointer is taken, so that a
/// node reached as a [`JitOutVar`](crate::pcode::emu::jit::var::JitOutVar) (see
/// [`identity_of_out_var`]) has the same identity as the same node reached as a [`JitVal`], as it
/// does in Java.
fn identity_of(val: &dyn JitVal) -> usize {
    (val as *const dyn JitVal).cast::<()>() as usize
}

/// The identity of an output variable node. See [`identity_of`].
///
/// An out var is only ever reached through the op that defines it, which hands back the
/// `JitOutVar` view of the node rather than the `JitVal` one; the two views share an address.
fn identity_of_out_var(out: &Arc<dyn JitOutVar>) -> usize {
    Arc::as_ptr(out).cast::<()>() as usize
}

/// A contest to determine a type assignment.
///
/// Port of `JitTypeModel.Contest`.
#[derive(Debug, Default)]
struct Contest {
    /// The vote count for each candidate. A candidate absent from the map has no votes.
    counts: HashMap<JitTypeBehavior, i32>,
}

impl Contest {
    /// Start a new contest.
    ///
    /// Port of the no-arg `Contest()`.
    fn new() -> Self {
        Self::default()
    }

    /// Cast `c` votes for the given candidate.
    ///
    /// Port of the private `vote(JitTypeBehavior, int)`.
    fn vote_n(&mut self, candidate: JitTypeBehavior, c: i32) {
        if candidate == JitTypeBehavior::Any || candidate == JitTypeBehavior::Copy {
            return;
        }
        *self.counts.entry(candidate).or_insert(0) += c;
    }

    /// Cast a vote for the given candidate.
    ///
    /// Port of `vote(JitTypeBehavior)`.
    fn vote(&mut self, candidate: JitTypeBehavior) {
        self.vote_n(candidate, 1);
    }

    /// Compute the winner of the contest, or [`JitTypeBehavior::Any`] if no votes were cast.
    ///
    /// Port of `winner()`.
    fn winner(&self) -> JitTypeBehavior {
        self.counts
            .iter()
            .max_by(|ent1, ent2| compare_candidate_entries(*ent1, *ent2))
            .map(|(candidate, _)| *candidate)
            .unwrap_or(JitTypeBehavior::Any)
    }
}

/// Compare the votes between two candidates, and select the winner.
///
/// [`Contest::winner`] seeks the "max" candidate, so the vote counts are compared in the usual
/// fashion. The comparison of the behaviors is inverted, though: [`JitTypeBehavior::Integer`]
/// sorts before [`JitTypeBehavior::Float`], but int is the preferred winner on a tie.
///
/// Port of the static `Contest.compareCandidateEntries(Entry, Entry)`. Since the behaviors are
/// distinct map keys, this never returns [`Ordering::Equal`], so the maximum is unambiguous.
fn compare_candidate_entries(
    ent1: (&JitTypeBehavior, &i32),
    ent2: (&JitTypeBehavior, &i32),
) -> Ordering {
    ent1.1.cmp(ent2.1).then_with(|| JitTypeBehavior::compare(*ent2.0, *ent1.0))
}

/// The values of the use-def graph, numbered so that they can key an assignment table.
///
/// See the "Differences from Java" note on this module: this stands in for the identity semantics
/// of Java's `HashMap<JitVal, ..>` and `LinkedHashSet<JitVal>`.
#[derive(Debug, Default)]
struct ValIndex {
    /// Each value's number, by [`identity_of`].
    numbers: HashMap<usize, usize>,
}

impl ValIndex {
    /// Number each of the given values, in the order reported.
    fn of(vals: &[Arc<dyn JitVal>]) -> Self {
        Self {
            numbers: vals
                .iter()
                .enumerate()
                .map(|(i, val)| (identity_of(&**val), i))
                .collect(),
        }
    }

    /// The number of the value with the given identity, or `None` if it is not among the graph's
    /// values.
    fn get(&self, identity: usize) -> Option<usize> {
        self.numbers.get(&identity).copied()
    }
}

/// The type analysis for JIT-accelerated emulation.
///
/// Port of `ghidra.pcode.emu.jit.analysis.JitTypeModel`. Constructing one performs the analysis;
/// [`type_of`](Self::type_of) then reports the final assignment of any value in the graph.
pub struct JitTypeModel {
    /// The values of the use-def graph, as reported by the data flow model. Held so that the
    /// addresses [`index`](Self::index) is keyed by stay valid and unique.
    vals: Vec<Arc<dyn JitVal>>,
    /// The number of each value in [`vals`](Self::vals).
    index: ValIndex,
    /// The type assignment of each value, positionally matching [`vals`](Self::vals).
    ///
    /// Port of `assignments`.
    assignments: Vec<JitTypeBehavior>,
}

impl JitTypeModel {
    /// Construct the type model and perform the analysis.
    ///
    /// Port of `JitTypeModel(JitDataFlowModel)`, whose constructor likewise calls `analyze()`.
    pub fn new(dfm: &dyn JitDataFlowModel) -> Self {
        let vals = dfm.all_values();
        let index = ValIndex::of(&vals);
        let assignments = vec![JitTypeBehavior::Any; vals.len()];
        let mut model = Self { vals, index, assignments };
        model.analyze();
        model
    }

    /// The current tentative assignment of the given value.
    ///
    /// Port of `assignments.get(v)`.
    ///
    /// # Panics
    ///
    /// If the value is not one of those the data flow model reported, where Java's `get` would
    /// return `null` and its caller would throw a `NullPointerException`. Every value reachable
    /// through the use-def graph is in `allValues()`, so this indicates an inconsistent graph.
    fn assignment_of(&self, identity: usize) -> JitTypeBehavior {
        match self.index.get(identity) {
            Some(i) => self.assignments[i],
            None => panic!("NullPointerException: value is not in the data flow model's graph"),
        }
    }

    /// Compute the new tentative assignment for the value numbered `i`.
    ///
    /// As discussed in this module's docs, this tallies up the votes among the value's uses and
    /// defining op, then selects the winner.
    ///
    /// Port of `computeNewAssignment(JitVal)`.
    fn compute_new_assignment(&self, i: usize) -> JitTypeBehavior {
        let val = &self.vals[i];
        let mut contest = Contest::new();

        // Downstream votes
        for use_ in val.uses() {
            let mut type_ = use_.type_();
            if type_ == JitTypeBehavior::Copy {
                if let Some(def) = use_.op.as_def_op() {
                    let downstream = def.out();
                    type_ = self.assignment_of(identity_of_out_var(&downstream));
                }
            }
            contest.vote(type_);
        }

        // Upstream votes
        if let Some(out) = val.as_out_var() {
            let mut def_type = JitTypeBehavior::Any;
            if let Some(def) = out.definition() {
                def_type = def.type_();
                if def_type == JitTypeBehavior::Copy {
                    let mut sub_contest = Contest::new();
                    for upstream in def.inputs() {
                        sub_contest.vote(self.assignment_of(identity_of(&*upstream)));
                    }
                    def_type = sub_contest.winner();
                }
            }
            contest.vote(def_type);
        }

        contest.winner()
    }

    /// The numbers of the neighbors of the value numbered `i`.
    ///
    /// Neighbors are any values connected to the given one via a copy or phi -- or any op with an
    /// operand requiring [`JitTypeBehavior::Copy`], should additional ones appear in the future.
    /// They must be re-processed because those ops may change their vote now that this value's
    /// tentative type has changed.
    ///
    /// Port of `queueNeighbors(JitVal)`, which adds them straight to the queue; here the caller
    /// owns the queue (see this module's docs), so they are returned instead. A neighbor the data
    /// flow model did not report is skipped: it has no assignment to update.
    fn neighbors(&self, i: usize) -> Vec<usize> {
        let val = &self.vals[i];
        let mut neighbors = Vec::new();

        for use_ in val.uses() {
            if use_.type_() == JitTypeBehavior::Copy {
                if let Some(def) = use_.op.as_def_op() {
                    neighbors.extend(self.index.get(identity_of_out_var(&def.out())));
                }
            }
        }

        if let Some(out) = val.as_out_var() {
            if let Some(def) = out.definition() {
                if def.type_() == JitTypeBehavior::Copy {
                    neighbors.extend(
                        def.inputs().iter().filter_map(|up| self.index.get(identity_of(&**up))),
                    );
                }
            }
        }

        neighbors
    }

    /// Perform the analysis.
    ///
    /// This queues every value up to be processed at least once and then runs the algorithm to
    /// termination. Each value in the queue is removed and a voting contest run to update its type
    /// assignment. If the new assignment differs from its old assignment, its neighbors (if any)
    /// are re-added to the queue.
    ///
    /// Port of `analyze()`. Java's `SequencedSet` becomes a queue of value numbers paired with a
    /// set of the numbers it holds, so that re-adding a value already queued is the no-op it is in
    /// Java, rather than a duplicate visit.
    fn analyze(&mut self) {
        let mut queue: VecDeque<usize> = (0..self.vals.len()).collect();
        let mut queued: HashSet<usize> = (0..self.vals.len()).collect();

        while let Some(i) = queue.pop_front() {
            queued.remove(&i);
            let type_ = self.compute_new_assignment(i);
            let old = std::mem::replace(&mut self.assignments[i], type_);
            if old != type_ {
                for neighbor in self.neighbors(i) {
                    if queued.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }
    }

    /// Get the final type assignment for the given value.
    ///
    /// Port of `typeOf(JitVal)`. A value that received no votes is assigned
    /// [`JitTypeBehavior::Any`], which resolves to the integer type of its size.
    ///
    /// # Panics
    ///
    /// If the value is not one of those the data flow model reported. See
    /// [`assignment_of`](Self::assignment_of).
    pub fn type_of(&self, val: &dyn JitVal) -> AnyJitType {
        self.assignment_of(identity_of(val)).type_of(val.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::pcode::emu::jit::analysis::jit_type::{
        DoubleJitType, FloatJitType, IntJitType, LongJitType,
    };
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::{JitOutVar, JitVar, JitVarnodeVar, ValUse};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;

    /// A value node with a fixed size and an explicit use list, standing in for the constants and
    /// input variables of a real passage.
    struct TestVal {
        size: i32,
        uses: Mutex<Vec<ValUse>>,
    }

    impl TestVal {
        fn new(size: i32) -> Self {
            Self { size, uses: Mutex::new(Vec::new()) }
        }
    }

    impl JitVal for TestVal {
        fn size(&self) -> i32 {
            self.size
        }

        fn uses(&self) -> Vec<ValUse> {
            self.uses.lock().unwrap().clone()
        }

        fn add_use(&self, op: &dyn JitOp, _position: i32) {
            let _ = op;
        }

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    /// An output variable node: a [`TestVal`] that also reports its defining op.
    struct TestOutVar {
        val: TestVal,
        definition: Mutex<Option<Arc<dyn JitDefOp>>>,
    }

    impl TestOutVar {
        fn new(size: i32) -> Self {
            Self { val: TestVal::new(size), definition: Mutex::new(None) }
        }
    }

    impl JitVal for TestOutVar {
        fn size(&self) -> i32 {
            self.val.size()
        }

        fn uses(&self) -> Vec<ValUse> {
            self.val.uses()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn as_out_var(&self) -> Option<&dyn JitOutVar> {
            Some(self)
        }
    }

    impl JitVar for TestOutVar {
        fn id(&self) -> i32 {
            0
        }

        fn space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("unique", 64, 1, AddressSpaceType::Unique, 0)
        }
    }

    impl JitVarnodeVar for TestOutVar {
        fn varnode(&self) -> Varnode {
            let addr = Address::new(JitVar::space(self), 0);
            Varnode::new(addr, self.val.size())
        }
    }

    impl JitOutVar for TestOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}

        fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
            *self.definition.lock().unwrap() = definition;
        }

        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            self.definition.lock().unwrap().clone()
        }
    }

    /// A def op with a uniform operand behavior, e.g. `FLOAT_ADD` (float in, float out) or `COPY`
    /// (copy in, copy out).
    struct TestOp {
        out: Arc<TestOutVar>,
        inputs: Vec<Arc<dyn JitVal>>,
        behavior: JitTypeBehavior,
    }

    impl JitOp for TestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            self.behavior
        }

        fn link(&self) {}

        fn unlink(&self) {}

        fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
            self.inputs.clone()
        }

        fn as_def_op(&self) -> Option<&dyn JitDefOp> {
            Some(self)
        }
    }

    impl JitDefOp for TestOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            Arc::clone(&self.out) as Arc<dyn JitOutVar>
        }

        fn type_(&self) -> JitTypeBehavior {
            self.behavior
        }
    }

    /// Wire up an op: record it as each input's use, and as its output's definition.
    ///
    /// Stands in for `JitOp.link()`, which the ported nodes cannot do themselves (see
    /// [`JitOutVar::set_definition_arc`]).
    fn link(op: Arc<TestOp>, inputs: &[&Arc<TestVal>]) {
        for (position, input) in inputs.iter().enumerate() {
            input
                .uses
                .lock()
                .unwrap()
                .push(ValUse::new(Arc::clone(&op) as Arc<dyn JitOp>, position as i32));
        }
        op.out.set_definition_arc(Some(op.clone() as Arc<dyn JitDefOp>));
    }

    /// Record a use of `val` by `op` at `position`, for values that feed an op built separately.
    fn add_use(val: &Arc<TestOutVar>, op: &Arc<TestOp>, position: i32) {
        val.val
            .uses
            .lock()
            .unwrap()
            .push(ValUse::new(Arc::clone(op) as Arc<dyn JitOp>, position));
    }

    /// A data flow model that reports a fixed set of values.
    struct TestDfm {
        vals: Vec<Arc<dyn JitVal>>,
    }

    impl JitDataFlowModel for TestDfm {
        fn generate_out_var(&self, _out: &Varnode) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }

        fn notify_op(&self, _op: Arc<dyn JitOp>) {}

        fn all_values(&self) -> Vec<Arc<dyn JitVal>> {
            self.vals.clone()
        }
    }

    // Java's worked example: `$U00:4 = FLOAT_ADD r0, r1` votes float4 for $U00, while the
    // subsequent `r2 = INT_2COMP $U00` votes int4. Ties favor int, so $U00 is assigned int4 --
    // and each op's own operands take their op's behavior.
    #[test]
    fn tied_votes_favor_integer() {
        let r0 = Arc::new(TestVal::new(4));
        let r1 = Arc::new(TestVal::new(4));
        let u00 = Arc::new(TestOutVar::new(4));
        let r2 = Arc::new(TestOutVar::new(4));

        let add = Arc::new(TestOp {
            out: Arc::clone(&u00),
            inputs: vec![Arc::clone(&r0) as Arc<dyn JitVal>, Arc::clone(&r1) as Arc<dyn JitVal>],
            behavior: JitTypeBehavior::Float,
        });
        link(Arc::clone(&add), &[&r0, &r1]);

        let comp = Arc::new(TestOp {
            out: Arc::clone(&r2),
            inputs: vec![Arc::clone(&u00) as Arc<dyn JitVal>],
            behavior: JitTypeBehavior::Integer,
        });
        link(Arc::clone(&comp), &[]);
        add_use(&u00, &comp, 0);

        let dfm = TestDfm {
            vals: vec![
                Arc::clone(&r0) as Arc<dyn JitVal>,
                Arc::clone(&r1) as Arc<dyn JitVal>,
                Arc::clone(&u00) as Arc<dyn JitVal>,
                Arc::clone(&r2) as Arc<dyn JitVal>,
            ],
        };
        let model = JitTypeModel::new(&dfm);

        // One vote float (from FLOAT_ADD's output) and one vote int (from INT_2COMP's operand).
        assert_eq!(model.type_of(&*u00), AnyJitType::Int(IntJitType::I4));
        // The addends are only ever used as floats.
        assert_eq!(model.type_of(&*r0), AnyJitType::Float(FloatJitType::F4));
        assert_eq!(model.type_of(&*r1), AnyJitType::Float(FloatJitType::F4));
    }

    // A value with two float uses and one int use wins float, 2 to 1.
    #[test]
    fn the_majority_behavior_wins() {
        let src = Arc::new(TestVal::new(8));
        let outs: Vec<Arc<TestOutVar>> = (0..3).map(|_| Arc::new(TestOutVar::new(8))).collect();

        for (i, out) in outs.iter().enumerate() {
            let op = Arc::new(TestOp {
                out: Arc::clone(out),
                inputs: vec![Arc::clone(&src) as Arc<dyn JitVal>],
                behavior: if i < 2 { JitTypeBehavior::Float } else { JitTypeBehavior::Integer },
            });
            link(op, &[&src]);
        }

        let mut vals: Vec<Arc<dyn JitVal>> = vec![Arc::clone(&src) as Arc<dyn JitVal>];
        vals.extend(outs.iter().map(|o| Arc::clone(o) as Arc<dyn JitVal>));
        let model = JitTypeModel::new(&TestDfm { vals });

        assert_eq!(model.type_of(&*src), AnyJitType::Double(DoubleJitType::F8));
        // Each output takes its own op's behavior; the int op's output has no other vote.
        assert_eq!(model.type_of(&*outs[0]), AnyJitType::Double(DoubleJitType::F8));
        assert_eq!(model.type_of(&*outs[2]), AnyJitType::Long(LongJitType::I8));
    }

    // A copy is typeless: `r1 = COPY r0` must propagate the votes about r1 back onto r0, so that
    // both locals get the same JVM type and the copy needs no cast. Here r1's only other use is
    // as a float, so r0 -- which no op interprets directly -- comes out float too.
    #[test]
    fn copy_propagates_the_type_across_the_graph() {
        let r0 = Arc::new(TestVal::new(4));
        let r1 = Arc::new(TestOutVar::new(4));
        let r2 = Arc::new(TestOutVar::new(4));

        let copy = Arc::new(TestOp {
            out: Arc::clone(&r1),
            inputs: vec![Arc::clone(&r0) as Arc<dyn JitVal>],
            behavior: JitTypeBehavior::Copy,
        });
        link(Arc::clone(&copy), &[&r0]);

        let sqrt = Arc::new(TestOp {
            out: Arc::clone(&r2),
            inputs: vec![Arc::clone(&r1) as Arc<dyn JitVal>],
            behavior: JitTypeBehavior::Float,
        });
        link(Arc::clone(&sqrt), &[]);
        add_use(&r1, &sqrt, 0);

        let dfm = TestDfm {
            vals: vec![
                Arc::clone(&r0) as Arc<dyn JitVal>,
                Arc::clone(&r1) as Arc<dyn JitVal>,
                Arc::clone(&r2) as Arc<dyn JitVal>,
            ],
        };
        let model = JitTypeModel::new(&dfm);

        assert_eq!(model.type_of(&*r1), AnyJitType::Float(FloatJitType::F4));
        // r0's own use is the copy, which votes whatever r1 was assigned.
        assert_eq!(model.type_of(&*r0), AnyJitType::Float(FloatJitType::F4));
    }

    // A value nothing interprets stays ANY, which resolves to the integer type of its size --
    // "any assignment that remains ANY is treated as if INT."
    #[test]
    fn unvoted_values_default_to_integers() {
        let orphan5 = Arc::new(TestVal::new(5));
        let orphan16 = Arc::new(TestVal::new(16));
        let dfm = TestDfm {
            vals: vec![
                Arc::clone(&orphan5) as Arc<dyn JitVal>,
                Arc::clone(&orphan16) as Arc<dyn JitVal>,
            ],
        };
        let model = JitTypeModel::new(&dfm);

        assert_eq!(model.type_of(&*orphan5), AnyJitType::Long(LongJitType::I5));
        assert_eq!(
            model.type_of(&*orphan16),
            JitTypeBehavior::Integer.type_of(16)
        );
    }

    // Java's Contest: ANY and COPY contribute no votes, an empty contest's winner is ANY, and
    // equal counts go to INTEGER (`compareCandidateEntries` negates the key comparison).
    #[test]
    fn contest_counts_only_typed_votes_and_breaks_ties_toward_integer() {
        let mut contest = Contest::new();
        assert_eq!(contest.winner(), JitTypeBehavior::Any);

        contest.vote(JitTypeBehavior::Any);
        contest.vote(JitTypeBehavior::Copy);
        assert_eq!(contest.winner(), JitTypeBehavior::Any);

        contest.vote(JitTypeBehavior::Float);
        assert_eq!(contest.winner(), JitTypeBehavior::Float);

        contest.vote(JitTypeBehavior::Integer);
        assert_eq!(contest.winner(), JitTypeBehavior::Integer);

        contest.vote(JitTypeBehavior::Float);
        assert_eq!(contest.winner(), JitTypeBehavior::Float);
    }

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn type_of_rejects_a_value_outside_the_graph() {
        let model = JitTypeModel::new(&TestDfm { vals: Vec::new() });
        model.type_of(&TestVal::new(4));
    }
}
