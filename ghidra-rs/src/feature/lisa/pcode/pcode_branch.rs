//! Port of `ghidra.lisa.pcode.PcodeBranch`.

use std::fmt;
use std::hash::Hash;

use crate::feature::lisa::pcode::work_item::PredType;

/// Stand-in for the one operation [`PcodeBranch`] performs on Java's
/// `NodeList<CFG, Statement, Edge> cfgMatrix`: looking up a statement's successors in the CFG
/// being built (Java: `cfgMatrix.followersOf(Statement)`).
///
/// Generic over `S`, the caller's chosen stand-in for LiSA's `Statement` (the same role
/// [`WorkItemStatement`](crate::feature::lisa::pcode::work_item::WorkItemStatement) plays for
/// [`WorkItem`](crate::feature::lisa::pcode::work_item::WorkItem)).
pub trait PcodeBranchCfgMatrix<S> {
    /// Java: `cfgMatrix.followersOf(Statement)`.
    fn followers_of(&self, statement: &S) -> Vec<S>;
}

/// One `if`/`then`/`else` control-flow structure discovered while translating p-code into a LiSA
/// CFG: the "true" successor of a conditional branch, and the "false" (fall-through) successor.
///
/// Corresponds to `ghidra.lisa.pcode.PcodeBranch` in the Java source, which `extends
/// it.unive.lisa.program.cfg.controlFlow.ControlFlowStructure`. That LiSA base class (and the
/// `CFG`/`Statement`/`Edge`/`NodeList` types its constructor and abstract methods are built on) is
/// an external third-party dependency with no Rust port anywhere in this crate (the same situation
/// [`WorkItem`](crate::feature::lisa::pcode::work_item::WorkItem)'s docs describe for the sibling
/// `WorkItem` class). Following that established convention:
///
/// * This struct holds the data Java's `ControlFlowStructure` superclass constructor call
///   (`super(cfgMatrix, condition, null)`) actually stores -- `cfgMatrix`, `condition`, and
///   `firstFollower` (initially `null`) -- rather than re-deriving a `ControlFlowStructure` base
///   class.
/// * Java's `NodeList<CFG, Statement, Edge> cfgMatrix` is narrowed to exactly the one operation
///   this class calls on it (`followersOf`), via the small [`PcodeBranchCfgMatrix`] trait above.
/// * Java's `Statement` (used for `condition`, `firstFollower`, `branch`, `fallThrough`, and every
///   method parameter/return here) has no Rust port; this struct is generic over `S`, the caller's
///   chosen stand-in for it, matching
///   [`WorkItem<P>`](crate::feature::lisa::pcode::work_item::WorkItem)'s own `P` type parameter.
pub struct PcodeBranch<S, M> {
    /// Java: `cfgMatrix`, inherited from the `ControlFlowStructure` superclass.
    cfg_matrix: M,
    /// Java: `condition`, inherited from the `ControlFlowStructure` superclass -- the branch's
    /// guard statement, e.g. a `CBranch` p-code op.
    condition: S,
    /// Java: `firstFollower`, inherited from the `ControlFlowStructure` superclass. Populated by
    /// [`PcodeBranch::add_statement`] (Java: `setFirstFollower(st)`) when a fall-through statement
    /// is added.
    first_follower: Option<S>,
    /// Java: `private Statement branch` -- the "true" successor of the condition.
    branch: Option<S>,
    /// Java: `private Statement fallThrough` -- the "false"/fall-through successor of the
    /// condition.
    fall_through: Option<S>,
}

impl<S, M> PcodeBranch<S, M>
where
    S: Clone + Eq + Hash,
    M: PcodeBranchCfgMatrix<S>,
{
    /// Java: `protected PcodeBranch(NodeList<CFG, Statement, Edge> cfgMatrix, Statement
    /// condition)`, which delegates to `super(cfgMatrix, condition, null)`.
    pub fn new(cfg_matrix: M, condition: S) -> Self {
        Self { cfg_matrix, condition, first_follower: None, branch: None, fall_through: None }
    }

    /// Java: `protected Collection<Statement> bodyStatements()`.
    pub fn body_statements(&self) -> std::collections::HashSet<S> {
        let mut all = self.get_true_branch();
        all.extend(self.get_false_branch());
        all
    }

    /// Java: `private Collection<Statement> getFalseBranch()`.
    fn get_false_branch(&self) -> std::collections::HashSet<S> {
        match &self.fall_through {
            None => std::collections::HashSet::new(),
            Some(st) => self.cfg_matrix.followers_of(st).into_iter().collect(),
        }
    }

    /// Java: `private Collection<Statement> getTrueBranch()`.
    fn get_true_branch(&self) -> std::collections::HashSet<S> {
        match &self.branch {
            None => std::collections::HashSet::new(),
            Some(st) => self.cfg_matrix.followers_of(st).into_iter().collect(),
        }
    }

    /// Java: `public boolean contains(Statement st)`.
    pub fn contains(&self, st: &S) -> bool {
        self.body_statements().contains(st)
    }

    /// Java: `public void simplify()`, `// Nothing required here`.
    pub fn simplify(&self) {}

    /// Java: `public Collection<Statement> getTargetedStatements()`.
    pub fn get_targeted_statements(&self) -> std::collections::HashSet<S> {
        self.body_statements()
    }

    /// Java: `public void addStatement(Statement st, PredType type)`.
    ///
    /// # Java quirk preserved
    ///
    /// Java's `if (type.equals(PredType.TRUE)) { branch = st; } else { fallThrough = st;
    /// setFirstFollower(st); }` treats *any* non-`TRUE` `PredType` -- not just `FALSE`, but also
    /// `SEQ` -- as the fall-through case. Reproduced here as-is via the same `if pred_type ==
    /// PredType::True { .. } else { .. }` shape rather than matching `PredType::False`
    /// specifically.
    pub fn add_statement(&mut self, st: S, pred_type: PredType) {
        if pred_type == PredType::True {
            self.branch = Some(st);
        }
        else {
            self.fall_through = Some(st.clone());
            self.first_follower = Some(st);
        }
    }

    /// Java: `public Statement getBranch()`.
    pub fn get_branch(&self) -> Option<&S> {
        self.branch.as_ref()
    }

    /// Java: `public Statement getFallThrough()`.
    pub fn get_fall_through(&self) -> Option<&S> {
        self.fall_through.as_ref()
    }

    /// Java: `getCondition()`, inherited from the `ControlFlowStructure` superclass -- exposed
    /// here since [`PcodeBranch`]'s own `toString` override (this port's [`Display`](fmt::Display)
    /// impl) reads it.
    pub fn get_condition(&self) -> &S {
        &self.condition
    }

    /// Java: inherited `getFirstFollower()`-style accessor for the `firstFollower` field
    /// [`PcodeBranch::add_statement`] populates.
    pub fn get_first_follower(&self) -> Option<&S> {
        self.first_follower.as_ref()
    }
}

impl<S: fmt::Display, M> fmt::Display for PcodeBranch<S, M> {
    /// Java: `public String toString()`, `"if-then-else[" + getCondition() + "]"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "if-then-else[{}]", self.condition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct St(&'static str);

    impl fmt::Display for St {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    struct MockMatrix {
        followers: HashMap<St, Vec<St>>,
    }

    impl PcodeBranchCfgMatrix<St> for MockMatrix {
        fn followers_of(&self, statement: &St) -> Vec<St> {
            self.followers.get(statement).cloned().unwrap_or_default()
        }
    }

    fn matrix() -> MockMatrix {
        let mut followers = HashMap::new();
        followers.insert(St("cbranch"), vec![St("true_target")]);
        followers.insert(St("fallthrough"), vec![St("false_target")]);
        MockMatrix { followers }
    }

    #[test]
    fn new_starts_with_no_branch_fall_through_or_first_follower() {
        let branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        assert!(branch.get_branch().is_none());
        assert!(branch.get_fall_through().is_none());
        assert!(branch.get_first_follower().is_none());
        assert_eq!(branch.get_condition(), &St("cbranch"));
    }

    #[test]
    fn add_statement_true_sets_branch_only() {
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("true_target"), PredType::True);
        assert_eq!(branch.get_branch(), Some(&St("true_target")));
        assert!(branch.get_fall_through().is_none());
        assert!(branch.get_first_follower().is_none());
    }

    #[test]
    fn add_statement_false_sets_fall_through_and_first_follower() {
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("fallthrough"), PredType::False);
        assert!(branch.get_branch().is_none());
        assert_eq!(branch.get_fall_through(), Some(&St("fallthrough")));
        assert_eq!(branch.get_first_follower(), Some(&St("fallthrough")));
    }

    #[test]
    fn add_statement_seq_also_takes_the_fall_through_path() {
        // Preserved Java quirk: the "else" branch fires for any non-TRUE PredType, including SEQ.
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("fallthrough"), PredType::Seq);
        assert_eq!(branch.get_fall_through(), Some(&St("fallthrough")));
        assert_eq!(branch.get_first_follower(), Some(&St("fallthrough")));
    }

    #[test]
    fn body_statements_is_empty_when_neither_branch_nor_fall_through_are_set() {
        let branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        assert!(branch.body_statements().is_empty());
        assert!(branch.get_targeted_statements().is_empty());
    }

    #[test]
    fn body_statements_unions_the_followers_of_branch_and_fall_through() {
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("cbranch"), PredType::True);
        branch.add_statement(St("fallthrough"), PredType::False);

        let body = branch.body_statements();
        assert_eq!(body.len(), 2);
        assert!(body.contains(&St("true_target")));
        assert!(body.contains(&St("false_target")));
        assert_eq!(branch.get_targeted_statements(), body);
    }

    #[test]
    fn contains_reflects_body_statements() {
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("cbranch"), PredType::True);

        assert!(branch.contains(&St("true_target")));
        assert!(!branch.contains(&St("false_target")));
    }

    #[test]
    fn simplify_is_a_no_op() {
        let mut branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        branch.add_statement(St("cbranch"), PredType::True);
        let before = branch.body_statements();
        branch.simplify();
        assert_eq!(branch.body_statements(), before);
    }

    #[test]
    fn display_matches_java_format() {
        let branch: PcodeBranch<St, MockMatrix> = PcodeBranch::new(matrix(), St("cbranch"));
        assert_eq!(branch.to_string(), "if-then-else[cbranch]");
    }
}
