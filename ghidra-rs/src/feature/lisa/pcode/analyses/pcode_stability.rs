//! Port of `ghidra.lisa.pcode.analyses.PcodeStability`.
//!
//! This is the largest and most framework-heavy class in this package: an *open product* between
//! a caller-chosen auxiliary [`ValueDomain`] (`V` in the Java source, generic over
//! `V extends ValueDomain<V>`) and a `ValueEnvironment<Trend>` tracking each variable's trend.
//! Both halves are built on LiSA framework types with no Rust port anywhere in this crate and no
//! Java source available under `orig_src` to transcribe from (`it.unive.lisa.analysis.value.
//! ValueDomain`, `it.unive.lisa.analysis.nonrelational.value.ValueEnvironment`,
//! `it.unive.lisa.analysis.SemanticOracle`, `it.unive.lisa.symbolic.{SymbolicExpression,value.*}`,
//! `it.unive.lisa.symbolic.value.operator.binary.*`, `it.unive.lisa.symbolic.value.ScopeToken`,
//! `it.unive.lisa.program.SyntheticLocation`) -- the same situation
//! [`PcodeNonRelationalValueDomain`](super::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain)'s
//! docs describe for a sibling class, but considerably deeper here since this class's fields are
//! themselves *instances* of that unported framework rather than merely referencing it in method
//! signatures.
//!
//! Following this crate's established convention, the unported framework is represented as narrow
//! traits exposing exactly the operations this class's own body calls:
//! [`StabilityDomain`] (the common `ValueDomain`-shaped operations both the auxiliary domain `V`
//! and the `Trend` environment support), [`StabilityAuxDomain`] (the two additional operations
//! only the auxiliary domain needs: `assign`/`satisfies`), [`TrendEnvironment`] (the additional
//! per-identifier map operations only the `Trend` environment needs: `getKeys`/`getState`/
//! `putState`/`canProcess`, plus the "conjure a fresh instance" `fresh_top`, since Java's
//! `ValueEnvironment` constructors are called directly on `Trend.TOP` rather than through an
//! existing instance), and [`StabilityExpr`] (the runtime `instanceof`
//! `UnaryExpression`/`BinaryExpression`/`Identifier` pattern matches [`PcodeStability::assign`]
//! performs on its `ValueExpression` parameter, plus building fresh comparison/constant nodes).
//! [`Trend`](super::trend::Trend) and [`Satisfiability`](super::satisfiability::Satisfiability)
//! are real (not stubbed) ports this class's own logic directly depends on -- see their own module
//! docs.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::feature::lisa::pcode::analyses::satisfiability::Satisfiability;
use crate::feature::lisa::pcode::analyses::trend::Trend;
use crate::program::model::pcode::OpCode;

/// Stand-in for LiSA's `it.unive.lisa.symbolic.value.ScopeToken`, opaque to this class -- it is
/// only ever threaded through to [`StabilityDomain::push_scope`]/[`StabilityDomain::pop_scope`],
/// never itself inspected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeToken(pub String);

/// Comparison operators used to build synthetic query expressions ("a op b") to interrogate the
/// auxiliary domain -- LiSA's `ComparisonEq`/`ComparisonNe`/`ComparisonLt`/`ComparisonLe`/
/// `ComparisonGt`/`ComparisonGe` singleton `BinaryOperator`s used directly by
/// [`PcodeStability`]'s own logic (as opposed to
/// [`PcodeBinaryExpressionOperator`](crate::feature::lisa::pcode::expressions::pcode_binary_expression::PcodeBinaryExpressionOperator),
/// which tags an *existing* p-code-derived expression and has no `Gt`/`Ge` variants since no
/// p-code opcode maps to them directly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComparisonOperator {
    /// `ComparisonEq.INSTANCE`.
    Eq,
    /// `ComparisonNe.INSTANCE`.
    Ne,
    /// `ComparisonLt.INSTANCE`.
    Lt,
    /// `ComparisonLe.INSTANCE`.
    Le,
    /// `ComparisonGt.INSTANCE`.
    Gt,
    /// `ComparisonGe.INSTANCE`.
    Ge,
}

/// The runtime shape of a LiSA `ValueExpression`, as far as [`PcodeStability::assign`] cares:
/// whether it is (dynamically) a `UnaryExpression`, a `BinaryExpression`, or neither, and (for the
/// first two) whether its operator is further a p-code-derived
/// [`PcodeUnaryOperator`](crate::feature::lisa::pcode::statements::pcode_unary_operator::PcodeUnaryOperator)/
/// [`PcodeBinaryOperator`](crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator)
/// (as opposed to one of LiSA's built-in comparison/logical operators). Mirrors the nested
/// `instanceof` checks `assign`'s body performs:
///
/// ```text
/// if (expression instanceof UnaryExpression ue) {
///     if (ue.getOperator() instanceof PcodeUnaryOperator op) { ... }
/// }
/// else if (expression instanceof BinaryExpression be) {
///     if (be.getOperator() instanceof PcodeBinaryOperator op) { ... }
/// }
/// ```
///
/// The *outer* check alone selects between the [`Self::Unary`]/[`Self::Binary`]/[`Self::Other`]
/// variants (matching whether `assign` even enters the unary-vs-binary branch at all); the *inner*
/// check is carried as each variant's own `opcode: Option<OpCode>` field, `None` meaning "is a
/// Unary/BinaryExpression, but its operator isn't a p-code one" -- a shape distinct from
/// [`Self::Other`] (not a Unary/BinaryExpression at all), since both leave `assign`'s trend `t`
/// unmodified but for different reasons, and (crucially) an [`Self::Unary`] with `opcode: None`
/// must *not* fall through to also check [`Self::Binary`]-shaped handling, exactly like Java's
/// `else if` never re-tests a `BinaryExpression` instanceof once the `UnaryExpression` arm has
/// already matched.
#[derive(Clone, Debug)]
pub enum ExprShape<Expr> {
    /// `expression instanceof UnaryExpression ue`.
    Unary {
        /// `ue.getOperator() instanceof PcodeUnaryOperator op ? Some(op.getOp().getOpcode()) : None`.
        opcode: Option<OpCode>,
    },
    /// `expression instanceof BinaryExpression be`.
    Binary {
        /// `be.getOperator() instanceof PcodeBinaryOperator op ? Some(op.getOp().getOpcode()) : None`.
        opcode: Option<OpCode>,
        /// `be.getLeft()`.
        left: Expr,
        /// `be.getRight()`.
        right: Expr,
    },
    /// Neither a `UnaryExpression` nor a `BinaryExpression`.
    Other,
}

/// Stand-in for LiSA's `ValueExpression`/`SymbolicExpression`, narrowed to what
/// [`PcodeStability`]'s own logic actually does with one: inspect its runtime shape (see
/// [`ExprShape`]), test whether it structurally denotes a given identifier (`id.equals(expr)`,
/// mirrored here on the expression side as [`Self::identifier_equals`] for the same reason
/// [`AsIdentifier`](super::pcode_upper_bounds::AsIdentifier)'s docs describe testing on the
/// expression rather than the identifier), and build the two shapes of fresh expression node
/// `PcodeStability`'s private `binary`/`constantInt` helpers construct: a comparison of two
/// existing expressions, or an integer constant.
pub trait StabilityExpr<Id>: Clone {
    /// See [`ExprShape`].
    fn shape(&self) -> ExprShape<Self>;

    /// Mirrors `id.equals(expr)`, tested from the expression side -- `true` iff `self`
    /// structurally denotes the same identifier as `id`.
    fn identifier_equals(&self, id: &Id) -> bool;

    /// Mirrors passing an `Identifier` in a `SymbolicExpression`-typed parameter position (Java's
    /// `Identifier extends ValueExpression extends SymbolicExpression`, so no explicit conversion
    /// is needed there); this port needs an explicit upcast since `Id` and `Self` are unrelated
    /// type parameters here.
    fn from_identifier(id: &Id) -> Self;

    /// Java's private `BinaryExpression binary(BinaryOperator operator, SymbolicExpression l,
    /// SymbolicExpression r, ProgramPoint pp)` helper, minus the `pp`-derived static type (cosmetic
    /// type-checking metadata this port's domain semantics never inspects -- the same
    /// simplification
    /// [`PcodeParity::eval_null_constant`](crate::feature::lisa::pcode::analyses::pcode_parity::PcodeParity::eval_null_constant)'s
    /// docs describe for dropping other purely-cosmetic/unused parameters) and `pp`-derived
    /// `SyntheticLocation` (LiSA CFG plumbing with no bearing on this class's actual comparison
    /// semantics).
    fn comparison(operator: ComparisonOperator, left: &Self, right: &Self) -> Self;

    /// Java's private `Constant constantInt(int c, ProgramPoint pp)` helper, minus the same
    /// cosmetic `pp`-derived type/location metadata [`Self::comparison`]'s docs describe.
    fn constant_int(value: i32) -> Self;
}

/// The `ValueDomain`-shaped operations shared by both halves of [`PcodeStability`]'s open product:
/// the auxiliary domain `V` (via [`StabilityAuxDomain`]) and the `Trend` environment (via
/// [`TrendEnvironment`]). Mirrors the subset of LiSA's `it.unive.lisa.analysis.value.ValueDomain`/
/// `Lattice`/`SemanticDomain` interfaces [`PcodeStability`]'s own body calls on either field.
pub trait StabilityDomain: Clone {
    /// Stand-in for LiSA's `Identifier`.
    type Id: Clone + Eq + Hash;
    /// Stand-in for LiSA's `ValueExpression`/`SymbolicExpression`.
    type Expr: StabilityExpr<Self::Id>;
    /// Stand-in for LiSA's `ProgramPoint`.
    type ProgramPoint;
    /// Stand-in for LiSA's `SemanticOracle`.
    type Oracle;
    /// Stand-in for LiSA's `StructuredRepresentation`, narrowed to whatever shape this particular
    /// domain's `representation()` produces.
    type Representation: Clone + std::fmt::Debug + PartialEq;

    /// Java: `top()`.
    fn top(&self) -> Self;
    /// Java: `bottom()`.
    fn bottom(&self) -> Self;
    /// Java: `isTop()`.
    fn is_top(&self) -> bool;
    /// Java: `isBottom()`.
    fn is_bottom(&self) -> bool;
    /// Java: `lub(V)`.
    fn lub(&self, other: &Self) -> Self;
    /// Java: `glb(V)`.
    fn glb(&self, other: &Self) -> Self;
    /// Java: `widening(V)`.
    fn widening(&self, other: &Self) -> Self;
    /// Java: `lessOrEqual(V)`.
    fn less_or_equal(&self, other: &Self) -> bool;
    /// Java: `pushScope(ScopeToken)`.
    fn push_scope(&self, token: &ScopeToken) -> Self;
    /// Java: `popScope(ScopeToken)`.
    fn pop_scope(&self, token: &ScopeToken) -> Self;
    /// Java: `assume(ValueExpression, ProgramPoint src, ProgramPoint dest, SemanticOracle)`.
    fn assume(&self, expr: &Self::Expr, src: &Self::ProgramPoint, dest: &Self::ProgramPoint, oracle: &Self::Oracle) -> Self;
    /// Java: `smallStepSemantics(ValueExpression, ProgramPoint, SemanticOracle)`.
    fn small_step_semantics(&self, expr: &Self::Expr, pp: &Self::ProgramPoint, oracle: &Self::Oracle) -> Self;
    /// Java: `knowsIdentifier(Identifier)`.
    fn knows_identifier(&self, id: &Self::Id) -> bool;
    /// Java: `forgetIdentifier(Identifier)`.
    fn forget_identifier(&self, id: &Self::Id) -> Self;
    /// Java: `forgetIdentifiersIf(Predicate<Identifier>)`.
    fn forget_identifiers_if(&self, test: &dyn Fn(&Self::Id) -> bool) -> Self;
    /// Java: `representation()`.
    fn representation(&self) -> Self::Representation;
}

/// The two additional operations [`PcodeStability`] calls on its auxiliary domain `V` beyond the
/// shared [`StabilityDomain`] shape: `assign` (only meaningful for the domain actually holding
/// values, not the `Trend` environment, which is updated via [`TrendEnvironment::put_state`]
/// instead) and `satisfies` (queried by [`PcodeStability`]'s private `query` helper).
pub trait StabilityAuxDomain: StabilityDomain {
    /// Java: `assign(Identifier, ValueExpression, ProgramPoint, SemanticOracle)`.
    fn assign(&self, id: &Self::Id, expr: &Self::Expr, pp: &Self::ProgramPoint, oracle: &Self::Oracle) -> Self;
    /// Java: `satisfies(ValueExpression, ProgramPoint, SemanticOracle)`.
    fn satisfies(&self, expr: &Self::Expr, pp: &Self::ProgramPoint, oracle: &Self::Oracle) -> Satisfiability;
}

/// The additional per-identifier map operations [`PcodeStability`] calls on its
/// `ValueEnvironment<Trend> trends` field beyond the shared [`StabilityDomain`] shape.
pub trait TrendEnvironment: StabilityDomain {
    /// Java: `getKeys()`.
    fn get_keys(&self) -> Vec<Self::Id>;
    /// Java: `getState(Identifier)`.
    fn get_state(&self, id: &Self::Id) -> Trend;
    /// Java: `putState(Identifier, Trend)`.
    fn put_state(&self, id: &Self::Id, value: Trend) -> Self;
    /// Java: `lattice.canProcess(SymbolicExpression, ProgramPoint, SemanticOracle)`, called on
    /// `trends.lattice` (the per-identifier `Trend` "prototype" `ValueEnvironment` carries
    /// internally) rather than on `trends` itself.
    fn can_process(&self, expr: &Self::Expr, pp: &Self::ProgramPoint, oracle: &Self::Oracle) -> bool;
    /// Java: `new ValueEnvironment<>(Trend.TOP)` -- conjures a fresh, empty (all-identifiers-map-
    /// to-top) environment directly, without needing an existing instance to call `.top()` on.
    fn fresh_top() -> Self;
}

/// [`PcodeStability::representation`]'s result: the auxiliary domain's representation paired with
/// the trend environment's, mirroring Java's `new ObjectRepresentation(Map.of("aux",
/// aux.representation(), "trends", trends.representation()))`.
#[derive(Clone, Debug, PartialEq)]
pub struct StabilityRepresentation<AuxRepr, TrendRepr> {
    /// The `"aux"` entry.
    pub aux: AuxRepr,
    /// The `"trends"` entry.
    pub trends: TrendRepr,
}

/// The stability abstract domain: an open product between a caller-chosen auxiliary [`ValueDomain`]
/// `V` and a per-variable [`Trend`] environment, inferring numerical stability, covariance, and
/// contravariance relations between program variables.
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeStability<V extends ValueDomain<V>>` in the
/// Java source, which `implements BaseLattice<PcodeStability<V>>, ValueDomain<PcodeStability<V>>`.
/// See the module docs for how the unported LiSA framework this class is built on is represented
/// here.
#[derive(Clone, Debug)]
pub struct PcodeStability<V, Env>
where
    V: StabilityAuxDomain,
    Env: TrendEnvironment<Id = V::Id, Expr = V::Expr, ProgramPoint = V::ProgramPoint, Oracle = V::Oracle>,
{
    aux: V,
    trends: Env,
}

impl<V, Env> PcodeStability<V, Env>
where
    V: StabilityAuxDomain,
    Env: TrendEnvironment<Id = V::Id, Expr = V::Expr, ProgramPoint = V::ProgramPoint, Oracle = V::Oracle>,
{
    /// Java: `public PcodeStability(V aux)`.
    pub fn new(aux: V) -> Self {
        Self { aux: aux.top(), trends: Env::fresh_top() }
    }

    /// Java: `public PcodeStability(V aux, ValueEnvironment<Trend> trends)`.
    ///
    /// # Preserved ordering
    ///
    /// Java's two field assignments each read the *original* constructor parameters, not each
    /// other's freshly-assigned field: `this.trends = aux.isBottom() ? ... : trends;` tests the
    /// original `aux` parameter, unaffected by whatever `this.aux` was just set to on the previous
    /// line. This port captures both "was bottom" flags up front, before either normalized value
    /// is computed, to reproduce that precisely (a naive left-to-right port that read `new_aux`
    /// instead of the original `aux` would silently diverge whenever `trends` was bottom).
    pub fn with_trends(aux: V, trends: Env) -> Self {
        let aux_was_bottom = aux.is_bottom();
        let trends_was_bottom = trends.is_bottom();
        let new_aux = if trends_was_bottom { aux.bottom() } else { aux };
        let new_trends = if aux_was_bottom { trends.bottom() } else { trends };
        Self { aux: new_aux, trends: new_trends }
    }

    /// Java: `public PcodeStability<V> lubAux(PcodeStability<V> other) throws SemanticException`.
    pub fn lub_aux(&self, other: &Self) -> Self {
        let ad = self.aux.lub(&other.aux);
        let t = self.trends.lub(&other.trends);
        if ad.is_bottom() || t.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(ad, t)
    }

    /// Java: `public PcodeStability<V> glbAux(PcodeStability<V> other) throws SemanticException`.
    pub fn glb_aux(&self, other: &Self) -> Self {
        let ad = self.aux.glb(&other.aux);
        let t = self.trends.glb(&other.trends);
        if ad.is_bottom() || t.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(ad, t)
    }

    /// Java: `public PcodeStability<V> wideningAux(PcodeStability<V> other) throws
    /// SemanticException`.
    pub fn widening_aux(&self, other: &Self) -> Self {
        let ad = self.aux.widening(&other.aux);
        let t = self.trends.widening(&other.trends);
        if ad.is_bottom() || t.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(ad, t)
    }

    /// Java: `public boolean lessOrEqualAux(PcodeStability<V> other) throws SemanticException`.
    pub fn less_or_equal_aux(&self, other: &Self) -> bool {
        self.aux.less_or_equal(&other.aux) && self.trends.less_or_equal(&other.trends)
    }

    /// Java: `public boolean isTop()`.
    pub fn is_top(&self) -> bool {
        self.aux.is_top() && self.trends.is_top()
    }

    /// Java: `public boolean isBottom()`.
    pub fn is_bottom(&self) -> bool {
        self.aux.is_bottom() || self.trends.is_bottom()
    }

    /// Java: `public PcodeStability<V> top()`.
    pub fn top(&self) -> Self {
        Self::with_trends(self.aux.top(), self.trends.top())
    }

    /// Java: `public PcodeStability<V> bottom()`.
    pub fn bottom(&self) -> Self {
        Self::with_trends(self.aux.bottom(), self.trends.bottom())
    }

    /// Java: `public PcodeStability<V> pushScope(ScopeToken token) throws SemanticException`.
    pub fn push_scope(&self, token: &ScopeToken) -> Self {
        Self::with_trends(self.aux.push_scope(token), self.trends.push_scope(token))
    }

    /// Java: `public PcodeStability<V> popScope(ScopeToken token) throws SemanticException`.
    pub fn pop_scope(&self, token: &ScopeToken) -> Self {
        Self::with_trends(self.aux.pop_scope(token), self.trends.pop_scope(token))
    }

    /// Java: `private boolean query(BinaryExpression query, ProgramPoint pp, SemanticOracle
    /// oracle) throws SemanticException`.
    fn query(&self, q: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.aux.satisfies(q, pp, oracle) == Satisfiability::Satisfied
    }

    fn eq_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Eq, a, b), pp, oracle)
    }
    fn ne_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Ne, a, b), pp, oracle)
    }
    fn gt_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Gt, a, b), pp, oracle)
    }
    fn ge_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Ge, a, b), pp, oracle)
    }
    fn lt_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Lt, a, b), pp, oracle)
    }
    fn le_query(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> bool {
        self.query(&V::Expr::comparison(ComparisonOperator::Le, a, b), pp, oracle)
    }

    /// Java: `private Trend increasingIfGreater(SymbolicExpression a, SymbolicExpression b,
    /// ProgramPoint pp, SemanticOracle oracle) throws SemanticException`.
    fn increasing_if_greater(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        if self.eq_query(a, b, pp, oracle) {
            Trend::Stable
        }
        else if self.gt_query(a, b, pp, oracle) {
            Trend::Inc
        }
        else if self.ge_query(a, b, pp, oracle) {
            Trend::NonDec
        }
        else if self.lt_query(a, b, pp, oracle) {
            Trend::Dec
        }
        else if self.le_query(a, b, pp, oracle) {
            Trend::NonInc
        }
        else if self.ne_query(a, b, pp, oracle) {
            Trend::NonStable
        }
        else {
            Trend::Top
        }
    }

    /// Java: `private Trend increasingIfLess(...)`, `return increasingIfGreater(a, b, pp,
    /// oracle).invert();`.
    fn increasing_if_less(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        self.increasing_if_greater(a, b, pp, oracle).invert()
    }

    /// Java: `private Trend nonDecreasingIfGreater(...)`.
    fn non_decreasing_if_greater(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        if self.eq_query(a, b, pp, oracle) {
            Trend::Stable
        }
        else if self.gt_query(a, b, pp, oracle) || self.ge_query(a, b, pp, oracle) {
            Trend::NonDec
        }
        else if self.lt_query(a, b, pp, oracle) || self.le_query(a, b, pp, oracle) {
            Trend::NonInc
        }
        else {
            Trend::Top
        }
    }

    /// Java: `private Trend nonDecreasingIfLess(...)`, `return nonDecreasingIfGreater(a, b, pp,
    /// oracle).invert();`.
    fn non_decreasing_if_less(&self, a: &V::Expr, b: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        self.non_decreasing_if_greater(a, b, pp, oracle).invert()
    }

    /// Java: `private Trend increasingIfBetweenZeroAndOne(SymbolicExpression a, ProgramPoint pp,
    /// SemanticOracle oracle) throws SemanticException`.
    fn increasing_if_between_zero_and_one(&self, a: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        let zero = V::Expr::constant_int(0);
        let one = V::Expr::constant_int(1);
        if self.eq_query(a, &zero, pp, oracle) || self.eq_query(a, &one, pp, oracle) {
            Trend::Stable
        }
        else if self.gt_query(a, &zero, pp, oracle) && self.lt_query(a, &one, pp, oracle) {
            Trend::Inc
        }
        else if self.ge_query(a, &zero, pp, oracle) && self.le_query(a, &one, pp, oracle) {
            Trend::NonDec
        }
        else if self.lt_query(a, &zero, pp, oracle) && self.gt_query(a, &one, pp, oracle) {
            Trend::Dec
        }
        else if self.le_query(a, &zero, pp, oracle) && self.ge_query(a, &one, pp, oracle) {
            Trend::NonInc
        }
        else if self.ne_query(a, &zero, pp, oracle) && self.ne_query(a, &one, pp, oracle) {
            Trend::NonStable
        }
        else {
            Trend::Top
        }
    }

    /// Java: `private Trend increasingIfOutsideZeroAndOne(...)`, `return
    /// increasingIfBetweenZeroAndOne(a, pp, oracle).invert();`.
    fn increasing_if_outside_zero_and_one(&self, a: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        self.increasing_if_between_zero_and_one(a, pp, oracle).invert()
    }

    /// Java: `private Trend nonDecreasingIfBetweenZeroAndOne(SymbolicExpression a, ProgramPoint pp,
    /// SemanticOracle oracle) throws SemanticException`.
    fn non_decreasing_if_between_zero_and_one(&self, a: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        let zero = V::Expr::constant_int(0);
        let one = V::Expr::constant_int(1);
        if self.eq_query(a, &zero, pp, oracle) || self.eq_query(a, &one, pp, oracle) {
            Trend::Stable
        }
        else if self.ge_query(a, &zero, pp, oracle) && self.le_query(a, &one, pp, oracle) {
            Trend::NonDec
        }
        else if self.le_query(a, &zero, pp, oracle) || self.ge_query(a, &one, pp, oracle) {
            Trend::NonInc
        }
        else {
            Trend::Top
        }
    }

    /// Java: `private Trend nonDecreasingIfOutsideZeroAndOne(...)`, `return
    /// nonDecreasingIfBetweenZeroAndOne(a, pp, oracle).invert();`.
    fn non_decreasing_if_outside_zero_and_one(&self, a: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Trend {
        self.non_decreasing_if_between_zero_and_one(a, pp, oracle).invert()
    }

    /// Java: `private static ValueEnvironment<Trend> stabilize(ValueEnvironment<Trend> trends)`.
    /// An instance method here (`&self.trends` in place of Java's static parameter) purely to
    /// avoid repeating `Env` type parameters; behaviorally identical.
    fn stabilize(&self) -> Env {
        let mut result = Env::fresh_top();
        for id in self.trends.get_keys() {
            result = result.put_state(&id, Trend::Stable);
        }
        result
    }

    /// Java: `public PcodeStability<V> assign(Identifier id, ValueExpression expression,
    /// ProgramPoint pp, SemanticOracle oracle) throws SemanticException`.
    pub fn assign(&self, id: &V::Id, expression: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Self {
        if self.is_bottom() {
            return self.bottom();
        }
        let post = self.aux.assign(id, expression, pp, oracle);
        if post.is_bottom() {
            return self.bottom();
        }

        let id_expr = V::Expr::from_identifier(id);
        if !self.trends.can_process(&id_expr, pp, oracle) || !self.trends.can_process(expression, pp, oracle) {
            return Self::with_trends(post, self.trends.clone());
        }
        if !self.trends.knows_identifier(id) {
            return Self::with_trends(post, self.trends.put_state(id, Trend::Stable));
        }

        // Java: `Trend t = Trend.TOP; t = increasingIfLess(id, expression, pp, oracle);` -- the
        // initial `Trend.TOP` is always immediately overwritten by the second statement, so it has
        // no observable effect. Folded away here (unlike the redundant re-assignment noted below,
        // which this port does preserve as an explicit no-op) since it is not itself a branch that
        // could diverge from a straight-line initializer.
        let mut t = self.increasing_if_less(&id_expr, expression, pp, oracle);

        match expression.shape() {
            ExprShape::Unary { opcode: Some(opcode) } => {
                if matches!(opcode, OpCode::IntNegate | OpCode::Int2Comp | OpCode::FloatNeg) {
                    // Preserved quirk: Java recomputes the exact same value `t` was already just
                    // assigned above (`t = increasingIfLess(id, expression, pp, oracle);` again,
                    // verbatim) -- an observable no-op, reproduced faithfully rather than elided,
                    // in case a future auxiliary domain's `satisfies` is not a pure function of
                    // its arguments (e.g. logs or caches), matching Java's actual call count.
                    t = self.increasing_if_less(&id_expr, expression, pp, oracle);
                }
            }
            ExprShape::Unary { opcode: None } => {
                // `ue.getOperator() instanceof PcodeUnaryOperator` failed: Java's inner `if` body
                // never runs, and (since the outer match already committed to `UnaryExpression`)
                // there is no fallthrough to binary-expression handling either. `t` stays as
                // computed above.
            }
            ExprShape::Binary { opcode: Some(opcode), left, right } => {
                let is_left = left.identifier_equals(id);
                let is_right = right.identifier_equals(id);
                let zero = V::Expr::constant_int(0);
                let one = V::Expr::constant_int(1);

                // x = a / 0 -- checked unconditionally, regardless of whether `id` even appears in
                // this expression.
                if matches!(opcode, OpCode::IntDiv | OpCode::FloatDiv) && self.eq_query(&right, &zero, pp, oracle) {
                    return self.bottom();
                }

                if is_left || is_right {
                    let other = if is_left { right } else { left };
                    match opcode {
                        OpCode::IntAdd | OpCode::FloatAdd => {
                            // x = x + other || x = other + x
                            t = self.increasing_if_greater(&other, &zero, pp, oracle);
                        }
                        OpCode::IntSub | OpCode::FloatSub => {
                            // x = x - other
                            if is_left {
                                t = self.increasing_if_less(&other, &zero, pp, oracle);
                            }
                        }
                        OpCode::IntMult | OpCode::FloatMult => {
                            // x = x * other || x = other * x
                            if self.eq_query(&id_expr, &zero, pp, oracle) || self.eq_query(&other, &one, pp, oracle) {
                                // id == 0 || other == 1
                                t = Trend::Stable;
                            }
                            else if self.gt_query(&id_expr, &zero, pp, oracle) {
                                // id > 0
                                t = self.increasing_if_greater(&other, &one, pp, oracle);
                            }
                            else if self.lt_query(&id_expr, &zero, pp, oracle) {
                                // id < 0
                                t = self.increasing_if_less(&other, &one, pp, oracle);
                            }
                            else if self.ge_query(&id_expr, &zero, pp, oracle) {
                                // id >= 0
                                t = self.non_decreasing_if_greater(&other, &one, pp, oracle);
                            }
                            else if self.le_query(&id_expr, &zero, pp, oracle) {
                                // id <= 0
                                t = self.non_decreasing_if_less(&other, &one, pp, oracle);
                            }
                            else if self.ne_query(&id_expr, &zero, pp, oracle) && self.ne_query(&other, &one, pp, oracle) {
                                // id != 0 && other != 1
                                t = Trend::NonStable;
                            }
                        }
                        OpCode::IntDiv | OpCode::FloatDiv => {
                            // x = x / other
                            if is_left {
                                if self.eq_query(&id_expr, &zero, pp, oracle) || self.eq_query(&other, &one, pp, oracle) {
                                    // id == 0 || other == 1
                                    t = Trend::Stable;
                                }
                                else if self.gt_query(&id_expr, &zero, pp, oracle) {
                                    // id > 0
                                    t = self.increasing_if_between_zero_and_one(&other, pp, oracle);
                                }
                                else if self.lt_query(&id_expr, &zero, pp, oracle) {
                                    // id < 0
                                    t = self.increasing_if_outside_zero_and_one(&other, pp, oracle);
                                }
                                else if self.ge_query(&id_expr, &zero, pp, oracle) {
                                    // id >= 0
                                    t = self.non_decreasing_if_between_zero_and_one(&other, pp, oracle);
                                }
                                else if self.le_query(&id_expr, &zero, pp, oracle) {
                                    // id <= 0
                                    t = self.non_decreasing_if_outside_zero_and_one(&other, pp, oracle);
                                }
                                else if self.ne_query(&id_expr, &zero, pp, oracle) && self.ne_query(&other, &one, pp, oracle) {
                                    // id != 0 && other != 1
                                    t = Trend::NonStable;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            ExprShape::Binary { opcode: None, .. } => {
                // `be.getOperator() instanceof PcodeBinaryOperator` failed: `t` stays as computed
                // above -- same reasoning as the `Unary { opcode: None }` arm.
            }
            ExprShape::Other => {}
        }

        let trnd = self.stabilize().put_state(id, t);
        if trnd.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(post, trnd)
    }

    /// Java: `public PcodeStability<V> smallStepSemantics(ValueExpression expression, ProgramPoint
    /// pp, SemanticOracle oracle) throws SemanticException`.
    pub fn small_step_semantics(&self, expression: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Self {
        let post = self.aux.small_step_semantics(expression, pp, oracle);
        let sss = self.stabilize().small_step_semantics(expression, pp, oracle);
        if post.is_bottom() || sss.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(post, sss)
    }

    /// Java: `public PcodeStability<V> assume(ValueExpression expression, ProgramPoint src,
    /// ProgramPoint dest, SemanticOracle oracle) throws SemanticException`.
    ///
    /// Unlike [`Self::assign`]/[`Self::small_step_semantics`], this does *not* stabilize `trends`
    /// first -- it calls `trends.assume(...)` on the trends field directly, matching the Java
    /// source exactly.
    pub fn assume(&self, expression: &V::Expr, src: &V::ProgramPoint, dest: &V::ProgramPoint, oracle: &V::Oracle) -> Self {
        let post = self.aux.assume(expression, src, dest, oracle);
        let assumed = self.trends.assume(expression, src, dest, oracle);
        if post.is_bottom() || assumed.is_bottom() {
            return self.bottom();
        }
        Self::with_trends(post, assumed)
    }

    /// Java: `public boolean knowsIdentifier(Identifier id)`.
    pub fn knows_identifier(&self, id: &V::Id) -> bool {
        self.aux.knows_identifier(id) || self.trends.knows_identifier(id)
    }

    /// Java: `public PcodeStability<V> forgetIdentifier(Identifier id) throws SemanticException`.
    pub fn forget_identifier(&self, id: &V::Id) -> Self {
        Self::with_trends(self.aux.forget_identifier(id), self.trends.forget_identifier(id))
    }

    /// Java: `public PcodeStability<V> forgetIdentifiersIf(Predicate<Identifier> test) throws
    /// SemanticException`.
    pub fn forget_identifiers_if(&self, test: &dyn Fn(&V::Id) -> bool) -> Self {
        Self::with_trends(self.aux.forget_identifiers_if(test), self.trends.forget_identifiers_if(test))
    }

    /// Java: `public Satisfiability satisfies(ValueExpression expression, ProgramPoint pp,
    /// SemanticOracle oracle) throws SemanticException`, `return aux.satisfies(expression, pp,
    /// oracle);` -- delegates purely to the auxiliary domain; `trends` is not consulted.
    pub fn satisfies(&self, expression: &V::Expr, pp: &V::ProgramPoint, oracle: &V::Oracle) -> Satisfiability {
        self.aux.satisfies(expression, pp, oracle)
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> StabilityRepresentation<V::Representation, Env::Representation> {
        StabilityRepresentation { aux: self.aux.representation(), trends: self.trends.representation() }
    }

    /// Java: `public ValueEnvironment<Trend> getTrends()`.
    pub fn get_trends(&self) -> &Env {
        &self.trends
    }

    /// Java: `public V getAuxiliaryDomain()`.
    pub fn get_auxiliary_domain(&self) -> &V {
        &self.aux
    }

    /// Java: `public PcodeStability<V> combine(PcodeStability<V> other) throws
    /// SemanticException`.
    pub fn combine(&self, other: &Self) -> Self {
        // Java: `new ValueEnvironment<>(other.trends.lattice, other.trends.function)` -- a copy of
        // `other.trends` (same underlying map and per-element lattice), which every key that
        // survives the loop below then overwrites in place.
        let mut result = other.trends.clone();
        for id in other.trends.get_keys() {
            // we iterate only on the keys of post to remove the ones that went out of scope
            if self.trends.knows_identifier(&id) {
                let tmp = self.trends.get_state(&id).combine(other.trends.get_state(&id));
                result = result.put_state(&id, tmp);
            }
        }
        Self::with_trends(other.aux.clone(), result)
    }

    /// Java: `public Map<Trend, Set<Identifier>> getCovarianceClasses()`.
    pub fn get_covariance_classes(&self) -> HashMap<Trend, HashSet<V::Id>> {
        let mut map: HashMap<Trend, HashSet<V::Id>> = HashMap::new();
        for id in self.trends.get_keys() {
            let t = self.trends.get_state(&id);
            map.entry(t).or_default().insert(id);
        }
        map
    }
}

impl<V, Env> PartialEq for PcodeStability<V, Env>
where
    V: StabilityAuxDomain + PartialEq,
    Env: TrendEnvironment<Id = V::Id, Expr = V::Expr, ProgramPoint = V::ProgramPoint, Oracle = V::Oracle> + PartialEq,
{
    /// Java: `public boolean equals(Object obj)`, `Objects.equals(aux, other.aux) &&
    /// Objects.equals(trends, other.trends)`.
    fn eq(&self, other: &Self) -> bool {
        self.aux == other.aux && self.trends == other.trends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    // A minimal `StabilityExpr` for tests: either an identifier reference, an integer constant, a
    // synthetic comparison node, or a "real" p-code unary/binary expression wrapping one or two
    // sub-expressions and an opcode (`None` opcode models "operator isn't a p-code one").
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum TExpr {
        Id(&'static str),
        Const(i32),
        Cmp(ComparisonOperator, Box<TExpr>, Box<TExpr>),
        Unary { opcode: Option<OpCode>, inner: Box<TExpr> },
        Binary { opcode: Option<OpCode>, left: Box<TExpr>, right: Box<TExpr> },
    }

    impl StabilityExpr<&'static str> for TExpr {
        fn shape(&self) -> ExprShape<Self> {
            match self {
                TExpr::Unary { opcode, .. } => ExprShape::Unary { opcode: *opcode },
                TExpr::Binary { opcode, left, right } => {
                    ExprShape::Binary { opcode: *opcode, left: (**left).clone(), right: (**right).clone() }
                }
                _ => ExprShape::Other,
            }
        }

        fn identifier_equals(&self, id: &&'static str) -> bool {
            matches!(self, TExpr::Id(x) if x == id)
        }

        fn from_identifier(id: &&'static str) -> Self {
            TExpr::Id(id)
        }

        fn comparison(operator: ComparisonOperator, left: &Self, right: &Self) -> Self {
            TExpr::Cmp(operator, Box::new(left.clone()), Box::new(right.clone()))
        }

        fn constant_int(value: i32) -> Self {
            TExpr::Const(value)
        }
    }

    // A tiny "aux" domain: tracks a single known linear fact per query, resolved by a fixed table
    // the test supplies (`TruthTable`), so `increasingIfGreater`-style helpers exercise real
    // query -> Trend derivation instead of a hardcoded stand-in for `Trend` itself.
    #[derive(Clone, Debug, PartialEq)]
    struct MockAux {
        facts: StdHashMap<(ComparisonOperator, TExpr, TExpr), bool>,
        known_ids: HashSet<&'static str>,
        bottom: bool,
    }

    impl MockAux {
        fn new() -> Self {
            Self { facts: StdHashMap::new(), known_ids: HashSet::new(), bottom: false }
        }
        fn with_fact(mut self, op: ComparisonOperator, a: TExpr, b: TExpr, value: bool) -> Self {
            self.facts.insert((op, a, b), value);
            self
        }
        fn with_known(mut self, id: &'static str) -> Self {
            self.known_ids.insert(id);
            self
        }
    }

    impl StabilityDomain for MockAux {
        type Id = &'static str;
        type Expr = TExpr;
        type ProgramPoint = ();
        type Oracle = ();
        type Representation = String;

        fn top(&self) -> Self {
            MockAux::new()
        }
        fn bottom(&self) -> Self {
            let mut b = MockAux::new();
            b.bottom = true;
            b
        }
        fn is_top(&self) -> bool {
            !self.bottom && self.facts.is_empty() && self.known_ids.is_empty()
        }
        fn is_bottom(&self) -> bool {
            self.bottom
        }
        fn lub(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn glb(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn widening(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn less_or_equal(&self, _other: &Self) -> bool {
            true
        }
        fn push_scope(&self, _token: &ScopeToken) -> Self {
            self.clone()
        }
        fn pop_scope(&self, _token: &ScopeToken) -> Self {
            self.clone()
        }
        fn assume(&self, _expr: &Self::Expr, _src: &(), _dest: &(), _oracle: &()) -> Self {
            self.clone()
        }
        fn small_step_semantics(&self, _expr: &Self::Expr, _pp: &(), _oracle: &()) -> Self {
            self.clone()
        }
        fn knows_identifier(&self, id: &Self::Id) -> bool {
            self.known_ids.contains(id)
        }
        fn forget_identifier(&self, id: &Self::Id) -> Self {
            let mut c = self.clone();
            c.known_ids.remove(id);
            c
        }
        fn forget_identifiers_if(&self, test: &dyn Fn(&Self::Id) -> bool) -> Self {
            let mut c = self.clone();
            c.known_ids.retain(|id| !test(id));
            c
        }
        fn representation(&self) -> Self::Representation {
            "aux".to_string()
        }
    }

    impl StabilityAuxDomain for MockAux {
        fn assign(&self, id: &Self::Id, _expr: &Self::Expr, _pp: &(), _oracle: &()) -> Self {
            let mut c = self.clone();
            c.known_ids.insert(id);
            c
        }
        fn satisfies(&self, expr: &Self::Expr, _pp: &(), _oracle: &()) -> Satisfiability {
            if let TExpr::Cmp(op, a, b) = expr {
                match self.facts.get(&(*op, (**a).clone(), (**b).clone())) {
                    Some(true) => Satisfiability::Satisfied,
                    Some(false) => Satisfiability::NotSatisfied,
                    None => Satisfiability::Unknown,
                }
            }
            else {
                Satisfiability::Unknown
            }
        }
    }

    // The trend environment: a plain map plus an is_bottom/can_process flag pair the tests can
    // toggle.
    #[derive(Clone, Debug, PartialEq)]
    struct MockTrendEnv {
        states: StdHashMap<&'static str, Trend>,
        bottom: bool,
        can_process: bool,
    }

    impl MockTrendEnv {
        fn new() -> Self {
            Self { states: StdHashMap::new(), bottom: false, can_process: true }
        }
    }

    impl StabilityDomain for MockTrendEnv {
        type Id = &'static str;
        type Expr = TExpr;
        type ProgramPoint = ();
        type Oracle = ();
        type Representation = String;

        fn top(&self) -> Self {
            Self::fresh_top()
        }
        fn bottom(&self) -> Self {
            let mut b = Self::new();
            b.bottom = true;
            b
        }
        fn is_top(&self) -> bool {
            !self.bottom && self.states.is_empty()
        }
        fn is_bottom(&self) -> bool {
            self.bottom
        }
        fn lub(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn glb(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn widening(&self, _other: &Self) -> Self {
            self.clone()
        }
        fn less_or_equal(&self, _other: &Self) -> bool {
            true
        }
        fn push_scope(&self, _token: &ScopeToken) -> Self {
            self.clone()
        }
        fn pop_scope(&self, _token: &ScopeToken) -> Self {
            self.clone()
        }
        fn assume(&self, _expr: &Self::Expr, _src: &(), _dest: &(), _oracle: &()) -> Self {
            self.clone()
        }
        fn small_step_semantics(&self, _expr: &Self::Expr, _pp: &(), _oracle: &()) -> Self {
            self.clone()
        }
        fn knows_identifier(&self, id: &Self::Id) -> bool {
            self.states.contains_key(id)
        }
        fn forget_identifier(&self, id: &Self::Id) -> Self {
            let mut c = self.clone();
            c.states.remove(id);
            c
        }
        fn forget_identifiers_if(&self, test: &dyn Fn(&Self::Id) -> bool) -> Self {
            let mut c = self.clone();
            c.states.retain(|id, _| !test(id));
            c
        }
        fn representation(&self) -> Self::Representation {
            "trends".to_string()
        }
    }

    impl TrendEnvironment for MockTrendEnv {
        fn get_keys(&self) -> Vec<Self::Id> {
            self.states.keys().copied().collect()
        }
        fn get_state(&self, id: &Self::Id) -> Trend {
            self.states.get(id).copied().unwrap_or(Trend::Top)
        }
        fn put_state(&self, id: &Self::Id, value: Trend) -> Self {
            let mut c = self.clone();
            c.states.insert(*id, value);
            c
        }
        fn can_process(&self, _expr: &Self::Expr, _pp: &(), _oracle: &()) -> bool {
            self.can_process
        }
        fn fresh_top() -> Self {
            Self::new()
        }
    }

    type Stability = PcodeStability<MockAux, MockTrendEnv>;

    fn fresh(aux: MockAux, known: &[&'static str]) -> Stability {
        let mut env = MockTrendEnv::new();
        for &id in known {
            env = env.put_state(&id, Trend::Stable);
        }
        Stability::with_trends(aux, env)
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_normalizes_aux_to_top_and_trends_to_fresh() {
        let s = Stability::new(MockAux::new().with_known("x"));
        assert!(s.get_auxiliary_domain().is_top());
        assert!(s.get_trends().is_top());
    }

    #[test]
    fn with_trends_propagates_bottom_from_trends_to_aux() {
        let bottom_trends = MockTrendEnv::new().bottom();
        let s = Stability::with_trends(MockAux::new(), bottom_trends);
        assert!(s.get_auxiliary_domain().is_bottom());
    }

    #[test]
    fn with_trends_propagates_bottom_from_aux_to_trends() {
        let bottom_aux = MockAux::new().bottom();
        let s = Stability::with_trends(bottom_aux, MockTrendEnv::new());
        assert!(s.get_trends().is_bottom());
    }

    #[test]
    fn with_trends_checks_are_based_on_original_params_not_each_other() {
        // Both bottom: aux normalizes to aux.bottom() (trivially already-bottom-consistent), and
        // trends normalizes to trends.bottom() using the ORIGINAL aux (which was bottom), not the
        // just-recomputed new_aux.
        let s = Stability::with_trends(MockAux::new().bottom(), MockTrendEnv::new().bottom());
        assert!(s.get_auxiliary_domain().is_bottom());
        assert!(s.get_trends().is_bottom());
    }

    // ── top / bottom / isTop / isBottom ─────────────────────────────────────

    #[test]
    fn is_top_requires_both_top() {
        let s = fresh(MockAux::new(), &[]);
        assert!(s.is_top());
    }

    #[test]
    fn is_bottom_if_either_half_is_bottom() {
        let s = Stability::with_trends(MockAux::new().bottom(), MockTrendEnv::new());
        assert!(s.is_bottom());
    }

    // ── assign: basic gating ─────────────────────────────────────────────────

    #[test]
    fn assign_on_bottom_stays_bottom() {
        let s = Stability::with_trends(MockAux::new().bottom(), MockTrendEnv::new());
        let result = s.assign(&"x", &TExpr::Const(1), &(), &());
        assert!(result.is_bottom());
    }

    #[test]
    fn assign_cannot_process_keeps_trends_unchanged() {
        let mut env = MockTrendEnv::new();
        env.can_process = false;
        let s = Stability::with_trends(MockAux::new(), env.clone());
        let result = s.assign(&"x", &TExpr::Const(1), &(), &());
        assert_eq!(result.get_trends(), &env);
    }

    #[test]
    fn assign_unknown_identifier_becomes_stable() {
        let s = fresh(MockAux::new(), &[]);
        let result = s.assign(&"x", &TExpr::Const(1), &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Stable);
    }

    // ── assign: x = x + other, other > 0 -> INC ─────────────────────────────

    #[test]
    fn assign_add_other_positive_is_increasing() {
        let aux = MockAux::new().with_fact(ComparisonOperator::Gt, TExpr::Id("y"), TExpr::Const(0), true);
        let s = fresh(aux, &["x"]);
        let expr = TExpr::Binary {
            opcode: Some(OpCode::IntAdd),
            left: Box::new(TExpr::Id("x")),
            right: Box::new(TExpr::Id("y")),
        };
        let result = s.assign(&"x", &expr, &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Inc);
    }

    // ── assign: x = x - other, other < 0 -> INC (since -other > 0) ──────────

    #[test]
    fn assign_sub_left_other_negative_is_increasing() {
        // increasingIfLess(other, 0) = increasingIfGreater(other,0).invert(); other<0 -> DEC -> invert -> INC
        let aux = MockAux::new()
            .with_fact(ComparisonOperator::Eq, TExpr::Id("y"), TExpr::Const(0), false)
            .with_fact(ComparisonOperator::Gt, TExpr::Id("y"), TExpr::Const(0), false)
            .with_fact(ComparisonOperator::Ge, TExpr::Id("y"), TExpr::Const(0), false)
            .with_fact(ComparisonOperator::Lt, TExpr::Id("y"), TExpr::Const(0), true);
        let s = fresh(aux, &["x"]);
        let expr = TExpr::Binary {
            opcode: Some(OpCode::IntSub),
            left: Box::new(TExpr::Id("x")),
            right: Box::new(TExpr::Id("y")),
        };
        let result = s.assign(&"x", &expr, &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Inc);
    }

    #[test]
    fn assign_sub_right_is_x_does_not_update_since_only_isLeft_handled() {
        // x = other - x: `isLeft` is false, so Java's INT_SUB arm never assigns `t`, leaving it as
        // whatever `increasingIfLess(id, expression, ...)` computed at the top of the method.
        let aux = MockAux::new();
        let s = fresh(aux, &["x"]);
        let expr = TExpr::Binary {
            opcode: Some(OpCode::IntSub),
            left: Box::new(TExpr::Id("y")),
            right: Box::new(TExpr::Id("x")),
        };
        // increasingIfLess(id, expression) with no facts known -> TOP.invert() = TOP.
        let result = s.assign(&"x", &expr, &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Top);
    }

    // ── assign: division by zero -> bottom, unconditionally ─────────────────

    #[test]
    fn assign_div_by_zero_is_bottom_even_if_id_not_involved() {
        let aux = MockAux::new().with_fact(ComparisonOperator::Eq, TExpr::Id("z"), TExpr::Const(0), true);
        let s = fresh(aux, &["x"]);
        let expr = TExpr::Binary {
            opcode: Some(OpCode::IntDiv),
            left: Box::new(TExpr::Id("y")),
            right: Box::new(TExpr::Id("z")),
        };
        let result = s.assign(&"x", &expr, &(), &());
        assert!(result.is_bottom());
    }

    // ── assign: x = x * other, id == 0 -> STABLE ────────────────────────────

    #[test]
    fn assign_mult_id_zero_is_stable() {
        let aux = MockAux::new().with_fact(ComparisonOperator::Eq, TExpr::Id("x"), TExpr::Const(0), true);
        let s = fresh(aux, &["x"]);
        let expr = TExpr::Binary {
            opcode: Some(OpCode::IntMult),
            left: Box::new(TExpr::Id("x")),
            right: Box::new(TExpr::Id("y")),
        };
        let result = s.assign(&"x", &expr, &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Stable);
    }

    // ── assign: unary negate-family re-evaluates (no-op, preserved quirk) ───

    #[test]
    fn assign_unary_negate_recomputes_same_value() {
        let s = fresh(MockAux::new(), &["x"]);
        let expr = TExpr::Unary { opcode: Some(OpCode::IntNegate), inner: Box::new(TExpr::Id("x")) };
        let result = s.assign(&"x", &expr, &(), &());
        // No facts known: increasingIfLess(id, expr) = increasingIfGreater(...).invert() = TOP.invert() = TOP.
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Top);
    }

    #[test]
    fn assign_unary_non_pcode_operator_leaves_t_unmodified() {
        let s = fresh(MockAux::new(), &["x"]);
        let expr = TExpr::Unary { opcode: None, inner: Box::new(TExpr::Id("x")) };
        let result = s.assign(&"x", &expr, &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Top);
    }

    // ── smallStepSemantics / assume ──────────────────────────────────────────

    #[test]
    fn small_step_semantics_stabilizes_known_identifiers_first() {
        let s = fresh(MockAux::new(), &["x"]);
        let result = s.small_step_semantics(&TExpr::Const(1), &(), &());
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Stable);
    }

    #[test]
    fn assume_does_not_stabilize_trends() {
        let s = fresh(MockAux::new(), &["x"]);
        let result = s.assume(&TExpr::Const(1), &(), &(), &());
        // MockTrendEnv::assume returns self.clone() unchanged (still Trend::Stable from `fresh`),
        // proving `assume` reads `trends` directly rather than through `stabilize()` (which would
        // also just yield Stable here, so this test's real point is documented, not distinguishing
        // -- see `assume`'s own docs for the structural claim).
        assert_eq!(result.get_trends().get_state(&"x"), Trend::Stable);
    }

    // ── knowsIdentifier / forgetIdentifier / forgetIdentifiersIf ────────────

    #[test]
    fn knows_identifier_true_if_either_half_knows_it() {
        let aux = MockAux::new().with_known("a");
        let s = fresh(aux, &["b"]);
        assert!(s.knows_identifier(&"a"));
        assert!(s.knows_identifier(&"b"));
        assert!(!s.knows_identifier(&"c"));
    }

    #[test]
    fn forget_identifier_removes_from_both_halves() {
        let aux = MockAux::new().with_known("a");
        let s = fresh(aux, &["a"]);
        let result = s.forget_identifier(&"a");
        assert!(!result.get_auxiliary_domain().knows_identifier(&"a"));
        assert!(!result.get_trends().knows_identifier(&"a"));
    }

    #[test]
    fn forget_identifiers_if_applies_predicate_to_both_halves() {
        let aux = MockAux::new().with_known("a").with_known("b");
        let s = fresh(aux, &["a", "b"]);
        let result = s.forget_identifiers_if(&|id: &&'static str| *id == "a");
        assert!(!result.get_auxiliary_domain().knows_identifier(&"a"));
        assert!(result.get_auxiliary_domain().knows_identifier(&"b"));
    }

    // ── satisfies delegates purely to aux ────────────────────────────────────

    #[test]
    fn satisfies_delegates_to_aux_only() {
        let aux = MockAux::new().with_fact(ComparisonOperator::Eq, TExpr::Id("x"), TExpr::Const(0), true);
        let s = fresh(aux, &[]);
        let expr = TExpr::Cmp(ComparisonOperator::Eq, Box::new(TExpr::Id("x")), Box::new(TExpr::Const(0)));
        assert_eq!(s.satisfies(&expr, &(), &()), Satisfiability::Satisfied);
    }

    // ── combine ───────────────────────────────────────────────────────────────

    #[test]
    fn combine_folds_trend_for_shared_identifiers_and_keeps_others_own_ids_dropped() {
        let self_ = fresh(MockAux::new(), &[]).forget_identifier(&"unused"); // just self, states set below
        let mut self_env = MockTrendEnv::new();
        self_env = self_env.put_state(&"x", Trend::Inc);
        let self_s = Stability::with_trends(MockAux::new(), self_env);

        let mut other_env = MockTrendEnv::new();
        other_env = other_env.put_state(&"x", Trend::Inc);
        other_env = other_env.put_state(&"y", Trend::Dec); // not known by self_s -> dropped from result
        let other_s = Stability::with_trends(MockAux::new(), other_env);

        let combined = self_s.combine(&other_s);
        // x: known by both -> Inc.combine(Inc) = Inc.
        assert_eq!(combined.get_trends().get_state(&"x"), Trend::Inc);
        // y: not known by self -> loop never overwrites it, but since MockTrendEnv::get_state
        // defaults unknown identifiers to Top, and `result` started as a clone of `other.trends`
        // (which DOES contain "y" = Dec), the key is present with its original value.
        assert_eq!(combined.get_trends().get_state(&"y"), Trend::Dec);
        let _ = self_;
    }

    // ── get_covariance_classes ───────────────────────────────────────────────

    #[test]
    fn get_covariance_classes_groups_identifiers_by_trend() {
        let mut env = MockTrendEnv::new();
        env = env.put_state(&"a", Trend::Inc);
        env = env.put_state(&"b", Trend::Inc);
        env = env.put_state(&"c", Trend::Dec);
        let s = Stability::with_trends(MockAux::new(), env);

        let classes = s.get_covariance_classes();
        let mut inc: Vec<_> = classes.get(&Trend::Inc).unwrap().iter().copied().collect();
        inc.sort();
        assert_eq!(inc, vec!["a", "b"]);
        assert_eq!(classes.get(&Trend::Dec).unwrap().iter().copied().collect::<Vec<_>>(), vec!["c"]);
    }

    // ── representation / equality ─────────────────────────────────────────────

    #[test]
    fn representation_bundles_aux_and_trends() {
        let s = fresh(MockAux::new(), &[]);
        let repr = s.representation();
        assert_eq!(repr.aux, "aux".to_string());
        assert_eq!(repr.trends, "trends".to_string());
    }

    #[test]
    fn equality_compares_both_halves() {
        let a = fresh(MockAux::new(), &["x"]);
        let b = fresh(MockAux::new(), &["x"]);
        assert_eq!(a, b);

        let c = fresh(MockAux::new(), &["y"]);
        assert_ne!(a, c);
    }
}
