//! Port of `ghidra.lisa.pcode.analyses.PcodeParity`.

use std::hash::{Hash, Hasher};

use crate::feature::lisa::pcode::analyses::constant_value::ConstantValue;
use crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain;
use crate::feature::lisa::pcode::analyses::pcode_upper_bounds::AsIdentifier;
use crate::feature::lisa::pcode::expressions::pcode_binary_expression::PcodeBinaryExpressionOperator;
use crate::program::model::pcode::OpCode;
use crate::program::model::lang::register_value::RegisterValue;
use crate::util::Msg;

/// Stand-in for LiSA's `it.unive.lisa.util.representation.StructuredRepresentation`, narrowed to
/// the shapes [`PcodeParity::representation`] actually builds, the same convention
/// [`UpperBoundsRepresentation`](super::pcode_upper_bounds::UpperBoundsRepresentation)'s own docs
/// describe for the sibling class in this package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParityRepresentation {
    /// Java: `Lattice.topRepresentation()`.
    Top,
    /// Java: `Lattice.bottomRepresentation()`.
    Bottom,
    /// Java: `new StringRepresentation(repr)`, `repr` being `"Even"` or `"Odd"`.
    Str(&'static str),
}

/// The overflow-insensitive Parity abstract domain: tracks whether a numeric value is even or
/// odd.
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeParity` in the Java source, which `implements
/// PcodeNonRelationalValueDomain<PcodeParity>`. As with
/// [`PcodeUpperBounds`](super::pcode_upper_bounds::PcodeUpperBounds)'s own docs, the full LiSA
/// `BaseNonRelationalValueDomain`/`Lattice` framework this class's `top()`/`bottom()`/`lubAux`/
/// `lessOrEqualAux` overrides are built on has no Rust port in this crate.
///
/// # Representation: `parity` byte + `canonical` flag
///
/// Java's four named instances (`EVEN`/`ODD`/`TOP`/`BOTTOM`) are `private static final` fields --
/// specific objects assigned once at class-load time -- while `isEven()`/`isOdd()` test *reference
/// identity* against them (`this == EVEN`), not value equality. The public `PcodeParity(byte)`
/// constructor, meanwhile, lets any caller build an object that is *value-equal* to one of those
/// four (same `parity` byte, so `.equals()` returns `true`) without *being* it (so `this == EVEN`
/// is `false`). [`PcodeParity::get_value`] is exactly such a caller: it builds a fresh instance
/// with `new PcodeParity((byte) (... ? 3 : 2))` rather than returning the `EVEN`/`ODD` constants.
///
/// This struct's `canonical: bool` field reproduces that identity/equality distinction without
/// modeling Java object identity wholesale: it is `true` only on the four values built via
/// [`Self::EVEN`]/[`Self::ODD`]/[`Self::TOP`]/[`Self::BOTTOM`] (and everything derived from them
/// by `Copy`, e.g. [`Self::top`]/[`Self::bottom`]/[`Self::eval_unary_expression`]'s passthrough),
/// `false` on anything built via [`Self::new`]/[`Self::with_parity`] (mirroring `new
/// PcodeParity(...)`, including [`Self::get_value`]'s internal use of it). [`Self::is_even`]/
/// [`Self::is_odd`] check `canonical` alongside the byte value (mirroring `this ==`); [`PartialEq`]/
/// [`Hash`] (mirroring `.equals()`/`.hashCode()`, and this struct's own [`Self::is_top`]/
/// [`Self::is_bottom`], built on `.equals(top())`/`.equals(bottom())` per the LiSA `Lattice`
/// default) deliberately ignore it, comparing only the `parity` byte -- see
/// [`Self::get_value`]'s own docs for the resulting, faithfully-reproduced quirk.
#[derive(Clone, Copy, Debug)]
pub struct PcodeParity {
    parity: i8,
    canonical: bool,
}

impl PcodeParity {
    /// The abstract even element. Java: `public static final PcodeParity EVEN`.
    pub const EVEN: Self = Self { parity: 3, canonical: true };
    /// The abstract odd element. Java: `public static final PcodeParity ODD`.
    pub const ODD: Self = Self { parity: 2, canonical: true };
    /// The abstract top element. Java: `public static final PcodeParity TOP`.
    pub const TOP: Self = Self { parity: 0, canonical: true };
    /// The abstract bottom element. Java: `public static final PcodeParity BOTTOM`.
    pub const BOTTOM: Self = Self { parity: 1, canonical: true };

    /// Java: `public PcodeParity()`, `this((byte) 0);` -- builds a fresh, non-canonical instance
    /// that is value-equal to (but not identical to) [`Self::TOP`]. See the struct docs.
    pub fn new() -> Self {
        Self::with_parity(0)
    }

    /// Java: `public PcodeParity(byte parity)` -- builds a fresh, non-canonical instance. See the
    /// struct docs.
    pub fn with_parity(parity: i8) -> Self {
        Self { parity, canonical: false }
    }

    /// Java: `public PcodeParity top()`.
    pub fn top(&self) -> Self {
        Self::TOP
    }

    /// Java: `public PcodeParity bottom()`.
    pub fn bottom(&self) -> Self {
        Self::BOTTOM
    }

    /// Java: inherited `isTop()` default (`equals(top())`) from LiSA's unported `Lattice`
    /// interface, the same reconstruction
    /// [`PcodeUpperBounds::is_top`](super::pcode_upper_bounds::PcodeUpperBounds::is_top)'s docs
    /// describe. Value-based (via [`PartialEq`]), *not* identity-based -- see the struct docs.
    pub fn is_top(&self) -> bool {
        *self == Self::TOP
    }

    /// Java: inherited `isBottom()` default (`equals(bottom())`). Value-based, not
    /// identity-based -- see [`Self::is_top`]'s docs.
    pub fn is_bottom(&self) -> bool {
        *self == Self::BOTTOM
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> ParityRepresentation {
        if self.is_bottom() {
            return ParityRepresentation::Bottom;
        }
        if self.is_top() {
            return ParityRepresentation::Top;
        }
        // Java: `this == EVEN ? "Even" : "Odd"` -- identity, not value equality.
        if self.is_identically(&Self::EVEN) { ParityRepresentation::Str("Even") } else { ParityRepresentation::Str("Odd") }
    }

    /// Java: `public PcodeParity evalNullConstant(ProgramPoint pp, SemanticOracle oracle)`,
    /// `return top();`. Java's unused `pp`/`oracle` parameters are dropped, the same established
    /// convention
    /// [`PcodeUpperBounds::assume_binary_expression`](super::pcode_upper_bounds::PcodeUpperBounds::assume_binary_expression)'s
    /// docs describe for its own unused parameters.
    pub fn eval_null_constant(&self) -> Self {
        self.top()
    }

    /// Java: `public PcodeParity evalNonNullConstant(Constant constant, ProgramPoint pp,
    /// SemanticOracle oracle)`. Java's unused `pp`/`oracle` parameters are dropped -- see
    /// [`Self::eval_null_constant`]'s docs. Java's `Constant constant` is narrowed to the
    /// [`ConstantValue`] its `getValue()` actually returns -- see that type's own docs.
    pub fn eval_non_null_constant(&self, cval: ConstantValue) -> Self {
        match cval {
            ConstantValue::Long(lval) => if lval % 2 == 0 { Self::EVEN } else { Self::ODD },
            ConstantValue::Integer(ival) => if ival % 2 == 0 { Self::EVEN } else { Self::ODD },
            ConstantValue::Short(sval) => if sval % 2 == 0 { Self::EVEN } else { Self::ODD },
            ConstantValue::Byte(bval) => if bval % 2 == 0 { Self::EVEN } else { Self::ODD },
            ConstantValue::Boolean(bval) => if bval { Self::ODD } else { Self::EVEN },
            ConstantValue::Other => {
                Msg::error("PcodeParity", &"Unknown type for constant");
                self.top()
            }
        }
    }

    /// Java: `public boolean isEven()`, `return this == EVEN;` -- reference identity. See the
    /// struct docs.
    pub fn is_even(&self) -> bool {
        self.is_identically(&Self::EVEN)
    }

    /// Java: `public boolean isOdd()`, `return this == ODD;` -- reference identity. See the
    /// struct docs.
    pub fn is_odd(&self) -> bool {
        self.is_identically(&Self::ODD)
    }

    fn is_identically(&self, singleton: &Self) -> bool {
        self.canonical && singleton.canonical && self.parity == singleton.parity
    }

    /// Java: `public PcodeParity evalUnaryExpression(UnaryOperator operator, PcodeParity arg,
    /// ProgramPoint pp, SemanticOracle oracle)`, `return arg;`. Java's unused `operator`/`pp`/
    /// `oracle` parameters are dropped -- see [`Self::eval_null_constant`]'s docs.
    pub fn eval_unary_expression(&self, arg: Self) -> Self {
        arg
    }

    /// Java: `public PcodeParity evalBinaryExpression(BinaryOperator operator, PcodeParity left,
    /// PcodeParity right, ProgramPoint pp, SemanticOracle oracle)`.
    ///
    /// Java's `operator` parameter is declared but never read (the method dispatches purely on
    /// `((PcodeLocation) pp.getLocation()).op.getOpcode()`); its unused `operator` is dropped, and
    /// the resolved `opcode` is taken directly instead of modeling the `ProgramPoint`/
    /// `PcodeLocation` downcast machinery to extract it -- the same simplification
    /// [`PcodeNonRelationalValueDomain::get_value_at_program_point`]'s docs describe for handing
    /// back only what a caller actually touches.
    ///
    /// # Preserved quirk
    ///
    /// Java's `else if (opcode == PcodeOp.INT_AND) { ... }`, `INT_OR`, and `INT_XOR` branches
    /// (lines 203-219 of the Java source) are dead code: each is a second, differently-implemented
    /// arm for an opcode already matched by an earlier `if`/`else if` in the same chain
    /// (`INT_AND`/`BOOL_AND` at the top, `INT_OR`/`BOOL_OR` next, `INT_XOR`/`BOOL_XOR` after that),
    /// so the earlier arm always wins and the later one can never execute. Reproduced faithfully
    /// by simply omitting the unreachable arms (an `if`/`else if` chain's later duplicate-condition
    /// branches being unreachable is not independently observable in a Rust `match`, since a
    /// `match` requires non-overlapping patterns in the first place -- there is nothing to
    /// preserve *as dead code*, only the *reachable* behavior, which is exactly what the kept
    /// arms below implement).
    pub fn eval_binary_expression(&self, left: Self, right: Self, opcode: OpCode) -> Self {
        if left.is_top() || right.is_top() {
            return self.top();
        }

        match opcode {
            OpCode::IntAdd | OpCode::FloatAdd | OpCode::IntSub | OpCode::FloatSub => {
                if right == left { Self::EVEN } else { Self::ODD }
            }
            OpCode::IntAnd | OpCode::BoolAnd => {
                if right == left { left } else { Self::EVEN }
            }
            OpCode::IntOr | OpCode::BoolOr => {
                if right == left { left } else { Self::ODD }
            }
            OpCode::IntXor | OpCode::BoolXor => {
                if right == left { Self::EVEN } else { Self::ODD }
            }
            OpCode::IntMult | OpCode::FloatMult => {
                if left.is_even() || right.is_even() { Self::EVEN } else { Self::ODD }
            }
            OpCode::IntDiv | OpCode::FloatDiv => {
                if left.is_odd() {
                    if right.is_odd() { Self::ODD } else { Self::EVEN }
                }
                else if right.is_odd() {
                    Self::EVEN
                }
                else {
                    self.top()
                }
            }
            OpCode::IntRem | OpCode::IntSrem => self.top(),
            _ => left,
        }
    }

    /// Java: `public PcodeParity lubAux(PcodeParity other) throws SemanticException`, `return
    /// TOP;`.
    pub fn lub_aux(&self, _other: &Self) -> Self {
        Self::TOP
    }

    /// Java: `public boolean lessOrEqualAux(PcodeParity other) throws SemanticException`, `return
    /// false;`.
    pub fn less_or_equal_aux(&self, _other: &Self) -> bool {
        false
    }

    /// Java: `public ValueEnvironment<PcodeParity> assumeBinaryExpression(
    /// ValueEnvironment<PcodeParity> environment, BinaryOperator operator, ValueExpression left,
    /// ValueExpression right, ProgramPoint src, ProgramPoint dest, SemanticOracle oracle) throws
    /// SemanticException`.
    ///
    /// Java's unused `dest` parameter is dropped -- see [`Self::eval_null_constant`]'s docs. Java's
    /// `eval(SymbolicExpression, ValueEnvironment, ProgramPoint, SemanticOracle)` call (inherited
    /// from LiSA's unported `SemanticDomain`/`BaseNonRelationalValueDomain` machinery -- a general
    /// recursive expression evaluator, not something this class implements itself) is modeled via
    /// [`ParityExpression::eval`], which `left`/`right`'s `Expr` type must implement.
    pub fn assume_binary_expression<Id, Env, Expr, Pp, Oracle>(
        &self,
        environment: Env,
        operator: &PcodeBinaryExpressionOperator,
        left: &Expr,
        right: &Expr,
        src: &Pp,
        oracle: &Oracle,
    ) -> Env
    where
        Env: ParityEnvironment<Id>,
        Expr: ParityExpression<Id, Env, Pp, Oracle>,
    {
        if !matches!(operator, PcodeBinaryExpressionOperator::ComparisonEq) {
            return environment;
        }
        if let Some(x) = left.as_identifier() {
            let eval = right.eval(&environment, src, oracle);
            if eval.is_bottom() {
                return environment.bottom();
            }
            return environment.put_state(x, eval);
        }
        else if let Some(y) = right.as_identifier() {
            let eval = left.eval(&environment, src, oracle);
            if eval.is_bottom() {
                return environment.bottom();
            }
            return environment.put_state(y, eval);
        }
        environment
    }
}

impl Default for PcodeParity {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for PcodeParity {
    /// Java: `public boolean equals(Object obj)` -- compares only the `parity` byte (plus a
    /// `getClass()` check that is always true between two [`PcodeParity`] values in Rust's typed
    /// world). Deliberately ignores `canonical` -- see the struct docs.
    fn eq(&self, other: &Self) -> bool {
        self.parity == other.parity
    }
}

impl Eq for PcodeParity {}

impl Hash for PcodeParity {
    /// Java: `public int hashCode()`, `31 * 1 + parity`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.parity.hash(state);
    }
}

/// Stand-in for the runtime `instanceof Identifier` pattern match, evaluating an arbitrary
/// expression, and reading/updating a [`PcodeParity`]-valued environment that
/// [`PcodeParity::assume_binary_expression`] performs on its (LiSA-typed, unported)
/// `ValueEnvironment`/`ValueExpression` parameters. Mirrors
/// [`ValueEnvironmentLike`](super::pcode_upper_bounds::ValueEnvironmentLike)'s role for
/// [`PcodeUpperBounds`](super::pcode_upper_bounds::PcodeUpperBounds), narrowed to the `getState`-free
/// subset [`PcodeParity::assume_binary_expression`] actually calls (`putState`/`bottom()`, no
/// `getState`).
pub trait ParityEnvironment<Id>: Sized {
    /// Java: `environment.putState(id, value)`.
    fn put_state(self, id: &Id, value: PcodeParity) -> Self;
    /// Java: `environment.bottom()`.
    fn bottom(&self) -> Self;
}

/// Stand-in for LiSA's `ValueExpression`, narrowed to what
/// [`PcodeParity::assume_binary_expression`] actually does with `left`/`right`: check whether it
/// is (dynamically) an `Identifier`, and otherwise recursively evaluate it against an environment
/// to a [`PcodeParity`]. See [`AsIdentifier`] and [`ParityEnvironment`]'s own docs for why each
/// half is modeled this way.
pub trait ParityExpression<Id, Env, Pp, Oracle>: AsIdentifier<Id> {
    /// Java: `eval(SymbolicExpression, ValueEnvironment, ProgramPoint, SemanticOracle)`, inherited
    /// from LiSA's unported `SemanticDomain`/`BaseNonRelationalValueDomain` machinery.
    fn eval(&self, environment: &Env, pp: &Pp, oracle: &Oracle) -> PcodeParity;
}

impl PcodeNonRelationalValueDomain<PcodeParity> for PcodeParity {
    /// Java: `public PcodeParity getValue(RegisterValue rv)`.
    ///
    /// # Preserved quirk
    ///
    /// Java builds a *fresh* `new PcodeParity((byte) (... ? 3 : 2))` here rather than returning
    /// the `EVEN`/`ODD` singletons -- so a value returned from this method is always
    /// non-canonical (per the struct docs): [`PcodeParity::is_even`]/[`PcodeParity::is_odd`]
    /// return `false` on it even when it is value-equal to [`PcodeParity::EVEN`]/
    /// [`PcodeParity::ODD`] (see `get_value_of_even_register_is_not_identically_even` below for a
    /// dedicated regression test).
    fn get_value(&self, rv: Option<&RegisterValue>) -> Option<PcodeParity> {
        if let Some(rv) = rv {
            if rv.has_value() {
                let val = rv.unsigned_value_ignore_mask();
                return Some(Self::with_parity(if val % 2 == 0 { 3 } else { 2 }));
            }
        }
        Some(self.top())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── top / bottom / representation ───────────────────────────────────────

    #[test]
    fn top_is_top_and_not_bottom() {
        assert!(PcodeParity::TOP.is_top());
        assert!(!PcodeParity::TOP.is_bottom());
    }

    #[test]
    fn bottom_is_bottom_and_not_top() {
        assert!(PcodeParity::BOTTOM.is_bottom());
        assert!(!PcodeParity::BOTTOM.is_top());
    }

    #[test]
    fn default_and_new_match_top_by_value() {
        assert_eq!(PcodeParity::new(), PcodeParity::TOP);
        assert_eq!(PcodeParity::default(), PcodeParity::TOP);
    }

    #[test]
    fn representation_top_bottom_even_odd() {
        assert_eq!(PcodeParity::TOP.representation(), ParityRepresentation::Top);
        assert_eq!(PcodeParity::BOTTOM.representation(), ParityRepresentation::Bottom);
        assert_eq!(PcodeParity::EVEN.representation(), ParityRepresentation::Str("Even"));
        assert_eq!(PcodeParity::ODD.representation(), ParityRepresentation::Str("Odd"));
    }

    // ── is_even / is_odd: identity, not value equality ─────────────────────

    #[test]
    fn is_even_and_is_odd_true_for_the_canonical_singletons() {
        assert!(PcodeParity::EVEN.is_even());
        assert!(!PcodeParity::EVEN.is_odd());
        assert!(PcodeParity::ODD.is_odd());
        assert!(!PcodeParity::ODD.is_even());
    }

    #[test]
    fn is_even_is_false_for_a_freshly_constructed_value_equal_instance() {
        // Preserved quirk: with_parity(3) .equals(EVEN) but is not identically EVEN.
        let fresh = PcodeParity::with_parity(3);
        assert_eq!(fresh, PcodeParity::EVEN);
        assert!(!fresh.is_even());
    }

    // ── eval_null_constant / eval_non_null_constant ─────────────────────────

    #[test]
    fn eval_null_constant_is_top() {
        assert_eq!(PcodeParity::TOP.eval_null_constant(), PcodeParity::TOP);
    }

    #[test]
    fn eval_non_null_constant_dispatches_by_boxed_type_and_parity() {
        let d = PcodeParity::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Long(4)), PcodeParity::EVEN);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Long(3)), PcodeParity::ODD);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Integer(2)), PcodeParity::EVEN);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Short(3)), PcodeParity::ODD);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Byte(4)), PcodeParity::EVEN);
    }

    #[test]
    fn eval_non_null_constant_boolean_is_inverted() {
        // Preserved Java quirk: `bval ? ODD : EVEN` -- true maps to ODD, false to EVEN.
        let d = PcodeParity::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Boolean(true)), PcodeParity::ODD);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Boolean(false)), PcodeParity::EVEN);
    }

    #[test]
    fn eval_non_null_constant_unknown_type_logs_and_returns_top() {
        let d = PcodeParity::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Other), PcodeParity::TOP);
    }

    // ── eval_unary_expression ────────────────────────────────────────────────

    #[test]
    fn eval_unary_expression_returns_arg_unchanged() {
        let d = PcodeParity::TOP;
        assert_eq!(d.eval_unary_expression(PcodeParity::EVEN), PcodeParity::EVEN);
    }

    // ── eval_binary_expression ───────────────────────────────────────────────

    #[test]
    fn eval_binary_expression_top_operand_yields_top() {
        let d = PcodeParity::TOP;
        assert_eq!(d.eval_binary_expression(PcodeParity::TOP, PcodeParity::EVEN, OpCode::IntAdd), PcodeParity::TOP);
    }

    #[test]
    fn eval_binary_expression_add_sub_same_parity_is_even() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::EVEN, OpCode::IntAdd),
            PcodeParity::EVEN
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::IntSub),
            PcodeParity::ODD
        );
    }

    #[test]
    fn eval_binary_expression_and_same_is_left_else_even() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::ODD, OpCode::IntAnd),
            PcodeParity::ODD
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::EVEN, OpCode::BoolAnd),
            PcodeParity::EVEN
        );
    }

    #[test]
    fn eval_binary_expression_or_same_is_left_else_odd() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::EVEN, OpCode::IntOr),
            PcodeParity::EVEN
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::BoolOr),
            PcodeParity::ODD
        );
    }

    #[test]
    fn eval_binary_expression_xor_same_is_even_else_odd() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::EVEN, OpCode::IntXor),
            PcodeParity::EVEN
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::BoolXor),
            PcodeParity::ODD
        );
    }

    #[test]
    fn eval_binary_expression_mult_even_if_either_is_even() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::IntMult),
            PcodeParity::EVEN
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::ODD, OpCode::FloatMult),
            PcodeParity::ODD
        );
    }

    #[test]
    fn eval_binary_expression_div_cases() {
        let d = PcodeParity::TOP;
        // odd/odd = odd
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::ODD, OpCode::IntDiv),
            PcodeParity::ODD
        );
        // odd/even = even
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::EVEN, OpCode::IntDiv),
            PcodeParity::EVEN
        );
        // even/odd = even
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::FloatDiv),
            PcodeParity::EVEN
        );
        // even/even = top
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::EVEN, OpCode::IntDiv),
            PcodeParity::TOP
        );
    }

    #[test]
    fn eval_binary_expression_rem_is_top() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::IntRem),
            PcodeParity::TOP
        );
        assert_eq!(
            d.eval_binary_expression(PcodeParity::EVEN, PcodeParity::ODD, OpCode::IntSrem),
            PcodeParity::TOP
        );
    }

    #[test]
    fn eval_binary_expression_unmatched_opcode_returns_left() {
        let d = PcodeParity::TOP;
        assert_eq!(
            d.eval_binary_expression(PcodeParity::ODD, PcodeParity::EVEN, OpCode::Copy),
            PcodeParity::ODD
        );
    }

    // ── lub_aux / less_or_equal_aux ──────────────────────────────────────────

    #[test]
    fn lub_aux_is_always_top() {
        assert_eq!(PcodeParity::EVEN.lub_aux(&PcodeParity::ODD), PcodeParity::TOP);
    }

    #[test]
    fn less_or_equal_aux_is_always_false() {
        assert!(!PcodeParity::EVEN.less_or_equal_aux(&PcodeParity::EVEN));
    }

    // ── equals / hash ────────────────────────────────────────────────────────

    #[test]
    fn equals_ignores_canonical_flag() {
        assert_eq!(PcodeParity::EVEN, PcodeParity::with_parity(3));
    }

    #[test]
    fn hash_matches_between_canonical_and_non_canonical_equal_values() {
        use std::collections::hash_map::DefaultHasher;
        let mut h1 = DefaultHasher::new();
        PcodeParity::EVEN.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        PcodeParity::with_parity(3).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // ── get_value ─────────────────────────────────────────────────────────────

    /// A real register value over a 4-byte test register: fully known (`value`) when `has_value`,
    /// otherwise carrying no known bits.
    fn register_value(value: u128, has_value: bool) -> RegisterValue {
        let space = crate::program::model::address::AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            0,
        );
        let register = crate::program::model::lang::register::Register::new(
            "r0",
            "",
            crate::program::model::address::Address::new(space, 0),
            4,
            false,
            0,
        );
        if has_value {
            RegisterValue::with_value(register, value)
        } else {
            RegisterValue::new(register)
        }
    }

    #[test]
    fn get_value_none_is_top() {
        let d = PcodeParity::TOP;
        assert_eq!(PcodeNonRelationalValueDomain::get_value(&d, None), Some(PcodeParity::TOP));
    }

    #[test]
    fn get_value_without_a_value_is_top() {
        let d = PcodeParity::TOP;
        let rv = register_value(4, false);
        assert_eq!(PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)), Some(PcodeParity::TOP));
    }

    #[test]
    fn get_value_of_even_register_is_value_equal_to_even() {
        let d = PcodeParity::TOP;
        let rv = register_value(4, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert_eq!(result, PcodeParity::EVEN);
    }

    #[test]
    fn get_value_of_odd_register_is_value_equal_to_odd() {
        let d = PcodeParity::TOP;
        let rv = register_value(7, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert_eq!(result, PcodeParity::ODD);
    }

    #[test]
    fn get_value_of_even_register_is_not_identically_even() {
        // Preserved quirk: see PcodeParity::get_value's own docs.
        let d = PcodeParity::TOP;
        let rv = register_value(4, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert!(!result.is_even());
    }

    // ── assume_binary_expression ─────────────────────────────────────────────

    #[derive(Clone, Debug)]
    struct MockExpr {
        id: Option<&'static str>,
        eval_result: PcodeParity,
    }

    impl AsIdentifier<&'static str> for MockExpr {
        fn as_identifier(&self) -> Option<&&'static str> {
            self.id.as_ref()
        }
    }

    impl ParityExpression<&'static str, MockEnv, (), ()> for MockExpr {
        fn eval(&self, _environment: &MockEnv, _pp: &(), _oracle: &()) -> PcodeParity {
            self.eval_result
        }
    }

    #[derive(Clone, Debug, Default)]
    struct MockEnv {
        states: HashMap<&'static str, PcodeParity>,
        is_bottom: bool,
    }

    impl ParityEnvironment<&'static str> for MockEnv {
        fn put_state(mut self, id: &&'static str, value: PcodeParity) -> Self {
            self.states.insert(*id, value);
            self
        }
        fn bottom(&self) -> Self {
            MockEnv { states: self.states.clone(), is_bottom: true }
        }
    }

    fn ident(id: &'static str, eval_result: PcodeParity) -> MockExpr {
        MockExpr { id: Some(id), eval_result }
    }

    fn not_ident(eval_result: PcodeParity) -> MockExpr {
        MockExpr { id: None, eval_result }
    }

    #[test]
    fn assume_binary_expression_left_identifier_takes_evaluated_right() {
        let d = PcodeParity::TOP;
        let env = MockEnv::default();
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x", PcodeParity::TOP),
            &not_ident(PcodeParity::EVEN),
            &(),
            &(),
        );
        assert_eq!(result.states.get("x"), Some(&PcodeParity::EVEN));
        assert!(!result.is_bottom);
    }

    #[test]
    fn assume_binary_expression_right_identifier_takes_evaluated_left() {
        let d = PcodeParity::TOP;
        let env = MockEnv::default();
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &not_ident(PcodeParity::ODD),
            &ident("y", PcodeParity::TOP),
            &(),
            &(),
        );
        assert_eq!(result.states.get("y"), Some(&PcodeParity::ODD));
    }

    #[test]
    fn assume_binary_expression_bottom_eval_yields_bottom_environment() {
        let d = PcodeParity::TOP;
        let env = MockEnv::default();
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x", PcodeParity::TOP),
            &not_ident(PcodeParity::BOTTOM),
            &(),
            &(),
        );
        assert!(result.is_bottom);
    }

    #[test]
    fn assume_binary_expression_neither_side_identifier_passes_through() {
        let d = PcodeParity::TOP;
        let env = MockEnv::default().put_state(&"z", PcodeParity::EVEN);
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &not_ident(PcodeParity::TOP),
            &not_ident(PcodeParity::TOP),
            &(),
            &(),
        );
        assert_eq!(result.states, env.states);
    }

    #[test]
    fn assume_binary_expression_non_eq_operator_passes_through() {
        let d = PcodeParity::TOP;
        let env = MockEnv::default();
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonLt,
            &ident("x", PcodeParity::TOP),
            &not_ident(PcodeParity::EVEN),
            &(),
            &(),
        );
        assert_eq!(result.states, env.states);
    }
}
