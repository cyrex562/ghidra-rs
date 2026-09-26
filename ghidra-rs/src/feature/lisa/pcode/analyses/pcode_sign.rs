//! Port of `ghidra.lisa.pcode.analyses.PcodeSign`.

use std::hash::{Hash, Hasher};

use crate::feature::lisa::pcode::analyses::constant_value::ConstantValue;
use crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain;
use crate::feature::lisa::pcode::analyses::pcode_upper_bounds::AsIdentifier;
use crate::feature::lisa::pcode::analyses::satisfiability::Satisfiability;
use crate::feature::lisa::pcode::expressions::pcode_binary_expression::PcodeBinaryExpressionOperator;
use crate::program::model::pcode::OpCode;
use crate::program::model::lang::register_value::RegisterValue;
use crate::util::Msg;

/// Stand-in for LiSA's `it.unive.lisa.util.representation.StructuredRepresentation`, narrowed to
/// the shapes [`PcodeSign::representation`] actually builds -- the same convention
/// [`ParityRepresentation`](super::pcode_parity::ParityRepresentation)'s docs describe for the
/// sibling class in this package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignRepresentation {
    /// Java: `Lattice.topRepresentation()`.
    Top,
    /// Java: `Lattice.bottomRepresentation()`.
    Bottom,
    /// Java: `new StringRepresentation(repr)`, `repr` being `"0"`, `"+"`, or `"-"`.
    Str(&'static str),
}

/// The basic overflow-insensitive Sign abstract domain: tracks zero, strictly positive, and
/// strictly negative integer values.
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeSign` in the Java source, which `implements
/// PcodeNonRelationalValueDomain<PcodeSign>`. As with
/// [`PcodeParity`](super::pcode_parity::PcodeParity)'s own docs, the full LiSA
/// `BaseNonRelationalValueDomain`/`Lattice` framework this class's `top()`/`bottom()`/`lubAux`/
/// `lessOrEqualAux` overrides are built on has no Rust port in this crate.
///
/// # Representation: `sign` byte + `canonical` flag
///
/// Exactly the same reference-identity-vs-value-equality distinction described on
/// [`PcodeParity`](super::pcode_parity::PcodeParity)'s own docs applies here: `isPositive()`/
/// `isZero()`/`isNegative()` test `this == POS`/`ZERO`/`NEG` (reference identity), while the
/// public `PcodeSign(byte)` constructor lets a caller build a value-equal-but-not-identical
/// instance. See [`Self::get_value`]'s docs for where that distinction becomes directly
/// observable (and buggy) in this class's own code.
#[derive(Clone, Copy, Debug)]
pub struct PcodeSign {
    sign: i8,
    canonical: bool,
}

impl PcodeSign {
    /// Java: `public static final PcodeSign POS`.
    pub const POS: Self = Self { sign: 4, canonical: true };
    /// Java: `public static final PcodeSign NEG`.
    pub const NEG: Self = Self { sign: 3, canonical: true };
    /// Java: `public static final PcodeSign ZERO`.
    pub const ZERO: Self = Self { sign: 2, canonical: true };
    /// Java: `public static final PcodeSign TOP`.
    pub const TOP: Self = Self { sign: 0, canonical: true };
    /// Java: `public static final PcodeSign BOTTOM`.
    pub const BOTTOM: Self = Self { sign: 1, canonical: true };

    /// Java: `public PcodeSign()`, `this((byte) 0);` -- builds a fresh, non-canonical instance
    /// that is value-equal to (but not identical to) [`Self::TOP`]. See the struct docs.
    pub fn new() -> Self {
        Self::with_sign(0)
    }

    /// Java: `public PcodeSign(byte sign)` -- builds a fresh, non-canonical instance. See the
    /// struct docs.
    pub fn with_sign(sign: i8) -> Self {
        Self { sign, canonical: false }
    }

    /// Java: `public PcodeSign top()`.
    pub fn top(&self) -> Self {
        Self::TOP
    }

    /// Java: `public PcodeSign bottom()`.
    pub fn bottom(&self) -> Self {
        Self::BOTTOM
    }

    /// Java: inherited `isTop()` default (`equals(top())`). Value-based, not identity-based --
    /// see the struct docs and
    /// [`PcodeParity::is_top`](super::pcode_parity::PcodeParity::is_top)'s docs for the same
    /// reconstruction.
    pub fn is_top(&self) -> bool {
        *self == Self::TOP
    }

    /// Java: inherited `isBottom()` default (`equals(bottom())`). Value-based, not
    /// identity-based.
    pub fn is_bottom(&self) -> bool {
        *self == Self::BOTTOM
    }

    fn is_identically(&self, singleton: &Self) -> bool {
        self.canonical && singleton.canonical && self.sign == singleton.sign
    }

    /// Java: `public boolean isPositive()`, `return this == POS;` -- reference identity.
    pub fn is_positive(&self) -> bool {
        self.is_identically(&Self::POS)
    }

    /// Java: `public boolean isZero()`, `return this == ZERO;` -- reference identity.
    pub fn is_zero(&self) -> bool {
        self.is_identically(&Self::ZERO)
    }

    /// Java: `public boolean isNegative()`, `return this == NEG;` -- reference identity.
    pub fn is_negative(&self) -> bool {
        self.is_identically(&Self::NEG)
    }

    /// Java: `public PcodeSign opposite()`.
    ///
    /// # Preserved quirk
    ///
    /// Since [`Self::is_positive`]/[`Self::is_negative`] are identity-based, this only correctly
    /// negates the canonical [`Self::POS`]/[`Self::NEG`] singletons: any other non-top/non-bottom
    /// value (including a value-equal-but-non-canonical positive or negative instance, e.g. one
    /// built via [`Self::with_sign`]) falls through both checks and returns [`Self::ZERO`]
    /// regardless of its actual sign.
    pub fn opposite(&self) -> Self {
        if self.is_top() || self.is_bottom() {
            return *self;
        }
        if self.is_positive() {
            Self::NEG
        }
        else if self.is_negative() {
            Self::POS
        }
        else {
            Self::ZERO
        }
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> SignRepresentation {
        if self.is_bottom() {
            return SignRepresentation::Bottom;
        }
        if self.is_top() {
            return SignRepresentation::Top;
        }
        // Java: `this == ZERO ? "0" : this == POS ? "+" : "-"` -- identity, not value equality.
        let repr = if self.is_identically(&Self::ZERO) {
            "0"
        }
        else if self.is_identically(&Self::POS) {
            "+"
        }
        else {
            "-"
        };
        SignRepresentation::Str(repr)
    }

    /// Java: `public PcodeSign evalNullConstant(ProgramPoint pp, SemanticOracle oracle)`, `return
    /// top();`. Java's unused `pp`/`oracle` parameters are dropped -- see
    /// [`PcodeParity::eval_null_constant`](super::pcode_parity::PcodeParity::eval_null_constant)'s
    /// docs for the established convention.
    pub fn eval_null_constant(&self) -> Self {
        self.top()
    }

    /// Java: `public PcodeSign evalNonNullConstant(Constant constant, ProgramPoint pp,
    /// SemanticOracle oracle)`. Java's unused `pp`/`oracle` parameters are dropped; Java's
    /// `Constant constant` is narrowed to [`ConstantValue`] -- see
    /// [`PcodeParity::eval_non_null_constant`](super::pcode_parity::PcodeParity::eval_non_null_constant)'s
    /// docs.
    pub fn eval_non_null_constant(&self, cval: ConstantValue) -> Self {
        fn sign_of(v: i64) -> PcodeSign {
            if v == 0 {
                PcodeSign::ZERO
            }
            else if v > 0 {
                PcodeSign::POS
            }
            else {
                PcodeSign::NEG
            }
        }
        match cval {
            ConstantValue::Long(lval) => sign_of(lval),
            ConstantValue::Integer(ival) => sign_of(ival as i64),
            ConstantValue::Short(sval) => sign_of(sval as i64),
            ConstantValue::Byte(bval) => sign_of(bval as i64),
            ConstantValue::Boolean(bval) => if bval { Self::POS } else { Self::ZERO },
            ConstantValue::Other => {
                Msg::error("PcodeSign", &"Unknown type for constant");
                self.top()
            }
        }
    }

    /// Java: `public PcodeSign evalUnaryExpression(UnaryOperator operator, PcodeSign arg,
    /// ProgramPoint pp, SemanticOracle oracle)`.
    ///
    /// Java's unused `operator` parameter is dropped, and the resolved `opcode` is taken directly
    /// instead of modeling the `ProgramPoint`/`PcodeLocation` downcast machinery to extract it --
    /// see
    /// [`PcodeParity::eval_binary_expression`](super::pcode_parity::PcodeParity::eval_binary_expression)'s
    /// docs for the same simplification.
    ///
    /// # Preserved quirk
    ///
    /// For a negate-family opcode, Java's inner `if (arg.isPositive()) ... else if
    /// (arg.isNegative()) ... else if (arg.isZero()) ...` has no final `else`: if `arg` is none
    /// of those three *identically* (e.g. it is [`Self::TOP`]/[`Self::BOTTOM`], or a
    /// value-equal-but-non-canonical instance), execution falls through to `return arg;` at the
    /// very end unchanged, rather than negating it.
    pub fn eval_unary_expression(&self, arg: Self, opcode: OpCode) -> Self {
        if matches!(opcode, OpCode::IntNegate | OpCode::Int2Comp | OpCode::FloatNeg) {
            if arg.is_positive() {
                return Self::NEG;
            }
            else if arg.is_negative() {
                return Self::POS;
            }
            else if arg.is_zero() {
                return Self::ZERO;
            }
        }
        if matches!(opcode, OpCode::FloatAbs) {
            return Self::POS;
        }
        arg
    }

    /// Java: `public PcodeSign evalBinaryExpression(BinaryOperator operator, PcodeSign left,
    /// PcodeSign right, ProgramPoint pp, SemanticOracle oracle)`. Java's unused `operator` is
    /// dropped and `opcode` taken directly -- see [`Self::eval_unary_expression`]'s docs.
    ///
    /// # Preserved quirk
    ///
    /// Java's `else if (opcode == PcodeOp.INT_XOR) { ... }` arm (the very last one, right before
    /// the final `else { return left; }`) is dead code: `INT_XOR` is already matched by the
    /// earlier `INT_SUB || FLOAT_SUB || INT_XOR` arm, so the later arm can never execute. Omitted
    /// here for the same reason
    /// [`PcodeParity::eval_binary_expression`](super::pcode_parity::PcodeParity::eval_binary_expression)'s
    /// docs describe for its own duplicate-opcode dead branches -- a `match` cannot express an
    /// unreachable duplicate pattern in the first place.
    pub fn eval_binary_expression(&self, left: Self, right: Self, opcode: OpCode) -> Self {
        match opcode {
            OpCode::IntAdd | OpCode::FloatAdd => {
                if left.is_zero() {
                    right
                }
                else if right.is_zero() {
                    left
                }
                else if left == right {
                    left
                }
                else {
                    self.top()
                }
            }
            OpCode::IntSub | OpCode::FloatSub | OpCode::IntXor => {
                if left.is_zero() {
                    right.opposite()
                }
                else if right.is_zero() {
                    left
                }
                else if left == right {
                    self.top()
                }
                else {
                    left
                }
            }
            OpCode::IntSdiv | OpCode::FloatDiv => {
                if right.is_zero() {
                    self.bottom()
                }
                else if left.is_zero() {
                    Self::ZERO
                }
                else if left == right {
                    // top/top = top; +/+ = +; -/- = +
                    if left.is_top() { left } else { Self::POS }
                }
                else if !left.is_top() && left == right.opposite() {
                    // +/- = -; -/+ = -
                    Self::NEG
                }
                else {
                    self.top()
                }
            }
            OpCode::IntMult | OpCode::FloatMult => {
                if left.is_zero() || right.is_zero() {
                    Self::ZERO
                }
                else if left == right {
                    Self::POS
                }
                else {
                    Self::NEG
                }
            }
            OpCode::IntAnd => {
                if left.is_zero() || right.is_zero() {
                    Self::ZERO
                }
                else if left == Self::POS || right == Self::POS {
                    Self::POS
                }
                else {
                    Self::NEG
                }
            }
            OpCode::IntOr => {
                if left.is_zero() && right.is_zero() {
                    Self::ZERO
                }
                else if left == Self::NEG || right == Self::NEG {
                    Self::NEG
                }
                else {
                    Self::POS
                }
            }
            _ => left,
        }
    }

    /// Java: `public PcodeSign lubAux(PcodeSign other) throws SemanticException`, `return TOP;`.
    pub fn lub_aux(&self, _other: &Self) -> Self {
        Self::TOP
    }

    /// Java: `public boolean lessOrEqualAux(PcodeSign other) throws SemanticException`, `return
    /// false;`.
    pub fn less_or_equal_aux(&self, _other: &Self) -> bool {
        false
    }

    /// Java: `public Satisfiability satisfiesBinaryExpression(BinaryOperator operator, PcodeSign
    /// left, PcodeSign right, ProgramPoint pp, SemanticOracle oracle)`. Java's unused `pp`/
    /// `oracle` parameters are dropped.
    pub fn satisfies_binary_expression(
        operator: &PcodeBinaryExpressionOperator,
        left: Self,
        right: Self,
    ) -> Satisfiability {
        if left.is_top() || right.is_top() {
            return Satisfiability::Unknown;
        }
        match operator {
            PcodeBinaryExpressionOperator::ComparisonEq => left.eq_sat(right),
            // e1 <= e2 same as !(e1 > e2)
            PcodeBinaryExpressionOperator::ComparisonLe => left.gt(right).negate(),
            // e1 < e2 -> !(e1 >= e2) && !(e1 == e2)
            PcodeBinaryExpressionOperator::ComparisonLt => {
                left.gt(right).negate().and(left.eq_sat(right).negate())
            }
            PcodeBinaryExpressionOperator::ComparisonNe => left.eq_sat(right).negate(),
            _ => Satisfiability::Unknown,
        }
    }

    /// Java: `public Satisfiability eq(PcodeSign other)`. Renamed to `eq_sat` to avoid colliding
    /// with [`PartialEq::eq`].
    pub fn eq_sat(&self, other: Self) -> Satisfiability {
        if *self != other {
            Satisfiability::NotSatisfied
        }
        else if self.is_zero() {
            Satisfiability::Satisfied
        }
        else {
            Satisfiability::Unknown
        }
    }

    /// Java: `public Satisfiability gt(PcodeSign other)`.
    pub fn gt(&self, other: Self) -> Satisfiability {
        if *self == other {
            if self.is_zero() { Satisfiability::NotSatisfied } else { Satisfiability::Unknown }
        }
        else if self.is_zero() {
            if other.is_positive() { Satisfiability::NotSatisfied } else { Satisfiability::Satisfied }
        }
        else if self.is_positive() {
            Satisfiability::Satisfied
        }
        else {
            Satisfiability::NotSatisfied
        }
    }

    /// Java: `public Satisfiability satisfiesTernaryExpression(TernaryOperator operator, PcodeSign
    /// left, PcodeSign middle, PcodeSign right, ProgramPoint pp, SemanticOracle oracle)`, `return
    /// UNKNOWN;`. Every parameter is unused in Java, so all are dropped here -- see
    /// [`Self::eval_null_constant`]'s docs.
    pub fn satisfies_ternary_expression() -> Satisfiability {
        Satisfiability::Unknown
    }

    /// Java: `public ValueEnvironment<PcodeSign> assumeBinaryExpression(
    /// ValueEnvironment<PcodeSign> environment, BinaryOperator operator, ValueExpression left,
    /// ValueExpression right, ProgramPoint src, ProgramPoint dest, SemanticOracle oracle) throws
    /// SemanticException`. Java's unused `dest` parameter is dropped -- see
    /// [`Self::eval_null_constant`]'s docs. Java's `eval(...)` call is modeled via
    /// [`SignExpression::eval`], the same convention
    /// [`ParityExpression`](super::pcode_parity::ParityExpression)'s docs describe.
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
        Env: SignEnvironment<Id>,
        Expr: SignExpression<Id, Env, Pp, Oracle>,
    {
        let (id, eval, right_is_expr): (&Id, Self, bool) = if let Some(id) = left.as_identifier() {
            (id, right.eval(&environment, src, oracle), true)
        }
        else if let Some(id) = right.as_identifier() {
            (id, left.eval(&environment, src, oracle), false)
        }
        else {
            return environment;
        };

        let starting = environment.get_state(id);
        if eval.is_bottom() || starting.is_bottom() {
            return environment.bottom();
        }

        let mut update: Option<Self> = None;
        if !matches!(operator, PcodeBinaryExpressionOperator::Other(_)) {
            match operator {
                PcodeBinaryExpressionOperator::ComparisonEq => {
                    update = Some(eval);
                }
                PcodeBinaryExpressionOperator::ComparisonLe => {
                    if right_is_expr && eval.is_negative() {
                        update = Some(eval);
                    }
                    else if !right_is_expr && eval.is_positive() {
                        update = Some(eval);
                    }
                }
                PcodeBinaryExpressionOperator::ComparisonLt => {
                    if right_is_expr && (eval.is_negative() || eval.is_zero()) {
                        // x < 0/-
                        update = Some(Self::NEG);
                    }
                    else if !right_is_expr && (eval.is_positive() || eval.is_zero()) {
                        // 0/+ < x
                        update = Some(Self::POS);
                    }
                }
                _ => {}
            }
        }

        match update {
            None => environment,
            Some(update) if update.is_bottom() => environment.bottom(),
            Some(update) => environment.put_state(id, update),
        }
    }
}

impl Default for PcodeSign {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for PcodeSign {
    /// Java: `public boolean equals(Object obj)` -- compares only the `sign` byte. Deliberately
    /// ignores `canonical` -- see the struct docs.
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign
    }
}

impl Eq for PcodeSign {}

impl Hash for PcodeSign {
    /// Java: `public int hashCode()`, `31 * 1 + sign`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
    }
}

/// Stand-in for LiSA's `ValueEnvironment<PcodeSign>`, narrowed to what
/// [`PcodeSign::assume_binary_expression`] actually calls: `getState`, `putState`, `bottom()`.
/// Unlike [`ParityEnvironment`](super::pcode_parity::ParityEnvironment) (whose
/// `PcodeParity::assume_binary_expression` never reads existing state), this domain's
/// `assumeBinaryExpression` reads the identifier's `starting` state before deciding whether to
/// update it.
pub trait SignEnvironment<Id>: Sized {
    /// Java: `environment.getState(id)`.
    fn get_state(&self, id: &Id) -> PcodeSign;
    /// Java: `environment.putState(id, value)`.
    fn put_state(self, id: &Id, value: PcodeSign) -> Self;
    /// Java: `environment.bottom()`.
    fn bottom(&self) -> Self;
}

/// Stand-in for LiSA's `ValueExpression`, the same role
/// [`ParityExpression`](super::pcode_parity::ParityExpression) plays for
/// [`PcodeParity`](super::pcode_parity::PcodeParity).
pub trait SignExpression<Id, Env, Pp, Oracle>: AsIdentifier<Id> {
    /// Java: `eval(SymbolicExpression, ValueEnvironment, ProgramPoint, SemanticOracle)`.
    fn eval(&self, environment: &Env, pp: &Pp, oracle: &Oracle) -> PcodeSign;
}

impl PcodeNonRelationalValueDomain<PcodeSign> for PcodeSign {
    /// Java: `public PcodeSign getValue(RegisterValue rv)`.
    ///
    /// # Preserved quirks
    ///
    /// Java's `BigInteger.longValue()` truncates to the low 64 bits (reinterpreted as signed) when
    /// the value doesn't fit in a `long`; this port's [`RegisterValue::get_unsigned_value_ignore_mask`]
    /// returns a `u128` directly (no intermediate `BigInteger`), so that same truncation is
    /// reproduced explicitly below, preserving two distinct bugs this method has:
    ///
    /// 1. The zero check (`val.longValue() == 0L`) is performed on the *truncated* value, so a
    ///    huge register value whose low 64 bits happen to be all-zero (e.g. exactly `2^64`) is
    ///    treated as zero even though the true value is not.
    /// 2. On the "zero" branch, Java returns `new PcodeSign()` -- a fresh, non-canonical instance
    ///    that is value-equal to [`PcodeSign::TOP`] (sign byte `0`), *not* [`PcodeSign::ZERO`]
    ///    (sign byte `2`) as the code's intent clearly suggests. On the nonzero branch, Java
    ///    returns `new PcodeSign((byte) (val.longValue() > 0 ? 1 : -1))`: sign byte `1` for a
    ///    positive truncated value -- which is value-equal to [`PcodeSign::BOTTOM`] (also byte
    ///    `1`), not [`PcodeSign::POS`] (byte `4`) -- or sign byte `-1` (matching none of the five
    ///    named constants) for a truncated value that reads negative. Every nonzero result of this
    ///    method is therefore either indistinguishable-by-value from [`PcodeSign::BOTTOM`], or an
    ///    orphan sign byte that is neither top, bottom, nor any of the three ordinary signs.
    fn get_value(&self, rv: Option<&RegisterValue>) -> Option<PcodeSign> {
        if let Some(rv) = rv {
            if rv.has_value() {
                let val = rv.unsigned_value_ignore_mask();
                // Java: `BigInteger.longValue()` -- low 64 bits, reinterpreted as signed.
                let truncated = (val & 0xFFFF_FFFF_FFFF_FFFFu128) as u64 as i64;
                if truncated == 0 {
                    return Some(Self::with_sign(0));
                }
                return Some(Self::with_sign(if truncated > 0 { 1 } else { -1 }));
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
        assert!(PcodeSign::TOP.is_top());
        assert!(!PcodeSign::TOP.is_bottom());
    }

    #[test]
    fn bottom_is_bottom_and_not_top() {
        assert!(PcodeSign::BOTTOM.is_bottom());
        assert!(!PcodeSign::BOTTOM.is_top());
    }

    #[test]
    fn default_and_new_match_top_by_value() {
        assert_eq!(PcodeSign::new(), PcodeSign::TOP);
        assert_eq!(PcodeSign::default(), PcodeSign::TOP);
    }

    #[test]
    fn representation_top_bottom_zero_pos_neg() {
        assert_eq!(PcodeSign::TOP.representation(), SignRepresentation::Top);
        assert_eq!(PcodeSign::BOTTOM.representation(), SignRepresentation::Bottom);
        assert_eq!(PcodeSign::ZERO.representation(), SignRepresentation::Str("0"));
        assert_eq!(PcodeSign::POS.representation(), SignRepresentation::Str("+"));
        assert_eq!(PcodeSign::NEG.representation(), SignRepresentation::Str("-"));
    }

    // ── isPositive/isZero/isNegative: identity, not value equality ─────────

    #[test]
    fn is_positive_zero_negative_true_for_canonical_singletons_only() {
        assert!(PcodeSign::POS.is_positive());
        assert!(PcodeSign::ZERO.is_zero());
        assert!(PcodeSign::NEG.is_negative());

        let fresh_pos = PcodeSign::with_sign(4);
        assert_eq!(fresh_pos, PcodeSign::POS);
        assert!(!fresh_pos.is_positive());
    }

    // ── opposite ─────────────────────────────────────────────────────────────

    #[test]
    fn opposite_flips_canonical_pos_and_neg() {
        assert_eq!(PcodeSign::POS.opposite(), PcodeSign::NEG);
        assert_eq!(PcodeSign::NEG.opposite(), PcodeSign::POS);
    }

    #[test]
    fn opposite_leaves_top_and_bottom_unchanged() {
        assert_eq!(PcodeSign::TOP.opposite(), PcodeSign::TOP);
        assert_eq!(PcodeSign::BOTTOM.opposite(), PcodeSign::BOTTOM);
    }

    #[test]
    fn opposite_of_zero_is_zero() {
        assert_eq!(PcodeSign::ZERO.opposite(), PcodeSign::ZERO);
    }

    #[test]
    fn opposite_of_non_canonical_positive_is_zero_not_negative() {
        // Preserved quirk: see PcodeSign::opposite's own docs.
        let fresh_pos = PcodeSign::with_sign(4);
        assert_eq!(fresh_pos.opposite(), PcodeSign::ZERO);
    }

    // ── eval_non_null_constant ───────────────────────────────────────────────

    #[test]
    fn eval_non_null_constant_dispatches_by_boxed_type_and_sign() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Long(5)), PcodeSign::POS);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Long(-5)), PcodeSign::NEG);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Long(0)), PcodeSign::ZERO);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Integer(-1)), PcodeSign::NEG);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Short(1)), PcodeSign::POS);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Byte(0)), PcodeSign::ZERO);
    }

    #[test]
    fn eval_non_null_constant_boolean_maps_true_to_pos_false_to_zero() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Boolean(true)), PcodeSign::POS);
        assert_eq!(d.eval_non_null_constant(ConstantValue::Boolean(false)), PcodeSign::ZERO);
    }

    #[test]
    fn eval_non_null_constant_unknown_type_logs_and_returns_top() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_non_null_constant(ConstantValue::Other), PcodeSign::TOP);
    }

    // ── eval_unary_expression ────────────────────────────────────────────────

    #[test]
    fn eval_unary_expression_negates_pos_neg_zero_for_negate_family() {
        for opcode in [OpCode::IntNegate, OpCode::Int2Comp, OpCode::FloatNeg] {
            let d = PcodeSign::TOP;
            assert_eq!(d.eval_unary_expression(PcodeSign::POS, opcode), PcodeSign::NEG);
            assert_eq!(d.eval_unary_expression(PcodeSign::NEG, opcode), PcodeSign::POS);
            assert_eq!(d.eval_unary_expression(PcodeSign::ZERO, opcode), PcodeSign::ZERO);
        }
    }

    #[test]
    fn eval_unary_expression_negate_family_on_top_falls_through_unchanged() {
        // Preserved quirk: no final `else` in the inner if-chain -- see the method's own docs.
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_unary_expression(PcodeSign::TOP, OpCode::IntNegate), PcodeSign::TOP);
    }

    #[test]
    fn eval_unary_expression_float_abs_is_pos() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_unary_expression(PcodeSign::NEG, OpCode::FloatAbs), PcodeSign::POS);
    }

    #[test]
    fn eval_unary_expression_other_opcode_returns_arg() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_unary_expression(PcodeSign::NEG, OpCode::Copy), PcodeSign::NEG);
    }

    // ── eval_binary_expression ───────────────────────────────────────────────

    #[test]
    fn eval_binary_expression_add_zero_identity_and_equal_operands() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::POS, OpCode::IntAdd), PcodeSign::POS);
        assert_eq!(d.eval_binary_expression(PcodeSign::NEG, PcodeSign::ZERO, OpCode::FloatAdd), PcodeSign::NEG);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::POS, OpCode::IntAdd), PcodeSign::POS);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, OpCode::IntAdd), PcodeSign::TOP);
    }

    #[test]
    fn eval_binary_expression_sub_and_xor_share_the_same_reachable_branch() {
        let d = PcodeSign::TOP;
        for opcode in [OpCode::IntSub, OpCode::FloatSub, OpCode::IntXor] {
            assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::POS, opcode), PcodeSign::NEG);
            assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::ZERO, opcode), PcodeSign::POS);
            assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::POS, opcode), PcodeSign::TOP);
            assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, opcode), PcodeSign::POS);
        }
    }

    #[test]
    fn eval_binary_expression_sdiv_cases() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::ZERO, OpCode::IntSdiv), PcodeSign::BOTTOM);
        assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::POS, OpCode::IntSdiv), PcodeSign::ZERO);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::POS, OpCode::IntSdiv), PcodeSign::POS);
        assert_eq!(d.eval_binary_expression(PcodeSign::TOP, PcodeSign::TOP, OpCode::IntSdiv), PcodeSign::TOP);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, OpCode::FloatDiv), PcodeSign::NEG);
        assert_eq!(d.eval_binary_expression(PcodeSign::TOP, PcodeSign::POS, OpCode::IntSdiv), PcodeSign::TOP);
    }

    #[test]
    fn eval_binary_expression_mult_cases() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::POS, OpCode::IntMult), PcodeSign::ZERO);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::POS, OpCode::IntMult), PcodeSign::POS);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, OpCode::FloatMult), PcodeSign::NEG);
    }

    #[test]
    fn eval_binary_expression_and_or_cases() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::NEG, OpCode::IntAnd), PcodeSign::ZERO);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, OpCode::IntAnd), PcodeSign::POS);
        assert_eq!(d.eval_binary_expression(PcodeSign::NEG, PcodeSign::NEG, OpCode::IntAnd), PcodeSign::NEG);

        assert_eq!(d.eval_binary_expression(PcodeSign::ZERO, PcodeSign::ZERO, OpCode::IntOr), PcodeSign::ZERO);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::NEG, OpCode::IntOr), PcodeSign::NEG);
        assert_eq!(d.eval_binary_expression(PcodeSign::POS, PcodeSign::POS, OpCode::IntOr), PcodeSign::POS);
    }

    #[test]
    fn eval_binary_expression_unmatched_opcode_returns_left() {
        let d = PcodeSign::TOP;
        assert_eq!(d.eval_binary_expression(PcodeSign::NEG, PcodeSign::POS, OpCode::Copy), PcodeSign::NEG);
    }

    // ── satisfiesBinaryExpression / eq / gt ─────────────────────────────────

    #[test]
    fn satisfies_binary_expression_top_operand_is_unknown() {
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonEq,
            PcodeSign::TOP,
            PcodeSign::POS,
        );
        assert_eq!(result, Satisfiability::Unknown);
    }

    #[test]
    fn satisfies_binary_expression_eq_pos_pos_is_unknown_not_satisfied() {
        // eq(POS, POS): equal but not zero -> UNKNOWN.
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonEq,
            PcodeSign::POS,
            PcodeSign::POS,
        );
        assert_eq!(result, Satisfiability::Unknown);
    }

    #[test]
    fn satisfies_binary_expression_eq_zero_zero_is_satisfied() {
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonEq,
            PcodeSign::ZERO,
            PcodeSign::ZERO,
        );
        assert_eq!(result, Satisfiability::Satisfied);
    }

    #[test]
    fn satisfies_binary_expression_ne_pos_neg_is_satisfied() {
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonNe,
            PcodeSign::POS,
            PcodeSign::NEG,
        );
        assert_eq!(result, Satisfiability::Satisfied);
    }

    #[test]
    fn satisfies_binary_expression_le_pos_neg_is_not_satisfied() {
        // gt(POS, NEG) = SATISFIED (self positive) -> negate() = NOT_SATISFIED.
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonLe,
            PcodeSign::POS,
            PcodeSign::NEG,
        );
        assert_eq!(result, Satisfiability::NotSatisfied);
    }

    #[test]
    fn satisfies_binary_expression_lt_neg_pos_is_satisfied() {
        // gt(NEG, POS) = NOT_SATISFIED -> negate() = SATISFIED; eq(NEG,POS)=NOT_SATISFIED -> negate()=SATISFIED;
        // SATISFIED.and(SATISFIED) = SATISFIED.
        let result = PcodeSign::satisfies_binary_expression(
            &PcodeBinaryExpressionOperator::ComparisonLt,
            PcodeSign::NEG,
            PcodeSign::POS,
        );
        assert_eq!(result, Satisfiability::Satisfied);
    }

    #[test]
    fn gt_zero_zero_is_not_satisfied() {
        assert_eq!(PcodeSign::ZERO.gt(PcodeSign::ZERO), Satisfiability::NotSatisfied);
    }

    #[test]
    fn gt_zero_pos_is_not_satisfied_zero_neg_is_satisfied() {
        assert_eq!(PcodeSign::ZERO.gt(PcodeSign::POS), Satisfiability::NotSatisfied);
        assert_eq!(PcodeSign::ZERO.gt(PcodeSign::NEG), Satisfiability::Satisfied);
    }

    #[test]
    fn gt_pos_is_satisfied_neg_is_not_satisfied() {
        assert_eq!(PcodeSign::POS.gt(PcodeSign::ZERO), Satisfiability::Satisfied);
        assert_eq!(PcodeSign::NEG.gt(PcodeSign::ZERO), Satisfiability::NotSatisfied);
    }

    #[test]
    fn satisfies_ternary_expression_is_always_unknown() {
        assert_eq!(PcodeSign::satisfies_ternary_expression(), Satisfiability::Unknown);
    }

    // ── lub_aux / less_or_equal_aux ──────────────────────────────────────────

    #[test]
    fn lub_aux_is_always_top() {
        assert_eq!(PcodeSign::POS.lub_aux(&PcodeSign::NEG), PcodeSign::TOP);
    }

    #[test]
    fn less_or_equal_aux_is_always_false() {
        assert!(!PcodeSign::POS.less_or_equal_aux(&PcodeSign::POS));
    }

    // ── equals / hash ────────────────────────────────────────────────────────

    #[test]
    fn equals_ignores_canonical_flag() {
        assert_eq!(PcodeSign::POS, PcodeSign::with_sign(4));
    }

    // ── get_value ─────────────────────────────────────────────────────────────

    /// A real register value over a 16-byte test register (wide enough for the 128-bit values
    /// below): fully known (`value`) when `has_value`,
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
            16,
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
        let d = PcodeSign::TOP;
        assert_eq!(PcodeNonRelationalValueDomain::get_value(&d, None), Some(PcodeSign::TOP));
    }

    #[test]
    fn get_value_without_a_value_is_top() {
        let d = PcodeSign::TOP;
        let rv = register_value(5, false);
        assert_eq!(
            PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)),
            Some(PcodeSign::TOP)
        );
    }

    #[test]
    fn get_value_of_zero_register_is_value_equal_to_top_not_zero() {
        // Preserved quirk: see PcodeSign::get_value's own docs.
        let d = PcodeSign::TOP;
        let rv = register_value(0, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert_eq!(result, PcodeSign::TOP);
        assert!(result.is_top());
        assert!(!result.is_zero());
    }

    #[test]
    fn get_value_of_positive_register_is_value_equal_to_bottom_not_pos() {
        // Preserved quirk: see PcodeSign::get_value's own docs.
        let d = PcodeSign::TOP;
        let rv = register_value(5, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert_eq!(result, PcodeSign::BOTTOM);
        assert!(result.is_bottom());
        assert!(!result.is_positive());
    }

    #[test]
    fn get_value_truncates_like_javas_biginteger_long_value() {
        // A value whose low 64 bits are all zero (here, exactly 2^64) is treated as zero, even
        // though the true unsigned value is not -- Java's `BigInteger.longValue()` truncation.
        let d = PcodeSign::TOP;
        let rv = register_value(1u128 << 64, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        assert_eq!(result, PcodeSign::TOP);
    }

    #[test]
    fn get_value_truncation_can_read_as_negative() {
        // Low 64 bits all-ones (u64::MAX) reinterpret as -1 when truncated to a signed long.
        let d = PcodeSign::TOP;
        let rv = register_value(u64::MAX as u128, true);
        let result = PcodeNonRelationalValueDomain::get_value(&d, Some(&rv)).unwrap();
        // sign byte -1: matches none of the five named constants.
        assert_ne!(result, PcodeSign::TOP);
        assert_ne!(result, PcodeSign::BOTTOM);
        assert_ne!(result, PcodeSign::ZERO);
        assert_ne!(result, PcodeSign::POS);
        assert_ne!(result, PcodeSign::NEG);
    }

    // ── assume_binary_expression ─────────────────────────────────────────────

    #[derive(Clone, Debug)]
    struct MockExpr {
        id: Option<&'static str>,
        eval_result: PcodeSign,
    }

    impl AsIdentifier<&'static str> for MockExpr {
        fn as_identifier(&self) -> Option<&&'static str> {
            self.id.as_ref()
        }
    }

    impl SignExpression<&'static str, MockEnv, (), ()> for MockExpr {
        fn eval(&self, _environment: &MockEnv, _pp: &(), _oracle: &()) -> PcodeSign {
            self.eval_result
        }
    }

    #[derive(Clone, Debug, Default)]
    struct MockEnv {
        states: HashMap<&'static str, PcodeSign>,
        is_bottom: bool,
    }

    impl SignEnvironment<&'static str> for MockEnv {
        fn get_state(&self, id: &&'static str) -> PcodeSign {
            self.states.get(id).copied().unwrap_or(PcodeSign::TOP)
        }
        fn put_state(mut self, id: &&'static str, value: PcodeSign) -> Self {
            self.states.insert(*id, value);
            self
        }
        fn bottom(&self) -> Self {
            MockEnv { states: self.states.clone(), is_bottom: true }
        }
    }

    fn ident(id: &'static str, eval_result: PcodeSign) -> MockExpr {
        MockExpr { id: Some(id), eval_result }
    }

    fn not_ident(eval_result: PcodeSign) -> MockExpr {
        MockExpr { id: None, eval_result }
    }

    #[test]
    fn assume_binary_expression_eq_updates_to_evaluated_value() {
        let d = PcodeSign::TOP;
        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::POS),
            &(),
            &(),
        );
        assert_eq!(result.states.get("x"), Some(&PcodeSign::POS));
    }

    #[test]
    fn assume_binary_expression_le_right_is_expr_and_negative_updates() {
        // x <= expr, expr evaluates to NEG -> update NEG.
        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonLe,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::NEG),
            &(),
            &(),
        );
        assert_eq!(result.states.get("x"), Some(&PcodeSign::NEG));
    }

    #[test]
    fn assume_binary_expression_le_right_is_expr_and_positive_no_update() {
        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonLe,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::POS),
            &(),
            &(),
        );
        assert_eq!(result.states, env.states);
    }

    #[test]
    fn assume_binary_expression_lt_forces_neg_or_pos() {
        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let d = PcodeSign::TOP;
        // x < expr, expr is ZERO -> update NEG (x < 0).
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonLt,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::ZERO),
            &(),
            &(),
        );
        assert_eq!(result.states.get("x"), Some(&PcodeSign::NEG));

        // expr < x, expr is ZERO -> update POS (0 < x).
        let result2 = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonLt,
            &not_ident(PcodeSign::ZERO),
            &ident("x", PcodeSign::TOP),
            &(),
            &(),
        );
        assert_eq!(result2.states.get("x"), Some(&PcodeSign::POS));
    }

    #[test]
    fn assume_binary_expression_pcode_operator_guard_blocks_update() {
        use crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator;
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{PcodeOp, SequenceNumber};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        let op = PcodeOp::new(OpCode::IntAdd, seq, vec![], None);

        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::Other(PcodeBinaryOperator::new(op)),
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::POS),
            &(),
            &(),
        );
        assert_eq!(result.states, env.states);
    }

    #[test]
    fn assume_binary_expression_bottom_starting_state_yields_bottom() {
        let env = MockEnv::default().put_state(&"x", PcodeSign::BOTTOM);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::POS),
            &(),
            &(),
        );
        assert!(result.is_bottom);
    }

    #[test]
    fn assume_binary_expression_bottom_eval_yields_bottom() {
        let env = MockEnv::default().put_state(&"x", PcodeSign::TOP);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x", PcodeSign::TOP),
            &not_ident(PcodeSign::BOTTOM),
            &(),
            &(),
        );
        assert!(result.is_bottom);
    }

    #[test]
    fn assume_binary_expression_neither_side_identifier_passes_through() {
        let env = MockEnv::default().put_state(&"z", PcodeSign::POS);
        let d = PcodeSign::TOP;
        let result = d.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &not_ident(PcodeSign::TOP),
            &not_ident(PcodeSign::TOP),
            &(),
            &(),
        );
        assert_eq!(result.states, env.states);
    }
}
