//! Port of `ghidra.lisa.pcode.types.PcodeStaticTypes`.
//!
//! A sibling of [`PcodeInferredTypes`](super::pcode_inferred_types::PcodeInferredTypes) built on
//! the same [`PcodeTypeContext`](super::pcode_inferred_types::PcodeTypeContext) seam (see that
//! module's own docs for the overall "no Rust port of the LiSA framework exists" strategy this
//! reuses). Where `PcodeInferredTypes` tracks a *set* of possible types per program point,
//! `PcodeStaticTypes` tracks a single `Type` -- Java's `evalIdentifier` falls back to
//! `id.getStaticType()` rather than `allInstances`, and `satisfiesBinaryExpression` delegates
//! entirely to a fresh `PcodeInferredTypes` built from this value's `allInstances` set (ported
//! here as a direct call into [`PcodeInferredTypes::satisfies_binary_expression`], reusing that
//! already-tested logic rather than duplicating it).
//!
//! # Extending `PcodeTypeContext`
//!
//! `PcodeStaticTypes::eval` (the top-level `BaseNonRelationalTypeDomain.eval` override, not one
//! of the six standard `eval*` callbacks) needs to recursively evaluate `ValueExpression`
//! operands and special-case Ghidra's own `PcodeOp.CAST` opcode -- capabilities
//! `PcodeTypeContext` doesn't expose (nothing in `PcodeInferredTypes`'s own body needs them).
//! Rather than growing the shared trait with methods only this sibling calls, this module defines
//! [`PcodeStaticTypeContext`]: a subtrait adding exactly those extra operations, matching this
//! crate's "narrow seams, only what's actually called" convention.
//!
//! # Dropped Java exception path: `ClassCastException` on `evalIdentifier`'s recursive casts
//!
//! Java's `eval(ValueExpression, ...)` casts `binary.getLeft()`/`binary.getRight()` (statically
//! typed `Expression`, a `ValueExpression` supertype) down to `ValueExpression`, wrapped in a
//! `try`/`catch (ClassCastException e) { throw new SemanticException(...); }`. Every real p-code
//! expression tree built by this package's frontend is composed entirely of `ValueExpression`s,
//! so the cast can never actually fail in practice. This port folds `Expression` and
//! `ValueExpression` into one associated type ([`PcodeStaticTypeContext::Expression`]), dropping
//! the unreachable failure path -- the same reasoning `PcodeInferredTypes`'s own module docs give
//! for several other `null`/cast edge cases that have no real caller.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use super::pcode_inferred_types::{PcodeInferredTypes, PcodeTypeContext};
use crate::feature::lisa::pcode::analyses::satisfiability::Satisfiability;
use crate::program::model::pcode::OpCode;

/// Extends [`PcodeTypeContext`] with the extra LiSA operations
/// [`PcodeStaticTypes::eval`]/[`PcodeStaticTypes::lub_aux`]/[`PcodeStaticTypes::less_or_equal_aux`]
/// need, beyond what `PcodeInferredTypes` already requires. See the module docs for why these
/// live on a separate subtrait rather than growing [`PcodeTypeContext`] itself.
pub trait PcodeStaticTypeContext: PcodeTypeContext {
    /// `it.unive.lisa.program.cfg.statement.Expression`, standing in for `eval`'s
    /// `ValueExpression` parameter and its recursively-evaluated left/right operands. See the
    /// module docs for why the Java `(ValueExpression) binary.getLeft()` cast collapses to a
    /// direct `Self::Expression` here.
    type Expression;

    /// The `Untyped.INSTANCE` singleton. Mirrors the no-arg constructor's `this(null,
    /// Untyped.INSTANCE)` and [`PcodeStaticTypes::top`]'s `new PcodeStaticTypes(types,
    /// Untyped.INSTANCE)`.
    fn untyped_type() -> Self::Type;

    /// Fused `expression instanceof BinaryExpression` + the successful cast, mirroring this
    /// crate's established "as_x" fusion pattern. `None` when `expression` is not a
    /// `BinaryExpression`.
    fn expression_as_binary(expression: &Self::Expression) -> Option<&Self::BinaryExpression>;

    /// `binaryExpression.getLeft()`, narrowed straight to [`Self::Expression`] (see that type's
    /// own docs for why the Java `ValueExpression` cast is dropped).
    fn binary_expression_left(expr: &Self::BinaryExpression) -> &Self::Expression;

    /// `binaryExpression.getRight()`, as [`Self::binary_expression_left`].
    fn binary_expression_right(expr: &Self::BinaryExpression) -> &Self::Expression;

    /// Fused `binaryOperator instanceof PcodeBinaryOperator` + `.getOp().getOpcode()`, reusing
    /// the already-ported [`OpCode`] directly (matching how `PcodeInferredTypes` reuses
    /// [`PcodeLocation`](crate::feature::lisa::pcode::locations::PcodeLocation)/`Satisfiability`
    /// directly rather than re-abstracting them). `None` when `operator` is not a
    /// `PcodeBinaryOperator`.
    fn binary_operator_pcode_opcode(operator: &Self::BinaryOperator) -> Option<OpCode>;

    /// `Expression.getStaticType()`.
    fn expression_static_type(expression: &Self::Expression) -> Self::Type;

    /// `Type.commonSupertype(Set<Type>, Type)`, used by `eval`'s `CAST` branch.
    fn type_common_supertype_of_set(elements: &HashSet<Self::Type>, default: Self::Type) -> Self::Type;

    /// `Type.commonSupertype(Type)` (the two-`Type` instance-method overload), used by
    /// [`PcodeStaticTypes::lub_aux`].
    fn type_common_supertype_pairwise(a: &Self::Type, b: &Self::Type) -> Self::Type;

    /// `Type.canBeAssignedTo(Type)`, used by [`PcodeStaticTypes::less_or_equal_aux`].
    fn type_can_be_assigned_to(a: &Self::Type, b: &Self::Type) -> bool;

    /// Stands in for `BaseNonRelationalTypeDomain.super.evalIdentifier(id, environment, pp,
    /// oracle)` specialized to `PcodeStaticTypes` (a *different* instantiation of the same LiSA
    /// default method than [`PcodeTypeContext::default_eval_identifier`], which is specialized to
    /// `PcodeInferredTypes` instead -- Java's `BaseNonRelationalTypeDomain<T>` is generic in the
    /// concrete domain `T`, so each sibling needs its own seam). See
    /// [`PcodeTypeContext::default_eval_identifier`]'s own docs for why this is modeled as a
    /// required seam rather than a fabricated implementation.
    fn default_eval_identifier_static(
        id: &Self::Identifier,
        environment: &Self::TypeEnvironment,
        pp: &Self::ProgramPoint,
        oracle: &Self::Oracle,
    ) -> PcodeStaticTypes<Self>
    where
        Self: Sized;
}

/// An `InferredValue` holding a single `Type`, representing the statically-declared type of an
/// `Expression`.
///
/// Port of `ghidra.lisa.pcode.types.PcodeStaticTypes`. See the module docs for the overall port
/// strategy and its relationship to
/// [`PcodeInferredTypes`](super::pcode_inferred_types::PcodeInferredTypes).
pub struct PcodeStaticTypes<C: PcodeStaticTypeContext> {
    /// Java: `private final Type type`. `None` mirrors Java's `null` -- the `BOTTOM` singleton's
    /// state (`new PcodeStaticTypes(null, null)`).
    type_: Option<C::Type>,
    /// Java: `private final TypeSystem types`. `None` mirrors Java's `null`, as `type_` above.
    types: Option<C::TypeSystem>,
}

impl<C: PcodeStaticTypeContext> Clone for PcodeStaticTypes<C>
where
    C::Type: Clone,
    C::TypeSystem: Clone,
{
    fn clone(&self) -> Self {
        PcodeStaticTypes { type_: self.type_.clone(), types: self.types.clone() }
    }
}

impl<C: PcodeStaticTypeContext> std::fmt::Debug for PcodeStaticTypes<C> {
    /// Java's `equals`/`hashCode` only ever consult `type` (see [`PartialEq`]/[`Hash`] below);
    /// this mirrors that by omitting `types` (which, unlike `Type`, carries no `Debug` bound on
    /// [`PcodeTypeContext`]) from the debug representation too.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcodeStaticTypes").field("type", &self.type_).finish()
    }
}

impl<C: PcodeStaticTypeContext> PartialEq for PcodeStaticTypes<C> {
    /// Port of `equals(Object)`. Compares `type` only -- Java's `equals` never inspects `types`
    /// at all, a real (if perhaps unintentional) asymmetry versus
    /// [`PcodeInferredTypes`](super::pcode_inferred_types::PcodeInferredTypes)'s own `equals`,
    /// preserved faithfully here rather than "fixed" to also compare `types`.
    fn eq(&self, other: &Self) -> bool {
        self.type_ == other.type_
    }
}

impl<C: PcodeStaticTypeContext> Eq for PcodeStaticTypes<C> {}

impl<C: PcodeStaticTypeContext> Hash for PcodeStaticTypes<C> {
    /// Port of `hashCode()`: `31 * 1 + (type == null ? 0 : type.hashCode())`, i.e. `type` only.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.type_.hash(state);
    }
}

impl<C: PcodeStaticTypeContext> PcodeStaticTypes<C> {
    /// Builds the inferred types. The object built through this constructor represents an empty
    /// set of types.
    ///
    /// Port of the no-arg `PcodeStaticTypes()`, which delegates to `this(null,
    /// Untyped.INSTANCE)`.
    pub fn new() -> Self {
        PcodeStaticTypes { type_: Some(C::untyped_type()), types: None }
    }

    /// Builds the inferred types, representing only the given `Type`.
    ///
    /// Port of the package-private `PcodeStaticTypes(TypeSystem, Type)` constructor: a direct
    /// field assignment with no derived `isTop` bookkeeping (unlike
    /// [`PcodeInferredTypes::of_types`](super::pcode_inferred_types::PcodeInferredTypes::of_types),
    /// this class has no `isTop` field at all -- [`Self::is_top`] is computed from `type` alone).
    pub fn of(types: C::TypeSystem, type_: C::Type) -> Self {
        PcodeStaticTypes { type_: Some(type_), types: Some(types) }
    }

    /// Builds the inferred types directly from optional `types`/`type` fields. Exposed primarily
    /// for constructing the bottom value and for tests.
    pub fn raw(types: Option<C::TypeSystem>, type_: Option<C::Type>) -> Self {
        PcodeStaticTypes { types, type_ }
    }

    /// The `BOTTOM` singleton's state: `new PcodeStaticTypes(null, null)`.
    fn bottom_value() -> Self {
        Self::raw(None, None)
    }

    /// Returns the runtime types this element represents.
    ///
    /// Port of `getRuntimeTypes()`.
    ///
    /// # Preserved bug: unconditional `type.allInstances(types)` on `BOTTOM`
    /// Java's body is:
    /// ```java
    /// public Set<Type> getRuntimeTypes() {
    ///     if (this.isBottom())
    ///         Collections.emptySet();
    ///     return type.allInstances(types);
    /// }
    /// ```
    /// which, like `PcodeInferredTypes.getRuntimeTypes()`, is missing a `return` before
    /// `Collections.emptySet()` -- but *unlike* that sibling's version of the bug (which is
    /// unreachable in practice, per its own module docs), this one genuinely bites here: `BOTTOM`
    /// itself has `type == null`, so calling this on the bottom value reaches `type
    /// .allInstances(types)` with a `null` receiver and throws `NullPointerException` for real.
    /// This port panics the same way rather than returning an empty set.
    ///
    /// # Panics
    /// If `self` is (or was built like) `BOTTOM`, i.e. `type` is `None` -- mirroring the real
    /// Java `NullPointerException`.
    pub fn get_runtime_types(&self) -> HashSet<C::Type> {
        let ty = self.type_.as_ref().expect(
            "NullPointerException: type is null (mirrors Java's getRuntimeTypes() dead \
             `if (isBottom())` branch reaching `type.allInstances(types)` unconditionally, which \
             is reachable here because BOTTOM itself has a null `type`)",
        );
        let types = self
            .types
            .as_ref()
            .expect("NullPointerException: types is null (BOTTOM's `types` field is also null)");
        C::type_all_instances(ty, types)
    }

    /// Port of `top()`: `new PcodeStaticTypes(types, Untyped.INSTANCE)`, preserving `self.types`
    /// (the *current* type system), not re-deriving it.
    pub fn top(&self) -> Self
    where
        C::TypeSystem: Clone,
    {
        PcodeStaticTypes { type_: Some(C::untyped_type()), types: self.types.clone() }
    }

    /// Port of `isTop()`: `type == Untyped.INSTANCE` (Java reference identity against the
    /// singleton). Ported via [`PcodeTypeContext::type_is_untyped`], under the assumption
    /// (matching every other real `Type` in the LiSA framework) that only the `Untyped` singleton
    /// itself reports `isUntyped() == true` -- the same predicate
    /// [`PcodeInferredTypes::eval_push_any`](super::pcode_inferred_types::PcodeInferredTypes::eval_push_any)
    /// already relies on for an equivalent purpose.
    pub fn is_top(&self) -> bool {
        self.type_.as_ref().is_some_and(|t| C::type_is_untyped(t))
    }

    /// Port of `bottom()`.
    pub fn bottom(&self) -> Self {
        Self::bottom_value()
    }

    /// Port of `isBottom()`. Java does **not** override `isBottom()` on this class at all, so it
    /// falls to the standard LiSA `Lattice.isBottom()` default, `equals(bottom())` -- which,
    /// since [`PartialEq`] above only compares `type`, reduces to exactly `self.type_.is_none()`
    /// (`BOTTOM.type` is `None`).
    pub fn is_bottom(&self) -> bool {
        self.type_.is_none()
    }

    /// Port of `representation()`.
    pub fn representation(&self) -> PcodeStaticTypesRepresentation<C::Type> {
        if self.is_top() {
            return PcodeStaticTypesRepresentation::Top;
        }
        if self.is_bottom() {
            return PcodeStaticTypesRepresentation::Bottom;
        }
        PcodeStaticTypesRepresentation::Single(self.type_.clone().unwrap())
    }

    /// Port of `toString()`: `representation().toString()`.
    pub fn to_display_string(&self) -> String
    where
        C::Type: Clone,
    {
        self.representation().to_string()
    }

    /// Port of `evalIdentifier(Identifier, TypeEnvironment<PcodeStaticTypes>, ProgramPoint,
    /// SemanticOracle)`.
    pub fn eval_identifier(
        &self,
        id: &C::Identifier,
        environment: &C::TypeEnvironment,
        pp: &C::ProgramPoint,
        oracle: &C::Oracle,
    ) -> Self {
        let eval = C::default_eval_identifier_static(id, environment, pp, oracle);
        if !eval.is_top() && !eval.is_bottom() {
            return eval;
        }
        let types = C::program_point_types(pp);
        let static_type = C::identifier_static_type(id);
        Self::of(types, static_type)
    }

    /// Port of `evalPushAny(PushAny, ProgramPoint, SemanticOracle)`.
    pub fn eval_push_any(&self, push_any: &C::PushAny, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        let static_type = C::push_any_static_type(push_any);
        Self::of(types, static_type)
    }

    /// Port of `evalPushInv(PushInv, ProgramPoint, SemanticOracle)`. Unlike
    /// [`PcodeInferredTypes::eval_push_inv`](super::pcode_inferred_types::PcodeInferredTypes::eval_push_inv)
    /// (which ignores its `PushInv` argument entirely and always returns `bottom()`), this
    /// sibling genuinely uses `pushInv.getStaticType()` -- a real difference between the two
    /// classes' Java sources, not an oversight.
    pub fn eval_push_inv(&self, push_inv: &C::PushInv, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self
    where
        C::PushInv: PushInvStaticType<C>,
    {
        let types = C::program_point_types(pp);
        let static_type = push_inv.static_type();
        Self::of(types, static_type)
    }

    /// Port of `evalNullConstant(ProgramPoint, SemanticOracle)`.
    pub fn eval_null_constant(&self, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        Self::of(types, C::null_type())
    }

    /// Port of `evalNonNullConstant(Constant, ProgramPoint, SemanticOracle)`.
    pub fn eval_non_null_constant(&self, constant: &C::Constant, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        let static_type = C::constant_static_type(constant);
        Self::of(types, static_type)
    }

    /// Port of `eval(ValueExpression, TypeEnvironment<PcodeStaticTypes>, ProgramPoint,
    /// SemanticOracle)`.
    ///
    /// # Dropped Java exception path
    /// See the module docs for why the `ClassCastException`-guarded recursive casts to
    /// `ValueExpression` have no Rust counterpart here (this method cannot fail, unlike Java's
    /// `throws SemanticException`).
    pub fn eval(
        &self,
        expression: &C::Expression,
        environment: &C::TypeEnvironment,
        pp: &C::ProgramPoint,
        oracle: &C::Oracle,
    ) -> Self {
        if let Some(binary) = C::expression_as_binary(expression) {
            let operator = C::binary_expression_operator(binary);
            if let Some(opcode) = C::binary_operator_pcode_opcode(&operator) {
                if opcode == OpCode::Cast {
                    let etypes = C::program_point_types(pp);
                    let left = self.eval(C::binary_expression_left(binary), environment, pp, oracle);
                    let right = self.eval(C::binary_expression_right(binary), environment, pp, oracle);

                    let lelems = C::type_all_instances(left.type_.as_ref().unwrap(), &etypes);
                    let relems = C::type_all_instances(right.type_.as_ref().unwrap(), &etypes);
                    let inferred = C::binary_type_inference(&operator, &etypes, &lelems, &relems);
                    if inferred.is_empty() {
                        return Self::bottom_value();
                    }
                    let types = C::program_point_types(pp);
                    let common = C::type_common_supertype_of_set(&inferred, C::untyped_type());
                    return Self::of(types, common);
                }
            }
        }

        let types = C::program_point_types(pp);
        let static_type = C::expression_static_type(expression);
        Self::of(types, static_type)
    }

    /// Port of `satisfiesBinaryExpression(BinaryOperator, PcodeStaticTypes, PcodeStaticTypes,
    /// ProgramPoint, SemanticOracle)`. Delegates entirely to
    /// [`PcodeInferredTypes::satisfies_binary_expression`](super::pcode_inferred_types::PcodeInferredTypes::satisfies_binary_expression),
    /// exactly as Java's implementation does (`new PcodeInferredTypes().satisfiesBinaryExpression(...)`).
    pub fn satisfies_binary_expression(
        &self,
        operator: &C::BinaryOperator,
        left: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        oracle: &C::Oracle,
    ) -> Satisfiability {
        let stypes = C::program_point_types(pp);
        let lelems = C::type_all_instances(left.type_.as_ref().unwrap(), &stypes);
        let relems = C::type_all_instances(right.type_.as_ref().unwrap(), &stypes);

        let base = PcodeInferredTypes::<C>::new();
        base.satisfies_binary_expression(
            operator,
            &PcodeInferredTypes::of_types(&stypes, lelems),
            &PcodeInferredTypes::of_types(&stypes, relems),
            pp,
            oracle,
        )
    }

    /// Port of `lubAux(PcodeStaticTypes)`: `new PcodeStaticTypes(types, type.commonSupertype(other.type))`,
    /// preserving `self.types` as-is (not re-derived from either operand).
    pub fn lub_aux(&self, other: &Self) -> Self
    where
        C::TypeSystem: Clone,
    {
        let common = C::type_common_supertype_pairwise(
            self.type_.as_ref().unwrap(),
            other.type_.as_ref().unwrap(),
        );
        PcodeStaticTypes { type_: Some(common), types: self.types.clone() }
    }

    /// Port of `lessOrEqualAux(PcodeStaticTypes)`: `type.canBeAssignedTo(other.type)`.
    pub fn less_or_equal_aux(&self, other: &Self) -> bool {
        C::type_can_be_assigned_to(self.type_.as_ref().unwrap(), other.type_.as_ref().unwrap())
    }
}

/// Seam for `PushInv.getStaticType()`, needed only by
/// [`PcodeStaticTypes::eval_push_inv`] -- kept separate from [`PcodeStaticTypeContext`] since
/// it operates on `C::PushInv` itself (an owned-by-the-caller value) rather than being a
/// `C`-indexed static operation, mirroring how this crate models small single-method "as
/// implemented by the type itself" seams elsewhere.
pub trait PushInvStaticType<C: PcodeTypeContext> {
    /// `PushInv.getStaticType()`.
    fn static_type(&self) -> C::Type;
}

impl<C: PcodeStaticTypeContext> Default for PcodeStaticTypes<C> {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of [`PcodeStaticTypes::representation`]. As
/// [`PcodeInferredTypesRepresentation`](super::pcode_inferred_types::PcodeInferredTypesRepresentation),
/// but the non-top/non-bottom case wraps a single `Type` (`StringRepresentation`) rather than a
/// set.
#[derive(Debug, Clone, PartialEq)]
pub enum PcodeStaticTypesRepresentation<T> {
    /// `Lattice.topRepresentation()`.
    Top,
    /// `Lattice.bottomRepresentation()`.
    Bottom,
    /// `new StringRepresentation(type.toString())`.
    Single(T),
}

impl<T: std::fmt::Debug> std::fmt::Display for PcodeStaticTypesRepresentation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcodeStaticTypesRepresentation::Top => write!(f, "#TOP#"),
            PcodeStaticTypesRepresentation::Bottom => write!(f, "_|_"),
            PcodeStaticTypesRepresentation::Single(item) => write!(f, "{item:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, closed test `Type`, mirroring `PcodeInferredTypes`'s own test harness (`TType`)
    /// but extended with a distinguished `Untyped` marker used for `top()`/`isTop()`.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum TType {
        A,
        B,
        Null,
        Untyped,
    }

    #[derive(Clone, Debug)]
    struct TTypeSystem {
        all: HashSet<TType>,
    }

    struct TId(TType);
    struct TConst(TType);
    struct TPushAny(TType);
    struct TPushInv(TType);
    struct TEnv;
    struct TOracle;
    struct TProgramPoint;

    impl PushInvStaticType<TestContext> for TPushInv {
        fn static_type(&self) -> TType {
            self.0.clone()
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TBinaryOp {
        Union,
        ToBottom,
        /// Mirrors a genuine `PcodeOp.CAST`-opcode `PcodeBinaryOperator`: `typeInference` behaves
        /// like `Union`, but `binary_operator_pcode_opcode` reports it as `OpCode::Cast`, so
        /// `eval` routes it through the CAST branch.
        Cast,
        /// As `Cast`, but `typeInference` always returns an empty set -- exercises `eval`'s CAST
        /// branch's "empty inference is bottom" path.
        CastEmpty,
    }

    /// A leaf value expression, or a binary expression over two more `TExpr`s. Mirrors the LiSA
    /// `Expression`/`BinaryExpression` distinction `eval`'s `expression_as_binary` downcast needs
    /// to actually exercise the CAST branch in tests.
    enum TExpr {
        Leaf(TType),
        Binary(Box<TBinaryExpr>),
    }

    struct TBinaryExpr {
        left: TExpr,
        right: TExpr,
        operator: TBinaryOp,
    }

    struct TestContext;

    impl PcodeTypeContext for TestContext {
        type Type = TType;
        type TypeSystem = TTypeSystem;
        type ProgramPoint = TProgramPoint;
        type Oracle = TOracle;
        type Identifier = TId;
        type Constant = TConst;
        type PushAny = TPushAny;
        type PushInv = TPushInv;
        type TypeEnvironment = TEnv;
        type UnaryOperator = ();
        type BinaryOperator = TBinaryOp;
        type TernaryOperator = ();
        type BinaryExpression = TBinaryExpr;

        fn type_is_type_token_type(_ty: &Self::Type) -> bool {
            false
        }
        fn type_token_types(_ty: &Self::Type) -> HashSet<Self::Type> {
            HashSet::new()
        }
        fn type_is_untyped(ty: &Self::Type) -> bool {
            matches!(ty, TType::Untyped)
        }
        fn type_all_instances(ty: &Self::Type, types: &Self::TypeSystem) -> HashSet<Self::Type> {
            if matches!(ty, TType::Untyped) {
                types.all.clone()
            } else {
                let mut s = HashSet::new();
                s.insert(ty.clone());
                s
            }
        }
        fn null_type() -> Self::Type {
            TType::Null
        }
        fn type_system_get_types(types: &Self::TypeSystem) -> HashSet<Self::Type> {
            types.all.clone()
        }
        fn type_system_cast(
            _types: &Self::TypeSystem,
            from: &HashSet<Self::Type>,
            _to: &HashSet<Self::Type>,
            _might_fail: &mut bool,
        ) -> HashSet<Self::Type> {
            from.clone()
        }
        fn program_point_types(_pp: &Self::ProgramPoint) -> Self::TypeSystem {
            all_types_system()
        }
        fn program_point_location(_pp: &Self::ProgramPoint) -> Option<&crate::feature::lisa::pcode::locations::PcodeLocation> {
            None
        }
        fn identifier_static_type(id: &Self::Identifier) -> Self::Type {
            id.0.clone()
        }
        fn constant_static_type(constant: &Self::Constant) -> Self::Type {
            constant.0.clone()
        }
        fn push_any_static_type(push_any: &Self::PushAny) -> Self::Type {
            push_any.0.clone()
        }
        fn unary_type_inference(
            _op: &Self::UnaryOperator,
            _types: &Self::TypeSystem,
            arg: &HashSet<Self::Type>,
        ) -> HashSet<Self::Type> {
            arg.clone()
        }
        fn binary_type_inference(
            op: &Self::BinaryOperator,
            _types: &Self::TypeSystem,
            left: &HashSet<Self::Type>,
            right: &HashSet<Self::Type>,
        ) -> HashSet<Self::Type> {
            match op {
                TBinaryOp::Union => left.union(right).cloned().collect(),
                TBinaryOp::ToBottom => HashSet::new(),
                TBinaryOp::Cast => left.union(right).cloned().collect(),
                TBinaryOp::CastEmpty => HashSet::new(),
            }
        }
        fn ternary_type_inference(
            _op: &Self::TernaryOperator,
            _types: &Self::TypeSystem,
            left: &HashSet<Self::Type>,
            _middle: &HashSet<Self::Type>,
            _right: &HashSet<Self::Type>,
        ) -> HashSet<Self::Type> {
            left.clone()
        }
        fn type_cast_operator() -> Self::BinaryOperator {
            TBinaryOp::Cast
        }
        fn binary_expression_operator(expr: &Self::BinaryExpression) -> Self::BinaryOperator {
            expr.operator
        }
        fn default_eval_identifier(
            _id: &Self::Identifier,
            _environment: &Self::TypeEnvironment,
            _pp: &Self::ProgramPoint,
            _oracle: &Self::Oracle,
        ) -> PcodeInferredTypes<Self> {
            PcodeInferredTypes::raw(true, None)
        }
    }

    impl PcodeStaticTypeContext for TestContext {
        type Expression = TExpr;

        fn untyped_type() -> Self::Type {
            TType::Untyped
        }

        fn expression_as_binary(expression: &Self::Expression) -> Option<&Self::BinaryExpression> {
            match expression {
                TExpr::Binary(b) => Some(b),
                TExpr::Leaf(_) => None,
            }
        }

        fn binary_expression_left(expr: &Self::BinaryExpression) -> &Self::Expression {
            &expr.left
        }

        fn binary_expression_right(expr: &Self::BinaryExpression) -> &Self::Expression {
            &expr.right
        }

        fn binary_operator_pcode_opcode(operator: &Self::BinaryOperator) -> Option<OpCode> {
            match operator {
                TBinaryOp::Cast | TBinaryOp::CastEmpty => Some(OpCode::Cast),
                TBinaryOp::Union | TBinaryOp::ToBottom => None,
            }
        }

        fn expression_static_type(expression: &Self::Expression) -> Self::Type {
            match expression {
                TExpr::Leaf(t) => t.clone(),
                // Not exercised by any real test path (a Binary expression whose operator isn't
                // recognized as a CAST opcode still falls through to here, per `eval`'s Java
                // structure), but must be total.
                TExpr::Binary(_) => TType::Untyped,
            }
        }

        fn type_common_supertype_of_set(_elements: &HashSet<Self::Type>, default: Self::Type) -> Self::Type {
            default
        }

        fn type_common_supertype_pairwise(a: &Self::Type, b: &Self::Type) -> Self::Type {
            if a == b { a.clone() } else { TType::Untyped }
        }

        fn type_can_be_assigned_to(a: &Self::Type, b: &Self::Type) -> bool {
            a == b || matches!(b, TType::Untyped)
        }

        fn default_eval_identifier_static(
            _id: &Self::Identifier,
            _environment: &Self::TypeEnvironment,
            _pp: &Self::ProgramPoint,
            _oracle: &Self::Oracle,
        ) -> PcodeStaticTypes<Self> {
            // Test double for the unported LiSA default: always reports "unknown" (top), so
            // eval_identifier always falls into its getStaticType fallback path -- matching real
            // observable behavior whenever the environment doesn't already track `id`.
            PcodeStaticTypes::raw(None, Some(TType::Untyped))
        }
    }

    type Types = PcodeStaticTypes<TestContext>;

    fn all_types_system() -> TTypeSystem {
        let mut all = HashSet::new();
        all.insert(TType::A);
        all.insert(TType::B);
        all.insert(TType::Null);
        TTypeSystem { all }
    }

    // ── construction ──────────────────────────────────────────────────────

    #[test]
    fn new_is_untyped_and_reports_top() {
        let t = Types::new();
        assert!(t.is_top());
        assert!(!t.is_bottom());
    }

    #[test]
    fn of_wraps_a_single_type_and_is_not_top() {
        let ts = all_types_system();
        let t = Types::of(ts, TType::A);
        assert!(!t.is_top());
        assert!(!t.is_bottom());
    }

    #[test]
    fn top_preserves_the_current_type_system() {
        let ts = all_types_system();
        let t = Types::of(ts, TType::A);
        let top = t.top();
        assert!(top.is_top());
        // top() keeps `self.types`, so runtime types still resolve against the full set.
        assert_eq!(top.get_runtime_types(), all_types_system().all);
    }

    #[test]
    fn bottom_is_not_top_and_reports_bottom() {
        let t = Types::new().bottom();
        assert!(t.is_bottom());
        assert!(!t.is_top());
    }

    // ── preserved bug: getRuntimeTypes on BOTTOM panics ──────────────────

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn get_runtime_types_on_bottom_panics_like_javas_npe() {
        // Faithful reproduction: Java's missing `return` before `Collections.emptySet()` in the
        // dead `if (isBottom())` branch means `BOTTOM.getRuntimeTypes()` reaches
        // `type.allInstances(types)` with `type == null`, throwing NullPointerException for real
        // (unlike the sibling PcodeInferredTypes bug, which has no reachable caller).
        let t = Types::new().bottom();
        t.get_runtime_types();
    }

    #[test]
    fn get_runtime_types_for_a_real_type_resolves_all_instances() {
        let ts = all_types_system();
        let t = Types::of(ts, TType::A);
        assert_eq!(t.get_runtime_types(), {
            let mut s = HashSet::new();
            s.insert(TType::A);
            s
        });
    }

    // ── isTop / isBottom ──────────────────────────────────────────────────

    #[test]
    fn is_top_is_identity_against_untyped_not_equality_of_contents() {
        assert!(Types::raw(None, Some(TType::Untyped)).is_top());
        assert!(!Types::raw(None, Some(TType::A)).is_top());
        assert!(!Types::raw(None, None).is_top());
    }

    #[test]
    fn is_bottom_is_true_only_when_type_is_none() {
        assert!(Types::raw(None, None).is_bottom());
        assert!(!Types::raw(None, Some(TType::A)).is_bottom());
        assert!(!Types::raw(None, Some(TType::Untyped)).is_bottom());
    }

    // ── representation / display ──────────────────────────────────────────

    #[test]
    fn representation_distinguishes_top_bottom_and_single() {
        assert_eq!(Types::new().representation(), PcodeStaticTypesRepresentation::Top);
        assert_eq!(Types::new().bottom().representation(), PcodeStaticTypesRepresentation::Bottom);
        let ts = all_types_system();
        assert_eq!(Types::of(ts, TType::A).representation(), PcodeStaticTypesRepresentation::Single(TType::A));
    }

    #[test]
    fn to_display_string_renders_each_shape() {
        assert_eq!(Types::new().to_display_string(), "#TOP#");
        assert_eq!(Types::new().bottom().to_display_string(), "_|_");
        let ts = all_types_system();
        assert_eq!(Types::of(ts, TType::A).to_display_string(), "A");
    }

    // ── evalIdentifier ────────────────────────────────────────────────────

    #[test]
    fn eval_identifier_falls_back_to_static_type_when_default_is_top() {
        let id = TId(TType::A);
        let t = Types::new();
        let result = t.eval_identifier(&id, &TEnv, &TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::A));
    }

    // ── evalPushAny / evalPushInv ─────────────────────────────────────────

    #[test]
    fn eval_push_any_always_uses_the_static_type_directly() {
        // Unlike PcodeInferredTypes::eval_push_any, this sibling has no "untyped -> full type
        // set" special case: it always wraps the static type as-is.
        let push_any = TPushAny(TType::A);
        let t = Types::new();
        let result = t.eval_push_any(&push_any, &TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::A));
    }

    #[test]
    fn eval_push_inv_uses_the_argument_unlike_the_inferred_types_sibling() {
        let push_inv = TPushInv(TType::B);
        let t = Types::new();
        let result = t.eval_push_inv(&push_inv, &TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::B));
    }

    // ── evalNullConstant / evalNonNullConstant ───────────────────────────

    #[test]
    fn eval_null_constant_is_the_null_type() {
        let t = Types::new();
        let result = t.eval_null_constant(&TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::Null));
    }

    #[test]
    fn eval_non_null_constant_is_the_constants_static_type() {
        let t = Types::new();
        let result = t.eval_non_null_constant(&TConst(TType::B), &TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::B));
    }

    // ── eval (top-level dispatcher) ───────────────────────────────────────

    #[test]
    fn eval_of_a_non_binary_expression_uses_its_static_type() {
        let t = Types::new();
        let result = t.eval(&TExpr::Leaf(TType::A), &TEnv, &TProgramPoint, &TOracle);
        assert_eq!(result, Types::of(all_types_system(), TType::A));
    }

    #[test]
    fn eval_of_a_binary_expression_whose_operator_is_not_a_cast_opcode_uses_static_type() {
        // Java: `eval` only special-cases BinaryExpressions wrapping a `PcodeBinaryOperator`
        // whose opcode is `PcodeOp.CAST`; every other BinaryExpression (including one wrapping a
        // *different* PcodeBinaryOperator) falls through to the generic
        // `expression.getStaticType()` path at the bottom of the method.
        let t = Types::new();
        let binary = TExpr::Binary(Box::new(TBinaryExpr {
            left: TExpr::Leaf(TType::A),
            right: TExpr::Leaf(TType::B),
            operator: TBinaryOp::Union,
        }));
        let result = t.eval(&binary, &TEnv, &TProgramPoint, &TOracle);
        // TestContext::expression_static_type for a Binary expression that isn't routed through
        // the CAST branch returns Untyped.
        assert!(result.is_top());
    }

    #[test]
    fn eval_cast_empty_inference_is_bottom() {
        let t = Types::new();
        let binary = TExpr::Binary(Box::new(TBinaryExpr {
            left: TExpr::Leaf(TType::A),
            right: TExpr::Leaf(TType::B),
            operator: TBinaryOp::CastEmpty,
        }));
        let result = t.eval(&binary, &TEnv, &TProgramPoint, &TOracle);
        assert!(result.is_bottom());
    }

    #[test]
    fn eval_cast_non_empty_inference_wraps_the_common_supertype() {
        let t = Types::new();
        let binary = TExpr::Binary(Box::new(TBinaryExpr {
            left: TExpr::Leaf(TType::A),
            right: TExpr::Leaf(TType::B),
            operator: TBinaryOp::Cast,
        }));
        let result = t.eval(&binary, &TEnv, &TProgramPoint, &TOracle);
        // TestContext::type_common_supertype_of_set always returns the provided default
        // (Untyped) in this harness, regardless of the (non-empty) inferred set -- so the CAST
        // branch's success path always yields a top value here.
        assert!(result.is_top());
        assert!(!result.is_bottom());
    }

    // ── satisfiesBinaryExpression (delegates to PcodeInferredTypes) ──────

    #[test]
    #[should_panic(expected = "PcodeLocation-backed ProgramPoint")]
    fn satisfies_binary_expression_delegates_to_pcode_inferred_types() {
        // Proves the delegation is real (not stubbed out): `PcodeInferredTypes
        // ::satisfies_binary_expression` unconditionally requires a PcodeLocation-backed
        // ProgramPoint (see that method's own docs) *before* it ever looks at the operator, and
        // `TestContext::program_point_location` always returns `None` -- so this call reaches all
        // the way into the real (already-tested) `PcodeInferredTypes` logic and hits its
        // documented panic, rather than e.g. silently returning a placeholder value.
        let ts = all_types_system();
        let left = Types::of(ts.clone(), TType::A);
        let right = Types::of(ts, TType::A);
        let t = Types::new();
        t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &TProgramPoint, &TOracle);
    }

    // ── lubAux / lessOrEqualAux ───────────────────────────────────────────

    #[test]
    fn lub_aux_computes_the_pairwise_common_supertype_and_keeps_types() {
        let ts = all_types_system();
        let a = Types::of(ts.clone(), TType::A);
        let b = Types::of(ts, TType::A);
        let result = a.lub_aux(&b);
        assert_eq!(result, Types::of(all_types_system(), TType::A));
    }

    #[test]
    fn lub_aux_of_different_types_falls_back_to_untyped() {
        let ts = all_types_system();
        let a = Types::of(ts.clone(), TType::A);
        let b = Types::of(ts, TType::B);
        let result = a.lub_aux(&b);
        assert!(result.is_top());
    }

    #[test]
    fn less_or_equal_aux_uses_can_be_assigned_to() {
        let ts = all_types_system();
        let a = Types::of(ts.clone(), TType::A);
        let untyped = Types::of(ts, TType::Untyped);
        assert!(a.less_or_equal_aux(&untyped));
        assert!(!untyped.less_or_equal_aux(&a));
    }

    // ── equality / hashing (type-only, per the Java quirk) ───────────────

    #[test]
    fn equality_compares_type_only_not_types() {
        let mut ts_a = all_types_system();
        ts_a.all.insert(TType::Untyped);
        let ts_b = all_types_system();

        let a = Types::of(ts_a, TType::A);
        let b = Types::of(ts_b, TType::A);
        // Different `types` (TypeSystem) contents, same `type` -- still equal, faithfully
        // matching Java's `equals()` never consulting `types`.
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_when_type_differs() {
        let ts = all_types_system();
        let a = Types::of(ts.clone(), TType::A);
        let b = Types::of(ts, TType::B);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet as StdHashSet;
        let ts = all_types_system();
        let a = Types::of(ts.clone(), TType::A);
        let b = Types::of(ts, TType::A);
        let mut set = StdHashSet::new();
        set.insert(HashableWrapper(a));
        assert!(set.contains(&HashableWrapper(b)));
    }

    /// [`PcodeStaticTypes`] doesn't derive [`Hash`]/[`Eq`] automatically (its manual impls have
    /// no `Copy`/`Clone` requirement baked in), so wrap it for a `HashSet`-based equality-vs-hash
    /// consistency check.
    #[derive(PartialEq, Eq)]
    struct HashableWrapper(Types);
    impl Hash for HashableWrapper {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(Types::default(), Types::new());
    }
}
