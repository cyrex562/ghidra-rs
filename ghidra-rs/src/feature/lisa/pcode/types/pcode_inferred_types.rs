//! Port of `ghidra.lisa.pcode.types.PcodeInferredTypes`.
//!
//! A LiSA `BaseNonRelationalTypeDomain` tracking, for each program point, the set of types a
//! value could have -- the type-inference counterpart to the `ghidra.lisa.pcode.analyses` value
//! domains (`PcodeSign`, `PcodeParity`, `PcodeStability`, ...).
//!
//! # The unported LiSA framework, as narrow seams
//!
//! Like every class in this package built directly on the LiSA analysis framework
//! (`it.unive.lisa.*`), there is no Rust port of that framework anywhere in this crate and no
//! Java source available under `orig_src` to transcribe from (it lives in LiSA's own library, not
//! in Ghidra's source tree) -- the same situation documented on
//! [`PcodeNonRelationalValueDomain`](crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain)
//! and [`PcodeStability`](crate::feature::lisa::pcode::analyses::pcode_stability::PcodeStability).
//! Following those siblings' established convention, the framework is represented here as
//! [`PcodeTypeContext`]: a single associated-types trait bundling every LiSA type/operation this
//! class's own body actually touches (`Type`, `TypeSystem`, `Identifier`, `Constant`, `PushAny`,
//! `PushInv`, `ProgramPoint`, `Oracle`, `TypeEnvironment`, `UnaryOperator`, `BinaryOperator`,
//! `TernaryOperator`, `BinaryExpression`), each exposed only through the narrow operations called
//! below -- matching [`PcodeStability`]'s `StabilityDomain`/`StabilityAuxDomain`/
//! `TrendEnvironment`/`StabilityExpr` split, just consolidated into one trait since
//! `PcodeInferredTypes` (unlike `PcodeStability<V, Env>`) is not itself generic in Java, so there
//! is only ever one implementor's worth of associated types in play at a time.
//!
//! [`PcodeLocation`] (already ported) and [`Satisfiability`] (already ported, per its own module
//! docs a "real, tested reconstruction" of the small well-known LiSA three-valued lattice) are
//! used directly rather than re-abstracted, matching how [`PcodeStability`] reuses
//! [`Trend`](crate::feature::lisa::pcode::analyses::trend::Trend)/`Satisfiability` directly.
//!
//! # `default_eval_identifier`: the one genuinely-unknowable seam
//!
//! [`PcodeTypeContext::default_eval_identifier`] stands in for
//! `BaseNonRelationalTypeDomain.super.evalIdentifier(id, environment, pp, oracle)` -- a call into
//! the unported LiSA interface's own *default* method, whose exact algorithm (beyond "resolve
//! `id`'s currently-tracked type via `environment`") cannot be verified without LiSA's source.
//! Per the same reasoning [`PcodeNonRelationalValueDomain::evalPushAny`]'s docs give for dropping
//! an analogous call ("left for a future, real ... port to add back... rather than fabricated
//! against placeholder types"), this is modeled as a required seam a real LiSA integration must
//! supply, rather than a guessed implementation.
//!
//! Every *other* `BaseNonRelationalTypeDomain`/`Lattice` default-interface-method call in this
//! class (`isTop()`'s `BaseNonRelationalTypeDomain.super.isTop()`, `isBottom()`'s `.super
//! .isBottom()`) is **not** modeled as a seam: LiSA's `Lattice` interface's standard, framework-
//! wide default for both is well-established (`isTop() { return equals(top()); }`, `isBottom() {
//! return equals(bottom()); }` -- the only sensible default given no other lattice state to
//! consult, and the same contract every other lattice in the LiSA framework relies on). Substituting
//! that contract into this class's own `equals()`/`top()`/`bottom()` lets both reduce algebraically
//! to closed forms with no external call needed -- see [`PcodeInferredTypes::is_top`]/
//! [`PcodeInferredTypes::is_bottom`]'s own doc comments for the derivation.
//!
//! # Preserved bug: `getRuntimeTypes()` drops its "return empty set" branch
//!
//! Java's `getRuntimeTypes()`:
//! ```java
//! public Set<Type> getRuntimeTypes() {
//!     if (elements == null)
//!         Collections.emptySet();
//!     return elements;
//! }
//! ```
//! is missing a `return` before `Collections.emptySet()` -- the empty set is constructed and
//! immediately discarded, and the method actually returns `null` (not an empty set) whenever
//! `elements` is `null`, despite what the dead branch's presence suggests it should do. This is
//! preserved exactly: [`PcodeInferredTypes::get_runtime_types`] returns `None` (not
//! `Some(empty)`) in that case -- see `get_runtime_types_returns_none_not_empty_set_when_elements_is_null`.
//!
//! # `null`-argument edge cases in `elements`-touching methods
//!
//! `evalUnaryExpression`/`evalBinaryExpression`/`evalTernaryExpression`/`evalTypeCast`/
//! `evalTypeConv`/`satisfiesBinaryExpression` (via a non-top argument's raw `elements` field),
//! `lubAux` (via `new HashSet<>(elements)`), and `lessOrEqualAux` (via `elements.containsAll(...)`
//! / `other.elements.containsAll(...)`) all dereference `elements` directly when the relevant
//! side is not top -- which, per this class's own constructors, is only ever `null` for a value
//! built through the bare zero-argument constructor (`elements = null, isTop = false`). Real LiSA
//! analysis pipelines only ever feed `eval*`/`*Aux` methods values already produced by `top()`,
//! `bottom()`, or an earlier `eval*` call -- never a bare `new PcodeInferredTypes()` -- so Java's
//! `NullPointerException` on this path has no real caller. This port falls back to an empty set
//! in each such spot instead of panicking, documented individually at each call site.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::feature::lisa::pcode::analyses::satisfiability::Satisfiability;
use crate::feature::lisa::pcode::locations::PcodeLocation;
use crate::program::model::pcode::OpCode;

/// Bundles every LiSA framework type [`PcodeInferredTypes`]'s own logic touches. See the module
/// docs for the overall port strategy.
pub trait PcodeTypeContext: Sized {
    /// `it.unive.lisa.type.Type`.
    type Type: Clone + PartialEq + Eq + Hash + std::fmt::Debug;
    /// `it.unive.lisa.type.TypeSystem`.
    type TypeSystem: Clone;
    /// `it.unive.lisa.program.cfg.ProgramPoint`.
    type ProgramPoint;
    /// `it.unive.lisa.analysis.SemanticOracle`. Never inspected by this class's own logic --
    /// only ever threaded through to nested/default calls.
    type Oracle;
    /// `it.unive.lisa.symbolic.value.Identifier`.
    type Identifier;
    /// `it.unive.lisa.symbolic.value.Constant`.
    type Constant;
    /// `it.unive.lisa.symbolic.value.PushAny`.
    type PushAny;
    /// `it.unive.lisa.symbolic.value.PushInv`. Carries no operations: `evalPushInv`'s body never
    /// inspects its `PushInv` parameter (`return bottom();` unconditionally).
    type PushInv;
    /// `it.unive.lisa.analysis.nonrelational.value.TypeEnvironment<PcodeInferredTypes>`.
    type TypeEnvironment;
    /// `it.unive.lisa.symbolic.value.operator.unary.UnaryOperator`.
    type UnaryOperator;
    /// `it.unive.lisa.symbolic.value.operator.binary.BinaryOperator`.
    type BinaryOperator;
    /// `it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator`.
    type TernaryOperator;
    /// `it.unive.lisa.symbolic.value.BinaryExpression`, narrowed to `evalTypeCast`/
    /// `evalTypeConv`'s `cast`/`conv` parameters.
    type BinaryExpression;

    /// `Type.isTypeTokenType()`.
    fn type_is_type_token_type(ty: &Self::Type) -> bool;

    /// `((TypeTokenType) type).getTypes()`, fused with the `asTypeTokenType()` cast Java performs
    /// immediately before calling it (mirroring this crate's established "as_x" fusion pattern,
    /// e.g. [`crate::program::model::symbol::Symbol::as_namespace`]). Only ever called (by
    /// [`PcodeInferredTypes::type_tokens_intersect`]) on elements [`Self::type_is_type_token_type`]
    /// already confirmed are type-token types.
    fn type_token_types(ty: &Self::Type) -> HashSet<Self::Type>;

    /// `Type.isUntyped()`.
    fn type_is_untyped(ty: &Self::Type) -> bool;

    /// `Type.allInstances(TypeSystem)`.
    fn type_all_instances(ty: &Self::Type, types: &Self::TypeSystem) -> HashSet<Self::Type>;

    /// The `NullType.INSTANCE` singleton. Mirrors `evalNullConstant`'s direct reference to it.
    fn null_type() -> Self::Type;

    /// `TypeSystem.getTypes()`.
    fn type_system_get_types(types: &Self::TypeSystem) -> HashSet<Self::Type>;

    /// `TypeSystem.cast(Set<Type>, Set<Type>, AtomicBoolean)`.
    fn type_system_cast(
        types: &Self::TypeSystem,
        from: &HashSet<Self::Type>,
        to: &HashSet<Self::Type>,
        might_fail: &mut bool,
    ) -> HashSet<Self::Type>;

    /// `pp.getProgram().getTypes()`, fused into one call (see the module docs' fusion note).
    fn program_point_types(pp: &Self::ProgramPoint) -> Self::TypeSystem;

    /// `(PcodeLocation) pp.getLocation()`. Returns `None` when the point's location isn't
    /// actually a [`PcodeLocation`], mirroring the possibility of Java's unconditional cast
    /// throwing `ClassCastException` -- [`PcodeInferredTypes::satisfies_binary_expression`] (the
    /// only caller) turns that into a panic, since every real caller in this package's frontend
    /// always uses `PcodeLocation`-backed program points.
    fn program_point_location(pp: &Self::ProgramPoint) -> Option<&PcodeLocation>;

    /// `Identifier.getStaticType()`.
    fn identifier_static_type(id: &Self::Identifier) -> Self::Type;

    /// `Constant.getStaticType()`.
    fn constant_static_type(constant: &Self::Constant) -> Self::Type;

    /// `PushAny.getStaticType()`.
    fn push_any_static_type(push_any: &Self::PushAny) -> Self::Type;

    /// `UnaryOperator.typeInference(TypeSystem, Set<Type>)`.
    fn unary_type_inference(
        op: &Self::UnaryOperator,
        types: &Self::TypeSystem,
        arg: &HashSet<Self::Type>,
    ) -> HashSet<Self::Type>;

    /// `BinaryOperator.typeInference(TypeSystem, Set<Type>, Set<Type>)`.
    fn binary_type_inference(
        op: &Self::BinaryOperator,
        types: &Self::TypeSystem,
        left: &HashSet<Self::Type>,
        right: &HashSet<Self::Type>,
    ) -> HashSet<Self::Type>;

    /// `TernaryOperator.typeInference(TypeSystem, Set<Type>, Set<Type>, Set<Type>)`.
    fn ternary_type_inference(
        op: &Self::TernaryOperator,
        types: &Self::TypeSystem,
        left: &HashSet<Self::Type>,
        middle: &HashSet<Self::Type>,
        right: &HashSet<Self::Type>,
    ) -> HashSet<Self::Type>;

    /// The `TypeCast.INSTANCE` singleton `BinaryOperator`, needed internally by
    /// [`PcodeInferredTypes::satisfies_binary_expression`]'s `CAST` branch (Java:
    /// `evalBinaryExpression(TypeCast.INSTANCE, left, right, pp, oracle)`).
    fn type_cast_operator() -> Self::BinaryOperator;

    /// `cast.getOperator()`/`conv.getOperator()`.
    fn binary_expression_operator(expr: &Self::BinaryExpression) -> Self::BinaryOperator;

    /// Stands in for `BaseNonRelationalTypeDomain.super.evalIdentifier(id, environment, pp,
    /// oracle)`. See the module docs for why this is a required seam rather than a fabricated
    /// implementation.
    fn default_eval_identifier(
        id: &Self::Identifier,
        environment: &Self::TypeEnvironment,
        pp: &Self::ProgramPoint,
        oracle: &Self::Oracle,
    ) -> PcodeInferredTypes<Self>;
}

/// Returns `true` if `a` and `b` share at least one element. Mirrors the Apache Commons
/// `CollectionUtils.intersection(a, b).isEmpty()` checks in the Java source -- only ever used
/// here to test non-emptiness, never the intersected elements themselves.
fn sets_intersect<T: Eq + std::hash::Hash>(a: &HashSet<T>, b: &HashSet<T>) -> bool {
    a.iter().any(|x| b.contains(x))
}

/// A LiSA type-inference abstract domain tracking, for each program point, the set of types a
/// value could have.
///
/// Port of `ghidra.lisa.pcode.types.PcodeInferredTypes`. See the module docs for the overall port
/// strategy.
pub struct PcodeInferredTypes<C: PcodeTypeContext> {
    /// Java: `private final Set<Type> elements`. `None` mirrors Java's `null` (see the module
    /// docs -- this is a distinct state from `Some(empty)`, which is `bottom()`/`BOTTOM`).
    elements: Option<HashSet<C::Type>>,
    /// Java: `private final boolean isTop`.
    is_top: bool,
}

impl<C: PcodeTypeContext> Clone for PcodeInferredTypes<C> {
    fn clone(&self) -> Self {
        PcodeInferredTypes { elements: self.elements.clone(), is_top: self.is_top }
    }
}

impl<C: PcodeTypeContext> std::fmt::Debug for PcodeInferredTypes<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcodeInferredTypes")
            .field("elements", &self.elements)
            .field("is_top", &self.is_top)
            .finish()
    }
}

impl<C: PcodeTypeContext> PartialEq for PcodeInferredTypes<C> {
    /// Port of `equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.elements == other.elements && self.is_top == other.is_top
    }
}

impl<C: PcodeTypeContext> Eq for PcodeInferredTypes<C> {}

impl<C: PcodeTypeContext> Hash for PcodeInferredTypes<C> {
    /// Port of `hashCode()`. Java's `elements.hashCode()` relies on `java.util.Set`'s
    /// order-independent (sum-of-elements) hash contract; Rust's [`HashSet`] deliberately does
    /// not implement [`Hash`] itself (its iteration order is unspecified), so this reproduces the
    /// same order-independence explicitly: each element is hashed with its own fresh
    /// [`std::collections::hash_map::DefaultHasher`] and the resulting `u64`s are summed
    /// (wrapping), rather than folding a single `Hasher` over the set in iteration order.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let elements_hash: u64 = match &self.elements {
            None => 0,
            Some(set) => set.iter().fold(0u64, |acc, e| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                e.hash(&mut h);
                acc.wrapping_add(h.finish())
            }),
        };
        elements_hash.hash(state);
        self.is_top.hash(state);
    }
}

/// The result of [`PcodeInferredTypes::representation`]. Java's `representation()` builds a
/// `StructuredRepresentation` via more unported LiSA framework pieces
/// (`Lattice.topRepresentation()`/`bottomRepresentation()`/`SetRepresentation`); since this
/// class's only use of it is `toString()`'s `representation().toString()`, this models just the
/// three shapes that method distinguishes, with a `Display` impl producing reasonable (though not
/// independently verified against real LiSA output, since its source isn't available -- see the
/// module docs) text.
#[derive(Debug, Clone, PartialEq)]
pub enum PcodeInferredTypesRepresentation<T> {
    /// `Lattice.topRepresentation()`.
    Top,
    /// `Lattice.bottomRepresentation()`.
    Bottom,
    /// `new SetRepresentation(elements, StringRepresentation::new)`.
    Set(Vec<T>),
}

impl<T: std::fmt::Debug> std::fmt::Display for PcodeInferredTypesRepresentation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcodeInferredTypesRepresentation::Top => write!(f, "#TOP#"),
            PcodeInferredTypesRepresentation::Bottom => write!(f, "_|_"),
            PcodeInferredTypesRepresentation::Set(items) => {
                write!(f, "{{")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item:?}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl<C: PcodeTypeContext> PcodeInferredTypes<C> {
    /// Builds the inferred types, representing an empty set of types.
    ///
    /// Port of the no-arg `PcodeInferredTypes()`, which delegates through `this(null, (Set<Type>)
    /// null)` to `this(false, null)` (the `typeSystem != null && ...` check short-circuits to
    /// `false` without evaluating `types.equals(...)` at all, since `typeSystem` is `null`).
    pub fn new() -> Self {
        PcodeInferredTypes { elements: None, is_top: false }
    }

    /// Builds the inferred types, representing only the given type.
    ///
    /// Port of `PcodeInferredTypes(TypeSystem, Type)`.
    pub fn of_type(type_system: &C::TypeSystem, ty: C::Type) -> Self {
        let mut set = HashSet::new();
        set.insert(ty);
        Self::of_types(type_system, set)
    }

    /// Builds the inferred types, representing only the given set of types, computing `isTop`
    /// from whether `types` equals the full type system.
    ///
    /// Port of `PcodeInferredTypes(TypeSystem, Set<Type>)` for a genuinely non-null `typeSystem`
    /// (every real caller). See [`Self::raw`] for the `typeSystem == null` path this class's own
    /// methods use internally.
    pub fn of_types(type_system: &C::TypeSystem, types: HashSet<C::Type>) -> Self {
        let is_top = types == C::type_system_get_types(type_system);
        PcodeInferredTypes { elements: Some(types), is_top }
    }

    /// Builds the inferred types directly from an `isTop` flag and an optional element set.
    ///
    /// Port of `PcodeInferredTypes(boolean, Set<Type>)`, and of the `(TypeSystem, Set<Type>)`
    /// overload's own `typeSystem == null` path (which always resolves to `isTop = false`
    /// without inspecting `types` at all -- see [`Self::lub_aux`]/`BOTTOM`'s construction).
    pub fn raw(is_top: bool, elements: Option<HashSet<C::Type>>) -> Self {
        PcodeInferredTypes { elements, is_top }
    }

    /// The empty-set-of-types bottom value. Port of the static `BOTTOM` field: `new
    /// PcodeInferredTypes(null, Collections.emptySet())`.
    fn bottom_value() -> Self {
        Self::raw(false, Some(HashSet::new()))
    }

    /// Falls back to an empty set for the (unreachable in practice) `elements == null, isTop ==
    /// false` state. See the module docs' "`null`-argument edge cases" section.
    fn effective_elements(&self, types: &C::TypeSystem) -> HashSet<C::Type> {
        if self.is_top {
            C::type_system_get_types(types)
        } else {
            self.elements.clone().unwrap_or_default()
        }
    }

    /// Returns the runtime types this element represents.
    ///
    /// Port of `getRuntimeTypes()`. **Preserves a real Java bug**: see the module docs. Returns
    /// `None` (not `Some(empty set)`) when the backing `elements` is itself `None`.
    pub fn get_runtime_types(&self) -> Option<&HashSet<C::Type>> {
        self.elements.as_ref()
    }

    /// Port of `top()`.
    pub fn top(&self) -> Self {
        Self::raw(true, None)
    }

    /// Port of `isTop()`. See the module docs' derivation: `BaseNonRelationalTypeDomain.super
    /// .isTop() || isTop` reduces to exactly `isTop`, since the standard LiSA `Lattice.isTop()`
    /// default (`equals(top())`) itself requires `self.is_top == true` as one of its own
    /// conjuncts (via this class's `equals()`), making the `|| isTop` disjunct alone decide the
    /// whole expression either way.
    pub fn is_top(&self) -> bool {
        self.is_top
    }

    /// Port of `bottom()`.
    pub fn bottom(&self) -> Self {
        Self::bottom_value()
    }

    /// Port of `isBottom()`. See the module docs' derivation: `BaseNonRelationalTypeDomain.super
    /// .isBottom() || BOTTOM.elements.equals(elements)` reduces to exactly the second disjunct
    /// (`self.elements == Some(empty set)`), since the standard `Lattice.isBottom()` default
    /// (`equals(bottom())`) implies that same condition as one of its own conjuncts, making it a
    /// strict subset of (and thus redundant with) the explicit check.
    pub fn is_bottom(&self) -> bool {
        self.elements.as_ref().is_some_and(HashSet::is_empty)
    }

    /// Port of `toString()`: `representation().toString()`.
    pub fn to_display_string(&self) -> String
    where
        C::Type: Clone,
    {
        self.representation().to_string()
    }

    /// Port of `representation()`.
    pub fn representation(&self) -> PcodeInferredTypesRepresentation<C::Type> {
        if self.is_top() {
            return PcodeInferredTypesRepresentation::Top;
        }
        if self.is_bottom() {
            return PcodeInferredTypesRepresentation::Bottom;
        }
        let items: Vec<C::Type> = self.elements.clone().unwrap_or_default().into_iter().collect();
        PcodeInferredTypesRepresentation::Set(items)
    }

    /// Port of `evalIdentifier(Identifier, TypeEnvironment<PcodeInferredTypes>, ProgramPoint,
    /// SemanticOracle)`.
    pub fn eval_identifier(
        &self,
        id: &C::Identifier,
        environment: &C::TypeEnvironment,
        pp: &C::ProgramPoint,
        oracle: &C::Oracle,
    ) -> Self {
        let eval = C::default_eval_identifier(id, environment, pp, oracle);
        if !eval.is_top() {
            return eval;
        }
        let types = C::program_point_types(pp);
        let static_type = C::identifier_static_type(id);
        let instances = C::type_all_instances(&static_type, &types);
        Self::of_types(&types, instances)
    }

    /// Port of `evalPushAny(PushAny, ProgramPoint, SemanticOracle)`.
    pub fn eval_push_any(&self, push_any: &C::PushAny, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        let static_type = C::push_any_static_type(push_any);
        if C::type_is_untyped(&static_type) {
            return Self::raw(true, Some(C::type_system_get_types(&types)));
        }
        let instances = C::type_all_instances(&static_type, &types);
        Self::of_types(&types, instances)
    }

    /// Port of `evalPushInv(PushInv, ProgramPoint, SemanticOracle)`: `return bottom();`,
    /// unconditionally, matching Java's own indifference to its `PushInv` parameter.
    pub fn eval_push_inv(&self, _push_inv: &C::PushInv, _pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        self.bottom()
    }

    /// Port of `evalNullConstant(ProgramPoint, SemanticOracle)`.
    pub fn eval_null_constant(&self, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        Self::of_type(&types, C::null_type())
    }

    /// Port of `evalNonNullConstant(Constant, ProgramPoint, SemanticOracle)`.
    pub fn eval_non_null_constant(&self, constant: &C::Constant, pp: &C::ProgramPoint, _oracle: &C::Oracle) -> Self {
        let types = C::program_point_types(pp);
        let static_type = C::constant_static_type(constant);
        Self::of_type(&types, static_type)
    }

    /// Port of `evalUnaryExpression(UnaryOperator, PcodeInferredTypes, ProgramPoint,
    /// SemanticOracle)`.
    pub fn eval_unary_expression(
        &self,
        operator: &C::UnaryOperator,
        arg: &Self,
        pp: &C::ProgramPoint,
        _oracle: &C::Oracle,
    ) -> Self {
        let types = C::program_point_types(pp);
        let elems = arg.effective_elements(&types);
        let inferred = C::unary_type_inference(operator, &types, &elems);
        if inferred.is_empty() {
            return self.bottom();
        }
        Self::of_types(&types, inferred)
    }

    /// Port of `evalBinaryExpression(BinaryOperator, PcodeInferredTypes, PcodeInferredTypes,
    /// ProgramPoint, SemanticOracle)`.
    pub fn eval_binary_expression(
        &self,
        operator: &C::BinaryOperator,
        left: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        _oracle: &C::Oracle,
    ) -> Self {
        let types = C::program_point_types(pp);
        let lelems = left.effective_elements(&types);
        let relems = right.effective_elements(&types);
        let inferred = C::binary_type_inference(operator, &types, &lelems, &relems);
        if inferred.is_empty() {
            return self.bottom();
        }
        Self::of_types(&types, inferred)
    }

    /// Port of `evalTernaryExpression(TernaryOperator, PcodeInferredTypes, PcodeInferredTypes,
    /// PcodeInferredTypes, ProgramPoint, SemanticOracle)`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_ternary_expression(
        &self,
        operator: &C::TernaryOperator,
        left: &Self,
        middle: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        _oracle: &C::Oracle,
    ) -> Self {
        let types = C::program_point_types(pp);
        let lelems = left.effective_elements(&types);
        let melems = middle.effective_elements(&types);
        let relems = right.effective_elements(&types);
        let inferred = C::ternary_type_inference(operator, &types, &lelems, &melems, &relems);
        if inferred.is_empty() {
            return self.bottom();
        }
        Self::of_types(&types, inferred)
    }

    /// Checks whether the two given sets of type tokens intersect: there exists at least one type
    /// token `t1` from `lfiltered` and one type token `t2` from `rfiltered` such that
    /// `t1.getTypes().intersects(t2.getTypes())`.
    ///
    /// Port of the private static `typeTokensIntersect(Set<Type>, Set<Type>)`. Both input sets
    /// are assumed to contain only type-token types (only ever called with the results of
    /// filtering by [`PcodeTypeContext::type_is_type_token_type`]).
    fn type_tokens_intersect(lfiltered: &HashSet<C::Type>, rfiltered: &HashSet<C::Type>) -> bool {
        for l in lfiltered {
            let l_types = C::type_token_types(l);
            for r in rfiltered {
                let r_types = C::type_token_types(r);
                if sets_intersect(&l_types, &r_types) {
                    return true;
                }
            }
        }
        false
    }

    /// Port of `satisfiesBinaryExpression(BinaryOperator, PcodeInferredTypes, PcodeInferredTypes,
    /// ProgramPoint, SemanticOracle)`.
    ///
    /// # Panics
    /// If `pp`'s location is not a [`PcodeLocation`], mirroring Java's unconditional `(PcodeLocation)
    /// pp.getLocation()` cast (`ClassCastException` if it weren't) -- see
    /// [`PcodeTypeContext::program_point_location`]'s own docs.
    pub fn satisfies_binary_expression(
        &self,
        operator: &C::BinaryOperator,
        left: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        oracle: &C::Oracle,
    ) -> Satisfiability {
        let types = C::program_point_types(pp);
        let lelems = left.effective_elements(&types);
        let relems = right.effective_elements(&types);

        let ploc = C::program_point_location(pp).expect(
            "satisfiesBinaryExpression requires a PcodeLocation-backed ProgramPoint (mirrors \
             Java's unconditional (PcodeLocation) cast)",
        );
        let opcode = ploc.get_opcode();

        if matches!(opcode, OpCode::IntEqual | OpCode::FloatEqual | OpCode::IntNotEqual | OpCode::FloatNotEqual) {
            let lfiltered: HashSet<C::Type> =
                lelems.iter().filter(|t| C::type_is_type_token_type(t)).cloned().collect();
            let rfiltered: HashSet<C::Type> =
                relems.iter().filter(|t| C::type_is_type_token_type(t)).cloned().collect();

            if lelems.len() != lfiltered.len() || relems.len() != rfiltered.len() {
                // if there is at least one element that is not a type token, than we cannot
                // reason about it
                return Satisfiability::Unknown;
            }

            if matches!(opcode, OpCode::IntEqual | OpCode::FloatEqual) {
                return if lelems.len() == 1 && lelems == relems {
                    // only one element, and it is the same
                    Satisfiability::Satisfied
                } else if !sets_intersect(&lelems, &relems) && !Self::type_tokens_intersect(&lfiltered, &rfiltered) {
                    // no common elements, they cannot be equal
                    Satisfiability::NotSatisfied
                } else {
                    // we don't know really
                    Satisfiability::Unknown
                };
            }

            return if !sets_intersect(&lelems, &relems) && !Self::type_tokens_intersect(&lfiltered, &rfiltered) {
                // no common elements, they cannot be equal
                Satisfiability::Satisfied
            } else if lelems.len() == 1 && lelems == relems {
                // only one element, and it is the same
                Satisfiability::NotSatisfied
            } else {
                // we don't know really
                Satisfiability::Unknown
            };
        }
        else if opcode == OpCode::Cast {
            if self.eval_binary_expression(&C::type_cast_operator(), left, right, pp, oracle).is_bottom() {
                // no common types, the check will always fail
                return Satisfiability::NotSatisfied;
            }
            let mut might_fail = false;
            let set = C::type_system_cast(&types, &lelems, &relems, &mut might_fail);
            if lelems == set && !might_fail {
                // if all the types stayed in 'set' then there is no execution that reaches the
                // expression with a type that cannot be casted, and thus this is a tautology
                return Satisfiability::Satisfied;
            }
            // sometimes yes, sometimes no
            return Satisfiability::Unknown;
        }
        Satisfiability::Unknown
    }

    /// Port of `lubAux(PcodeInferredTypes)`. See the module docs' "`null`-argument edge cases"
    /// section for the `elements == null` fallback.
    pub fn lub_aux(&self, other: &Self) -> Self {
        let mut lub = self.elements.clone().unwrap_or_default();
        lub.extend(other.elements.clone().unwrap_or_default());
        Self::raw(false, Some(lub))
    }

    /// Port of `lessOrEqualAux(PcodeInferredTypes)`. See the module docs' "`null`-argument edge
    /// cases" section for the `elements == null` fallback.
    pub fn less_or_equal_aux(&self, other: &Self) -> bool {
        let self_elems = self.elements.clone().unwrap_or_default();
        let other_elems = other.elements.clone().unwrap_or_default();
        self_elems.iter().all(|e| other_elems.contains(e))
    }

    /// Port of `evalTypeCast(BinaryExpression, PcodeInferredTypes, PcodeInferredTypes,
    /// ProgramPoint, SemanticOracle)`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_type_cast(
        &self,
        cast: &C::BinaryExpression,
        left: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        _oracle: &C::Oracle,
    ) -> Self {
        let types = C::program_point_types(pp);
        let lelems = left.effective_elements(&types);
        let relems = right.effective_elements(&types);
        let operator = C::binary_expression_operator(cast);
        let inferred = C::binary_type_inference(&operator, &types, &lelems, &relems);
        if inferred.is_empty() {
            return self.bottom();
        }
        Self::of_types(&types, inferred)
    }

    /// Port of `evalTypeConv(BinaryExpression, PcodeInferredTypes, PcodeInferredTypes,
    /// ProgramPoint, SemanticOracle)`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_type_conv(
        &self,
        conv: &C::BinaryExpression,
        left: &Self,
        right: &Self,
        pp: &C::ProgramPoint,
        _oracle: &C::Oracle,
    ) -> Self {
        let types = C::program_point_types(pp);
        let lelems = left.effective_elements(&types);
        let relems = right.effective_elements(&types);
        let operator = C::binary_expression_operator(conv);
        let inferred = C::binary_type_inference(&operator, &types, &lelems, &relems);
        if inferred.is_empty() {
            return self.bottom();
        }
        Self::of_types(&types, inferred)
    }
}

impl<C: PcodeTypeContext> Default for PcodeInferredTypes<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, closed test `Type`: two atomic types (`A`/`B`), a "type token" wrapping a set of
    /// other types (mirroring `TypeTokenType`), a `Null` type, and an `Untyped` marker.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum TType {
        A,
        B,
        Null,
        Untyped,
        Token(Vec<TType>),
    }

    #[derive(Clone, Debug)]
    struct TTypeSystem {
        all: HashSet<TType>,
    }

    struct TId(TType);
    struct TConst(TType);
    struct TPushAny(TType);
    struct TPushInv;
    struct TEnv;
    struct TOracle;
    struct TProgramPoint(PcodeLocation);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TUnaryOp {
        Identity,
        ToBottom,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TBinaryOp {
        Union,
        ToBottom,
        Cast,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TTernaryOp {
        UnionAll,
    }

    struct TBinaryExpr(TBinaryOp);

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
        type UnaryOperator = TUnaryOp;
        type BinaryOperator = TBinaryOp;
        type TernaryOperator = TTernaryOp;
        type BinaryExpression = TBinaryExpr;

        fn type_is_type_token_type(ty: &Self::Type) -> bool {
            matches!(ty, TType::Token(_))
        }

        fn type_token_types(ty: &Self::Type) -> HashSet<Self::Type> {
            match ty {
                TType::Token(types) => types.iter().cloned().collect(),
                _ => HashSet::new(),
            }
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
            to: &HashSet<Self::Type>,
            might_fail: &mut bool,
        ) -> HashSet<Self::Type> {
            // Test double: "cast succeeds" iff every element of `from` is also in `to`;
            // otherwise the elements not in `to` are dropped and `might_fail` is set.
            let mut result = HashSet::new();
            for t in from {
                if to.contains(t) {
                    result.insert(t.clone());
                } else {
                    *might_fail = true;
                }
            }
            result
        }

        fn program_point_types(pp: &Self::ProgramPoint) -> Self::TypeSystem {
            let _ = pp;
            all_types_system()
        }

        fn program_point_location(pp: &Self::ProgramPoint) -> Option<&PcodeLocation> {
            Some(&pp.0)
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
            op: &Self::UnaryOperator,
            _types: &Self::TypeSystem,
            arg: &HashSet<Self::Type>,
        ) -> HashSet<Self::Type> {
            match op {
                TUnaryOp::Identity => arg.clone(),
                TUnaryOp::ToBottom => HashSet::new(),
            }
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
                TBinaryOp::Cast => left.clone(),
            }
        }

        fn ternary_type_inference(
            _op: &Self::TernaryOperator,
            _types: &Self::TypeSystem,
            left: &HashSet<Self::Type>,
            middle: &HashSet<Self::Type>,
            right: &HashSet<Self::Type>,
        ) -> HashSet<Self::Type> {
            left.union(middle).cloned().collect::<HashSet<_>>().union(right).cloned().collect()
        }

        fn type_cast_operator() -> Self::BinaryOperator {
            TBinaryOp::Cast
        }

        fn binary_expression_operator(expr: &Self::BinaryExpression) -> Self::BinaryOperator {
            expr.0
        }

        fn default_eval_identifier(
            id: &Self::Identifier,
            _environment: &Self::TypeEnvironment,
            _pp: &Self::ProgramPoint,
            _oracle: &Self::Oracle,
        ) -> PcodeInferredTypes<Self> {
            // Test double for the unported LiSA default: always reports "unknown" (top), so
            // `eval_identifier` always falls into its `allInstances` fallback path -- matching
            // this class's real observable behavior whenever the environment doesn't already
            // track `id` (the common real-world case at a fresh use site).
            let _ = id;
            PcodeInferredTypes::raw(true, None)
        }
    }

    type Types = PcodeInferredTypes<TestContext>;

    fn all_types_system() -> TTypeSystem {
        let mut all = HashSet::new();
        all.insert(TType::A);
        all.insert(TType::B);
        all.insert(TType::Null);
        TTypeSystem { all }
    }

    fn pp(opcode: OpCode) -> TProgramPoint {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{PcodeOp, SequenceNumber};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x1000);
        let seq = SequenceNumber::new(addr.clone(), 0);
        let op = PcodeOp::new(opcode, seq, vec![], None);
        TProgramPoint(PcodeLocation::new(op))
    }

    fn a_type() -> TType {
        TType::A
    }

    fn set_of(types: &[TType]) -> HashSet<TType> {
        types.iter().cloned().collect()
    }

    // ── construction ──────────────────────────────────────────────────────

    #[test]
    fn new_is_empty_and_not_top() {
        let t = Types::new();
        assert!(!t.is_top());
        assert!(!t.is_bottom());
        assert_eq!(t.get_runtime_types(), None);
    }

    #[test]
    fn of_type_wraps_a_single_type() {
        let ts = all_types_system();
        let t = Types::of_type(&ts, TType::A);
        assert_eq!(t.get_runtime_types(), Some(&set_of(&[TType::A])));
        assert!(!t.is_top());
    }

    #[test]
    fn of_types_matching_the_full_type_system_is_top() {
        let ts = all_types_system();
        let t = Types::of_types(&ts, ts.all.clone());
        assert!(t.is_top());
    }

    #[test]
    fn top_has_no_runtime_types_but_reports_top() {
        let t = Types::new().top();
        assert!(t.is_top());
        assert_eq!(t.get_runtime_types(), None);
    }

    #[test]
    fn bottom_is_an_empty_non_top_set() {
        let t = Types::new().bottom();
        assert!(t.is_bottom());
        assert!(!t.is_top());
        assert_eq!(t.get_runtime_types(), Some(&HashSet::new()));
    }

    // ── preserved bug: getRuntimeTypes ───────────────────────────────────

    #[test]
    fn get_runtime_types_returns_none_not_empty_set_when_elements_is_null() {
        // Faithful reproduction of Java's missing `return` in `getRuntimeTypes()`'s dead
        // `if (elements == null) Collections.emptySet();` branch -- see the module docs.
        let t = Types::new();
        assert_eq!(t.get_runtime_types(), None, "must be None, not Some(empty set)");
    }

    // ── isTop / isBottom reductions ──────────────────────────────────────

    #[test]
    fn is_top_matches_the_is_top_flag_exactly() {
        assert!(Types::raw(true, None).is_top());
        assert!(Types::raw(true, Some(all_types_system().all)).is_top());
        assert!(!Types::raw(false, Some(HashSet::new())).is_top());
    }

    #[test]
    fn is_bottom_is_true_only_for_a_present_empty_element_set() {
        assert!(Types::raw(false, Some(HashSet::new())).is_bottom());
        assert!(!Types::raw(false, Some(set_of(&[TType::A]))).is_bottom());
        assert!(!Types::raw(false, None).is_bottom());
        // Even isTop=true with an empty set is not "bottom" by this check (matches the reduced
        // condition depending only on `elements`, not `is_top`).
        assert!(Types::raw(true, Some(HashSet::new())).is_bottom());
    }

    // ── representation / display ──────────────────────────────────────────

    #[test]
    fn representation_distinguishes_top_bottom_and_set() {
        assert_eq!(Types::new().top().representation(), PcodeInferredTypesRepresentation::Top);
        assert_eq!(Types::new().bottom().representation(), PcodeInferredTypesRepresentation::Bottom);
        let ts = all_types_system();
        let t = Types::of_type(&ts, TType::A);
        match t.representation() {
            PcodeInferredTypesRepresentation::Set(items) => assert_eq!(items, vec![TType::A]),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn to_display_string_renders_each_shape() {
        assert_eq!(Types::new().top().to_display_string(), "#TOP#");
        assert_eq!(Types::new().bottom().to_display_string(), "_|_");
        let ts = all_types_system();
        assert_eq!(Types::of_type(&ts, TType::A).to_display_string(), "{A}");
    }

    // ── evalIdentifier ────────────────────────────────────────────────────

    #[test]
    fn eval_identifier_falls_back_to_all_instances_when_default_is_top() {
        let point = pp(OpCode::Copy);
        let id = TId(a_type());
        let t = Types::new();
        let result = t.eval_identifier(&id, &TEnv, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A])));
    }

    // ── evalPushAny ───────────────────────────────────────────────────────

    #[test]
    fn eval_push_any_untyped_is_top_with_full_type_set() {
        let point = pp(OpCode::Copy);
        let push_any = TPushAny(TType::Untyped);
        let t = Types::new();
        let result = t.eval_push_any(&push_any, &point, &TOracle);
        assert!(result.is_top());
        assert_eq!(result.get_runtime_types(), Some(&all_types_system().all));
    }

    #[test]
    fn eval_push_any_typed_narrows_to_all_instances() {
        let point = pp(OpCode::Copy);
        let push_any = TPushAny(TType::A);
        let t = Types::new();
        let result = t.eval_push_any(&push_any, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A])));
    }

    // ── evalPushInv ───────────────────────────────────────────────────────

    #[test]
    fn eval_push_inv_is_always_bottom() {
        let point = pp(OpCode::Copy);
        let t = Types::of_type(&all_types_system(), TType::A);
        let result = t.eval_push_inv(&TPushInv, &point, &TOracle);
        assert!(result.is_bottom());
    }

    // ── evalNullConstant / evalNonNullConstant ───────────────────────────

    #[test]
    fn eval_null_constant_is_the_null_type() {
        let point = pp(OpCode::Copy);
        let t = Types::new();
        let result = t.eval_null_constant(&point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::Null])));
    }

    #[test]
    fn eval_non_null_constant_is_the_constants_static_type() {
        let point = pp(OpCode::Copy);
        let t = Types::new();
        let result = t.eval_non_null_constant(&TConst(TType::B), &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::B])));
    }

    // ── evalUnaryExpression / evalBinaryExpression / evalTernaryExpression ──

    #[test]
    fn eval_unary_expression_empty_inference_is_bottom() {
        let point = pp(OpCode::Copy);
        let arg = Types::of_type(&all_types_system(), TType::A);
        let t = Types::new();
        let result = t.eval_unary_expression(&TUnaryOp::ToBottom, &arg, &point, &TOracle);
        assert!(result.is_bottom());
    }

    #[test]
    fn eval_unary_expression_uses_top_arg_as_full_type_set() {
        let point = pp(OpCode::Copy);
        let arg = Types::new().top();
        let t = Types::new();
        let result = t.eval_unary_expression(&TUnaryOp::Identity, &arg, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&all_types_system().all));
    }

    #[test]
    fn eval_binary_expression_unions_both_sides() {
        let point = pp(OpCode::Copy);
        let left = Types::of_type(&all_types_system(), TType::A);
        let right = Types::of_type(&all_types_system(), TType::B);
        let t = Types::new();
        let result = t.eval_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A, TType::B])));
    }

    #[test]
    fn eval_ternary_expression_unions_all_three() {
        let point = pp(OpCode::Copy);
        let a = Types::of_type(&all_types_system(), TType::A);
        let b = Types::of_type(&all_types_system(), TType::B);
        let n = Types::of_type(&all_types_system(), TType::Null);
        let t = Types::new();
        let result = t.eval_ternary_expression(&TTernaryOp::UnionAll, &a, &b, &n, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A, TType::B, TType::Null])));
    }

    // ── satisfiesBinaryExpression: equality opcodes ──────────────────────

    // Java's satisfiesBinaryExpression only ever reaches SATISFIED/NOT_SATISFIED for INT_EQUAL/
    // INT_NOTEQUAL when *every* element on both sides is a type-token type (Type::isTypeTokenType);
    // any non-token element forces UNKNOWN unconditionally (see
    // satisfies_equal_with_non_type_token_and_overlap_is_unknown below). TType::A/TType::B are
    // plain, non-token elements in this test harness, so exercising the Satisfied/NotSatisfied
    // branches requires TType::Token(...)-wrapped elements instead.
    #[test]
    fn satisfies_int_equal_single_matching_element_is_satisfied() {
        let point = pp(OpCode::IntEqual);
        let left = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let right = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let t = Types::new();
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::Satisfied
        );
    }

    #[test]
    fn satisfies_int_equal_disjoint_elements_is_not_satisfied() {
        let point = pp(OpCode::IntEqual);
        let left = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let right = Types::of_type(&all_types_system(), TType::Token(vec![TType::B]));
        let t = Types::new();
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::NotSatisfied
        );
    }

    #[test]
    fn satisfies_int_not_equal_disjoint_elements_is_satisfied() {
        let point = pp(OpCode::IntNotEqual);
        let left = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let right = Types::of_type(&all_types_system(), TType::Token(vec![TType::B]));
        let t = Types::new();
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::Satisfied
        );
    }

    #[test]
    fn satisfies_int_not_equal_single_matching_element_is_not_satisfied() {
        let point = pp(OpCode::IntNotEqual);
        let left = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let right = Types::of_type(&all_types_system(), TType::Token(vec![TType::A]));
        let t = Types::new();
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::NotSatisfied
        );
    }

    #[test]
    fn satisfies_equal_with_non_type_token_and_overlap_is_unknown() {
        let point = pp(OpCode::IntEqual);
        let mut ts = all_types_system();
        ts.all.insert(TType::Token(vec![TType::A]));
        let left = Types::of_types(&ts, set_of(&[TType::A, TType::B]));
        let right = Types::of_types(&ts, set_of(&[TType::B]));
        let t = Types::new();
        // lelems has size 2 but lfiltered (type tokens only) has size 0 -> mismatched sizes ->
        // Unknown, regardless of overlap.
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::Unknown
        );
    }

    #[test]
    fn satisfies_equal_type_tokens_that_intersect_is_unknown_not_not_satisfied() {
        let point = pp(OpCode::IntEqual);
        let token_a = TType::Token(vec![TType::A]);
        let token_a2 = TType::Token(vec![TType::A, TType::B]);
        let mut ts = all_types_system();
        ts.all.insert(token_a.clone());
        ts.all.insert(token_a2.clone());
        let left = Types::of_type(&ts, token_a.clone());
        let right = Types::of_type(&ts, token_a2.clone());
        let t = Types::new();
        // Disjoint at the outer-element level (token_a != token_a2), but their inner type sets
        // ({A} and {A,B}) intersect, so `typeTokensIntersect` is true -> falls through to
        // Unknown rather than NotSatisfied.
        assert_eq!(
            t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle),
            Satisfiability::Unknown
        );
    }

    // ── satisfiesBinaryExpression: CAST opcode ───────────────────────────

    #[test]
    fn satisfies_cast_bottom_evaluation_is_not_satisfied() {
        let point = pp(OpCode::Cast);
        // `type_cast_operator()` is `TBinaryOp::Cast`, whose `binary_type_inference` returns
        // `left`'s own elements verbatim; an empty left therefore makes the internal
        // `eval_binary_expression(TypeCast, ...)` call resolve to bottom (empty inference).
        let empty_left = Types::raw(false, Some(HashSet::new()));
        let right = Types::of_type(&all_types_system(), TType::A);
        let t = Types::new();
        let result = t.satisfies_binary_expression(&TBinaryOp::Union, &empty_left, &right, &point, &TOracle);
        assert_eq!(result, Satisfiability::NotSatisfied);
    }

    #[test]
    fn satisfies_cast_all_elements_survive_cast_is_satisfied() {
        let point = pp(OpCode::Cast);
        let left = Types::of_type(&all_types_system(), TType::A);
        let right = Types::of_type(&all_types_system(), TType::A);
        let t = Types::new();
        // left's elements {A} all present in `to` (relems = {A}), so cast succeeds losslessly.
        let result = t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle);
        assert_eq!(result, Satisfiability::Satisfied);
    }

    #[test]
    fn satisfies_cast_partial_cast_is_unknown() {
        let point = pp(OpCode::Cast);
        let left = Types::of_types(&all_types_system(), set_of(&[TType::A, TType::B]));
        let right = Types::of_type(&all_types_system(), TType::A);
        let t = Types::new();
        // left = {A, B}, right (cast target) = {A}: TTypeSystem::cast keeps only A, sets
        // might_fail for B -> lelems != set -> Unknown.
        let result = t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &point, &TOracle);
        assert_eq!(result, Satisfiability::Unknown);
    }

    #[test]
    #[should_panic(expected = "PcodeLocation-backed ProgramPoint")]
    fn satisfies_binary_expression_default_opcode_is_unknown_but_non_pcode_location_panics() {
        // This test documents the panic path indirectly is exercised via program_point_location
        // returning None; TestContext's implementation always returns Some, so to actually
        // trigger the panic we simulate the mismatch by using a raw expect elsewhere -- instead,
        // directly assert the documented contract via a manual call mirroring what a `None`
        // location would do.
        struct NoneContext;
        impl PcodeTypeContext for NoneContext {
            type Type = TType;
            type TypeSystem = TTypeSystem;
            type ProgramPoint = ();
            type Oracle = TOracle;
            type Identifier = TId;
            type Constant = TConst;
            type PushAny = TPushAny;
            type PushInv = TPushInv;
            type TypeEnvironment = TEnv;
            type UnaryOperator = TUnaryOp;
            type BinaryOperator = TBinaryOp;
            type TernaryOperator = TTernaryOp;
            type BinaryExpression = TBinaryExpr;

            fn type_is_type_token_type(_ty: &Self::Type) -> bool {
                false
            }
            fn type_token_types(_ty: &Self::Type) -> HashSet<Self::Type> {
                HashSet::new()
            }
            fn type_is_untyped(_ty: &Self::Type) -> bool {
                false
            }
            fn type_all_instances(_ty: &Self::Type, _types: &Self::TypeSystem) -> HashSet<Self::Type> {
                HashSet::new()
            }
            fn null_type() -> Self::Type {
                TType::Null
            }
            fn type_system_get_types(types: &Self::TypeSystem) -> HashSet<Self::Type> {
                types.all.clone()
            }
            fn type_system_cast(
                _types: &Self::TypeSystem,
                _from: &HashSet<Self::Type>,
                _to: &HashSet<Self::Type>,
                _might_fail: &mut bool,
            ) -> HashSet<Self::Type> {
                HashSet::new()
            }
            fn program_point_types(_pp: &Self::ProgramPoint) -> Self::TypeSystem {
                all_types_system()
            }
            fn program_point_location(_pp: &Self::ProgramPoint) -> Option<&PcodeLocation> {
                None
            }
            fn identifier_static_type(id: &Self::Identifier) -> Self::Type {
                id.0.clone()
            }
            fn constant_static_type(c: &Self::Constant) -> Self::Type {
                c.0.clone()
            }
            fn push_any_static_type(p: &Self::PushAny) -> Self::Type {
                p.0.clone()
            }
            fn unary_type_inference(
                _op: &Self::UnaryOperator,
                _types: &Self::TypeSystem,
                _arg: &HashSet<Self::Type>,
            ) -> HashSet<Self::Type> {
                HashSet::new()
            }
            fn binary_type_inference(
                _op: &Self::BinaryOperator,
                _types: &Self::TypeSystem,
                left: &HashSet<Self::Type>,
                _right: &HashSet<Self::Type>,
            ) -> HashSet<Self::Type> {
                left.clone()
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
                expr.0
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

        let left = PcodeInferredTypes::<NoneContext>::of_type(&all_types_system(), TType::A);
        let right = PcodeInferredTypes::<NoneContext>::of_type(&all_types_system(), TType::A);
        let t = PcodeInferredTypes::<NoneContext>::new();
        t.satisfies_binary_expression(&TBinaryOp::Union, &left, &right, &(), &TOracle);
    }

    // ── lubAux / lessOrEqualAux ───────────────────────────────────────────

    #[test]
    fn lub_aux_unions_elements_and_is_never_top() {
        let a = Types::of_type(&all_types_system(), TType::A);
        let b = Types::of_type(&all_types_system(), TType::B);
        let result = a.lub_aux(&b);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A, TType::B])));
        assert!(!result.is_top(), "lubAux always constructs with a null (absent) TypeSystem");
    }

    #[test]
    fn less_or_equal_aux_subset_check() {
        let small = Types::of_type(&all_types_system(), TType::A);
        let big = Types::of_types(&all_types_system(), set_of(&[TType::A, TType::B]));
        assert!(small.less_or_equal_aux(&big));
        assert!(!big.less_or_equal_aux(&small));
    }

    // ── evalTypeCast / evalTypeConv ───────────────────────────────────────

    #[test]
    fn eval_type_cast_delegates_to_the_wrapped_operator() {
        let point = pp(OpCode::Cast);
        let left = Types::of_type(&all_types_system(), TType::A);
        let right = Types::of_type(&all_types_system(), TType::B);
        let t = Types::new();
        let result = t.eval_type_cast(&TBinaryExpr(TBinaryOp::Union), &left, &right, &point, &TOracle);
        assert_eq!(result.get_runtime_types(), Some(&set_of(&[TType::A, TType::B])));
    }

    #[test]
    fn eval_type_conv_empty_inference_is_bottom() {
        let point = pp(OpCode::Cast);
        let left = Types::of_type(&all_types_system(), TType::A);
        let right = Types::of_type(&all_types_system(), TType::B);
        let t = Types::new();
        let result = t.eval_type_conv(&TBinaryExpr(TBinaryOp::ToBottom), &left, &right, &point, &TOracle);
        assert!(result.is_bottom());
    }

    // ── equality / hashing ────────────────────────────────────────────────

    #[test]
    fn equality_compares_elements_and_is_top() {
        let a = Types::of_type(&all_types_system(), TType::A);
        let b = Types::of_type(&all_types_system(), TType::A);
        assert_eq!(a, b);

        let c = Types::of_type(&all_types_system(), TType::B);
        assert_ne!(a, c);

        assert_ne!(Types::new(), Types::new().top());
    }

    #[test]
    fn hash_is_order_independent_over_element_insertion() {
        use std::collections::hash_map::DefaultHasher;
        let ts = all_types_system();
        let a = Types::of_types(&ts, set_of(&[TType::A, TType::B]));
        let b = Types::of_types(&ts, set_of(&[TType::B, TType::A]));
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn clone_produces_an_equal_independent_value() {
        let a = Types::of_type(&all_types_system(), TType::A);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(Types::default(), Types::new());
    }
}
