//! Port of `ghidra.lisa.pcode.analyses.PcodeUpperBounds`.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain;
use crate::feature::lisa::pcode::expressions::pcode_binary_expression::PcodeBinaryExpressionOperator;
use crate::program::seam_stubs::RegisterValue;

/// Stand-in for the runtime `instanceof Identifier` pattern match `assumeBinaryExpression`
/// performs on its (LiSA-typed, unported) `ValueExpression left`/`right` parameters: `left
/// instanceof Identifier x`.
///
/// LiSA's `it.unive.lisa.symbolic.value.{ValueExpression,Identifier}` are an external third-party
/// dependency with no Rust port anywhere in this crate; [`PcodeUpperBounds`] is generic over `Id`,
/// the caller's chosen stand-in for `Identifier`, and any candidate "value expression" type
/// implements this trait to expose whether (and as what `Id`) it actually is one.
pub trait AsIdentifier<Id> {
    /// Returns the wrapped identifier if this expression dynamically is one, mirroring `x` bound
    /// by a successful `instanceof Identifier x` check; `None` mirrors a failed check.
    fn as_identifier(&self) -> Option<&Id>;
}

/// Stand-in for the subset of LiSA's `it.unive.lisa.analysis.nonrelational.value.
/// ValueEnvironment<PcodeUpperBounds>` that [`PcodeUpperBounds::assume_binary_expression`]
/// actually touches: reading and functionally updating the per-identifier abstract state.
///
/// External third-party dependency with no Rust port anywhere in this crate (the same situation
/// [`PcodeNonRelationalValueDomain`]'s docs describe); generic over `Id`, the same stand-in
/// [`AsIdentifier`] and [`PcodeUpperBounds`] itself are generic over.
pub trait ValueEnvironmentLike<Id>: Sized {
    /// Java: `environment.getState(id)`.
    fn get_state(&self, id: &Id) -> PcodeUpperBounds<Id>;

    /// Java: `environment.putState(id, value)`. LiSA's `ValueEnvironment` is a persistent/
    /// functional map -- `putState` returns a new environment rather than mutating in place --
    /// mirrored here by taking `self` by value and returning a (possibly new) `Self`, so callers
    /// can chain `environment.put_state(x, set.clone()).put_state(y, set)` exactly like Java's
    /// `environment.putState(x, set).putState(y, set)`.
    fn put_state(self, id: &Id, value: PcodeUpperBounds<Id>) -> Self;
}

/// Stand-in for LiSA's `it.unive.lisa.util.representation.StructuredRepresentation`, narrowed to
/// the three shapes [`PcodeUpperBounds::representation`] actually builds: `new
/// StringRepresentation("{}")` for a top domain, `Lattice.bottomRepresentation()` for a bottom
/// domain, or `new SetRepresentation(bounds, StringRepresentation::new)` otherwise. That LiSA type
/// (and the `StringRepresentation`/`SetRepresentation`/`Lattice.bottomRepresentation()` helpers
/// building it) is an external third-party dependency with no Rust port anywhere in this crate, so
/// this narrow enum takes its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpperBoundsRepresentation<Id> {
    /// Java: `new StringRepresentation("{}")`.
    Top,
    /// Java: `Lattice.bottomRepresentation()`.
    Bottom,
    /// Java: `new SetRepresentation(bounds, StringRepresentation::new)`.
    Set(Vec<Id>),
}

/// The upper bounds abstract domain: for each program variable identifier, the set of other
/// identifiers known to be upper bounds on its value (or the abstract top/bottom elements).
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeUpperBounds` in the Java source, which
/// `implements PcodeNonRelationalValueDomain<PcodeUpperBounds>, Iterable<Identifier>`. As with
/// [`PcodeNonRelationalValueDomain`]'s own docs, the full LiSA `BaseNonRelationalValueDomain`/
/// `Lattice` framework this class's `top()`/`bottom()`/`lubAux`/`glbAux`/`lessOrEqualAux`/
/// `wideningAux` overrides are built on has no Rust port in this crate. This port is generic over
/// `Id`, the caller's chosen stand-in for LiSA's `Identifier`.
///
/// # Deviations from Java
///
/// * Java's `TOP`/`BOTTOM` are `private static final` singleton instances, reused by reference
///   from [`PcodeUpperBounds::top`]/[`PcodeUpperBounds::bottom`]. Since `Id` is a type parameter
///   here, Rust has no way to express a single non-generic static shared across every
///   instantiation; [`top`](Self::top)/[`bottom`](Self::bottom) instead construct a fresh (but
///   value-equal, per the ported [`PartialEq`] impl below) instance on each call. Nothing in this
///   class (or its one caller, [`assume_binary_expression`](Self::assume_binary_expression))
///   relies on `TOP`/`BOTTOM` reference identity -- only on value equality and the `isTop`/
///   `isBottom`/`bounds` state those references carry -- so this is behavior-preserving.
/// * `.glb(...)` is called (not `.glbAux(...)`) inside `assumeBinaryExpression`'s body -- the
///   general, top/bottom-guarded lattice operation LiSA's unported `BaseLattice` interface
///   supplies as a default method over the abstract `*Aux` methods this class overrides. Since
///   that interface is itself external and unported, [`PcodeUpperBounds::glb`]/
///   [`PcodeUpperBounds::lub`] below are this port's reconstruction of `BaseLattice`'s well-known,
///   standard guard shape (short-circuit on equal operands, then on bottom/top, before falling
///   back to the `*_aux` override) -- not a byte-for-byte transcription of a file this port
///   actually read, since that file lives outside this repository. `assumeBinaryExpression` only
///   ever calls `.glb(...)` on ordinary (non-top, non-bottom) operands in every real call path
///   this class's own logic reaches, so the guarded branches are exercised by this port's tests
///   only as a best-effort reconstruction, not a verified-against-Java faithfulness claim the way
///   the rest of this file's ports are.
#[derive(Clone, Debug)]
pub struct PcodeUpperBounds<Id> {
    bounds: Option<HashSet<Id>>,
    is_top: bool,
}

impl<Id: Clone + Eq + Hash> PcodeUpperBounds<Id> {
    /// Java: `public PcodeUpperBounds()`, `this(true);`.
    pub fn new() -> Self {
        Self::with_top_flag(true)
    }

    /// Java: `public PcodeUpperBounds(boolean isTop)`.
    ///
    /// # Preserved quirk
    ///
    /// Java stores `bounds = null` unconditionally here, regardless of `is_top`. Calling
    /// [`is_bottom`](Self::is_bottom) on a `PcodeUpperBounds::with_top_flag(false)` therefore hits
    /// Java's `bounds.isEmpty()` on a `null` `bounds` -- a `NullPointerException` -- which this
    /// port reproduces as a panic rather than working around; see [`is_bottom`](Self::is_bottom)'s
    /// own docs. No call site in this file (or the [`top`](Self::top)/[`bottom`](Self::bottom)
    /// helpers) actually constructs this degenerate `is_top: false` shape -- it is only reachable
    /// via this public constructor, same as Java.
    pub fn with_top_flag(is_top: bool) -> Self {
        Self { bounds: None, is_top }
    }

    /// Java: `public PcodeUpperBounds(Set<Identifier> bounds)`.
    pub fn from_bounds(bounds: HashSet<Id>) -> Self {
        Self { bounds: Some(bounds), is_top: false }
    }

    /// Java: `top()`. See the struct docs' "Deviations from Java" note on why this constructs a
    /// fresh, value-equal instance rather than returning a shared singleton reference.
    pub fn top() -> Self {
        Self::with_top_flag(true)
    }

    /// Java: `bottom()`. See [`top`](Self::top)'s docs.
    pub fn bottom() -> Self {
        Self::from_bounds(HashSet::new())
    }

    /// Java: `isTop()`, inherited from LiSA's unported `Lattice` interface as a default method
    /// (`return equals(top())`, equivalent in practice to `this == TOP` for the shared singleton).
    /// For every instance constructible through this port's own API, that is exactly equivalent to
    /// reading the `isTop` field directly -- the only way to build an instance with the `isTop`
    /// field `true` also always leaves `bounds` `None` (matching `top()`'s own shape), so this is a
    /// direct field read rather than a reconstructed `equals(top())` call.
    pub fn is_top(&self) -> bool {
        self.is_top
    }

    /// Java: `public boolean isBottom()`, `return !isTop && bounds.isEmpty();`.
    ///
    /// # Preserved quirk
    ///
    /// Java's `&&` short-circuits: when `isTop` is `true`, `bounds.isEmpty()` is never evaluated,
    /// so a top instance (whose `bounds` is always `null`) never NPEs here. But
    /// [`with_top_flag`](Self::with_top_flag) can also construct an instance with the `isTop`
    /// field `false` and `bounds` still `None` (an edge case Java's own public API permits, if
    /// unusual in practice); calling `isBottom()` on *that* shape does throw
    /// `NullPointerException` in Java, reproduced here as a panic.
    ///
    /// # Panics
    ///
    /// If `is_top` is `false` and `bounds` is `None` -- see above.
    pub fn is_bottom(&self) -> bool {
        if self.is_top {
            return false;
        }
        self.bounds
            .as_ref()
            .expect(
                "PcodeUpperBounds::is_bottom: bounds is None with is_top=false (Java NullPointerException)",
            )
            .is_empty()
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> UpperBoundsRepresentation<Id> {
        if self.is_top() {
            return UpperBoundsRepresentation::Top;
        }
        if self.is_bottom() {
            return UpperBoundsRepresentation::Bottom;
        }
        let bounds = self.bounds.as_ref().expect(
            "PcodeUpperBounds::representation: bounds is None despite not being top (invariant violation)",
        );
        UpperBoundsRepresentation::Set(bounds.iter().cloned().collect())
    }

    /// Java: `public PcodeUpperBounds lubAux(PcodeUpperBounds other)`.
    ///
    /// # Panics
    ///
    /// If either operand's `bounds` is `None` (a `NullPointerException` in Java's `new
    /// HashSet<>(bounds)`); this method is meant to be reached only via the guarded
    /// [`lub`](Self::lub) (matching Java's own `BaseLattice.lub` -> `lubAux` dispatch, which never
    /// calls `lubAux` on a top/bottom operand), so this precondition is not expected to trigger
    /// through that path.
    pub fn lub_aux(&self, other: &Self) -> Self {
        let mut result = self.bounds.clone().expect("PcodeUpperBounds::lub_aux: bounds is None");
        let other_bounds =
            other.bounds.as_ref().expect("PcodeUpperBounds::lub_aux: other.bounds is None");
        result.retain(|id| other_bounds.contains(id));
        Self::from_bounds(result)
    }

    /// Java: `public PcodeUpperBounds glbAux(PcodeUpperBounds other)`. See
    /// [`lub_aux`](Self::lub_aux)'s docs for the panic precondition.
    pub fn glb_aux(&self, other: &Self) -> Self {
        let mut result = self.bounds.clone().expect("PcodeUpperBounds::glb_aux: bounds is None");
        let other_bounds =
            other.bounds.as_ref().expect("PcodeUpperBounds::glb_aux: other.bounds is None");
        result.extend(other_bounds.iter().cloned());
        Self::from_bounds(result)
    }

    /// Java: `public boolean lessOrEqualAux(PcodeUpperBounds other)`, `return
    /// bounds.containsAll(other.bounds);`. See [`lub_aux`](Self::lub_aux)'s docs for the panic
    /// precondition.
    pub fn less_or_equal_aux(&self, other: &Self) -> bool {
        let bounds =
            self.bounds.as_ref().expect("PcodeUpperBounds::less_or_equal_aux: bounds is None");
        let other_bounds = other
            .bounds
            .as_ref()
            .expect("PcodeUpperBounds::less_or_equal_aux: other.bounds is None");
        other_bounds.iter().all(|id| bounds.contains(id))
    }

    /// Java: `public PcodeUpperBounds wideningAux(PcodeUpperBounds other)`, `return
    /// other.bounds.containsAll(bounds) ? other : TOP;`. See [`lub_aux`](Self::lub_aux)'s docs for
    /// the panic precondition.
    pub fn widening_aux(&self, other: &Self) -> Self {
        let bounds = self.bounds.as_ref().expect("PcodeUpperBounds::widening_aux: bounds is None");
        let other_bounds = other
            .bounds
            .as_ref()
            .expect("PcodeUpperBounds::widening_aux: other.bounds is None");
        if bounds.iter().all(|id| other_bounds.contains(id)) {
            other.clone()
        }
        else {
            Self::top()
        }
    }

    /// Reconstruction of LiSA's unported `BaseLattice.glb` guard over [`glb_aux`](Self::glb_aux).
    /// See the struct docs' "Deviations from Java" note.
    pub fn glb(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        if self.is_bottom() || other.is_top() {
            return self.clone();
        }
        if self.is_top() || other.is_bottom() {
            return other.clone();
        }
        self.glb_aux(other)
    }

    /// Reconstruction of LiSA's unported `BaseLattice.lub` guard over [`lub_aux`](Self::lub_aux).
    /// See the struct docs' "Deviations from Java" note.
    pub fn lub(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        if self.is_bottom() || other.is_top() {
            return other.clone();
        }
        if self.is_top() || other.is_bottom() {
            return self.clone();
        }
        self.lub_aux(other)
    }

    /// Java: `public Iterator<Identifier> iterator()`.
    pub fn iter(&self) -> Box<dyn Iterator<Item = &Id> + '_> {
        match &self.bounds {
            Some(bounds) => Box::new(bounds.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    /// Java: `public boolean contains(Identifier id)`, `return bounds != null &&
    /// bounds.contains(id);`.
    pub fn contains(&self, id: &Id) -> bool {
        self.bounds.as_ref().is_some_and(|b| b.contains(id))
    }

    /// Java: `public PcodeUpperBounds add(Identifier id)`.
    pub fn add(&self, id: Id) -> Self {
        let mut res: HashSet<Id> = HashSet::new();
        if !self.is_top() && !self.is_bottom() {
            if let Some(bounds) = &self.bounds {
                res.extend(bounds.iter().cloned());
            }
        }
        res.insert(id);
        Self::from_bounds(res)
    }

    /// Java: `public ValueEnvironment<PcodeUpperBounds> assumeBinaryExpression(
    /// ValueEnvironment<PcodeUpperBounds> environment, BinaryOperator operator, ValueExpression
    /// left, ValueExpression right, ProgramPoint src, ProgramPoint dest, SemanticOracle oracle)
    /// throws SemanticException`.
    ///
    /// Java's `ProgramPoint src`/`dest`/`SemanticOracle oracle` parameters are declared (to
    /// satisfy the overridden interface method) but never read in the method body, so they are
    /// dropped from this port's signature -- the same established convention
    /// [`PcodeTernaryExpression::fwd_ternary_semantics`](crate::feature::lisa::pcode::expressions::pcode_ternary_expression::PcodeTernaryExpression::fwd_ternary_semantics)'s
    /// docs describe for its own unused `interprocedural`/`expressions` parameters.
    pub fn assume_binary_expression<Env, L, R>(
        &self,
        environment: Env,
        operator: &PcodeBinaryExpressionOperator,
        left: &L,
        right: &R,
    ) -> Env
    where
        Env: ValueEnvironmentLike<Id>,
        L: AsIdentifier<Id>,
        R: AsIdentifier<Id>,
    {
        let (Some(x), Some(y)) = (left.as_identifier(), right.as_identifier())
        else {
            return environment;
        };

        // "glb is the union!" -- Java source's own comment.
        if !matches!(operator, PcodeBinaryExpressionOperator::Other(_)) {
            match operator {
                PcodeBinaryExpressionOperator::ComparisonEq => {
                    // x == y
                    let set = environment.get_state(x).glb(&environment.get_state(y));
                    return environment.put_state(x, set.clone()).put_state(y, set);
                }
                PcodeBinaryExpressionOperator::ComparisonLt => {
                    // x < y
                    let singleton: HashSet<Id> = std::iter::once(y.clone()).collect();
                    let set = environment
                        .get_state(x)
                        .glb(&environment.get_state(y))
                        .glb(&Self::from_bounds(singleton));
                    return environment.put_state(x, set);
                }
                PcodeBinaryExpressionOperator::ComparisonLe => {
                    // x <= y
                    let set = environment.get_state(x).glb(&environment.get_state(y));
                    return environment.put_state(x, set);
                }
                _ => {}
            }
        }

        environment
    }
}

impl<Id: Clone + Eq + Hash> Default for PcodeUpperBounds<Id> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Id: Eq + Hash> PartialEq for PcodeUpperBounds<Id> {
    /// Java: `public boolean equals(Object obj)`, `return Objects.equals(bounds, other.bounds) &&
    /// isTop == other.isTop;`.
    fn eq(&self, other: &Self) -> bool {
        self.bounds == other.bounds && self.is_top == other.is_top
    }
}

impl<Id: Eq + Hash> Eq for PcodeUpperBounds<Id> {}

impl<Id: Hash + Eq> Hash for PcodeUpperBounds<Id> {
    /// Java: `public int hashCode()`, `return Objects.hash(bounds, isTop);`.
    ///
    /// Java's `Set.hashCode()` (used via `Objects.hash`) is defined as an order-independent sum
    /// of each element's hash code, so two value-equal `bounds` sets always hash equally
    /// regardless of iteration order -- reproduced here the same way (summing each element's hash
    /// via a scratch [`std::collections::hash_map::DefaultHasher`]) rather than hashing Rust's own
    /// `HashSet` iteration order directly, since `std::collections::HashSet` deliberately does not
    /// implement [`Hash`] itself.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.is_top.hash(state);
        let mut acc: u64 = 0;
        if let Some(bounds) = &self.bounds {
            for id in bounds {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                id.hash(&mut h);
                acc = acc.wrapping_add(h.finish());
            }
        }
        acc.hash(state);
    }
}

impl<'a, Id: Clone + Eq + Hash> IntoIterator for &'a PcodeUpperBounds<Id> {
    type Item = &'a Id;
    type IntoIter = Box<dyn Iterator<Item = &'a Id> + 'a>;

    /// Java: `public Iterator<Identifier> iterator()` (`Iterable<Identifier>`).
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<Id: Clone + Eq + Hash> PcodeNonRelationalValueDomain<PcodeUpperBounds<Id>> for PcodeUpperBounds<Id> {
    /// Java: `public PcodeUpperBounds getValue(RegisterValue rv)`, `return top();`.
    fn get_value(&self, rv: Option<&dyn RegisterValue>) -> Option<PcodeUpperBounds<Id>> {
        let _ = rv;
        Some(Self::top())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn set(ids: &[&'static str]) -> HashSet<&'static str> {
        ids.iter().copied().collect()
    }

    // ── top / bottom / representation ───────────────────────────────────────

    #[test]
    fn top_is_top_and_not_bottom() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        assert!(top.is_top());
        assert!(!top.is_bottom());
    }

    #[test]
    fn bottom_is_bottom_and_not_top() {
        let bottom: PcodeUpperBounds<&str> = PcodeUpperBounds::bottom();
        assert!(bottom.is_bottom());
        assert!(!bottom.is_top());
    }

    #[test]
    fn default_and_new_match_top() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::new();
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::default();
        assert_eq!(a, PcodeUpperBounds::top());
        assert_eq!(b, PcodeUpperBounds::top());
    }

    #[test]
    #[should_panic(expected = "Java NullPointerException")]
    fn is_bottom_panics_for_the_degenerate_with_top_flag_false_shape() {
        // Preserved quirk: with_top_flag(false) still leaves bounds None, matching Java's own
        // constructor, so is_bottom() NPEs on this shape exactly like Java does.
        let weird: PcodeUpperBounds<&str> = PcodeUpperBounds::with_top_flag(false);
        weird.is_bottom();
    }

    #[test]
    fn representation_top_and_bottom() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        assert_eq!(top.representation(), UpperBoundsRepresentation::Top);

        let bottom: PcodeUpperBounds<&str> = PcodeUpperBounds::bottom();
        assert_eq!(bottom.representation(), UpperBoundsRepresentation::Bottom);
    }

    #[test]
    fn representation_ordinary_set() {
        let bounds: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert_eq!(bounds.representation(), UpperBoundsRepresentation::Set(vec!["x"]));
    }

    // ── lub_aux / glb_aux / less_or_equal_aux / widening_aux ────────────────

    #[test]
    fn lub_aux_is_intersection() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y", "z"]));
        let result = a.lub_aux(&b);
        assert_eq!(result, PcodeUpperBounds::from_bounds(set(&["y"])));
    }

    #[test]
    fn glb_aux_is_union() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y"]));
        let result = a.glb_aux(&b);
        assert_eq!(result, PcodeUpperBounds::from_bounds(set(&["x", "y"])));
    }

    #[test]
    #[should_panic(expected = "bounds is None")]
    fn lub_aux_panics_on_a_top_operand() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let other: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        top.lub_aux(&other);
    }

    #[test]
    fn less_or_equal_aux_true_when_self_contains_all_of_other() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert!(a.less_or_equal_aux(&b));
        assert!(!b.less_or_equal_aux(&a));
    }

    #[test]
    fn widening_aux_returns_other_when_other_contains_all_of_self() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        assert_eq!(a.widening_aux(&b), b);
    }

    #[test]
    fn widening_aux_returns_top_when_other_does_not_contain_all_of_self() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "z"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        assert_eq!(a.widening_aux(&b), PcodeUpperBounds::top());
    }

    // ── glb / lub guards ─────────────────────────────────────────────────────

    #[test]
    fn glb_of_bottom_and_anything_is_bottom() {
        let bottom: PcodeUpperBounds<&str> = PcodeUpperBounds::bottom();
        let other: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert_eq!(bottom.glb(&other), bottom);
    }

    #[test]
    fn glb_of_top_and_x_is_x() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let other: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert_eq!(top.glb(&other), other);
    }

    #[test]
    fn glb_of_two_ordinary_sets_delegates_to_glb_aux() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y"]));
        assert_eq!(a.glb(&b), a.glb_aux(&b));
    }

    #[test]
    fn lub_of_bottom_and_x_is_x() {
        let bottom: PcodeUpperBounds<&str> = PcodeUpperBounds::bottom();
        let other: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert_eq!(bottom.lub(&other), other);
    }

    #[test]
    fn lub_of_top_and_anything_is_top() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let other: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert_eq!(top.lub(&other), top);
    }

    // ── contains / add / iter ────────────────────────────────────────────────

    #[test]
    fn contains_reflects_membership() {
        let bounds: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        assert!(bounds.contains(&"x"));
        assert!(!bounds.contains(&"y"));
    }

    #[test]
    fn contains_is_false_for_top_since_bounds_is_none() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        assert!(!top.contains(&"x"));
    }

    #[test]
    fn add_to_an_ordinary_set_extends_it() {
        let bounds: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let extended = bounds.add("y");
        assert!(extended.contains(&"x"));
        assert!(extended.contains(&"y"));
    }

    #[test]
    fn add_to_top_or_bottom_yields_a_fresh_singleton() {
        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let from_top = top.add("x");
        assert!(!from_top.is_top());
        assert_eq!(from_top, PcodeUpperBounds::from_bounds(set(&["x"])));

        let bottom: PcodeUpperBounds<&str> = PcodeUpperBounds::bottom();
        let from_bottom = bottom.add("x");
        assert_eq!(from_bottom, PcodeUpperBounds::from_bounds(set(&["x"])));
    }

    #[test]
    fn iter_yields_every_bound_and_is_empty_for_top() {
        let bounds: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        let mut collected: Vec<&&str> = bounds.iter().collect();
        collected.sort();
        assert_eq!(collected, vec![&"x", &"y"]);

        let top: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        assert_eq!(top.iter().count(), 0);

        // IntoIterator for &PcodeUpperBounds mirrors Iterable<Identifier>.
        let mut via_into_iter: Vec<&&str> = (&bounds).into_iter().collect();
        via_into_iter.sort();
        assert_eq!(via_into_iter, vec![&"x", &"y"]);
    }

    // ── equals / hash ────────────────────────────────────────────────────────

    #[test]
    fn equal_bounds_and_top_flag_are_equal() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y", "x"]));
        assert_eq!(a, b);
    }

    #[test]
    fn different_bounds_are_not_equal() {
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y"]));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_is_consistent_with_equality() {
        use std::collections::hash_map::DefaultHasher;
        let a: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x", "y"]));
        let b: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["y", "x"]));
        assert_eq!(a, b);

        let mut h1 = DefaultHasher::new();
        a.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // ── PcodeNonRelationalValueDomain::get_value ────────────────────────────

    #[test]
    fn get_value_always_returns_top() {
        let bounds: PcodeUpperBounds<&str> = PcodeUpperBounds::from_bounds(set(&["x"]));
        let value = PcodeNonRelationalValueDomain::get_value(&bounds, None);
        assert_eq!(value, Some(PcodeUpperBounds::top()));
    }

    // ── assume_binary_expression ─────────────────────────────────────────────

    #[derive(Clone, Debug)]
    struct MockExpr {
        id: Option<&'static str>,
    }

    impl AsIdentifier<&'static str> for MockExpr {
        fn as_identifier(&self) -> Option<&&'static str> {
            self.id.as_ref()
        }
    }

    fn ident(id: &'static str) -> MockExpr {
        MockExpr { id: Some(id) }
    }

    fn not_ident() -> MockExpr {
        MockExpr { id: None }
    }

    #[derive(Clone, Debug)]
    struct MockEnv {
        states: HashMap<&'static str, PcodeUpperBounds<&'static str>>,
    }

    impl MockEnv {
        fn new() -> Self {
            Self { states: HashMap::new() }
        }

        fn with(mut self, id: &'static str, value: PcodeUpperBounds<&'static str>) -> Self {
            self.states.insert(id, value);
            self
        }
    }

    impl ValueEnvironmentLike<&'static str> for MockEnv {
        fn get_state(&self, id: &&'static str) -> PcodeUpperBounds<&'static str> {
            self.states.get(id).cloned().unwrap_or_else(PcodeUpperBounds::top)
        }

        fn put_state(mut self, id: &&'static str, value: PcodeUpperBounds<&'static str>) -> Self {
            self.states.insert(*id, value);
            self
        }
    }

    #[test]
    fn assume_binary_expression_passes_through_when_left_is_not_an_identifier() {
        let dom: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let env = MockEnv::new().with("x", PcodeUpperBounds::from_bounds(set(&["a"])));
        let result = dom.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &not_ident(),
            &ident("y"),
        );
        assert_eq!(result.states, env.states);
    }

    #[test]
    fn assume_binary_expression_passes_through_for_an_unrecognized_operator() {
        use crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator;
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        let op = PcodeOp::new(OpCode::IntAdd, seq, vec![], None);

        let dom: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let env = MockEnv::new().with("x", PcodeUpperBounds::from_bounds(set(&["a"])));
        let result = dom.assume_binary_expression(
            env.clone(),
            &PcodeBinaryExpressionOperator::Other(PcodeBinaryOperator::new(op)),
            &ident("x"),
            &ident("y"),
        );
        assert_eq!(result.states, env.states);
    }

    #[test]
    fn assume_binary_expression_comparison_eq_glbs_and_shares_state_between_both_identifiers() {
        let dom: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let env = MockEnv::new()
            .with("x", PcodeUpperBounds::from_bounds(set(&["a", "b"])))
            .with("y", PcodeUpperBounds::from_bounds(set(&["b", "c"])));

        let result = dom.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonEq,
            &ident("x"),
            &ident("y"),
        );

        // glb is the union.
        let expected = PcodeUpperBounds::from_bounds(set(&["a", "b", "c"]));
        assert_eq!(result.get_state(&"x"), expected);
        assert_eq!(result.get_state(&"y"), expected);
    }

    #[test]
    fn assume_binary_expression_comparison_le_glbs_only_the_left_identifier() {
        let dom: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let env = MockEnv::new()
            .with("x", PcodeUpperBounds::from_bounds(set(&["a"])))
            .with("y", PcodeUpperBounds::from_bounds(set(&["b"])));

        let result = dom.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonLe,
            &ident("x"),
            &ident("y"),
        );

        assert_eq!(result.get_state(&"x"), PcodeUpperBounds::from_bounds(set(&["a", "b"])));
        // y is left untouched by putState.
        assert_eq!(result.get_state(&"y"), PcodeUpperBounds::from_bounds(set(&["b"])));
    }

    #[test]
    fn assume_binary_expression_comparison_lt_also_folds_in_y_itself_as_a_bound() {
        let dom: PcodeUpperBounds<&str> = PcodeUpperBounds::top();
        let env = MockEnv::new()
            .with("x", PcodeUpperBounds::from_bounds(set(&["a"])))
            .with("y", PcodeUpperBounds::from_bounds(set(&["b"])));

        let result = dom.assume_binary_expression(
            env,
            &PcodeBinaryExpressionOperator::ComparisonLt,
            &ident("x"),
            &ident("y"),
        );

        assert_eq!(result.get_state(&"x"), PcodeUpperBounds::from_bounds(set(&["a", "b", "y"])));
    }
}
