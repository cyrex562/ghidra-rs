//! Port of `ghidra.lisa.pcode.analyses.PcodeTaint`.

use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;

/// Stand-in for LiSA's `it.unive.lisa.program.annotations.{Annotations,Annotation}`, narrowed to
/// what [`PcodeTaint::default_approx`]/[`PcodeThreeLevelTaint::default_approx`]
/// (`ghidra.lisa.pcode.analyses.PcodeThreeLevelTaint`) actually touch: whether an identifier has
/// any annotations at all, and (if so) each annotation's name string. `Annotations`/`Annotation`
/// are external third-party dependencies with no Rust port anywhere in this crate, so, following
/// this crate's established seam-stub convention, this narrow trait takes their place.
pub trait HasAnnotations {
    /// Java: `id.getAnnotations()`, then each element's `.getAnnotationName()`. Returns the
    /// annotation names directly (an empty slice mirrors `Annotations.isEmpty()`).
    fn annotation_names(&self) -> &[String];
}

/// Stand-in for the runtime `pp.getLocation() instanceof PcodeLocation ploc` pattern match that
/// [`PcodeTaint::default_approx`]/[`PcodeThreeLevelTaint::default_approx`] perform on their
/// (LiSA-typed, unported) `ProgramPoint` parameter. Mirrors
/// [`ProgramPoint`](super::pcode_non_relational_value_domain::ProgramPoint)'s role for that other
/// class in this package, narrowed differently: this method needs the *p-code* location (for its
/// address), not the *instruction* location that trait exposes.
pub trait TaintProgramPoint {
    /// Returns the p-code location this program point occurs at, if it is (dynamically) one.
    /// `None` mirrors a failed `instanceof PcodeLocation` check.
    fn pcode_location(&self) -> Option<&PcodeLocation>;
}

/// A two-level taint abstract domain: clean or (possibly) tainted.
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeTaint` in the Java source, which `extends
/// it.unive.lisa.analysis.taint.BaseTaint<PcodeTaint>` (composition over inheritance: Java's
/// `extends` becomes this being a plain enum with no base-class field, since `BaseTaint` itself
/// carries no state of its own -- only unported default-method behavior, see [`Self::default_approx`]'s
/// docs).
///
/// # Representation
///
/// Java represents the three states (`TAINTED`/`CLEAN`/`BOTTOM`) as `private static final
/// PcodeTaint` singletons wrapping a nullable `Boolean taint` field (`true`/`false`/`null`), with
/// `isPossiblyTainted()` testing `this == TAINTED` (reference identity). Unlike
/// [`PcodeParity`](super::pcode_parity::PcodeParity)/[`PcodeSign`](super::pcode_sign::PcodeSign)
/// (whose backing `byte` field is open-ended, so a caller can construct a value-equal-but-not-
/// identical instance that observably behaves differently under an identity check), a Java
/// `Boolean` has exactly three possible values (`TRUE`/`FALSE`/`null`) and this class names all
/// three -- so *every* possible [`PcodeTaint`] instance, however constructed, is value-equal to
/// exactly one of [`Self::Tainted`]/[`Self::Clean`]/[`Self::Bottom`], with no room for an "orphan"
/// state the way [`PcodeSign::get_value`](super::pcode_sign::PcodeSign::get_value)'s quirk
/// produces. Nothing in this file ever constructs a fresh, non-canonical instance and relies on
/// identity to distinguish it from a canonical one (there is no `getValue`-style leaf method
/// here), so this port represents the three states as a plain enum and implements
/// [`Self::is_possibly_tainted`] via value comparison -- behaviorally equivalent to Java's
/// identity check for every instance this class's own code can ever produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PcodeTaint {
    /// Java: `private static final PcodeTaint TAINTED = new PcodeTaint(true);`.
    Tainted,
    /// Java: `private static final PcodeTaint CLEAN = new PcodeTaint(false);`.
    Clean,
    /// Java: `private static final PcodeTaint BOTTOM = new PcodeTaint(null);`.
    Bottom,
}

/// Stand-in for LiSA's `it.unive.lisa.util.representation.StructuredRepresentation`, narrowed to
/// the shapes [`PcodeTaint::representation`] actually builds -- the same convention
/// [`ParityRepresentation`](super::pcode_parity::ParityRepresentation)'s docs describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintRepresentation {
    /// Java: `Lattice.bottomRepresentation()`.
    Bottom,
    /// Java: `new StringRepresentation("#")`.
    Tainted,
    /// Java: `new StringRepresentation("_")`.
    Clean,
}

impl PcodeTaint {
    /// Java: `public PcodeTaint()`, `this(true);` -- builds a value-equal-to-[`Self::Tainted`]
    /// instance. See the enum docs for why this is exactly [`Self::Tainted`] rather than a
    /// distinct non-canonical value.
    pub fn new() -> Self {
        Self::Tainted
    }

    /// Java: `public PcodeTaint(Boolean taint)`: `true` -> tainted, `false` -> clean, `null` ->
    /// bottom.
    pub fn with_taint(taint: Option<bool>) -> Self {
        match taint {
            Some(true) => Self::Tainted,
            Some(false) => Self::Clean,
            None => Self::Bottom,
        }
    }

    /// Java: `protected PcodeTaint tainted()`, `return TAINTED;`.
    fn tainted(&self) -> Self {
        Self::Tainted
    }

    /// Java: `protected PcodeTaint clean()`, `return CLEAN;`.
    fn clean(&self) -> Self {
        Self::Clean
    }

    /// Java: `public boolean isPossiblyTainted()`, `return this == TAINTED;`. See the enum docs
    /// for why value equality is behaviorally equivalent here.
    pub fn is_possibly_tainted(&self) -> bool {
        matches!(self, Self::Tainted)
    }

    /// Java: `public boolean isAlwaysTainted()`, `return false;`. Hardcoded `false` regardless of
    /// `self` -- this two-level domain has no "always tainted" state distinct from
    /// [`Self::Tainted`] itself.
    pub fn is_always_tainted(&self) -> bool {
        false
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> TaintRepresentation {
        match self {
            Self::Bottom => TaintRepresentation::Bottom,
            Self::Tainted => TaintRepresentation::Tainted,
            Self::Clean => TaintRepresentation::Clean,
        }
    }

    /// Java: `public PcodeTaint top()`, `return CLEAN;`. Note this domain's lattice top is
    /// "clean", not an "unknown" element -- the class's own design choice, not a port artifact.
    pub fn top(&self) -> Self {
        Self::Clean
    }

    /// Java: `public PcodeTaint bottom()`, `return BOTTOM;`.
    pub fn bottom(&self) -> Self {
        Self::Bottom
    }

    /// Java: inherited `isTop()`/`isBottom()` defaults (`equals(top())`/`equals(bottom())`) from
    /// LiSA's unported `Lattice` interface, the same reconstruction
    /// [`PcodeParity::is_top`](super::pcode_parity::PcodeParity::is_top)'s docs describe.
    pub fn is_top(&self) -> bool {
        *self == self.top()
    }

    /// See [`Self::is_top`]'s docs.
    pub fn is_bottom(&self) -> bool {
        *self == Self::Bottom
    }

    /// Java: `protected PcodeTaint defaultApprox(Identifier id, ProgramPoint pp, SemanticOracle
    /// oracle) throws SemanticException`. Java's unused `oracle` parameter is dropped -- the same
    /// established convention
    /// [`PcodeParity::eval_null_constant`](super::pcode_parity::PcodeParity::eval_null_constant)'s
    /// docs describe.
    ///
    /// Java's `super.defaultApprox(id, pp, oracle)` call (the empty-annotations branch) reaches
    /// into LiSA's unported `BaseTaint` base class, whose default implementation this port has no
    /// source to transcribe (external `it.unive.lisa` dependency, same situation
    /// [`Trend`](super::trend::Trend)'s docs describe for a sibling reconstruction). This is
    /// modeled as `self.top()`, matching this whole codebase's established "no information ->
    /// `top()`" convention for exactly this kind of unported fallback (e.g.
    /// [`PcodeParity::eval_null_constant`]/[`PcodeSign::eval_null_constant`](super::pcode_sign::PcodeSign::eval_null_constant)),
    /// and matching `BaseTaint`'s own subclasses always designing `top()` as the "no information"
    /// element.
    pub fn default_approx<Id, Pp>(&self, id: &Id, pp: &Pp) -> Self
    where
        Id: HasAnnotations,
        Pp: TaintProgramPoint,
    {
        let annots = id.annotation_names();
        if annots.is_empty() {
            return self.top();
        }

        if let Some(ploc) = pp.pcode_location() {
            let needle = format!("@{}", ploc.get_address());
            for name in annots {
                if name.contains(&needle) {
                    if name.contains("Tainted") {
                        return self.tainted();
                    }
                    if name.contains("Clean") {
                        return self.clean();
                    }
                }
            }
        }

        self.bottom()
    }

    /// Java: `public PcodeTaint lub(PcodeTaint other) throws SemanticException`.
    ///
    /// Java's defensive `other == null` check has no Rust equivalent (`other: &Self` cannot be
    /// null), so it is dropped; Java's `this == other` and `this.equals(other)` disjuncts collapse
    /// to a single value comparison here since (per the enum docs) reference identity and value
    /// equality coincide for every instance this class can produce.
    pub fn lub(&self, other: &Self) -> Self {
        if other.is_bottom() || self.is_top() || self == other {
            *self
        }
        else if self.is_bottom() {
            *other
        }
        else {
            self.lub_aux(other)
        }
    }

    /// Java: `public PcodeTaint lubAux(PcodeTaint other) throws SemanticException`, `return
    /// TAINTED;`.
    pub fn lub_aux(&self, _other: &Self) -> Self {
        Self::Tainted
    }

    /// Java: `public PcodeTaint wideningAux(PcodeTaint other) throws SemanticException`, `return
    /// TAINTED; // should never happen`.
    pub fn widening_aux(&self, _other: &Self) -> Self {
        Self::Tainted
    }

    /// Java: `public boolean lessOrEqualAux(PcodeTaint other) throws SemanticException`, `return
    /// false; // should never happen`.
    pub fn less_or_equal_aux(&self, _other: &Self) -> bool {
        false
    }
}

impl Default for PcodeTaint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_and_default_are_tainted() {
        assert_eq!(PcodeTaint::new(), PcodeTaint::Tainted);
        assert_eq!(PcodeTaint::default(), PcodeTaint::Tainted);
    }

    #[test]
    fn with_taint_maps_true_false_none() {
        assert_eq!(PcodeTaint::with_taint(Some(true)), PcodeTaint::Tainted);
        assert_eq!(PcodeTaint::with_taint(Some(false)), PcodeTaint::Clean);
        assert_eq!(PcodeTaint::with_taint(None), PcodeTaint::Bottom);
    }

    // ── top / bottom ─────────────────────────────────────────────────────────

    #[test]
    fn top_is_clean() {
        assert_eq!(PcodeTaint::Tainted.top(), PcodeTaint::Clean);
        assert!(PcodeTaint::Clean.is_top());
        assert!(!PcodeTaint::Tainted.is_top());
    }

    #[test]
    fn bottom_is_bottom() {
        assert_eq!(PcodeTaint::Tainted.bottom(), PcodeTaint::Bottom);
        assert!(PcodeTaint::Bottom.is_bottom());
        assert!(!PcodeTaint::Clean.is_bottom());
    }

    // ── is_possibly_tainted / is_always_tainted ─────────────────────────────

    #[test]
    fn is_possibly_tainted_true_only_for_tainted() {
        assert!(PcodeTaint::Tainted.is_possibly_tainted());
        assert!(!PcodeTaint::Clean.is_possibly_tainted());
        assert!(!PcodeTaint::Bottom.is_possibly_tainted());
    }

    #[test]
    fn is_always_tainted_is_always_false() {
        assert!(!PcodeTaint::Tainted.is_always_tainted());
        assert!(!PcodeTaint::Clean.is_always_tainted());
        assert!(!PcodeTaint::Bottom.is_always_tainted());
    }

    // ── representation ───────────────────────────────────────────────────────

    #[test]
    fn representation_matches_each_variant() {
        assert_eq!(PcodeTaint::Bottom.representation(), TaintRepresentation::Bottom);
        assert_eq!(PcodeTaint::Tainted.representation(), TaintRepresentation::Tainted);
        assert_eq!(PcodeTaint::Clean.representation(), TaintRepresentation::Clean);
    }

    // ── default_approx ───────────────────────────────────────────────────────

    struct MockId {
        annotations: Vec<String>,
    }

    impl HasAnnotations for MockId {
        fn annotation_names(&self) -> &[String] {
            &self.annotations
        }
    }

    struct MockPp {
        location: Option<PcodeLocation>,
    }

    impl TaintProgramPoint for MockPp {
        fn pcode_location(&self) -> Option<&PcodeLocation> {
            self.location.as_ref()
        }
    }

    fn pcode_loc_at(offset: i64) -> PcodeLocation {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let seq = SequenceNumber::new(Address::new(space, offset), 0);
        PcodeLocation::new(PcodeOp::new(OpCode::Copy, seq, vec![], None))
    }

    #[test]
    fn default_approx_no_annotations_falls_back_to_top() {
        let d = PcodeTaint::Bottom;
        let id = MockId { annotations: vec![] };
        let pp = MockPp { location: None };
        assert_eq!(d.default_approx(&id, &pp), PcodeTaint::Clean);
    }

    #[test]
    fn default_approx_matching_tainted_annotation() {
        let d = PcodeTaint::Bottom;
        let loc = pcode_loc_at(0x1000);
        let addr = loc.get_address();
        let id = MockId { annotations: vec![format!("Tainted@{}", addr)] };
        let pp = MockPp { location: Some(loc) };
        assert_eq!(d.default_approx(&id, &pp), PcodeTaint::Tainted);
    }

    #[test]
    fn default_approx_matching_clean_annotation() {
        let d = PcodeTaint::Bottom;
        let loc = pcode_loc_at(0x2000);
        let addr = loc.get_address();
        let id = MockId { annotations: vec![format!("Clean@{}", addr)] };
        let pp = MockPp { location: Some(loc) };
        assert_eq!(d.default_approx(&id, &pp), PcodeTaint::Clean);
    }

    #[test]
    fn default_approx_annotation_present_but_no_address_match_is_bottom() {
        let d = PcodeTaint::Clean;
        let loc = pcode_loc_at(0x3000);
        let other_addr_annotation = "Tainted@ram:00004000".to_string();
        let id = MockId { annotations: vec![other_addr_annotation] };
        let pp = MockPp { location: Some(loc) };
        assert_eq!(d.default_approx(&id, &pp), PcodeTaint::Bottom);
    }

    #[test]
    fn default_approx_non_pcode_location_with_annotations_is_bottom() {
        let d = PcodeTaint::Clean;
        let id = MockId { annotations: vec!["Tainted@somewhere".to_string()] };
        let pp = MockPp { location: None };
        assert_eq!(d.default_approx(&id, &pp), PcodeTaint::Bottom);
    }

    // ── lub / lubAux / wideningAux / lessOrEqualAux ─────────────────────────

    #[test]
    fn lub_same_value_is_identity() {
        assert_eq!(PcodeTaint::Tainted.lub(&PcodeTaint::Tainted), PcodeTaint::Tainted);
    }

    #[test]
    fn lub_other_bottom_returns_self() {
        assert_eq!(PcodeTaint::Clean.lub(&PcodeTaint::Bottom), PcodeTaint::Clean);
    }

    #[test]
    fn lub_self_top_returns_self() {
        assert_eq!(PcodeTaint::Clean.lub(&PcodeTaint::Tainted), PcodeTaint::Clean);
    }

    #[test]
    fn lub_self_bottom_returns_other() {
        assert_eq!(PcodeTaint::Bottom.lub(&PcodeTaint::Tainted), PcodeTaint::Tainted);
    }

    #[test]
    fn lub_aux_is_always_tainted() {
        assert_eq!(PcodeTaint::Tainted.lub_aux(&PcodeTaint::Clean), PcodeTaint::Tainted);
    }

    #[test]
    fn widening_aux_is_always_tainted() {
        assert_eq!(PcodeTaint::Clean.widening_aux(&PcodeTaint::Bottom), PcodeTaint::Tainted);
    }

    #[test]
    fn less_or_equal_aux_is_always_false() {
        assert!(!PcodeTaint::Tainted.less_or_equal_aux(&PcodeTaint::Clean));
    }
}
