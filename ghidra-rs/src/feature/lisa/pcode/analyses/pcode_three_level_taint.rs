//! Port of `ghidra.lisa.pcode.analyses.PcodeThreeLevelTaint`.

use crate::feature::lisa::pcode::analyses::pcode_taint::{HasAnnotations, TaintProgramPoint};

/// Stand-in for LiSA's `it.unive.lisa.util.representation.StructuredRepresentation`, narrowed to
/// the shapes [`PcodeThreeLevelTaint::representation`] actually builds -- the same convention
/// [`TaintRepresentation`](super::pcode_taint::TaintRepresentation)'s docs describe for the
/// sibling class in this package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeLevelTaintRepresentation {
    /// Java: `Lattice.bottomRepresentation()`.
    Bottom,
    /// Java: `new StringRepresentation("_")`.
    Clean,
    /// Java: `new StringRepresentation("#")`.
    Tainted,
    /// Java: `Lattice.topRepresentation()`.
    Top,
}

/// A three-level taint abstract domain: clean, (always) tainted, or top (tainted along some but
/// not all paths).
///
/// Corresponds to `ghidra.lisa.pcode.analyses.PcodeThreeLevelTaint` in the Java source, which
/// `extends it.unive.lisa.analysis.taint.BaseTaint<PcodeThreeLevelTaint>` (composition over
/// inheritance -- see [`PcodeTaint`](super::pcode_taint::PcodeTaint)'s docs for the same
/// adaptation on its sibling class).
///
/// # Representation
///
/// Unlike [`PcodeTaint`](super::pcode_taint::PcodeTaint) (whose `byte`-backed sibling shares a
/// *public* constructor accepting any `byte`, opening the door to the identity-vs-equality quirks
/// documented on [`PcodeParity`](super::pcode_parity::PcodeParity)/[`PcodeSign`](super::pcode_sign::PcodeSign)),
/// this class's `private PcodeThreeLevelTaint(byte v)` constructor is *not* public -- Java code
/// outside this class can only ever obtain one of the four `TOP`/`TAINTED`/`CLEAN`/`BOTTOM`
/// singletons (via the public no-arg constructor, or this class's own methods), so every
/// reachable instance is both value-equal *and* identical to exactly one of them. This port is
/// therefore a plain 4-variant enum, with `==`/reference-identity checks (e.g. `this == TOP`)
/// ported as ordinary value comparisons -- behaviorally identical for every instance this class
/// can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PcodeThreeLevelTaint {
    /// Java: `private static final PcodeThreeLevelTaint TOP = new PcodeThreeLevelTaint((byte) 3);`.
    Top,
    /// Java: `private static final PcodeThreeLevelTaint TAINTED = new PcodeThreeLevelTaint((byte) 2);`.
    Tainted,
    /// Java: `private static final PcodeThreeLevelTaint CLEAN = new PcodeThreeLevelTaint((byte) 1);`.
    Clean,
    /// Java: `private static final PcodeThreeLevelTaint BOTTOM = new PcodeThreeLevelTaint((byte) 0);`.
    Bottom,
}

impl PcodeThreeLevelTaint {
    /// Java: `public PcodeThreeLevelTaint()`, `this((byte) 3);` -- builds [`Self::Top`].
    pub fn new() -> Self {
        Self::Top
    }

    /// Java: `protected PcodeThreeLevelTaint tainted()`, `return TAINTED;`.
    fn tainted(&self) -> Self {
        Self::Tainted
    }

    /// Java: `protected PcodeThreeLevelTaint clean()`, `return CLEAN;`.
    fn clean(&self) -> Self {
        Self::Clean
    }

    /// Java: `public boolean isAlwaysTainted()`, `return this == TAINTED;`.
    pub fn is_always_tainted(&self) -> bool {
        matches!(self, Self::Tainted)
    }

    /// Java: `public boolean isPossiblyTainted()`, `return this == TOP;`. Note this maps to
    /// [`Self::Top`], *not* [`Self::Tainted`] -- unlike
    /// [`PcodeTaint::is_possibly_tainted`](super::pcode_taint::PcodeTaint::is_possibly_tainted)'s
    /// two-level equivalent, which maps to its own `TAINTED`. This class's `TOP` represents
    /// "tainted along some but not all paths", which is exactly what "possibly tainted" (as
    /// opposed to *always* tainted) means here.
    pub fn is_possibly_tainted(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Java: `public StructuredRepresentation representation()`.
    pub fn representation(&self) -> ThreeLevelTaintRepresentation {
        match self {
            Self::Bottom => ThreeLevelTaintRepresentation::Bottom,
            Self::Clean => ThreeLevelTaintRepresentation::Clean,
            Self::Tainted => ThreeLevelTaintRepresentation::Tainted,
            Self::Top => ThreeLevelTaintRepresentation::Top,
        }
    }

    /// Java: `public PcodeThreeLevelTaint top()`, `return TOP;`.
    pub fn top(&self) -> Self {
        Self::Top
    }

    /// Java: `public PcodeThreeLevelTaint bottom()`, `return BOTTOM;`.
    pub fn bottom(&self) -> Self {
        Self::Bottom
    }

    /// Java: `protected PcodeThreeLevelTaint defaultApprox(Identifier id, ProgramPoint pp,
    /// SemanticOracle oracle) throws SemanticException`. Structurally identical to
    /// [`PcodeTaint::default_approx`](super::pcode_taint::PcodeTaint::default_approx) -- see that
    /// method's own docs, including for the `super.defaultApprox(...)` reconstruction.
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

    /// Java: `public PcodeThreeLevelTaint evalBinaryExpression(BinaryOperator operator,
    /// PcodeThreeLevelTaint left, PcodeThreeLevelTaint right, ProgramPoint pp, SemanticOracle
    /// oracle) throws SemanticException`. Java's unused `operator`/`pp`/`oracle` parameters are
    /// dropped -- see
    /// [`PcodeParity::eval_null_constant`](super::pcode_parity::PcodeParity::eval_null_constant)'s
    /// docs for the established convention.
    pub fn eval_binary_expression(left: Self, right: Self) -> Self {
        if left == Self::Tainted || right == Self::Tainted {
            return Self::Tainted;
        }
        if left == Self::Top || right == Self::Top {
            return Self::Top;
        }
        Self::Clean
    }

    /// Java: `public PcodeThreeLevelTaint evalTernaryExpression(TernaryOperator operator,
    /// PcodeThreeLevelTaint left, PcodeThreeLevelTaint middle, PcodeThreeLevelTaint right,
    /// ProgramPoint pp, SemanticOracle oracle) throws SemanticException`. Java's unused
    /// `operator`/`pp`/`oracle` parameters are dropped.
    pub fn eval_ternary_expression(left: Self, middle: Self, right: Self) -> Self {
        if left == Self::Tainted || right == Self::Tainted || middle == Self::Tainted {
            return Self::Tainted;
        }
        if left == Self::Top || right == Self::Top || middle == Self::Top {
            return Self::Top;
        }
        Self::Clean
    }

    /// Java: `public PcodeThreeLevelTaint lubAux(PcodeThreeLevelTaint other) throws
    /// SemanticException`, `return TOP; // only happens with clean and tainted, that are not
    /// comparable`.
    pub fn lub_aux(&self, _other: &Self) -> Self {
        Self::Top
    }

    /// Java: `public PcodeThreeLevelTaint wideningAux(PcodeThreeLevelTaint other) throws
    /// SemanticException`, `return TOP; // only happens with clean and tainted, that are not
    /// comparable`.
    pub fn widening_aux(&self, _other: &Self) -> Self {
        Self::Top
    }

    /// Java: `public boolean lessOrEqualAux(PcodeThreeLevelTaint other) throws
    /// SemanticException`, `return false; // only happens with clean and tainted, that are not
    /// comparable`.
    pub fn less_or_equal_aux(&self, _other: &Self) -> bool {
        false
    }
}

impl Default for PcodeThreeLevelTaint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;

    // ── construction / top / bottom ──────────────────────────────────────────

    #[test]
    fn new_and_default_are_top() {
        assert_eq!(PcodeThreeLevelTaint::new(), PcodeThreeLevelTaint::Top);
        assert_eq!(PcodeThreeLevelTaint::default(), PcodeThreeLevelTaint::Top);
    }

    #[test]
    fn top_and_bottom() {
        assert_eq!(PcodeThreeLevelTaint::Bottom.top(), PcodeThreeLevelTaint::Top);
        assert_eq!(PcodeThreeLevelTaint::Bottom.bottom(), PcodeThreeLevelTaint::Bottom);
    }

    // ── is_always_tainted / is_possibly_tainted ─────────────────────────────

    #[test]
    fn is_always_tainted_true_only_for_tainted() {
        assert!(PcodeThreeLevelTaint::Tainted.is_always_tainted());
        assert!(!PcodeThreeLevelTaint::Top.is_always_tainted());
        assert!(!PcodeThreeLevelTaint::Clean.is_always_tainted());
        assert!(!PcodeThreeLevelTaint::Bottom.is_always_tainted());
    }

    #[test]
    fn is_possibly_tainted_true_only_for_top() {
        // Preserved quirk: maps to TOP, not TAINTED -- see the method's own docs.
        assert!(PcodeThreeLevelTaint::Top.is_possibly_tainted());
        assert!(!PcodeThreeLevelTaint::Tainted.is_possibly_tainted());
        assert!(!PcodeThreeLevelTaint::Clean.is_possibly_tainted());
        assert!(!PcodeThreeLevelTaint::Bottom.is_possibly_tainted());
    }

    // ── representation ───────────────────────────────────────────────────────

    #[test]
    fn representation_matches_each_variant() {
        assert_eq!(PcodeThreeLevelTaint::Bottom.representation(), ThreeLevelTaintRepresentation::Bottom);
        assert_eq!(PcodeThreeLevelTaint::Clean.representation(), ThreeLevelTaintRepresentation::Clean);
        assert_eq!(PcodeThreeLevelTaint::Tainted.representation(), ThreeLevelTaintRepresentation::Tainted);
        assert_eq!(PcodeThreeLevelTaint::Top.representation(), ThreeLevelTaintRepresentation::Top);
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
        let d = PcodeThreeLevelTaint::Bottom;
        let id = MockId { annotations: vec![] };
        let pp = MockPp { location: None };
        assert_eq!(d.default_approx(&id, &pp), PcodeThreeLevelTaint::Top);
    }

    #[test]
    fn default_approx_matching_tainted_and_clean_annotations() {
        let d = PcodeThreeLevelTaint::Bottom;
        let loc = pcode_loc_at(0x1000);
        let addr = loc.get_address();
        let tainted_id = MockId { annotations: vec![format!("Tainted@{}", addr)] };
        let pp = MockPp { location: Some(loc.clone()) };
        assert_eq!(d.default_approx(&tainted_id, &pp), PcodeThreeLevelTaint::Tainted);

        let clean_id = MockId { annotations: vec![format!("Clean@{}", addr)] };
        let pp2 = MockPp { location: Some(loc) };
        assert_eq!(d.default_approx(&clean_id, &pp2), PcodeThreeLevelTaint::Clean);
    }

    #[test]
    fn default_approx_no_address_match_is_bottom() {
        let d = PcodeThreeLevelTaint::Clean;
        let loc = pcode_loc_at(0x3000);
        let id = MockId { annotations: vec!["Tainted@ram:00004000".to_string()] };
        let pp = MockPp { location: Some(loc) };
        assert_eq!(d.default_approx(&id, &pp), PcodeThreeLevelTaint::Bottom);
    }

    // ── eval_binary_expression ───────────────────────────────────────────────

    #[test]
    fn eval_binary_expression_tainted_wins_over_top() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_binary_expression(PcodeThreeLevelTaint::Tainted, PcodeThreeLevelTaint::Top),
            PcodeThreeLevelTaint::Tainted
        );
    }

    #[test]
    fn eval_binary_expression_top_wins_over_clean() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_binary_expression(PcodeThreeLevelTaint::Top, PcodeThreeLevelTaint::Clean),
            PcodeThreeLevelTaint::Top
        );
    }

    #[test]
    fn eval_binary_expression_both_clean_is_clean() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_binary_expression(PcodeThreeLevelTaint::Clean, PcodeThreeLevelTaint::Clean),
            PcodeThreeLevelTaint::Clean
        );
    }

    // ── eval_ternary_expression ──────────────────────────────────────────────

    #[test]
    fn eval_ternary_expression_tainted_wins() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_ternary_expression(
                PcodeThreeLevelTaint::Clean,
                PcodeThreeLevelTaint::Tainted,
                PcodeThreeLevelTaint::Top
            ),
            PcodeThreeLevelTaint::Tainted
        );
    }

    #[test]
    fn eval_ternary_expression_top_wins_over_clean() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_ternary_expression(
                PcodeThreeLevelTaint::Clean,
                PcodeThreeLevelTaint::Top,
                PcodeThreeLevelTaint::Clean
            ),
            PcodeThreeLevelTaint::Top
        );
    }

    #[test]
    fn eval_ternary_expression_all_clean_is_clean() {
        assert_eq!(
            PcodeThreeLevelTaint::eval_ternary_expression(
                PcodeThreeLevelTaint::Clean,
                PcodeThreeLevelTaint::Clean,
                PcodeThreeLevelTaint::Clean
            ),
            PcodeThreeLevelTaint::Clean
        );
    }

    // ── lubAux / wideningAux / lessOrEqualAux ────────────────────────────────

    #[test]
    fn lub_aux_widening_aux_are_top_less_or_equal_aux_is_false() {
        assert_eq!(PcodeThreeLevelTaint::Clean.lub_aux(&PcodeThreeLevelTaint::Tainted), PcodeThreeLevelTaint::Top);
        assert_eq!(
            PcodeThreeLevelTaint::Clean.widening_aux(&PcodeThreeLevelTaint::Tainted),
            PcodeThreeLevelTaint::Top
        );
        assert!(!PcodeThreeLevelTaint::Clean.less_or_equal_aux(&PcodeThreeLevelTaint::Tainted));
    }
}
