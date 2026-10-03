//! Stand-in for LiSA's `it.unive.lisa.analysis.stability.Trend`.
//!
//! `Trend` is an external third-party dependency (part of the `it.unive.lisa` library) with no
//! Rust port anywhere in this crate and no Java source available under `orig_src` to transcribe
//! from (it lives in LiSA's own jar, not in this repository) -- the same situation
//! [`Satisfiability`](super::satisfiability::Satisfiability)'s docs describe for another
//! `it.unive.lisa.*` type used directly by this package's own logic.
//!
//! Unlike most such stand-ins in this crate (narrow traits exposing only what a caller touches),
//! [`Trend::invert`] and [`Trend::combine`] are real logic that
//! [`PcodeStability`](super::pcode_stability) itself invokes and depends on for its own correct
//! behavior (`increasingIfLess = increasingIfGreater(...).invert()`, and
//! [`PcodeStability::combine`](super::pcode_stability::PcodeStability::combine) which folds
//! `Trend::combine` over every identifier shared between two stability states), so both are
//! implemented here as a genuine (not stub) reconstruction, built from two hard constraints:
//!
//! 1. [`PcodeStability`](super::pcode_stability)'s own doc comments pin down `invert`'s exact
//!    contract: `increasingIfGreater(a, b, ...)` returns [`Trend::Inc`] exactly when `a > b`
//!    (and its documented siblings for the other five outcomes), and `increasingIfLess(a, b,
//!    ...)` is documented to return [`Trend::Inc`] exactly when `a < b` while being *implemented*
//!    as `increasingIfGreater(a, b, ...).invert()` -- i.e. `invert()` must be exactly the
//!    substitution that turns "`a > b` variant" into "`a < b` variant" for all six non-`Top`
//!    outcomes.
//! 2. Every [`Trend`] variant names a set of allowed per-step "directions" a variable's value can
//!    take (zero change, a positive change, or a negative change): [`Trend::Stable`] = `{0}`,
//!    [`Trend::Inc`] = `{+}`, [`Trend::Dec`] = `{-}`, [`Trend::NonDec`] = `{0, +}`,
//!    [`Trend::NonInc`] = `{0, -}`, [`Trend::NonStable`] = `{+, -}`, [`Trend::Top`] = `{0, +, -}`
//!    (this reading is forced by constraint 1 together with the six variants' own names and the
//!    `NON_DEC`/`NON_INC` cases' documented double-condition definitions, e.g. `a > b || a >= b`
//!    for `NON_DEC`, which is exactly "the direction is zero-or-positive"). `invert` negates every
//!    direction in the set (`+` <-> `-`, `0` fixed), matching constraint 1 exactly for all seven
//!    variants (`Top` and [`Trend::NonStable`] are self-inverse, since `{0,+,-}` and `{+,-}` are
//!    each symmetric under negation).
//!
//! [`combine`](Trend::combine) is reconstructed from the same per-step "direction set" reading,
//! applied to [`PcodeStability`](super::pcode_stability)'s own doc comment describing it as
//! sequential composition ("a variable having `t1` trend in the former and `t2` trend in the
//! latter would have `t1.combine(t2)` as an overall trend"): the combined direction set is the
//! union, over every pair of a direction from `self`'s set and a direction from `other`'s set, of
//! that pair's possible net signs (`0+0=0`, `0+x=x`, `x+0=x`, `+++=+`, `-+-=-`, and `+` combined
//! with `-` conservatively yields all three signs, since an unbounded positive step and an
//! unbounded negative step can net to anything depending on their relative magnitudes, which nothing
//! here tracks). This is not a byte-for-byte transcription of a file this port actually read (that
//! file lives outside this repository) -- see [`Satisfiability`](super::satisfiability::Satisfiability)'s
//! docs for the same caveat on a sibling reconstruction -- but every result below is independently
//! checkable against the "direction set" reading above, and the tests exercise both that reading's
//! self-consistency (commutativity, [`Trend::Stable`] as the identity element, [`Trend::Top`] as
//! absorbing, `invert` as an involution) and every case [`PcodeStability`](super::pcode_stability)'s
//! own doc comments pin down directly.
//!
//! LiSA's real `Trend` enum also has a `BOTTOM` constant, but
//! [`PcodeStability`](super::pcode_stability) never constructs or inspects it (bottom-ness of a
//! per-variable trend is instead tracked at the surrounding `ValueEnvironment`/[`TrendEnvironment`
//! seam](super::pcode_stability) level), so it is omitted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Trend {
    /// No information about this variable's trend (the join of every other variant).
    Top,
    /// The variable's value never changes.
    Stable,
    /// The variable's value strictly increases on every step.
    Inc,
    /// The variable's value strictly decreases on every step.
    Dec,
    /// The variable's value never decreases (stable or increasing).
    NonDec,
    /// The variable's value never increases (stable or decreasing).
    NonInc,
    /// The variable's value always changes, but not consistently in one direction.
    NonStable,
}

impl Trend {
    /// This variant's allowed per-step directions, as `(includes_zero, includes_positive,
    /// includes_negative)`. See the module docs' "direction set" reading.
    fn directions(self) -> (bool, bool, bool) {
        match self {
            Self::Stable => (true, false, false),
            Self::Inc => (false, true, false),
            Self::Dec => (false, false, true),
            Self::NonDec => (true, true, false),
            Self::NonInc => (true, false, true),
            Self::NonStable => (false, true, true),
            Self::Top => (true, true, true),
        }
    }

    /// Inverse of [`Self::directions`]; panics on the empty set, which no variant maps to.
    fn from_directions(zero: bool, pos: bool, neg: bool) -> Self {
        match (zero, pos, neg) {
            (true, false, false) => Self::Stable,
            (false, true, false) => Self::Inc,
            (false, false, true) => Self::Dec,
            (true, true, false) => Self::NonDec,
            (true, false, true) => Self::NonInc,
            (false, true, true) => Self::NonStable,
            (true, true, true) => Self::Top,
            (false, false, false) => unreachable!("Trend::from_directions: empty direction set"),
        }
    }

    /// Mirrors `Trend.invert()`: flips every "increasing" outcome into the corresponding
    /// "decreasing" one and vice versa, leaving direction-less variants ([`Self::Stable`],
    /// [`Self::NonStable`], [`Self::Top`]) unchanged. See the module docs for the reasoning this
    /// reconstruction is built from.
    pub fn invert(self) -> Self {
        let (zero, pos, neg) = self.directions();
        Self::from_directions(zero, neg, pos)
    }

    /// Mirrors `Trend.combine(Trend)`: the trend of two (blocks of) instructions executed in
    /// sequence, given `self`'s trend for the first and `other`'s for the second. See the module
    /// docs for the reasoning this reconstruction is built from.
    pub fn combine(self, other: Self) -> Self {
        let (z1, p1, n1) = self.directions();
        let (z2, p2, n2) = other.directions();

        let mut zero = false;
        let mut pos = false;
        let mut neg = false;

        // 0 + 0 = 0; 0 + x = x; x + 0 = x.
        if z1 && z2 {
            zero = true;
        }
        if z1 && p2 || p1 && z2 {
            pos = true;
        }
        if z1 && n2 || n1 && z2 {
            neg = true;
        }
        // + + + = +; - + - = -.
        if p1 && p2 {
            pos = true;
        }
        if n1 && n2 {
            neg = true;
        }
        // + combined with - (in either order): an unbounded positive step and an unbounded
        // negative step can net to any sign, since neither direction's magnitude is tracked.
        if p1 && n2 || n1 && p2 {
            zero = true;
            pos = true;
            neg = true;
        }

        Self::from_directions(zero, pos, neg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Trend; 7] = [
        Trend::Top,
        Trend::Stable,
        Trend::Inc,
        Trend::Dec,
        Trend::NonDec,
        Trend::NonInc,
        Trend::NonStable,
    ];

    // ── invert ───────────────────────────────────────────────────────────────

    #[test]
    fn invert_swaps_inc_and_dec() {
        assert_eq!(Trend::Inc.invert(), Trend::Dec);
        assert_eq!(Trend::Dec.invert(), Trend::Inc);
    }

    #[test]
    fn invert_swaps_non_dec_and_non_inc() {
        assert_eq!(Trend::NonDec.invert(), Trend::NonInc);
        assert_eq!(Trend::NonInc.invert(), Trend::NonDec);
    }

    #[test]
    fn invert_fixes_direction_less_variants() {
        assert_eq!(Trend::Stable.invert(), Trend::Stable);
        assert_eq!(Trend::NonStable.invert(), Trend::NonStable);
        assert_eq!(Trend::Top.invert(), Trend::Top);
    }

    #[test]
    fn invert_is_an_involution_for_every_variant() {
        for &t in &ALL {
            assert_eq!(t.invert().invert(), t, "invert(invert({t:?})) != {t:?}");
        }
    }

    // ── combine: Stable is the identity element ─────────────────────────────

    #[test]
    fn stable_combine_anything_is_that_thing_on_both_sides() {
        for &t in &ALL {
            assert_eq!(Trend::Stable.combine(t), t, "Stable.combine({t:?})");
            assert_eq!(t.combine(Trend::Stable), t, "{t:?}.combine(Stable)");
        }
    }

    // ── combine: Top is absorbing ───────────────────────────────────────────

    #[test]
    fn top_combine_anything_is_top_on_both_sides() {
        for &t in &ALL {
            assert_eq!(Trend::Top.combine(t), Trend::Top, "Top.combine({t:?})");
            assert_eq!(t.combine(Trend::Top), Trend::Top, "{t:?}.combine(Top)");
        }
    }

    // ── combine: commutative ────────────────────────────────────────────────

    #[test]
    fn combine_is_commutative() {
        for &a in &ALL {
            for &b in &ALL {
                assert_eq!(a.combine(b), b.combine(a), "{a:?}.combine({b:?}) not commutative");
            }
        }
    }

    // ── combine: same-direction composition stays that direction ───────────

    #[test]
    fn inc_combine_inc_is_inc() {
        assert_eq!(Trend::Inc.combine(Trend::Inc), Trend::Inc);
    }

    #[test]
    fn dec_combine_dec_is_dec() {
        assert_eq!(Trend::Dec.combine(Trend::Dec), Trend::Dec);
    }

    #[test]
    fn non_dec_combine_non_dec_is_non_dec() {
        assert_eq!(Trend::NonDec.combine(Trend::NonDec), Trend::NonDec);
    }

    #[test]
    fn non_inc_combine_non_inc_is_non_inc() {
        assert_eq!(Trend::NonInc.combine(Trend::NonInc), Trend::NonInc);
    }

    // ── combine: a strict step absorbs a weak step of the same sign ────────

    #[test]
    fn inc_combine_non_dec_is_inc() {
        // Δ1 > 0, Δ2 >= 0 => Δ1 + Δ2 > 0 always.
        assert_eq!(Trend::Inc.combine(Trend::NonDec), Trend::Inc);
        assert_eq!(Trend::NonDec.combine(Trend::Inc), Trend::Inc);
    }

    #[test]
    fn dec_combine_non_inc_is_dec() {
        assert_eq!(Trend::Dec.combine(Trend::NonInc), Trend::Dec);
        assert_eq!(Trend::NonInc.combine(Trend::Dec), Trend::Dec);
    }

    // ── combine: opposite strict directions are unresolvable ───────────────

    #[test]
    fn inc_combine_dec_is_top() {
        // Unbounded +Δ then unbounded -Δ: net sign is unknowable (could over/under/exactly
        // cancel).
        assert_eq!(Trend::Inc.combine(Trend::Dec), Trend::Top);
        assert_eq!(Trend::Dec.combine(Trend::Inc), Trend::Top);
    }

    #[test]
    fn non_dec_combine_non_inc_is_top() {
        assert_eq!(Trend::NonDec.combine(Trend::NonInc), Trend::Top);
    }

    #[test]
    fn non_dec_combine_dec_is_top() {
        assert_eq!(Trend::NonDec.combine(Trend::Dec), Trend::Top);
    }

    #[test]
    fn non_stable_combine_non_stable_is_top() {
        assert_eq!(Trend::NonStable.combine(Trend::NonStable), Trend::Top);
    }
}
