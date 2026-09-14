//! Stand-in for LiSA's `it.unive.lisa.analysis.lattices.Satisfiability`.
//!
//! `Satisfiability` is an external third-party dependency (part of the `it.unive.lisa` library)
//! with no Rust port anywhere in this crate and no Java source available under `orig_src` to
//! transcribe from (it lives in LiSA's own jar, not in this repository) -- the same situation
//! documented on [`PcodeNonRelationalValueDomain`](super::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain)
//! for other `it.unive.lisa.*` types. Unlike those narrowly-scoped stand-ins, `Satisfiability` is
//! a small, well-known three-valued-logic lattice (`SATISFIED`/`NOT_SATISFIED`/`UNKNOWN`) whose
//! `negate()`/`and()` semantics are uniquely determined by standard three-valued logic and by the
//! exact call sites that exercise them in
//! [`PcodeSign`](super::pcode_sign::PcodeSign)/[`PcodeStability`](super::pcode_stability), so this
//! is a real, tested reconstruction of that lattice -- not a placeholder.

/// The three-valued satisfiability lattice: whether a boolean expression is definitely satisfied,
/// definitely not satisfied, or its satisfiability cannot be determined precisely.
///
/// Corresponds to `it.unive.lisa.analysis.lattices.Satisfiability` in the LiSA library. LiSA's
/// real enum also has a `BOTTOM` constant (for contradictory/unreachable satisfiability results),
/// but neither [`PcodeSign`](super::pcode_sign::PcodeSign) nor
/// [`PcodeStability`](super::pcode_stability) ever produces or inspects it, so it is omitted here
/// -- the same "port only what's actually exercised" convention
/// [`crate::feature::lisa::pcode::analyses::trend::Trend`]'s docs describe for dropping `Trend`'s
/// unused `BOTTOM` constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Satisfiability {
    /// The expression is definitely satisfied (always true).
    Satisfied,
    /// The expression is definitely not satisfied (always false).
    NotSatisfied,
    /// The expression may or may not be satisfied; not determined precisely.
    Unknown,
}

impl Satisfiability {
    /// Mirrors `Satisfiability.negate()`: swaps `SATISFIED`/`NOT_SATISFIED`, leaves `UNKNOWN`
    /// unchanged (standard three-valued-logic negation).
    pub fn negate(self) -> Self {
        match self {
            Self::Satisfied => Self::NotSatisfied,
            Self::NotSatisfied => Self::Satisfied,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Mirrors `Satisfiability.and(Satisfiability)`: standard three-valued-logic conjunction --
    /// `NOT_SATISFIED` is absorbing (`false && x == false`), `SATISFIED` is the identity, and
    /// `UNKNOWN` combined with anything other than a `NOT_SATISFIED` short-circuit stays
    /// `UNKNOWN`.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::NotSatisfied, _) | (_, Self::NotSatisfied) => Self::NotSatisfied,
            (Self::Satisfied, Self::Satisfied) => Self::Satisfied,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negate_swaps_satisfied_and_not_satisfied() {
        assert_eq!(Satisfiability::Satisfied.negate(), Satisfiability::NotSatisfied);
        assert_eq!(Satisfiability::NotSatisfied.negate(), Satisfiability::Satisfied);
    }

    #[test]
    fn negate_leaves_unknown_unchanged() {
        assert_eq!(Satisfiability::Unknown.negate(), Satisfiability::Unknown);
    }

    #[test]
    fn and_is_satisfied_only_when_both_are_satisfied() {
        assert_eq!(Satisfiability::Satisfied.and(Satisfiability::Satisfied), Satisfiability::Satisfied);
    }

    #[test]
    fn and_not_satisfied_is_absorbing() {
        assert_eq!(Satisfiability::NotSatisfied.and(Satisfiability::Satisfied), Satisfiability::NotSatisfied);
        assert_eq!(Satisfiability::Satisfied.and(Satisfiability::NotSatisfied), Satisfiability::NotSatisfied);
        assert_eq!(Satisfiability::NotSatisfied.and(Satisfiability::Unknown), Satisfiability::NotSatisfied);
        assert_eq!(Satisfiability::Unknown.and(Satisfiability::NotSatisfied), Satisfiability::NotSatisfied);
    }

    #[test]
    fn and_with_unknown_is_unknown_unless_not_satisfied_is_involved() {
        assert_eq!(Satisfiability::Unknown.and(Satisfiability::Satisfied), Satisfiability::Unknown);
        assert_eq!(Satisfiability::Satisfied.and(Satisfiability::Unknown), Satisfiability::Unknown);
        assert_eq!(Satisfiability::Unknown.and(Satisfiability::Unknown), Satisfiability::Unknown);
    }
}
