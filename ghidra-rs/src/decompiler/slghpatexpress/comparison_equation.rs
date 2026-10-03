//! Shared pattern-generation logic for `GreaterEqualEquation`, `GreaterEquation`,
//! `LessEqualEquation`, `LessEquation`, and `NotEqualEquation`.
//!
//! Java copy-pastes an identical ~30-line `genPattern` body into each of these five classes,
//! differing only in the comparison used to keep/skip an `lhsval` candidate and the error
//! message on an impossible-to-match constraint (right down to inheriting a copy-paste typo:
//! `LessEquation`'s message reads "LessEquation constraint is impossible to match" rather than
//! "Less than constraint..."). This file factors that shared body into one function
//! parameterized by the comparison and message, which each equation's own file calls with its
//! specific predicate -- unlike `EqualEquation`, whose single-value-per-combo algorithm is
//! genuinely different from this family's nested lhsval loop, so it keeps its own
//! `gen_equal_pattern` rather than sharing this one.

use crate::decompiler::context::SleighError;
use crate::decompiler::slghpatexpress::PatternExpression;
use crate::decompiler::slghpatexpress::express_utils::{advance_combo, build_pattern};
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::sleigh::grammar::Location;

/// Computes the token pattern for a comparison-constraint equation (everything but
/// `EqualEquation`) given its operands and the specific comparison to apply.
///
/// For every combination of values `rhs`'s `PatternValue` leaves can take on, and for every
/// `lhsval` in `[lhs.min_value(), lhs.max_value()]`, keeps `lhsval` (ORs its built pattern into
/// the accumulated result) exactly when `keep(lhsval, val)` is true, where `val` is `rhs`'s
/// value for that combination.
pub(crate) fn gen_comparison_pattern(
    lhs: &dyn PatternValue,
    rhs: &dyn PatternExpression,
    location: &Location,
    keep: impl Fn(i64, i64) -> bool,
    error_message: &str,
) -> Box<dyn TokenPattern> {
    let lhsmin = lhs.min_value();
    let lhsmax = lhs.max_value();

    let mut semval: Vec<&dyn PatternValue> = Vec::new();
    rhs.list_values(&mut semval);

    let mut min = VectorStl::new();
    let mut max = VectorStl::new();
    rhs.get_min_max(&mut min, &mut max);
    let mut cur = min.copy();

    let mut accumulated: Option<Box<dyn TokenPattern>> = None;
    loop {
        let mut listpos = MutableInt::new(0);
        let val = rhs.get_sub_value(&cur, &mut listpos);

        let mut lhsval = lhsmin;
        while lhsval <= lhsmax {
            if keep(lhsval, val) {
                let built = build_pattern(lhs, lhsval, &semval, &cur);
                accumulated = Some(match accumulated {
                    None => built,
                    Some(existing) => existing.do_or(built.as_ref()),
                });
            }
            lhsval += 1;
        }

        if !advance_combo(&mut cur, &min, &max) {
            break;
        }
    }

    accumulated.unwrap_or_else(|| {
        panic!("{}", SleighError::new(error_message, location.clone()))
    })
}
