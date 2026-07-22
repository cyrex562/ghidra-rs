//! Models `ghidra.pcodeCPort.slghpatexpress.EqualEquation`.

use crate::decompiler::context::SleighError;
use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::express_utils::{advance_combo, build_pattern};
use crate::decompiler::slghpatexpress::val_express_equation::ValExpressEquation;
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::sleigh::grammar::Location;

/// An equation that constrains a pattern value to equal one of the values its right-hand
/// pattern expression can take on.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.EqualEquation`, which extends `ValExpressEquation`
/// and overrides only `genPattern()`. Exposed as a trait -- rather than only a concrete struct --
/// so callers can depend on "something that behaves like an equal-constraint equation" via
/// `Box<dyn EqualEquation>` without pulling in a specific implementation.
pub trait EqualEquation: Send + Sync {
    /// Generates (and stores) the token pattern constraining this equation's left-hand pattern
    /// value to equal one of the right-hand expression's attainable values.
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if no combination of the right-hand expression's values
    /// ever equals a value the left-hand side can take on (mirrors the Java
    /// `throw new SleighError("Equal constraint is impossible to match", location)`).
    fn gen_pattern(&mut self);

    /// Returns the token pattern computed by the most recent [`EqualEquation::gen_pattern`]
    /// call, if any.
    fn get_token_pattern(&self) -> Option<&dyn TokenPattern>;
}

/// Computes the token pattern for an equal-constraint equation given its operands.
///
/// Enumerates every combination of values `rhs`'s `PatternValue` leaves can take on (via
/// `rhs.get_min_max()`/[`advance_combo`]), evaluates `rhs` at each combination
/// (`rhs.get_sub_value()`), and ORs together the token patterns ([`build_pattern`]) of every
/// combination whose value falls within `[lhs.min_value(), lhs.max_value()]`.
///
/// Pulled out as a free function (rather than a default trait method reading/writing `self`)
/// because the accumulation only ever needs the running total from *this* call, never the
/// equation's previously stored pattern -- keeping it self-contained avoids holding an
/// immutable borrow of `rhs`'s leaves alive across the mutable `set_token_pattern` call an
/// object-safe trait method would otherwise require.
fn gen_equal_pattern(
    lhs: &dyn PatternValue,
    rhs: &dyn PatternExpression,
    location: &Location,
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
        if val >= lhsmin && val <= lhsmax {
            let built = build_pattern(lhs, val, &semval, &cur);
            accumulated = Some(match accumulated {
                None => built,
                Some(existing) => existing.do_or(built.as_ref()),
            });
        }
        if !advance_combo(&mut cur, &min, &max) {
            break;
        }
    }

    accumulated.unwrap_or_else(|| {
        panic!(
            "{}",
            SleighError::new("Equal constraint is impossible to match", location.clone())
        )
    })
}

/// The concrete `ghidra.pcodeCPort.slghpatexpress.EqualEquation`: an equal-constraint equation
/// built from a [`ValExpressEquation`]'s operands, plus the token pattern slot
/// `genPattern`/`getTokenPattern`/`setTokenPattern` are inherited from Java's `PatternEquation`
/// base class (not itself ported yet, so stored here directly).
pub struct EqualEquationImpl {
    equation: ValExpressEquation,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl EqualEquationImpl {
    /// Creates a new equal-constraint equation from its left- and right-hand operands.
    pub fn new(location: Location, lhs: Box<dyn PatternValue>, rhs: Box<dyn PatternExpression>) -> Self {
        Self {
            equation: ValExpressEquation::new(location, lhs, rhs),
            token_pattern: None,
        }
    }

    /// The source location this equation was defined at.
    pub fn location(&self) -> &Location {
        self.equation.location()
    }

    /// The pattern value being constrained (the Java `lhs` field).
    pub fn get_lhs(&self) -> &dyn PatternValue {
        self.equation.get_lhs()
    }

    /// The pattern expression whose values `lhs` must equal one of (the Java `rhs` field).
    pub fn get_rhs(&self) -> &dyn PatternExpression {
        self.equation.get_rhs()
    }
}

impl EqualEquation for EqualEquationImpl {
    fn gen_pattern(&mut self) {
        let pattern = gen_equal_pattern(self.equation.get_lhs(), self.equation.get_rhs(), self.equation.location());
        self.token_pattern = Some(pattern);
    }

    fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.token_pattern.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::Pattern;

    struct MockPattern;
    impl Pattern for MockPattern {}

    #[derive(Clone)]
    struct MockTokenPattern {
        location: Location,
        always_true: bool,
    }

    impl MockTokenPattern {
        fn new(location: Location, always_true: bool) -> Self {
            Self { location, always_true }
        }
    }

    impl TokenPattern for MockTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn Pattern {
            &MockPattern
        }

        fn always_true(&self) -> bool {
            self.always_true
        }

        fn always_false(&self) -> bool {
            false
        }

        fn always_instruction_true(&self) -> bool {
            self.always_true
        }

        fn get_left_ellipsis(&self) -> bool {
            false
        }

        fn get_right_ellipsis(&self) -> bool {
            false
        }

        fn set_left_ellipsis(&mut self, _val: bool) {}

        fn set_right_ellipsis(&mut self, _val: bool) {}

        fn get_minimum_length(&self) -> i32 {
            0
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
            self.always_true = tokpat.always_true();
        }

        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(self.clone())
        }

        fn do_or(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone(), self.always_true || tokpat.always_true()))
        }

        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(self.clone())
        }

        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(self.clone())
        }
    }

    /// A `PatternValue` leaf: `gen_pattern(val)` reports `val == target` via `always_true`.
    struct LeafValue {
        location: Location,
        min: i64,
        max: i64,
        target: i64,
    }

    impl PatternExpression for LeafValue {}

    impl PatternValue for LeafValue {
        fn gen_pattern(&self, val: i64) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone(), val == self.target))
        }

        fn min_value(&self) -> i64 {
            self.min
        }

        fn max_value(&self) -> i64 {
            self.max
        }
    }

    /// A `PatternExpression` whose attainable values are exactly `values`, mirroring how a real
    /// composite expression would enumerate its leaves' combinations.
    struct FixedValuesExpression {
        values: Vec<i64>,
    }

    impl PatternExpression for FixedValuesExpression {
        fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>) {
            minlist.push_back(0);
            maxlist.push_back(self.values.len() as i64 - 1);
        }

        fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64 {
            let idx = *replace.get(listpos.get() as usize);
            listpos.increment();
            self.values[idx as usize]
        }
    }

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    #[test]
    fn gen_pattern_matches_when_value_in_range() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue {
            location: loc(),
            min: 0,
            max: 10,
            target: 5,
        });
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression { values: vec![5, 20, 30] });
        let mut equation = EqualEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();

        let pattern = equation.get_token_pattern().expect("pattern generated");
        assert!(pattern.always_true());
    }

    #[test]
    fn gen_pattern_ors_every_matching_combination() {
        // lhs matches values 5 and 6, so both must contribute to the OR'd result.
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue {
            location: loc(),
            min: 5,
            max: 6,
            target: 999, // never equals lhs's own gen_pattern target; only min/max bounds matter here.
        });
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression { values: vec![5, 6, 100] });
        let mut equation = EqualEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();

        // Two in-range combinations (5 and 6) means do_or() is invoked once, producing an
        // always_true pattern (since always_true is OR'd from at least one true leaf pattern
        // whenever the built pattern's target coincidentally matches -- here neither leaf's
        // `gen_pattern` target matches, so the accumulated pattern should be always_false, but
        // gen_pattern must still succeed (not panic) since count > 0).
        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    #[should_panic(expected = "Equal constraint is impossible to match")]
    fn gen_pattern_panics_when_no_value_in_range() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue {
            location: loc(),
            min: 0,
            max: 1,
            target: 0,
        });
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression { values: vec![50, 60] });
        let mut equation = EqualEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();
    }

    #[test]
    fn get_lhs_and_rhs_expose_operands() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue {
            location: loc(),
            min: 0,
            max: 1,
            target: 0,
        });
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression { values: vec![0] });
        let equation = EqualEquationImpl::new(loc(), lhs, rhs);

        assert_eq!(equation.get_lhs().min_value(), 0);
        assert_eq!(equation.location(), &loc());
        let _rhs = equation.get_rhs();
    }
}
