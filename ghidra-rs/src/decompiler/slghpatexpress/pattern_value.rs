//! Models `ghidra.pcodeCPort.slghpatexpress.PatternValue`.

use crate::decompiler::seam_stubs::{PatternExpression, TokenPattern};
use crate::decompiler::utils::MutableInt;

/// A [`PatternExpression`] that evaluates directly to a single value, rather than combining
/// sub-expressions: token fields, context fields, constants, start/end/next2 instruction
/// addresses, and operand references are all pattern values.
///
/// Models the abstract class `ghidra.pcodeCPort.slghpatexpress.PatternValue`, which extends
/// `PatternExpression` (stubbed as [`PatternExpression`] pending its own port).
pub trait PatternValue: PatternExpression {
    /// Generates the token pattern that constrains this value to equal `val`.
    fn gen_pattern(&self, val: i64) -> Box<dyn TokenPattern>;

    /// The smallest value this pattern value can take on.
    fn min_value(&self) -> i64;

    /// The largest value this pattern value can take on.
    fn max_value(&self) -> i64;

    /// Appends `self` to `list`, since a pattern value is itself a leaf of the expression tree.
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>)
    where
        Self: Sized,
    {
        list.push(self);
    }

    /// Appends this value's min/max bounds to `minlist`/`maxlist`.
    fn get_min_max(&self, minlist: &mut Vec<i64>, maxlist: &mut Vec<i64>) {
        minlist.push(self.min_value());
        maxlist.push(self.max_value());
    }

    /// Consumes the next replacement value at `listpos`, advancing `listpos` by one.
    fn get_sub_value(&self, replace: &[i64], listpos: &mut MutableInt) -> i64 {
        let res = replace[listpos.get() as usize];
        listpos.increment();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock proving the trait is object-safe and its default methods behave like the
    /// Java overrides.
    struct FixedValue {
        min: i64,
        max: i64,
    }

    struct MockPattern;
    impl TokenPattern for MockPattern {}
    impl PatternExpression for FixedValue {}

    impl PatternValue for FixedValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
            Box::new(MockPattern)
        }

        fn min_value(&self) -> i64 {
            self.min
        }

        fn max_value(&self) -> i64 {
            self.max
        }
    }

    #[test]
    fn gen_pattern_returns_token_pattern() {
        let value = FixedValue { min: 0, max: 3 };
        let dyn_value: &dyn PatternValue = &value;
        let _pattern = dyn_value.gen_pattern(2);
    }

    #[test]
    fn get_min_max_pushes_bounds() {
        let value = FixedValue { min: 1, max: 5 };
        let mut mins = Vec::new();
        let mut maxs = Vec::new();
        value.get_min_max(&mut mins, &mut maxs);
        assert_eq!(mins, vec![1]);
        assert_eq!(maxs, vec![5]);
    }

    #[test]
    fn get_sub_value_reads_and_advances_listpos() {
        let value = FixedValue { min: 0, max: 0 };
        let replace = vec![10, 20, 30];
        let mut listpos = MutableInt::new(1);
        let res = value.get_sub_value(&replace, &mut listpos);
        assert_eq!(res, 20);
        assert_eq!(listpos.get(), 2);
    }

    #[test]
    fn list_values_appends_self() {
        let value = FixedValue { min: 0, max: 0 };
        let mut list: Vec<&dyn PatternValue> = Vec::new();
        value.list_values(&mut list);
        assert_eq!(list.len(), 1);
    }
}
