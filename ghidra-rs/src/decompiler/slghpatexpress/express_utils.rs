//! Models `ghidra.pcodeCPort.slghpatexpress.ExpressUtils`.

use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::generic::stl::vector_stl::VectorStl;

/// Advances to the next combination of values, treating the vectors as multi-radix digits.
///
/// Starting from `val`, increments position 0. If it exceeds `max[0]`, resets it to `min[0]`
/// and carries to position 1, and so on. Returns `true` if advancement was successful (not
/// an overflow), or `false` if all positions overflowed.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.ExpressUtils.advance_combo()`.
pub fn advance_combo(val: &mut VectorStl<i64>, min: &VectorStl<i64>, max: &VectorStl<i64>) -> bool {
	let mut i = 0;
	while i < val.size() {
		val.set(i, val.get(i) + 1);
		if val.get(i) <= max.get(i) {
			return true;
		}
		val.set(i, *min.get(i));
		i += 1;
	}
	false
}

/// Builds a token pattern from LHS and a list of sub-patterns.
///
/// Starts with `lhs.gen_pattern(lhsval)` and AND's it with the pattern generated from
/// each element of `semval` paired with the corresponding value in `val`.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.ExpressUtils.buildPattern()`.
pub fn build_pattern(
	lhs: &dyn PatternValue,
	lhsval: i64,
	semval: &[&dyn PatternValue],
	val: &VectorStl<i64>,
) -> Box<dyn TokenPattern> {
	let mut respattern = lhs.gen_pattern(lhsval);

	for i in 0..semval.len() {
		let sub_pattern = semval[i].gen_pattern(*val.get(i));
		let combined = respattern.do_and(sub_pattern.as_ref());
		respattern.copy_into(combined.as_ref());
	}
	respattern
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::decompiler::seam_stubs::{Pattern, PatternExpression};
	use crate::sleigh::grammar::Location;

	struct MockPattern;
	impl Pattern for MockPattern {}

	struct MockTokenPattern {
		location: Location,
		pattern: Box<dyn Pattern>,
		left_ellipsis: bool,
		right_ellipsis: bool,
	}

	impl MockTokenPattern {
		fn new(location: Location) -> Self {
			Self {
				location,
				pattern: Box::new(MockPattern),
				left_ellipsis: false,
				right_ellipsis: false,
			}
		}
	}

	impl TokenPattern for MockTokenPattern {
		fn location(&self) -> &Location {
			&self.location
		}

		fn get_pattern(&self) -> &dyn Pattern {
			self.pattern.as_ref()
		}

		fn always_true(&self) -> bool {
			true
		}

		fn always_false(&self) -> bool {
			false
		}

		fn always_instruction_true(&self) -> bool {
			true
		}

		fn get_left_ellipsis(&self) -> bool {
			self.left_ellipsis
		}

		fn get_right_ellipsis(&self) -> bool {
			self.right_ellipsis
		}

		fn set_left_ellipsis(&mut self, val: bool) {
			self.left_ellipsis = val;
		}

		fn set_right_ellipsis(&mut self, val: bool) {
			self.right_ellipsis = val;
		}

		fn get_minimum_length(&self) -> i32 {
			0
		}

		fn simplify_pattern(&mut self) {}

		fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
			self.left_ellipsis = tokpat.get_left_ellipsis();
			self.right_ellipsis = tokpat.get_right_ellipsis();
		}

		fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
			Box::new(MockTokenPattern::new(self.location.clone()))
		}

		fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
			Box::new(MockTokenPattern::new(self.location.clone()))
		}

		fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
			Box::new(MockTokenPattern::new(self.location.clone()))
		}

		fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
			Box::new(MockTokenPattern::new(self.location.clone()))
		}
	}

	struct FixedValue {
		min: i64,
		max: i64,
	}

	impl PatternExpression for FixedValue {}

	impl PatternValue for FixedValue {
		fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
			Box::new(MockTokenPattern::new(Location::new("test.sleigh", 1)))
		}

		fn min_value(&self) -> i64 {
			self.min
		}

		fn max_value(&self) -> i64 {
			self.max
		}
	}

	#[test]
	fn advance_combo_increments_first_position() {
		let mut val = VectorStl::new();
		val.push_back(0);
		val.push_back(0);

		let mut min = VectorStl::new();
		min.push_back(0);
		min.push_back(0);

		let mut max = VectorStl::new();
		max.push_back(2);
		max.push_back(2);

		let result = advance_combo(&mut val, &min, &max);
		assert!(result);
		assert_eq!(*val.get(0), 1);
		assert_eq!(*val.get(1), 0);
	}

	#[test]
	fn advance_combo_carries_overflow() {
		let mut val = VectorStl::new();
		val.push_back(2);
		val.push_back(0);

		let mut min = VectorStl::new();
		min.push_back(0);
		min.push_back(0);

		let mut max = VectorStl::new();
		max.push_back(2);
		max.push_back(2);

		let result = advance_combo(&mut val, &min, &max);
		assert!(result);
		assert_eq!(*val.get(0), 0);
		assert_eq!(*val.get(1), 1);
	}

	#[test]
	fn advance_combo_returns_false_on_full_overflow() {
		let mut val = VectorStl::new();
		val.push_back(2);
		val.push_back(2);

		let mut min = VectorStl::new();
		min.push_back(0);
		min.push_back(0);

		let mut max = VectorStl::new();
		max.push_back(2);
		max.push_back(2);

		let result = advance_combo(&mut val, &min, &max);
		assert!(!result);
	}

	#[test]
	fn advance_combo_respects_max_inclusive() {
		let mut val = VectorStl::new();
		val.push_back(1);

		let mut min = VectorStl::new();
		min.push_back(0);

		let mut max = VectorStl::new();
		max.push_back(2);

		let result = advance_combo(&mut val, &min, &max);
		assert!(result);
		assert_eq!(*val.get(0), 2);

		let result2 = advance_combo(&mut val, &min, &max);
		assert!(!result2);
	}

	#[test]
	fn build_pattern_combines_subpatterns() {
		let lhs = FixedValue { min: 0, max: 10 };
		let lhs_ref: &dyn PatternValue = &lhs;

		let sub1 = FixedValue { min: 0, max: 5 };
		let sub1_ref: &dyn PatternValue = &sub1;

		let sub2 = FixedValue { min: 0, max: 5 };
		let sub2_ref: &dyn PatternValue = &sub2;

		let semval = vec![sub1_ref, sub2_ref];

		let mut val = VectorStl::new();
		val.push_back(1);
		val.push_back(2);

		let pattern = build_pattern(lhs_ref, 5, &semval, &val);
		assert!(pattern.always_true());
	}

	#[test]
	fn build_pattern_with_empty_semval() {
		let lhs = FixedValue { min: 0, max: 10 };
		let lhs_ref: &dyn PatternValue = &lhs;

		let semval: Vec<&dyn PatternValue> = vec![];

		let mut val = VectorStl::new();

		let pattern = build_pattern(lhs_ref, 5, &semval, &val);
		assert!(pattern.always_true());
	}
}
