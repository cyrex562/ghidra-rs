//! Shared test doubles for the `*Equation` family in this module (`equal_equation.rs` predates
//! this file and keeps its own private copy; the five comparison-equation ports added
//! alongside this file share these instead of each repeating the same ~150 lines).

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpattern::Pattern;
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::sleigh::grammar::Location;

pub(crate) struct MockPattern;
impl Pattern for MockPattern {
    fn simplify_clone(&self) -> Box<dyn Pattern> {
        Box::new(MockPattern)
    }
    fn shift_instruction(&mut self, _sa: i32) {}
    fn do_or(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
        Box::new(MockPattern)
    }
    fn do_and(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
        Box::new(MockPattern)
    }
    fn common_sub_pattern(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
        Box::new(MockPattern)
    }
    fn always_true(&self) -> bool {
        false
    }
    fn always_false(&self) -> bool {
        false
    }
    fn always_instruction_true(&self) -> bool {
        false
    }
    fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct MockTokenPattern {
    location: Location,
    always_true: bool,
}

impl MockTokenPattern {
    pub(crate) fn new(location: Location, always_true: bool) -> Self {
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
pub(crate) struct LeafValue {
    location: Location,
    min: i64,
    max: i64,
    target: i64,
}

impl LeafValue {
    pub(crate) fn new(location: Location, min: i64, max: i64, target: i64) -> Self {
        Self { location, min, max, target }
    }
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
pub(crate) struct FixedValuesExpression {
    values: Vec<i64>,
}

impl FixedValuesExpression {
    pub(crate) fn new(values: Vec<i64>) -> Self {
        Self { values }
    }
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

pub(crate) fn loc() -> Location {
    Location::new("test.sleigh", 1)
}
