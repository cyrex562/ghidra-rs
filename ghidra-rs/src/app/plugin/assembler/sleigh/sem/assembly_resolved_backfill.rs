use std::collections::HashMap;

use super::AssemblyResolution;
use crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver;
use crate::app::seam_stubs::AssemblyResolvedPatterns;

/// A backfill record produced during assembly resolution when part of the encoding cannot yet be
/// determined (e.g. because it depends on a symbol like `inst_next` that isn't defined until
/// later in the resolution process).
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill`, cut to a trait to
/// break a dependency cycle at this node in the port graph.
pub trait AssemblyResolvedBackfill: AssemblyResolution {
    /// Get the expected length of the instruction portion of the future encoding.
    ///
    /// This is used to make sure that operands following a to-be-determined encoding are placed
    /// properly. Even though the actual encoding cannot yet be determined, its length can.
    ///
    /// Returns the total expected length (including the offset).
    fn get_instruction_length(&self) -> i32;

    /// Shift the instruction byte pattern right by `amt` bytes.
    ///
    /// Ports the covariant-return override `AssemblyResolvedBackfill.shift(int)` of
    /// `AssemblyResolution.shift(int)`. Named distinctly from
    /// [`AssemblyResolution::shift`](super::AssemblyResolution::shift) (also required, via this
    /// trait's supertrait bound) because Rust trait objects cannot resolve two same-named methods
    /// with different return types without an ambiguous-method-call error at the call site.
    fn shift_backfill(&self, amt: i32) -> Box<dyn AssemblyResolvedBackfill>;

    /// Attempt (again) to solve the expression that generated this backfill record.
    ///
    /// This will attempt to solve the same expression and goal again, using the same parameters as
    /// were given to the original attempt, except with additional defined symbols. Typically, the
    /// symbol that required backfill is `inst_next`. This method will not indicate a missing
    /// symbol the way the original solve attempt could, since that would imply the missing
    /// symbol(s) from the original attempt are still missing. Instead, on failure it returns a
    /// resolution record representing an error.
    ///
    /// `solver` is a solver, usually the same as the one from the original attempt. `vals` are the
    /// defined symbols, usually the same, but with the missing symbol(s) added. `cur` is the
    /// resolution being built up.
    ///
    /// Returns the solution result.
    fn solve(
        &self,
        solver: &dyn RecursiveDescentSolver,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
    ) -> Box<dyn AssemblyResolution>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[derive(Debug, Clone)]
    struct Res {
        desc: String,
        backfill: bool,
        error: bool,
    }

    impl std::fmt::Display for Res {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl AssemblyResolution for Res {
        fn get_description(&self) -> String {
            self.desc.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            vec![]
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.desc.clone()
        }
        fn is_backfill(&self) -> bool {
            self.backfill
        }
        fn is_error(&self) -> bool {
            self.error
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(Res { desc: description.to_string(), backfill: false, error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    /// Stands in for a resolved `AssemblyResolvedPatterns`, e.g. the encoding built so far that
    /// `solve` is asked to extend.
    impl AssemblyResolvedPatterns for Res {
        fn get_instruction_length(&self) -> i32 {
            0
        }
        fn get_instruction(&self) -> Box<dyn crate::app::seam_stubs::AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![] })
        }
        fn get_context(&self) -> Box<dyn crate::app::seam_stubs::AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![] })
        }
    }

    #[derive(Debug, Clone)]
    struct MockBlock {
        vals: Vec<i8>,
    }

    impl crate::app::seam_stubs::AssemblyPatternBlock for MockBlock {
        fn get_vals(&self) -> Vec<i8> {
            self.vals.clone()
        }
        fn fill_mask(&self) -> Box<dyn crate::app::seam_stubs::AssemblyPatternBlock> {
            Box::new(self.clone())
        }
    }

    #[derive(Debug)]
    struct MockSolver;

    impl RecursiveDescentSolver for MockSolver {
        fn solve(
            &self,
            _factory: &dyn crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyResolutionFactory,
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
            _goal: crate::app::seam_stubs::MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _hints: &std::collections::HashSet<
                std::sync::Arc<dyn crate::app::plugin::assembler::sleigh::expr::SolverHint>,
            >,
            _description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, crate::app::plugin::assembler::sleigh::expr::NeedsBackfillException>
        {
            unimplemented!("not exercised by these tests")
        }

        fn get_value(
            &self,
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<
            Option<crate::app::seam_stubs::MaskedLong>,
            crate::app::plugin::assembler::sleigh::expr::NeedsBackfillException,
        > {
            unimplemented!("not exercised by these tests")
        }

        fn get_instruction_length(
            &self,
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
        ) -> i32 {
            unimplemented!("not exercised by these tests")
        }

        fn value_for_resolution(
            &self,
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
            _vals: &HashMap<String, i64>,
            _rc: &dyn AssemblyResolvedPatterns,
        ) -> crate::app::seam_stubs::MaskedLong {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A backfill record awaiting a single symbol (mimics needing `inst_next`).
    #[derive(Debug)]
    struct MockBackfill {
        instruction_length: i32,
        missing_symbol: String,
    }

    impl std::fmt::Display for MockBackfill {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "backfill({})", self.missing_symbol)
        }
    }

    impl AssemblyResolution for MockBackfill {
        fn get_description(&self) -> String {
            format!("backfill({})", self.missing_symbol)
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            vec![]
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.get_description()
        }
        fn is_backfill(&self) -> bool {
            true
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockBackfill {
                instruction_length: self.instruction_length + amt,
                missing_symbol: self.missing_symbol.clone(),
            })
        }
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(Res { desc: description.to_string(), backfill: false, error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.get_description())
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.get_description().cmp(&other.get_description())
        }
    }

    impl AssemblyResolvedBackfill for MockBackfill {
        fn get_instruction_length(&self) -> i32 {
            self.instruction_length
        }

        fn shift_backfill(&self, amt: i32) -> Box<dyn AssemblyResolvedBackfill> {
            Box::new(MockBackfill {
                instruction_length: self.instruction_length + amt,
                missing_symbol: self.missing_symbol.clone(),
            })
        }

        fn solve(
            &self,
            _solver: &dyn RecursiveDescentSolver,
            vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AssemblyResolution> {
            if vals.contains_key(&self.missing_symbol) {
                Box::new(Res {
                    desc: format!("solved {}", self.missing_symbol),
                    backfill: false,
                    error: false,
                })
            } else {
                Box::new(Res {
                    desc: format!("still missing {}", self.missing_symbol),
                    backfill: false,
                    error: true,
                })
            }
        }
    }

    fn make(missing_symbol: &str) -> MockBackfill {
        MockBackfill { instruction_length: 4, missing_symbol: missing_symbol.to_string() }
    }

    #[test]
    fn get_instruction_length_returns_value() {
        let bf = MockBackfill { instruction_length: 8, missing_symbol: "x".to_string() };
        assert_eq!(bf.get_instruction_length(), 8);
    }

    #[test]
    fn shift_backfill_increases_instruction_length_and_preserves_symbol() {
        let bf = make("inst_next");
        let shifted = bf.shift_backfill(3);
        assert_eq!(shifted.get_instruction_length(), 7);
    }

    #[test]
    fn solve_succeeds_once_missing_symbol_is_defined() {
        let bf = make("inst_next");
        let mut vals = HashMap::new();
        vals.insert("inst_next".to_string(), 0x1000i64);
        let cur = Res { desc: "cur".to_string(), backfill: false, error: false };

        let result = bf.solve(&MockSolver, &vals, &cur);

        assert!(!result.is_error());
        assert_eq!(result.get_description(), "solved inst_next");
    }

    #[test]
    fn solve_still_errors_when_symbol_remains_missing() {
        let bf = make("inst_next");
        let vals = HashMap::new();
        let cur = Res { desc: "cur".to_string(), backfill: false, error: false };

        let result = bf.solve(&MockSolver, &vals, &cur);

        assert!(result.is_error());
        assert_eq!(result.get_description(), "still missing inst_next");
    }

    #[test]
    fn is_backfill_is_true() {
        let bf = make("inst_next");
        assert!(bf.is_backfill());
        assert!(!bf.is_error());
    }

    #[test]
    fn trait_is_object_safe() {
        let bf: Box<dyn AssemblyResolvedBackfill> = Box::new(make("inst_next"));
        assert_eq!(bf.get_instruction_length(), 4);
        assert!(bf.is_backfill());
    }
}
