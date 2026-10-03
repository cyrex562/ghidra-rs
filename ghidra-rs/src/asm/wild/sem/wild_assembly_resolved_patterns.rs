//! Port of `ghidra.asm.wild.sem.WildAssemblyResolvedPatterns`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedPatterns;
use crate::app::seam_stubs::{AssemblyConstructorSemantic, AssemblyPatternBlock};
use crate::program::model::lang::sleigh::expression::PatternExpression;

use super::seam_stubs::WildOperandInfo;

/// The result of assembling an instruction with the wildcard assembler.
///
/// Port of `ghidra.asm.wild.sem.WildAssemblyResolvedPatterns`, a Java `interface extends
/// AssemblyResolvedPatterns` with one concrete implementer in the original tree, hence the
/// `trait` shape (see `scripts/shape_rules.py`).
pub trait WildAssemblyResolvedPatterns: AssemblyResolvedPatterns {
    /// The information for wildcarded operands in this instruction.
    ///
    /// Mirrors `getOperandInfo()`. Java returns a `Set<WildOperandInfo>`; this returns a `Vec`
    /// instead, since [`WildOperandInfo`] has no meaningful `Eq`/`Hash` impl to back a `HashSet`
    /// (see that type's docs).
    fn get_operand_info(&self) -> Vec<WildOperandInfo>;

    /// Create a copy of this result with added wildcard information.
    ///
    /// Mirrors `withWildInfo(String, List, AssemblyPatternBlock, PatternExpression, Object)`. See
    /// [`WildOperandInfo`] for the meaning of each parameter.
    fn with_wild_info(
        &self,
        wildcard: &str,
        path: Vec<Arc<dyn AssemblyConstructorSemantic>>,
        location: Box<dyn AssemblyPatternBlock>,
        expression: PatternExpression,
        choice: Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) -> Box<dyn WildAssemblyResolvedPatterns>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver;
    use crate::app::plugin::assembler::sleigh::sem::{AssemblyResolution, AssemblyResolvedBackfill};
    use crate::app::seam_stubs::{Constructor, MaskedLong};
    use crate::program::model::lang::sleigh::constructor::ContextOp;
    use crate::program::model::lang::sleigh::walker::ConstructState;
    use std::cmp::Ordering;
    use std::fmt;

    #[derive(Debug, Clone)]
    struct MockPatternBlock {
        vals: Vec<i8>,
    }

    impl AssemblyPatternBlock for MockPatternBlock {
        fn get_vals(&self) -> Vec<i8> {
            self.vals.clone()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock { vals: vec![-1; self.vals.len()] })
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyPatternBlock> {
            Box::new(self.clone())
        }
    }

    struct MockResolvedPatterns {
        description: String,
        operand_info: Vec<WildOperandInfo>,
    }

    impl fmt::Display for MockResolvedPatterns {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.description)
        }
    }

    impl fmt::Debug for MockResolvedPatterns {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockResolvedPatterns({})", self.description)
        }
    }

    impl AssemblyResolution for MockResolvedPatterns {
        fn get_description(&self) -> String {
            self.description.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            Vec::new()
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.description.clone()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockResolvedPatterns {
                description: self.description.clone(),
                operand_info: self.operand_info.clone(),
            })
        }
        fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            unimplemented!("not needed for this test")
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.description)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.description.cmp(&other.get_description())
        }
        fn as_resolved_patterns(&self) -> Option<&dyn AssemblyResolvedPatterns> {
            Some(self)
        }
        fn as_backfill(
            &self,
        ) -> Option<&dyn AssemblyResolvedBackfill> {
            None
        }
    }

    impl AssemblyResolvedPatterns for MockResolvedPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock { vals: Vec::new() })
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock { vals: Vec::new() })
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn get_instruction_length(&self) -> i32 {
            0
        }
        fn get_defined_instruction_length(&self) -> i32 {
            0
        }
        fn get_backfills(
            &self,
        ) -> Vec<Box<dyn AssemblyResolvedBackfill>> {
            Vec::new()
        }
        fn has_backfills(&self) -> bool {
            false
        }
        fn get_forbids(&self) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            Vec::new()
        }
        fn read_instruction(&self, _byte_start: i32, _size: i32) -> MaskedLong {
            unimplemented!("not needed for this test")
        }
        fn read_context(&self, _start: i32, _len: i32) -> MaskedLong {
            unimplemented!("not needed for this test")
        }
        fn read_context_op(
            &self,
            _cop: &ContextOp,
        ) -> MaskedLong {
            unimplemented!("not needed for this test")
        }
        fn bits_equal(&self, _that: &dyn AssemblyResolvedPatterns) -> bool {
            false
        }
        fn equivalent_construct_state(
            &self,
            _state: &ConstructState,
        ) -> bool {
            false
        }
        fn shift_patterns(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn with_description(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockResolvedPatterns {
                description: description.to_string(),
                operand_info: self.operand_info.clone(),
            })
        }
        fn with_right_patterns(
            &self,
            _right: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn with_constructor(
            &self,
            _cons: Arc<dyn Constructor>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn combine(
            &self,
            _pat: &dyn AssemblyResolvedPatterns,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            None
        }
        fn combine_backfill(
            &self,
            _bf: &dyn AssemblyResolvedBackfill,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn combine_less_backfill(
            &self,
            _that: &dyn AssemblyResolvedPatterns,
            _bf: &dyn AssemblyResolvedBackfill,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            None
        }
        fn parent_patterns(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn backfill(
            &self,
            _solver: &dyn RecursiveDescentSolver,
            _vals: &std::collections::HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not needed for this test")
        }
        fn check_not_forbidden(&self) -> Box<dyn AssemblyResolution> {
            unimplemented!("not needed for this test")
        }
        fn nop_left_sibling(&self) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn solve_context_changes_for_forbids(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _vals: &std::collections::HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn possible_ins_vals(&self, _for_ctx: &dyn AssemblyPatternBlock) -> Vec<Vec<u8>> {
            Vec::new()
        }
        fn dump_constructor_tree(&self) -> String {
            String::new()
        }
        fn truncate(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn with_forbids(
            &self,
            _more: Vec<Box<dyn AssemblyResolvedPatterns>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn mask_out(&self, _cop: &ContextOp) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
        fn write_context_op(
            &self,
            _cop: &ContextOp,
            _val: MaskedLong,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not needed for this test")
        }
    }

    impl WildAssemblyResolvedPatterns for MockResolvedPatterns {
        fn get_operand_info(&self) -> Vec<WildOperandInfo> {
            self.operand_info.clone()
        }

        fn with_wild_info(
            &self,
            wildcard: &str,
            path: Vec<Arc<dyn AssemblyConstructorSemantic>>,
            location: Box<dyn AssemblyPatternBlock>,
            expression: PatternExpression,
            choice: Option<Arc<dyn std::any::Any + Send + Sync>>,
        ) -> Box<dyn WildAssemblyResolvedPatterns> {
            let mut operand_info = self.operand_info.clone();
            operand_info.push(WildOperandInfo::new(
                wildcard,
                path,
                Arc::from(location),
                expression,
                choice,
            ));
            Box::new(MockResolvedPatterns { description: self.description.clone(), operand_info })
        }
    }

    fn expr() -> PatternExpression {
        PatternExpression::Constant(0)
    }

    #[test]
    fn get_operand_info_starts_empty() {
        let patterns =
            MockResolvedPatterns { description: "test".to_string(), operand_info: Vec::new() };
        assert!(patterns.get_operand_info().is_empty());
    }

    #[test]
    fn with_wild_info_appends_operand_info() {
        let patterns =
            MockResolvedPatterns { description: "test".to_string(), operand_info: Vec::new() };
        let location: Box<dyn AssemblyPatternBlock> = Box::new(MockPatternBlock { vals: vec![1, 2] });

        let updated = patterns.with_wild_info("Rd", Vec::new(), location, expr(), None);

        let info = updated.get_operand_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].wildcard, "Rd");
        assert_eq!(info[0].location.get_vals(), vec![1, 2]);
    }

    #[test]
    fn wild_operand_info_shift_preserves_wildcard_and_shifts_location() {
        let info = WildOperandInfo::new(
            "Rd",
            Vec::new(),
            Arc::new(MockPatternBlock { vals: vec![1, 2] }),
            expr(),
            None,
        );
        let shifted = info.shift(4);
        assert_eq!(shifted.wildcard, "Rd");
        assert_eq!(shifted.location.get_vals(), vec![1, 2]);
    }
}
