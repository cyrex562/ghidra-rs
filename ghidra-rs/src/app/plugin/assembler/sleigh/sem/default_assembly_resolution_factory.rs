//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolutionFactory`.

use super::AbstractAssemblyResolutionFactory;

/// The default assembly resolution factory.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolutionFactory`, a concrete
/// class extending `AbstractAssemblyResolutionFactory<AssemblyResolvedPatterns,
/// AssemblyResolvedBackfill>` and overriding exactly two methods:
///
/// ```java
/// public class DefaultAssemblyResolutionFactory extends
/// 		AbstractAssemblyResolutionFactory<AssemblyResolvedPatterns, AssemblyResolvedBackfill> {
/// 	@Override
/// 	public DefaultAssemblyResolvedPatternBuilder newPatternsBuilder() {
/// 		return new DefaultAssemblyResolvedPatternBuilder();
/// 	}
/// 	@Override
/// 	public DefaultAssemblyResolvedBackfillBuilder newBackfillBuilder() {
/// 		return new DefaultAssemblyResolvedBackfillBuilder();
/// 	}
/// }
/// ```
///
/// # Why this trait has no members
///
/// Both of Java's overrides pick the concrete builder pair (`DefaultAssemblyResolvedPatternBuilder`,
/// `DefaultAssemblyResolvedBackfillBuilder`) that the *inherited* terminal methods (`nop`, `error`,
/// `resolved`, `instrOnly`, `contextOnly`, `fromPattern`, `fromString`, `backfill`) build through --
/// `newPatternsBuilder`/`newBackfillBuilder` are never called directly by any other class; they
/// exist purely so `AbstractAssemblyResolutionFactory`'s own method bodies can reach a builder.
/// This port's [`AbstractAssemblyResolutionFactory`] trait, however, already excludes
/// `newPatternsBuilder`/`newBackfillBuilder` from its surface entirely, and instead leaves every
/// one of those terminal methods as a `required` (bodyless) trait method for implementors to
/// provide directly -- see that trait's own doc comment, which explains this is because the private
/// builder machinery those methods are built on (`AbstractAssemblyResolutionBuilder` and friends)
/// isn't ported, and neither is a concrete, constructible `DefaultAssemblyResolvedPatterns` (only
/// the [`AssemblyResolvedPatterns`](super::AssemblyResolvedPatterns) trait it would implement).
///
/// Consequently, `DefaultAssemblyResolutionFactory`'s entire reason for existing -- selecting which
/// builder pair backs the terminal methods -- has nothing to attach to on this port's supertrait.
/// This trait therefore models exactly what Java's `extends` clause establishes and nothing more: a
/// pure `is-a` relationship, `DefaultAssemblyResolutionFactory: AbstractAssemblyResolutionFactory`,
/// with an empty body. Any type that already implements [`AbstractAssemblyResolutionFactory`] can
/// opt into this trait for free (`impl DefaultAssemblyResolutionFactory for MyFactory {}`), the same
/// way [`DefaultAssemblyResolvedBackfill`](super::DefaultAssemblyResolvedBackfill) -- blocked on the
/// very same unported builder machinery -- keeps only the one member of its own Java class that
/// *is* expressible (its fixed-panic `withRight` override) and inherits the rest through its own
/// supertrait.
///
/// When `DefaultAssemblyResolvedPatterns`/`DefaultAssemblyResolvedPatternBuilder`/
/// `DefaultAssemblyResolvedBackfillBuilder` are eventually ported as concrete, constructible types,
/// [`AbstractAssemblyResolutionFactory`] will likely grow the excluded `new_patterns_builder`/
/// `new_backfill_builder` hooks (with real default bodies for the builder-backed terminal methods
/// built on them, mirroring the Java base class). At that point this trait becomes the natural place
/// to override just those two hooks and inherit everything else -- exactly mirroring the two-method
/// Java class above.
pub trait DefaultAssemblyResolutionFactory: AbstractAssemblyResolutionFactory {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        AssemblyPatternBlock, AssemblyResolutionEntry, AssemblyResolutionResults, Constructor,
        MaskedLong,
    };
    use crate::app::plugin::assembler::sleigh::sem::{AssemblyResolution, AssemblyResolvedPatterns};
    use crate::program::model::lang::sleigh::expression::PatternExpression;
    use crate::program::model::lang::sleigh::pattern::DisjointPattern;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    struct MockRes {
        desc: String,
    }

    impl std::fmt::Display for MockRes {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl AssemblyResolution for MockRes {
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
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: format!("{description}[{op_count}]<-{}", self.desc) })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    #[derive(Default)]
    struct MockResults {
        items: Vec<Box<dyn AssemblyResolution>>,
    }

    impl AssemblyResolutionResults for MockResults {
        fn resolutions(&self) -> Vec<AssemblyResolutionEntry> {
            Vec::new()
        }
        fn iter_all(&self) -> Vec<Box<dyn AssemblyResolution>> {
            self.items.iter().map(|r| r.shift(0)).collect()
        }
        fn add(&mut self, ar: Box<dyn AssemblyResolution>) {
            self.items.push(ar);
        }
    }

    #[derive(Clone)]
    struct MockPatternBlock;
    impl AssemblyPatternBlock for MockPatternBlock {
        fn get_vals(&self) -> Vec<i8> {
            Vec::new()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(self.clone())
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyPatternBlock> {
            Box::new(self.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct MockPatterns {
        desc: String,
    }
    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }
    impl AssemblyResolution for MockPatterns {
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
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockPatterns { desc: format!("{description}[{op_count}]") })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }
    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn get_instruction_length(&self) -> i32 {
            0
        }
        fn get_defined_instruction_length(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_backfills(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill>> {
            unimplemented!("not exercised by these tests")
        }
        fn has_backfills(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_forbids(&self) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn read_instruction(&self, _byte_start: i32, _size: i32) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context(&self, _start: i32, _len: i32) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context_op(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
        ) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn bits_equal(&self, _that: &dyn AssemblyResolvedPatterns) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn equivalent_construct_state(
            &self,
            _state: &crate::program::model::lang::sleigh::walker::ConstructState,
        ) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn shift_patterns(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_description(&self, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_right_patterns(
            &self,
            _right: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_constructor(&self, _cons: Arc<dyn Constructor>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine(
            &self,
            _pat: &dyn AssemblyResolvedPatterns,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_backfill(
            &self,
            _bf: &dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_less_backfill(
            &self,
            _that: &dyn AssemblyResolvedPatterns,
            _bf: &dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn parent_patterns(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn backfill(
            &self,
            _solver: &dyn crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn check_not_forbidden(&self) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn nop_left_sibling(&self) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn solve_context_changes_for_forbids(
            &self,
            _sem: &dyn crate::app::seam_stubs::AssemblyConstructorSemantic,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn possible_ins_vals(&self, _for_ctx: &dyn AssemblyPatternBlock) -> Vec<Vec<u8>> {
            unimplemented!("not exercised by these tests")
        }
        fn dump_constructor_tree(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn truncate(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_forbids(
            &self,
            _more: Vec<Box<dyn AssemblyResolvedPatterns>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn mask_out(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn write_context_op(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
            _val: MaskedLong,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A factory implementing every `AbstractAssemblyResolutionFactory` terminal method directly
    /// (as this port requires -- see the module docs), standing in for what
    /// `DefaultAssemblyResolutionFactory` would build through
    /// `DefaultAssemblyResolvedPatternBuilder`/`DefaultAssemblyResolvedBackfillBuilder` in Java.
    struct MockFactory;

    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            Box::new(MockResults::default())
        }
        fn nop(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn nop_with_children(
            &self,
            description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn error(&self, error: &str, _res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: error.to_string() })
        }
        fn backfill(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _inslen: i32,
            description: &str,
        ) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: description.to_string() })
        }
        fn resolved(
            &self,
            _ins: Box<dyn AssemblyPatternBlock>,
            _ctx: Box<dyn AssemblyPatternBlock>,
            description: &str,
            _cons: Option<Arc<dyn Constructor>>,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn instr_only(&self, _ins: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn context_only(&self, _ctx: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn from_pattern(
            &self,
            _pat: &DisjointPattern,
            _min_len: i32,
            description: &str,
            _cons: Option<Arc<dyn Constructor>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn from_string(
            &self,
            str: &str,
            description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
        ) -> Result<Box<dyn AssemblyResolvedPatterns>, String> {
            if str.is_empty() {
                Ok(Box::new(MockPatterns { desc: description.to_string() }))
            } else {
                Err(str.to_string())
            }
        }
        fn solve_or_backfill_masked(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            description: &str,
        ) -> Box<dyn AssemblyResolution> {
            if vals.contains_key("known") {
                Box::new(MockRes { desc: description.to_string() })
            } else {
                Box::new(MockRes { desc: format!("backfill:{description}") })
            }
        }
    }

    // No members to add: `DefaultAssemblyResolutionFactory` contributes nothing beyond the
    // `is-a AbstractAssemblyResolutionFactory` relationship in this port -- see the module docs.
    impl DefaultAssemblyResolutionFactory for MockFactory {}

    #[test]
    fn trait_is_object_safe_and_inherits_terminal_methods() {
        let f: Box<dyn DefaultAssemblyResolutionFactory> = Box::new(MockFactory);
        assert_eq!(f.nop("blank").get_description(), "blank");
        assert_eq!(f.error("oops", &MockRes { desc: "cause".to_string() }).get_description(), "oops");
    }

    /// The supertrait's own provided methods ([`results`](AbstractAssemblyResolutionFactory::results)/
    /// [`singleton`](AbstractAssemblyResolutionFactory::singleton)) are reachable through a
    /// `DefaultAssemblyResolutionFactory` reference too, since Rust dispatches supertrait methods
    /// through the same vtable.
    #[test]
    fn inherits_supertrait_provided_methods() {
        let f = MockFactory;
        let set = f.singleton(Box::new(MockRes { desc: "only".to_string() }));
        let items = set.iter_all();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get_description(), "only");
    }

    #[test]
    fn from_string_ok_and_err_paths_via_default_factory_reference() {
        let f: &dyn DefaultAssemblyResolutionFactory = &MockFactory;
        assert!(f.from_string("", "d", vec![]).is_ok());
        assert_eq!(f.from_string("garbage", "d", vec![]).unwrap_err(), "garbage");
    }
}
