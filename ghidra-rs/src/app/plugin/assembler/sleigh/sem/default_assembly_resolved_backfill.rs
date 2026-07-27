use super::{AssemblyResolution, AssemblyResolvedBackfill};

/// The default, buildable implementation of [`AssemblyResolvedBackfill`].
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolvedBackfill`, cut to a
/// trait to break a dependency cycle at this node in the port graph. The Java class's protected
/// `computeHash`/`copyBuilder`/`copy`/`shiftBuilder` helpers are internal construction details
/// tied to the not-yet-ported `AbstractAssemblyResolutionFactory` builder machinery and its
/// `AbstractAssemblyResolvedBackfillBuilder`, and are left out of this trait's public surface.
/// Only the one member this class adds beyond its `AssemblyResolvedBackfill` supertrait -- its
/// covariant, always-failing override of `AbstractAssemblyResolution.withRight` -- is modeled
/// here; the rest of the class's public API (`getInstructionLength`, `isError`, `isBackfill`,
/// `lineToString`, `shift`, `parent`, `solve`) is already covered by that supertrait (via its own
/// `AssemblyResolution` supertrait).
pub trait DefaultAssemblyResolvedBackfill: AssemblyResolvedBackfill {
    /// Attach a right sibling to this record.
    ///
    /// Named distinctly from a plain `with_right` (following the
    /// [`shift`](super::AssemblyResolution::shift)/
    /// [`shift_backfill`](AssemblyResolvedBackfill::shift_backfill) naming precedent already
    /// established in this module) so that if `AbstractAssemblyResolution.withRight` is later
    /// ported as a same-named supertrait method returning `Box<dyn AssemblyResolution>`, trait
    /// objects here won't hit an ambiguous-method-call error.
    ///
    /// Mirrors `DefaultAssemblyResolvedBackfill.withRight(AssemblyResolution)`, which
    /// unconditionally throws `AssertionError`: a backfill record's right sibling is always
    /// attached to the `AssemblyResolvedPatterns` record it's queued on, never to the backfill
    /// itself. The default implementation reproduces that fixed behavior so implementors don't
    /// each need to repeat it.
    fn with_right_backfill(
        &self,
        right: Box<dyn AssemblyResolution>,
    ) -> Box<dyn AssemblyResolvedBackfill> {
        let _ = right;
        panic!("DefaultAssemblyResolvedBackfill cannot take a right sibling")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{AssemblyResolvedPatterns, RecursiveDescentSolver};
    use std::cmp::Ordering;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct MockBackfill {
        instruction_length: i32,
    }

    impl std::fmt::Display for MockBackfill {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "backfill(len:{})", self.instruction_length)
        }
    }

    impl AssemblyResolution for MockBackfill {
        fn get_description(&self) -> String {
            "mock backfill".to_string()
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
            Box::new(MockBackfill { instruction_length: self.instruction_length + amt })
        }
        fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            panic!("DefaultAssemblyResolvedBackfill cannot take a parent")
        }
        fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>) {
            into.push(Box::new(self.clone()));
        }
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
            Box::new(MockBackfill { instruction_length: self.instruction_length + amt })
        }

        fn solve(
            &self,
            _solver: &dyn RecursiveDescentSolver,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
    }

    // No override needed: the default `with_right_backfill` reproduces the Java class's fixed
    // `AssertionError`-throwing behavior.
    impl DefaultAssemblyResolvedBackfill for MockBackfill {}

    #[test]
    fn trait_is_object_safe_and_inherits_backfill_behavior() {
        let bf: Box<dyn DefaultAssemblyResolvedBackfill> =
            Box::new(MockBackfill { instruction_length: 4 });
        assert_eq!(bf.get_instruction_length(), 4);
        assert!(bf.is_backfill());
        assert!(!bf.is_error());
        let shifted = bf.shift_backfill(3);
        assert_eq!(shifted.get_instruction_length(), 7);
    }

    #[test]
    fn with_right_backfill_panics_like_java_assertion_error() {
        let bf = MockBackfill { instruction_length: 4 };
        let sibling: Box<dyn AssemblyResolution> = Box::new(bf.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bf.with_right_backfill(sibling)
        }));
        assert!(result.is_err(), "with_right_backfill must panic, mirroring AssertionError");
    }
}
