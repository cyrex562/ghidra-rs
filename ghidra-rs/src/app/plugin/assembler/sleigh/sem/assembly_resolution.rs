use std::cmp::Ordering;
use std::rc::Rc;

use super::{AssemblyResolvedBackfill, AssemblyResolvedPatterns};

/// A single record produced during assembly resolution.
///
/// Implementors represent one possible outcome at a given resolution step: a
/// successfully resolved byte pattern, a backfill request, or an error.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution`.
pub trait AssemblyResolution: std::fmt::Display + std::fmt::Debug {
    /// Human-readable one-line label for this record.
    fn get_description(&self) -> String;

    /// Child records, as used by [`to_string_indented`](Self::to_string_indented)
    /// for multi-line display.
    fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>>;

    /// Returns `true` if this record has any children.
    ///
    /// Implementations with additional, subclass-specific children should
    /// override this to return `true` when such children are present.
    fn has_children(&self) -> bool;

    /// The next sibling in the right-linked list, if any.
    fn get_right(&self) -> Option<Box<dyn AssemblyResolution>>;

    /// One-line display of this record, omitting child details.
    fn line_to_string(&self) -> String;

    /// Returns `true` if this record represents a backfill request.
    fn is_backfill(&self) -> bool;

    /// Returns `true` if this record represents an error.
    fn is_error(&self) -> bool;

    /// Shift the instruction byte pattern right by `amt` bytes.
    ///
    /// Also shifts any backfill and forbidden-pattern records attached to this
    /// resolution.
    fn shift(&self, amt: i32) -> Box<dyn AssemblyResolution>;

    /// Wrap this resolution as a child, pushing right-siblings down.
    fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution>;

    /// Collect this record and all right-siblings into `into`.
    fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>);

    /// Multi-line description of this record, with each line prefixed by `indent`.
    ///
    /// Used by parent records when building their own [`to_string_indented`](Self::to_string_indented)
    /// output.
    fn to_string_indented(&self, indent: &str) -> String;

    /// Total ordering consistent with Java's `Comparable<AssemblyResolution>`.
    fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering;

    /// Attempt to view this record as an [`AssemblyResolvedPatterns`].
    ///
    /// Not part of the Java interface -- it exists to stand in for the unchecked
    /// `(AssemblyResolvedPatterns) res` casts Java code performs after checking
    /// [`is_error`](Self::is_error)/[`is_backfill`](Self::is_backfill) (e.g. throughout
    /// `AssemblyResolutionResults.apply`), which Rust's trait-object model has no direct
    /// equivalent for absent a full `Any`-based downcast. Defaults to `None`; concrete types that
    /// also implement `AssemblyResolvedPatterns` should override this to return `Some(self)`, at
    /// which point callers can rely on `!is_error() && !is_backfill()` implying `Some`, mirroring
    /// the guarantee Java's cast relies on (and panicking the same way Java's `ClassCastException`
    /// would if that invariant is ever violated).
    fn as_resolved_patterns(&self) -> Option<&dyn AssemblyResolvedPatterns> {
        None
    }

    /// Attempt to view this record as an [`AssemblyResolvedBackfill`].
    ///
    /// The backfill counterpart to [`as_resolved_patterns`](Self::as_resolved_patterns); see its
    /// docs for the rationale. Defaults to `None`; concrete backfill types should override this to
    /// return `Some(self)`, at which point `is_backfill()` implies `Some`.
    fn as_backfill(&self) -> Option<&dyn AssemblyResolvedBackfill> {
        None
    }
}

/// Lets one logical resolution be shared behind multiple, independently-owned
/// `Box<dyn AssemblyResolution>` handles.
///
/// `AssemblyResolution` deliberately doesn't require `Clone` (see e.g.
/// [`DefaultAssemblyResolvedError`](super::DefaultAssemblyResolvedError)'s doc comment), yet
/// several real Java call sites (e.g. `AssemblyResolutionResults.apply`'s inner loop) pass the
/// very same `AssemblyResolution` reference to more than one method that Rust's already-ported
/// signatures model as taking a owned `Box<dyn AssemblyResolution>` -- Java can do this freely
/// since object references are always shared, but Rust's ownership rules would otherwise force a
/// real duplicate. Wrapping a value behind `Rc` and relying on this blanket implementation (which
/// simply forwards every call through to the shared value) lets a caller mint as many independent,
/// owned `Box<dyn AssemblyResolution>` handles as it needs -- each just a cheap refcount bump --
/// without ever needing to duplicate the underlying data.
impl AssemblyResolution for Rc<dyn AssemblyResolution> {
    fn get_description(&self) -> String {
        (**self).get_description()
    }
    fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
        (**self).get_children()
    }
    fn has_children(&self) -> bool {
        (**self).has_children()
    }
    fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
        (**self).get_right()
    }
    fn line_to_string(&self) -> String {
        (**self).line_to_string()
    }
    fn is_backfill(&self) -> bool {
        (**self).is_backfill()
    }
    fn is_error(&self) -> bool {
        (**self).is_error()
    }
    fn shift(&self, amt: i32) -> Box<dyn AssemblyResolution> {
        (**self).shift(amt)
    }
    fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
        (**self).parent(description, op_count)
    }
    fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>) {
        (**self).collect_all_right(into)
    }
    fn to_string_indented(&self, indent: &str) -> String {
        (**self).to_string_indented(indent)
    }
    fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
        (**self).compare_to(other)
    }
    fn as_resolved_patterns(&self) -> Option<&dyn AssemblyResolvedPatterns> {
        (**self).as_resolved_patterns()
    }
    fn as_backfill(&self) -> Option<&dyn AssemblyResolvedBackfill> {
        (**self).as_backfill()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Res {
        desc: &'static str,
        backfill: bool,
        error: bool,
    }

    impl std::fmt::Display for Res {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl std::fmt::Debug for Res {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Res({})", self.desc)
        }
    }

    impl AssemblyResolution for Res {
        fn get_description(&self) -> String {
            self.desc.to_string()
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
            self.desc.to_string()
        }
        fn is_backfill(&self) -> bool {
            self.backfill
        }
        fn is_error(&self) -> bool {
            self.error
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(Res { desc: self.desc, backfill: self.backfill, error: self.error })
        }
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(Res { desc: Box::leak(description.to_string().into_boxed_str()), backfill: false, error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(other.get_description().as_str())
        }
    }

    fn make(desc: &'static str) -> Box<dyn AssemblyResolution> {
        Box::new(Res { desc, backfill: false, error: false })
    }

    #[test]
    fn get_description_returns_label() {
        let r = make("op0");
        assert_eq!(r.get_description(), "op0");
    }

    #[test]
    fn display_matches_description() {
        let r = make("label");
        assert_eq!(r.to_string(), "label");
    }

    #[test]
    fn line_to_string_matches_description() {
        let r = make("short");
        assert_eq!(r.line_to_string(), "short");
    }

    #[test]
    fn has_children_false_by_default() {
        let r = make("x");
        assert!(!r.has_children());
    }

    #[test]
    fn get_children_empty_by_default() {
        let r = make("x");
        assert!(r.get_children().is_empty());
    }

    #[test]
    fn get_right_none_by_default() {
        let r = make("x");
        assert!(r.get_right().is_none());
    }

    #[test]
    fn is_backfill_false_for_normal_resolution() {
        let r = make("x");
        assert!(!r.is_backfill());
    }

    #[test]
    fn is_error_false_for_normal_resolution() {
        let r = make("x");
        assert!(!r.is_error());
    }

    #[test]
    fn is_backfill_true_when_set() {
        let r: Box<dyn AssemblyResolution> = Box::new(Res { desc: "bf", backfill: true, error: false });
        assert!(r.is_backfill());
    }

    #[test]
    fn is_error_true_when_set() {
        let r: Box<dyn AssemblyResolution> = Box::new(Res { desc: "err", backfill: false, error: true });
        assert!(r.is_error());
    }

    #[test]
    fn shift_returns_equivalent_resolution() {
        let r = make("instr");
        let shifted = r.shift(2);
        assert_eq!(shifted.get_description(), "instr");
    }

    #[test]
    fn to_string_indented_prepends_indent() {
        let r = make("child");
        assert_eq!(r.to_string_indented("  "), "  child");
    }

    #[test]
    fn to_string_indented_empty_indent() {
        let r = make("child");
        assert_eq!(r.to_string_indented(""), "child");
    }

    #[test]
    fn collect_all_right_on_leaf_adds_nothing() {
        let r = make("leaf");
        let mut v: Vec<Box<dyn AssemblyResolution>> = vec![];
        r.collect_all_right(&mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn compare_to_equal_descriptions() {
        let a = make("abc");
        let b = make("abc");
        assert_eq!(a.compare_to(b.as_ref()), Ordering::Equal);
    }

    #[test]
    fn compare_to_less() {
        let a = make("abc");
        let b = make("xyz");
        assert_eq!(a.compare_to(b.as_ref()), Ordering::Less);
    }

    #[test]
    fn compare_to_greater() {
        let a = make("xyz");
        let b = make("abc");
        assert_eq!(a.compare_to(b.as_ref()), Ordering::Greater);
    }

    #[test]
    fn trait_is_object_safe() {
        let r: &dyn AssemblyResolution = &Res { desc: "test", backfill: false, error: false };
        assert_eq!(r.get_description(), "test");
    }

    #[test]
    fn as_resolved_patterns_defaults_to_none() {
        let r = make("x");
        assert!(r.as_resolved_patterns().is_none());
    }

    #[test]
    fn as_backfill_defaults_to_none() {
        let r = make("x");
        assert!(r.as_backfill().is_none());
    }

    // --- `Rc<dyn AssemblyResolution>` forwarding blanket impl ---

    #[test]
    fn rc_wrapper_forwards_every_call_to_the_shared_value() {
        let shared: Rc<dyn AssemblyResolution> = Rc::new(Res { desc: "shared", backfill: true, error: false });

        assert_eq!(shared.get_description(), "shared");
        assert_eq!(shared.line_to_string(), "shared");
        assert!(shared.is_backfill());
        assert!(!shared.is_error());
        assert!(shared.get_children().is_empty());
        assert!(shared.get_right().is_none());
        assert!(shared.as_resolved_patterns().is_none());
        assert!(shared.as_backfill().is_none());
        assert_eq!(shared.to_string_indented(">> "), ">> shared");
        assert_eq!(shared.compare_to((&*shared) as &dyn AssemblyResolution), Ordering::Equal);

        let mut collected = Vec::new();
        shared.collect_all_right(&mut collected);
        assert!(collected.is_empty());
    }

    #[test]
    fn rc_wrapper_mints_independent_owned_handles_to_the_same_value() {
        // Mirrors the real motivating scenario (`AssemblyResolutionResults.apply`'s inner loop):
        // one logical resolution ("cur") needs to be handed off, as an owned
        // `Box<dyn AssemblyResolution>`, to more than one call -- something Java does for free
        // via shared references, but which plain `Box` ownership can't, absent `Clone`.
        let shared: Rc<dyn AssemblyResolution> = Rc::new(Res { desc: "cur", backfill: false, error: false });

        let handle_a: Box<dyn AssemblyResolution> = Box::new(shared.clone());
        let handle_b: Box<dyn AssemblyResolution> = Box::new(shared.clone());

        // Two independently-owned boxes, both forwarding to the very same underlying value.
        assert_eq!(handle_a.get_description(), "cur");
        assert_eq!(handle_b.get_description(), "cur");
        assert_eq!(Rc::strong_count(&shared), 3);

        drop(handle_a);
        assert_eq!(Rc::strong_count(&shared), 2);
        drop(handle_b);
        assert_eq!(Rc::strong_count(&shared), 1);
    }
}
