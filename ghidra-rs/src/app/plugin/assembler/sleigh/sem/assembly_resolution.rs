use std::cmp::Ordering;

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
}
