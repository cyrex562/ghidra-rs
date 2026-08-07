use std::collections::HashSet;

use crate::trace::model::breakpoint::trace_breakpoint_kind::TraceBreakpointKind;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::seam_stubs::{TraceBreakpointCommon, TraceBreakpointLocation};

/// Key for the breakpoint's expression attribute.
pub const KEY_EXPRESSION: &str = "_expression";
/// Key for the breakpoint's kinds attribute.
pub const KEY_KINDS: &str = "_kinds";
/// Key for the breakpoint's "as bpt" attribute.
pub const KEY_AS_BPT: &str = "_bpt";

/// The specification of a breakpoint applied to a target object.
///
/// Port of `ghidra.trace.model.breakpoint.TraceBreakpointSpec`.
///
/// Note that a single specification could result in several locations, or no locations at all.
/// For example, a breakpoint placed on a function within a module which has not been loaded
/// ("pending" in GDB's nomenclature), will not have any location. On the other hand, a breakpoint
/// expressed by line number in a C++ template or a C macro could resolve to many addresses. The
/// children of this object include the resolved [`TraceBreakpointLocation`]s. If the debugger
/// does not share this same concept, then its breakpoints should implement both the specification
/// and the location; the specification need not have any children.
///
/// This object extends `TraceTogglable` for a transitional period only, per the Java doc.
/// Implementations whose breakpoint specifications can be toggled should declare that interface
/// explicitly. When the specification is user togglable, toggling it should effectively toggle
/// all locations -- whether or not the locations are user togglable.
///
/// NOTE: When enumerating trace breakpoints, use the locations, not the specifications.
///
/// Java overloads that differ only in taking a [`Lifespan`] versus a single snap are given
/// distinct names: the lifespan form keeps the base name (`set_kinds`), while the single-snap
/// form gets an `_at` suffix (`set_kinds_at`).
pub trait TraceBreakpointSpec: TraceBreakpointCommon {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceBreakpointSpec`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "BreakpointSpec",
            "breakpoint specification",
            [KEY_EXPRESSION, KEY_KINDS, KEY_AS_BPT],
            ["_display", KEY_EXPRESSION, KEY_KINDS],
        )
    }

    /// Get the expression used to specify this breakpoint.
    fn get_expression(&self, snap: i64) -> String;

    /// Set the kinds included in this breakpoint across the given span of time.
    ///
    /// See [`Self::get_kinds`]. Note that it is unusual for a breakpoint to change kinds during
    /// its life. Nevertheless, in the course of recording a trace, it may happen, or at least
    /// appear to happen.
    fn set_kinds(&mut self, lifespan: &dyn Lifespan, kinds: &[TraceBreakpointKind]);

    /// Set the kinds included in this breakpoint from the given snap on.
    ///
    /// See [`Self::get_kinds`]. Note that it is unusual for a breakpoint to change kinds during
    /// its life. Nevertheless, in the course of recording a trace, it may happen, or at least
    /// appear to happen.
    fn set_kinds_at(&mut self, snap: i64, kinds: &[TraceBreakpointKind]);

    /// Get the kinds included in this breakpoint.
    ///
    /// For example, an "access breakpoint" or "access watchpoint," depending on terminology,
    /// would include both [`TraceBreakpointKind::Read`] and [`TraceBreakpointKind::Write`].
    fn get_kinds(&self, snap: i64) -> HashSet<TraceBreakpointKind>;

    /// Get the locations for this breakpoint.
    fn get_locations(&self, snap: i64) -> Vec<Box<dyn TraceBreakpointLocation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLifespan;

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            0
        }

        fn lmax(&self) -> i64 {
            i64::MAX
        }

        fn contains(&self, n: i64) -> bool {
            n >= 0
        }

        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan)
        }

        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan)
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(std::iter::empty())
        }
    }

    struct MockBreakpointSpec {
        kinds: HashSet<TraceBreakpointKind>,
    }

    impl TraceBreakpointCommon for MockBreakpointSpec {}

    impl TraceBreakpointSpec for MockBreakpointSpec {
        fn get_expression(&self, _snap: i64) -> String {
            "*0x1234".to_string()
        }

        fn set_kinds(&mut self, _lifespan: &dyn Lifespan, kinds: &[TraceBreakpointKind]) {
            self.kinds = kinds.iter().copied().collect();
        }

        fn set_kinds_at(&mut self, _snap: i64, kinds: &[TraceBreakpointKind]) {
            self.kinds = kinds.iter().copied().collect();
        }

        fn get_kinds(&self, _snap: i64) -> HashSet<TraceBreakpointKind> {
            self.kinds.clone()
        }

        fn get_locations(&self, _snap: i64) -> Vec<Box<dyn TraceBreakpointLocation>> {
            Vec::new()
        }
    }

    fn as_dyn(spec: &MockBreakpointSpec) -> &dyn TraceBreakpointSpec {
        spec
    }

    #[test]
    fn is_object_safe() {
        let spec = MockBreakpointSpec {
            kinds: HashSet::new(),
        };
        let _dyn_ref = as_dyn(&spec);
    }

    #[test]
    fn set_and_get_kinds_roundtrip() {
        let mut spec = MockBreakpointSpec {
            kinds: HashSet::new(),
        };
        spec.set_kinds(&MockLifespan, &[TraceBreakpointKind::Read, TraceBreakpointKind::Write]);
        let kinds = spec.get_kinds(0);
        assert_eq!(kinds.len(), 2);
        assert!(kinds.contains(&TraceBreakpointKind::Read));
        assert!(kinds.contains(&TraceBreakpointKind::Write));

        spec.set_kinds_at(5, &[TraceBreakpointKind::SwExecute]);
        let kinds_at = spec.get_kinds(5);
        assert_eq!(kinds_at.len(), 1);
        assert!(kinds_at.contains(&TraceBreakpointKind::SwExecute));
    }

    #[test]
    fn get_expression_and_locations() {
        let spec = MockBreakpointSpec {
            kinds: HashSet::new(),
        };
        assert_eq!(spec.get_expression(0), "*0x1234");
        assert!(spec.get_locations(0).is_empty());
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = MockBreakpointSpec::trace_object_info();
        assert_eq!(info.schema_name, "BreakpointSpec");
        assert_eq!(info.short_name, "breakpoint specification");
        assert_eq!(
            info.attributes,
            vec![
                KEY_EXPRESSION.to_string(),
                KEY_KINDS.to_string(),
                KEY_AS_BPT.to_string(),
            ]
        );
        assert_eq!(
            info.fixed_keys,
            vec!["_display".to_string(), KEY_EXPRESSION.to_string(), KEY_KINDS.to_string()]
        );
    }
}
