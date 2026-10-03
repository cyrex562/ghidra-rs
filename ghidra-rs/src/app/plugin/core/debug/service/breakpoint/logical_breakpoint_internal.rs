//! Port of `ghidra.app.plugin.core.debug.service.breakpoint.LogicalBreakpointInternal`.

use std::sync::Arc;

use crate::app::plugin::core::debug::service::breakpoint::TrackedTooSoonException;
use crate::app::seam_stubs::BreakpointActionSet;
use crate::debug::seam_stubs::{LogicalBreakpoint, Target};
use crate::program::model::address::Address;
use crate::program::model::listing::{Bookmark, Program};
use crate::trace::model::breakpoint::trace_breakpoint_location::TraceBreakpointLocation;
use crate::trace::model::trace::Trace;

/// The breakpoint service's internal view of a [`LogicalBreakpoint`]: the mutators the service
/// uses to aggregate program bookmarks and trace breakpoint locations into one logical breakpoint,
/// and to plan enable/disable/delete actions on it.
///
/// Port of the Java `interface LogicalBreakpointInternal extends LogicalBreakpoint`. Its two
/// in-repo implementors (`LoneLogicalBreakpoint`, `MappedLogicalBreakpoint`) are separate
/// classes, so this is a trait.
///
/// Java overloads are split by argument kind: `canMerge(Program, Bookmark)` /
/// `canMerge(TraceBreakpointLocation, long)` become [`can_merge_bookmark`] /
/// [`can_merge_location`], and likewise for `trackBreakpoint` and `untrackBreakpoint`. Values an
/// implementor retains (the target, tracked bookmarks and locations) are passed as `Arc`s; values
/// that are only looked up or compared are passed by reference. A Java `null` "limit to this
/// trace" argument is `None`.
///
/// [`can_merge_bookmark`]: Self::can_merge_bookmark
/// [`can_merge_location`]: Self::can_merge_location
pub trait LogicalBreakpointInternal: LogicalBreakpoint {
    /// Set the expected address for trace breakpoints in the given trace.
    ///
    /// Port of `setTraceAddress(Trace, Address)`.
    fn set_trace_address(&mut self, trace: &dyn Trace, address: Address);

    /// Set the target through which breakpoints in the given trace are controlled.
    ///
    /// Port of `setTarget(Trace, Target)`.
    fn set_target(&mut self, trace: &dyn Trace, target: Arc<dyn Target>);

    /// Remove the given trace from this set.
    ///
    /// This happens when a trace's recorder stops or when a trace is closed.
    ///
    /// Port of `removeTrace(Trace)`.
    fn remove_trace(&mut self, trace: &dyn Trace);

    /// Check if this logical breakpoint can subsume the given breakpoint bookmark of `program`.
    ///
    /// Port of `canMerge(Program, Bookmark)`.
    fn can_merge_bookmark(&self, program: &dyn Program, bookmark: &dyn Bookmark) -> bool;

    /// Check if this logical breakpoint can subsume the given candidate trace breakpoint.
    ///
    /// Note that logical breakpoints only include trace breakpoints for traces being actively
    /// recorded. All statuses regarding trace breakpoints are derived from the target
    /// breakpoints, i.e., they show the present status, regardless of the view's current time. A
    /// separate breakpoint history provider handles displaying records from the past, including
    /// dead traces.
    ///
    /// Returns `Ok(true)` if it can be aggregated, or [`TrackedTooSoonException`] if the
    /// containing trace is still being added to the manager.
    ///
    /// Port of `canMerge(TraceBreakpointLocation, long)`.
    fn can_merge_location(
        &self,
        breakpoint: &dyn TraceBreakpointLocation,
        snap: i64,
    ) -> Result<bool, TrackedTooSoonException>;

    /// Begin tracking the given program breakpoint bookmark. Returns true if it was not already
    /// tracked.
    ///
    /// Port of `trackBreakpoint(Bookmark)`.
    fn track_bookmark(&mut self, bookmark: Arc<dyn Bookmark>) -> bool;

    /// Begin tracking the given trace breakpoint location. Returns true if it was not already
    /// tracked.
    ///
    /// Port of `trackBreakpoint(TraceBreakpointLocation)`.
    fn track_location(&mut self, breakpoint: Arc<dyn TraceBreakpointLocation>) -> bool;

    /// Stop tracking the given trace breakpoint location. Returns true if it was tracked.
    ///
    /// Port of `untrackBreakpoint(TraceBreakpointLocation)`.
    fn untrack_location(&mut self, breakpoint: &dyn TraceBreakpointLocation) -> bool;

    /// Stop tracking the given breakpoint bookmark of `program`. Returns true if it was tracked.
    ///
    /// Port of `untrackBreakpoint(Program, Bookmark)`.
    fn untrack_bookmark(&mut self, program: &dyn Program, bookmark: &dyn Bookmark) -> bool;

    /// Collect actions to enable this logical breakpoint into `actions` (the plan).
    ///
    /// `trace` limits the actions to the given trace, if given.
    ///
    /// Port of `planEnable(BreakpointActionSet, Trace)`.
    fn plan_enable(&self, actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>);

    /// Collect actions to disable this logical breakpoint into `actions` (the plan).
    ///
    /// `trace` limits the actions to the given trace, if given.
    ///
    /// Port of `planDisable(BreakpointActionSet, Trace)`.
    fn plan_disable(&self, actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>);

    /// Collect actions to delete this logical breakpoint into `actions` (the plan).
    ///
    /// `trace` limits the actions to the given trace, if given.
    ///
    /// Port of `planDelete(BreakpointActionSet, Trace)`.
    fn plan_delete(&self, actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::seam_stubs::{
        LogicalBreakpointConsistency, LogicalBreakpointMode, LogicalBreakpointState,
    };
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::{BookmarkType, MarkerColor};
    use std::cmp::Ordering;

    struct BreakpointType;

    impl BookmarkType for BreakpointType {
        fn get_type_string(&self) -> &str {
            "BreakpointEnabled"
        }
        fn get_icon(&self) -> Option<Box<dyn crate::program::model::data::playable::Icon>> {
            None
        }
        fn get_marker_color(&self) -> Option<MarkerColor> {
            None
        }
        fn get_marker_priority(&self) -> i32 {
            -1
        }
        fn has_bookmarks(&self) -> bool {
            true
        }
        fn get_type_id(&self) -> i32 {
            0
        }
    }

    struct BreakpointBookmark {
        id: i64,
        address: Address,
    }

    impl Bookmark for BreakpointBookmark {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_type(&self) -> &dyn BookmarkType {
            &BreakpointType
        }
        fn get_type_string(&self) -> &str {
            "BreakpointEnabled"
        }
        fn get_category(&self) -> &str {
            "SW_EXECUTE;1"
        }
        fn get_comment(&self) -> &str {
            ""
        }
        fn set(&mut self, _category: &str, _comment: &str) {}
        fn compare_to(&self, other: &dyn Bookmark) -> Ordering {
            self.id.cmp(&other.get_id())
        }
    }

    /// Records the bookmarks it tracks and the plans requested of it, modelling the
    /// bookmark-side bookkeeping of Java's `LoneLogicalBreakpoint`.
    #[derive(Default)]
    struct RecordingBreakpoint {
        bookmark_ids: Vec<i64>,
        plans: std::sync::Mutex<Vec<(&'static str, bool)>>,
    }

    impl LogicalBreakpoint for RecordingBreakpoint {
        fn compute_state(&self) -> LogicalBreakpointState {
            if self.bookmark_ids.is_empty() {
                LogicalBreakpointState::None
            } else {
                LogicalBreakpointState::from_fields(
                    Some(LogicalBreakpointMode::Enabled),
                    Some(LogicalBreakpointConsistency::Ineffective),
                )
            }
        }
        fn compute_state_for_program(&self, _program: &dyn Program) -> LogicalBreakpointState {
            self.compute_state()
        }
        fn compute_state_for_trace(&self, _trace: &dyn Trace) -> LogicalBreakpointState {
            LogicalBreakpointState::None
        }
        fn is_mapped_to_trace(&self, _trace: &dyn Trace) -> bool {
            false
        }
        fn has_mapped_traces(&self) -> bool {
            false
        }
    }

    impl LogicalBreakpointInternal for RecordingBreakpoint {
        fn set_trace_address(&mut self, _trace: &dyn Trace, _address: Address) {}
        fn set_target(&mut self, _trace: &dyn Trace, _target: Arc<dyn Target>) {}
        fn remove_trace(&mut self, _trace: &dyn Trace) {}
        fn can_merge_bookmark(&self, _program: &dyn Program, bookmark: &dyn Bookmark) -> bool {
            self.bookmark_ids.contains(&bookmark.get_id())
        }
        fn can_merge_location(
            &self,
            _breakpoint: &dyn TraceBreakpointLocation,
            _snap: i64,
        ) -> Result<bool, TrackedTooSoonException> {
            Err(TrackedTooSoonException)
        }
        fn track_bookmark(&mut self, bookmark: Arc<dyn Bookmark>) -> bool {
            let id = bookmark.get_id();
            if self.bookmark_ids.contains(&id) {
                return false;
            }
            self.bookmark_ids.push(id);
            true
        }
        fn track_location(&mut self, _breakpoint: Arc<dyn TraceBreakpointLocation>) -> bool {
            false
        }
        fn untrack_location(&mut self, _breakpoint: &dyn TraceBreakpointLocation) -> bool {
            false
        }
        fn untrack_bookmark(&mut self, _program: &dyn Program, bookmark: &dyn Bookmark) -> bool {
            let before = self.bookmark_ids.len();
            self.bookmark_ids.retain(|id| *id != bookmark.get_id());
            before != self.bookmark_ids.len()
        }
        fn plan_enable(&self, _actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>) {
            self.plans.lock().unwrap().push(("enable", trace.is_some()));
        }
        fn plan_disable(&self, _actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>) {
            self.plans.lock().unwrap().push(("disable", trace.is_some()));
        }
        fn plan_delete(&self, _actions: &mut BreakpointActionSet, trace: Option<&dyn Trace>) {
            self.plans.lock().unwrap().push(("delete", trace.is_some()));
        }
    }

    fn bookmark(id: i64, offset: i64) -> Arc<dyn Bookmark> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Arc::new(BreakpointBookmark { id, address: space.address(offset) })
    }

    #[test]
    fn track_bookmark_reports_whether_newly_tracked() {
        let mut bp = RecordingBreakpoint::default();
        let bm = bookmark(7, 0x400000);
        assert!(bp.track_bookmark(bm.clone()));
        assert!(!bp.track_bookmark(bm), "tracking the same bookmark twice is not a change");
        assert_eq!(bp.bookmark_ids, vec![7]);
    }

    #[test]
    fn tracked_bookmark_feeds_supertrait_state() {
        let mut bp = RecordingBreakpoint::default();
        assert_eq!(bp.compute_state(), LogicalBreakpointState::None);
        bp.track_bookmark(bookmark(1, 0x1000));
        assert_eq!(bp.compute_state(), LogicalBreakpointState::IneffectiveEnabled);
    }

    #[test]
    fn plans_are_collected_through_the_trait_object() {
        let rec = RecordingBreakpoint::default();
        {
            let bp: &dyn LogicalBreakpointInternal = &rec;
            let mut actions = BreakpointActionSet;
            bp.plan_enable(&mut actions, None);
            bp.plan_disable(&mut actions, None);
            bp.plan_delete(&mut actions, None);
            // Supertrait queries are answerable through the subtrait object.
            assert!(!bp.has_mapped_traces());
        }
        assert_eq!(
            *rec.plans.lock().unwrap(),
            vec![("enable", false), ("disable", false), ("delete", false)]
        );
    }
}
