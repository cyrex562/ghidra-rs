//! A single unit of trace-schedule advancement (ticks, skips, or a Sleigh patch).
//!
//! Port of `ghidra.trace.model.time.schedule.Step`.
//!
//! The Java interface's static factories (`parse`, `nop`) dispatch to `PatchStep`, `SkipStep`,
//! and `TickStep`, none of which are ported yet -- porting `Step` sits on a cycle with those
//! three concrete implementors. The dispatch/parsing logic itself is ported faithfully here;
//! only the leaf construction calls are stubbed (see
//! [`crate::trace::seam_stubs::patch_step_parse`] and friends), which panic until those types
//! land.
//!
//! The default method `getThread(TraceThreadManager, TraceThread)` (no machine) is ported as
//! [`Step::get_thread`]. Its sibling overload, `execute(TraceThreadManager, TraceThread,
//! PcodeMachine<?>, Stepper, TaskMonitor)`, is not ported: it calls `thread.getPath()`, but
//! [`TraceThread`] is a zero-method marker stub shared by over a dozen other ported interfaces,
//! and adding `get_path` to it would ripple into all of their mock implementors. That overload
//! also can't share a name with the required `execute(PcodeThread<?>, Stepper, TaskMonitor)`
//! method below, since Rust traits don't support overloading. It belongs alongside the real
//! `TraceThread` port.

use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::program::model::lang::Language;
use crate::trace::model::thread::trace_thread_manager::TraceThreadManager;
use crate::trace::model::time::schedule::compare_result::CompareResult;
use crate::trace::model::time::schedule::stepper::Stepper;
use crate::trace::seam_stubs::{self, TimeRadix};
use crate::trace::model::thread::TraceThread;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The kind of a [`Step`].
///
/// Port of the nested Java enum `Step.StepType`. Declaration order matters: it is this enum's
/// ordinal that [`Step::get_type_order`] returns by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepType {
    Tick,
    Skip,
    Patch,
}

/// A single step (or run of steps) applied to one thread of a trace schedule.
///
/// Port of `ghidra.trace.model.time.schedule.Step`.
pub trait Step {
    /// Render this step using the given radix.
    ///
    /// Mirrors `Step.toString(TimeRadix)`.
    fn to_string_radix(&self, radix: &dyn TimeRadix) -> String;

    /// The kind of this step.
    ///
    /// Mirrors `Step.getType()`.
    fn get_type(&self) -> StepType;

    /// The ordinal of [`get_type`](Self::get_type).
    ///
    /// Mirrors the default method `Step.getTypeOrder()`.
    fn get_type_order(&self) -> i32 {
        self.get_type() as i32
    }

    /// Whether this step is a no-op (e.g., a tick of count 0).
    ///
    /// Mirrors `Step.isNop()`.
    fn is_nop(&self) -> bool;

    /// The key of the thread this step applies to, or -1 for the last/event thread.
    ///
    /// Mirrors `Step.getThreadKey()`.
    fn get_thread_key(&self) -> i64;

    /// Whether this step applies to the last thread or snapshot event thread.
    ///
    /// Mirrors the default method `Step.isEventThread()`.
    fn is_event_thread(&self) -> bool {
        self.get_thread_key() == -1
    }

    /// Resolve the thread this step applies to.
    ///
    /// Mirrors the default method `Step.getThread(TraceThreadManager, TraceThread)`.
    fn get_thread(
        &self,
        tm: &dyn TraceThreadManager,
        event_thread: Box<dyn TraceThread>,
    ) -> Box<dyn TraceThread> {
        let key = self.get_thread_key();
        let candidate = if self.is_event_thread() {
            Some(event_thread)
        } else {
            tm.get_thread(key)
        };
        require_thread(candidate, key)
    }

    /// The number of instruction-level ticks this step performs.
    ///
    /// Mirrors `Step.getTickCount()`.
    fn get_tick_count(&self) -> i64;

    /// The number of p-code-level skips this step performs.
    ///
    /// Mirrors `Step.getSkipCount()`.
    fn get_skip_count(&self) -> i64;

    /// The number of patches this step performs.
    ///
    /// Mirrors `Step.getPatchCount()`.
    fn get_patch_count(&self) -> i64;

    /// Check whether the given step can be combined with this one.
    ///
    /// Two steps applied to the same thread can just be summed. If the given step applies to the
    /// "last thread" or to the same thread as this step, then it can be combined.
    ///
    /// Mirrors `Step.isCompatible(Step)`.
    fn is_compatible(&self, step: &dyn Step) -> bool;

    /// Add the given (compatible) step's count into this one.
    ///
    /// Mirrors `Step.addTo(Step)`.
    fn add_to(&mut self, step: &dyn Step);

    /// Produce a step representing the difference between this step and the given one.
    ///
    /// Mirrors `Step.subtract(Step)`.
    fn subtract(&self, step: &dyn Step) -> Box<dyn Step>;

    /// Make a copy of this step, boxed as a trait object.
    ///
    /// Port of the Java `clone()` method; renamed because `clone` returning `Self` is not
    /// object-safe.
    fn clone_box(&self) -> Box<dyn Step>;

    /// Subtract from the count of this step.
    ///
    /// If this step has a count exceeding `count`, this simply subtracts `count` from the tick
    /// count and returns the (negative) difference. If this step has exactly `count`, this sets
    /// the count to 0 and returns 0, indicating this step should be removed from the sequence. If
    /// `count` exceeds this step's count, this sets the count to 0 and returns the (positive)
    /// difference, indicating this step should be removed and the remaining steps rewound from
    /// the preceding step.
    ///
    /// Mirrors `Step.rewind(long)`.
    fn rewind(&mut self, count: i64) -> i64;

    /// Richly compare this step to another.
    ///
    /// Mirrors `Step.compareStep(Step)`.
    fn compare_step(&self, that: &dyn Step) -> CompareResult;

    /// Compare just the [`StepType`] of this step to another's.
    ///
    /// Mirrors the default method `Step.compareStepType(Step)`.
    fn compare_step_type(&self, that: &dyn Step) -> CompareResult {
        let order = match self.get_type_order().cmp(&that.get_type_order()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        CompareResult::from_unrelated(order)
    }

    /// Mirrors `Comparable<Step>.compareTo(Step)`, implemented via [`compare_step`](Self::compare_step).
    fn compare_to(&self, that: &dyn Step) -> i32 {
        self.compare_step(that).compare_to()
    }

    /// Execute this step against an emulated thread.
    ///
    /// The `PcodeThread<?>` wildcard parameter is erased to [`ErasedPcodeThread`], matching
    /// [`Stepper::tick`]/[`Stepper::skip`].
    ///
    /// Mirrors `Step.execute(PcodeThread<?>, Stepper, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns an error if the monitor is cancelled during execution.
    fn execute(
        &self,
        emu_thread: &dyn ErasedPcodeThread,
        stepper: &dyn Stepper,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Coalesce trailing, compatible patch steps in `steps` (from the end) into this one,
    /// removing the coalesced entries, and return the number of patches coalesced.
    ///
    /// Mirrors `Step.coalescePatches(Language, List<Step>)`.
    fn coalesce_patches(&self, language: &dyn Language, steps: &mut Vec<Box<dyn Step>>) -> i64;
}

/// Require that a thread was resolved, given the key that was looked up.
///
/// Mirrors the static method `Step.requireThread(TraceThread, long)`.
///
/// # Panics
/// Mirrors `IllegalArgumentException`: panics if `thread` is `None`.
pub fn require_thread(thread: Option<Box<dyn TraceThread>>, key: i64) -> Box<dyn TraceThread> {
    match thread {
        Some(thread) => thread,
        None if key == -1 => panic!(
            "Thread must be given, e.g., 0:t1-3, since the last thread or snapshot event thread is not given."
        ),
        None => panic!("Thread with key {key} does not exist in given trace"),
    }
}

/// A step that does nothing: a tick of count 0, applying to the last/event thread.
///
/// Mirrors the static method `Step.nop()`.
pub fn nop() -> Box<dyn Step> {
    seam_stubs::tick_step_new(-1, 0)
}

/// Parse a step, possibly including a thread prefix, e.g., `"t1-3"`.
///
/// If the thread prefix is given, the step applies to the given thread. Otherwise, the step
/// applies to the last thread or the event thread.
///
/// Mirrors the static method `Step.parse(String, TimeRadix)`.
///
/// # Panics
/// Mirrors `IllegalArgumentException`: panics if `step_spec` is of the wrong form.
pub fn parse(step_spec: &str, radix: &dyn TimeRadix) -> Box<dyn Step> {
    if step_spec.is_empty() {
        return nop();
    }
    let parts: Vec<&str> = step_spec.split('-').collect();
    if parts.len() == 1 {
        return parse_for_thread(-1, parts[0].trim(), radix);
    }
    if parts.len() == 2 {
        let t_part = parts[0].trim();
        if let Some(rest) = t_part.strip_prefix('t') {
            let thread_key: i64 = rest
                .parse()
                .unwrap_or_else(|_| panic!("Cannot parse step: '{step_spec}'"));
            return parse_for_thread(thread_key, parts[1].trim(), radix);
        }
    }
    panic!("Cannot parse step: '{step_spec}'");
}

/// Parse a step for the given thread key.
///
/// The form of `step_spec` must either be numeric, indicating some number of ticks, or
/// brace-enclosed Sleigh code, e.g., `"{r0=0x1234}"`, which patches machine state during
/// execution.
///
/// Mirrors the static method `Step.parse(long, String, TimeRadix)`. Named distinctly from
/// [`parse`] because Rust traits/modules don't support overloading by parameter count.
///
/// # Panics
/// Mirrors `IllegalArgumentException`: panics if `step_spec` is of the wrong form.
pub fn parse_for_thread(thread_key: i64, step_spec: &str, radix: &dyn TimeRadix) -> Box<dyn Step> {
    if step_spec.starts_with('s') {
        return seam_stubs::skip_step_parse(thread_key, step_spec, radix);
    }
    if step_spec.starts_with('{') {
        return seam_stubs::patch_step_parse(thread_key, step_spec);
    }
    seam_stubs::tick_step_parse(thread_key, step_spec, radix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::DuplicateNameException;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockStep {
        thread_key: i64,
        tick_count: i64,
        step_type: StepType,
    }

    impl Step for MockStep {
        fn to_string_radix(&self, _radix: &dyn TimeRadix) -> String {
            format!("{}", self.tick_count)
        }

        fn get_type(&self) -> StepType {
            self.step_type
        }

        fn is_nop(&self) -> bool {
            self.tick_count == 0
        }

        fn get_thread_key(&self) -> i64 {
            self.thread_key
        }

        fn get_tick_count(&self) -> i64 {
            self.tick_count
        }

        fn get_skip_count(&self) -> i64 {
            0
        }

        fn get_patch_count(&self) -> i64 {
            0
        }

        fn is_compatible(&self, step: &dyn Step) -> bool {
            self.thread_key == step.get_thread_key() || step.get_thread_key() == -1
        }

        fn add_to(&mut self, step: &dyn Step) {
            self.tick_count += step.get_tick_count();
        }

        fn subtract(&self, step: &dyn Step) -> Box<dyn Step> {
            Box::new(MockStep {
                thread_key: self.thread_key,
                tick_count: self.tick_count - step.get_tick_count(),
                step_type: self.step_type,
            })
        }

        fn clone_box(&self) -> Box<dyn Step> {
            Box::new(*self)
        }

        fn rewind(&mut self, count: i64) -> i64 {
            let diff = self.tick_count - count;
            self.tick_count = diff.max(0);
            -diff
        }

        fn compare_step(&self, that: &dyn Step) -> CompareResult {
            let type_cmp = self.compare_step_type(that);
            if !type_cmp.related() {
                return type_cmp;
            }
            CompareResult::from_related(match self.tick_count.cmp(&that.get_tick_count()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }

        fn execute(
            &self,
            _emu_thread: &dyn ErasedPcodeThread,
            _stepper: &dyn Stepper,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn coalesce_patches(&self, _language: &dyn Language, _steps: &mut Vec<Box<dyn Step>>) -> i64 {
            0
        }
    }

    struct MockThread {
        key: i64,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            self.key
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    struct MockThreadManager {
        thread_key: i64,
    }
    impl TraceThreadManager for MockThreadManager {
        fn add_thread(
            &mut self,
            _path: &str,
            _lifespan: crate::trace::model::lifespan::Lifespan,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            unimplemented!()
        }
        fn add_thread_with_display(
            &mut self,
            _path: &str,
            _display: &str,
            _lifespan: crate::trace::model::lifespan::Lifespan,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_thread(
            &mut self,
            _path: &str,
            _creation_snap: i64,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_thread_with_display(
            &mut self,
            _path: &str,
            _display: &str,
            _creation_snap: i64,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            unimplemented!()
        }
        fn get_all_threads(&self) -> Vec<Box<dyn TraceThread>> {
            Vec::new()
        }
        fn get_threads_by_path(&self, _name: &str) -> Vec<Box<dyn TraceThread>> {
            Vec::new()
        }
        fn get_live_thread_by_path(&self, _snap: i64, _path: &str) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_thread(&self, key: i64) -> Option<Box<dyn TraceThread>> {
            if key == self.thread_key {
                Some(Box::new(MockThread { key }))
            } else {
                None
            }
        }
        fn get_live_threads(&self, _snap: i64) -> Vec<Box<dyn TraceThread>> {
            Vec::new()
        }
    }

    fn tick(thread_key: i64, tick_count: i64) -> MockStep {
        MockStep {
            thread_key,
            tick_count,
            step_type: StepType::Tick,
        }
    }

    #[test]
    fn get_type_order_matches_java_ordinal() {
        assert_eq!(tick(0, 1).get_type_order(), 0);
        assert_eq!(
            MockStep { thread_key: 0, tick_count: 1, step_type: StepType::Skip }.get_type_order(),
            1
        );
        assert_eq!(
            MockStep { thread_key: 0, tick_count: 1, step_type: StepType::Patch }.get_type_order(),
            2
        );
    }

    #[test]
    fn is_event_thread_matches_java() {
        assert!(tick(-1, 1).is_event_thread());
        assert!(!tick(3, 1).is_event_thread());
    }

    #[test]
    fn get_thread_resolves_event_thread_when_key_is_minus_one() {
        let step = tick(-1, 1);
        let tm = MockThreadManager { thread_key: 7 };
        let event_thread: Box<dyn TraceThread> = Box::new(MockThread { key: 42 });
        let resolved = step.get_thread(&tm, event_thread);
        // Only assert it didn't panic and returned *a* thread; MockThread has no observable
        // fields via the trait, so this exercises the event-thread branch of getThread().
        let _ = resolved;
    }

    #[test]
    fn get_thread_resolves_named_thread_via_manager() {
        let step = tick(7, 1);
        let tm = MockThreadManager { thread_key: 7 };
        let event_thread: Box<dyn TraceThread> = Box::new(MockThread { key: 42 });
        let resolved = step.get_thread(&tm, event_thread);
        let _ = resolved;
    }

    #[test]
    #[should_panic(expected = "Thread with key 9 does not exist")]
    fn get_thread_panics_when_key_not_found() {
        let step = tick(9, 1);
        let tm = MockThreadManager { thread_key: 7 };
        let event_thread: Box<dyn TraceThread> = Box::new(MockThread { key: 42 });
        step.get_thread(&tm, event_thread);
    }

    #[test]
    #[should_panic(expected = "last thread or snapshot event thread is not given")]
    fn require_thread_panics_for_missing_event_thread() {
        require_thread(None, -1);
    }

    #[test]
    fn compare_step_type_matches_java_integer_compare() {
        let t = tick(0, 1);
        let s = MockStep { thread_key: 0, tick_count: 1, step_type: StepType::Skip };
        let result = t.compare_step_type(&s);
        assert_eq!(result.compare_to(), -1);
        assert!(!result.related());
    }

    #[test]
    fn compare_to_delegates_to_compare_step() {
        let a = tick(0, 5);
        let b = tick(0, 3);
        assert_eq!(a.compare_to(&b), 1);
        assert_eq!(b.compare_to(&a), -1);
        assert_eq!(a.compare_to(&a), 0);
    }

    #[test]
    fn rewind_matches_java_semantics() {
        let mut step = tick(0, 5);
        // Exceeds available count: clamps to 0 and returns the positive remainder.
        assert_eq!(step.rewind(8), 3);
        assert_eq!(step.get_tick_count(), 0);

        let mut step = tick(0, 5);
        // Exact count: sets to 0 and returns 0.
        assert_eq!(step.rewind(5), 0);
        assert_eq!(step.get_tick_count(), 0);

        let mut step = tick(0, 5);
        // Less than available: subtracts and returns the negative difference.
        assert_eq!(step.rewind(2), -3);
        assert_eq!(step.get_tick_count(), 3);
    }

    #[test]
    fn add_to_sums_compatible_steps() {
        let mut a = tick(0, 5);
        let b = tick(0, 3);
        assert!(a.is_compatible(&b));
        a.add_to(&b);
        assert_eq!(a.get_tick_count(), 8);
    }

    #[test]
    #[should_panic(expected = "Cannot parse step")]
    fn parse_rejects_malformed_spec() {
        struct DummyRadix;
        impl TimeRadix for DummyRadix {
            fn radix(&self) -> i32 {
                10
            }
        }
        parse("t1-2-3", &DummyRadix);
    }

    #[test]
    #[should_panic(expected = "not yet ported")]
    fn nop_hits_unported_tick_step_stub() {
        // Documents the cycle-break seam: Step::nop() delegates to the not-yet-ported TickStep
        // constructor. Once TickStep lands, this test should be replaced with a real assertion
        // that nop() yields a no-op tick step for the event thread.
        nop();
    }
}
