//! Shared state and concrete behavior for [`Step`] implementations that carry a thread key and a
//! tick count.
//!
//! Port of `ghidra.trace.model.time.schedule.AbstractStep`.
//!
//! Java's `AbstractStep` is an abstract class: it carries the `threadKey`/`tickCount` fields and
//! implements every method of `Step` except `toStringStepPart` (and the covariant-return-type
//! override of `clone`, which Rust already handles via [`Step::clone_box`]). Rust has no field
//! inheritance, so [`AbstractStepBase`] holds the shared fields plus the concrete (non-abstract)
//! logic, while [`AbstractStep`] declares only the one method a concrete step must still supply.
//! A concrete step (e.g. the not-yet-ported `TickStep`/`SkipStep`, the two in-repo subclasses of
//! `AbstractStep`; `PatchStep` implements `Step` directly and doesn't share this state) embeds
//! an `AbstractStepBase`, implements [`AbstractStep::base`]/[`AbstractStep::base_mut`] to expose
//! it, and implements [`Step`]'s methods by delegating to the helpers here (mirroring how
//! `AbstractStep`'s methods call through to the shared fields in Java).
//!
//! Java's `getClass() == this.getClass()` checks in `isCompatible`/`compareStep` (used to ensure
//! two steps are the same concrete kind before combining them) are approximated here by comparing
//! [`Step::get_type`]: since `AbstractStep` has exactly two concrete subclasses in Java
//! (`TickStep`, `SkipStep`), each reporting a distinct [`StepType`](super::step::StepType), the
//! two checks coincide (matching this crate's established approximation for `getClass()`
//! equality; see `AbstractIntegerDataType`'s module docs).
//!
//! Java's zero-arg `toString()` (which calls `toString(TimeRadix.DEFAULT)`) is not ported: there
//! is no ported `TimeRadix.DEFAULT` constant yet (`TimeRadix` is itself a placeholder stub with
//! only a `radix()` accessor), so no default radix is available to call
//! [`AbstractStepBase::to_string_radix`] with. [`Step::to_string_radix`], which takes an explicit
//! radix, is ported faithfully below.

use crate::program::model::lang::Language;
use crate::trace::model::time::schedule::compare_result::CompareResult;
use crate::trace::model::time::schedule::step::Step;
use crate::trace::seam_stubs::TimeRadix;

/// The shared state of an [`AbstractStep`] implementation: the thread key and tick count.
///
/// Port of the fields of `ghidra.trace.model.time.schedule.AbstractStep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AbstractStepBase {
    /// The key of the thread this step applies to, or -1 for the last/event thread.
    pub thread_key: i64,
    /// The number of ticks this step performs.
    pub tick_count: i64,
}

impl AbstractStepBase {
    /// Mirrors the constructor `AbstractStep(long threadKey, long tickCount)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `tick_count` is negative.
    pub fn new(thread_key: i64, tick_count: i64) -> Self {
        assert!(tick_count >= 0, "Cannot step a negative number");
        Self { thread_key, tick_count }
    }

    /// Render this step using the given radix, delegating the step-specific portion to
    /// [`AbstractStep::to_string_step_part`].
    ///
    /// Mirrors `AbstractStep.toString(TimeRadix)`.
    pub fn to_string_radix<S: AbstractStep + ?Sized>(step: &S, radix: &dyn TimeRadix) -> String {
        let part = step.to_string_step_part(radix);
        let thread_key = step.base().thread_key;
        if thread_key == -1 { part } else { format!("t{thread_key}-{part}") }
    }

    /// Whether this step is a no-op, i.e., has a tick count of 0.
    ///
    /// Mirrors `AbstractStep.isNop()`.
    pub fn is_nop(&self) -> bool {
        self.tick_count == 0
    }

    /// The number of patches this step performs: always 0 for a plain tick/skip step.
    ///
    /// Mirrors `AbstractStep.getPatchCount()`.
    pub fn get_patch_count(&self) -> i64 {
        0
    }

    /// Add to the count of this step.
    ///
    /// Mirrors `AbstractStep.advance(long)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `steps` is negative, or if the resulting
    /// count would overflow.
    pub fn advance(&mut self, steps: i64) {
        assert!(steps >= 0, "Cannot advance a negative number");
        self.tick_count = self
            .tick_count
            .checked_add(steps)
            .filter(|&n| n >= 0)
            .expect("Total step count exceeds LONG_MAX");
    }

    /// Subtract from the count of this step, clamping at 0.
    ///
    /// Mirrors `AbstractStep.rewind(long)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `steps` is negative.
    pub fn rewind(&mut self, steps: i64) -> i64 {
        assert!(steps >= 0, "Cannot rewind a negative number");
        let diff = self.tick_count - steps;
        self.tick_count = diff.max(0);
        -diff
    }

    /// Check whether `other` can be combined with `step`, i.e., they're the same kind of step
    /// (approximated via [`Step::get_type`]; see the module docs) and apply to the same thread
    /// (or `other` applies to the last/event thread).
    ///
    /// Mirrors `AbstractStep.isCompatible(Step)`.
    pub fn is_compatible<S: AbstractStep + ?Sized>(step: &S, other: &dyn Step) -> bool {
        if step.get_type() != other.get_type() {
            return false;
        }
        step.base().thread_key == other.get_thread_key() || other.get_thread_key() == -1
    }

    /// Add the given (compatible) step's count into `step`.
    ///
    /// Mirrors `AbstractStep.addTo(Step)`.
    pub fn add_to<S: AbstractStep + ?Sized>(step: &mut S, other: &dyn Step) {
        debug_assert!(step.is_compatible(other), "step is not compatible");
        let steps = other.get_tick_count();
        step.base_mut().advance(steps);
    }

    /// Richly compare `step` to `that`.
    ///
    /// Mirrors `AbstractStep.compareStep(Step)`.
    pub fn compare_step<S: AbstractStep + ?Sized>(step: &S, that: &dyn Step) -> CompareResult {
        let result = step.compare_step_type(that);
        if result != CompareResult::Equals {
            return result;
        }

        let result = CompareResult::from_unrelated(long_compare(step.base().thread_key, that.get_thread_key()));
        if result != CompareResult::Equals {
            return result;
        }

        let result = CompareResult::from_related(long_compare(step.base().tick_count, that.get_tick_count()));
        if result != CompareResult::Equals {
            return result;
        }

        CompareResult::Equals
    }

    /// Coalesce trailing, compatible patch steps: always 0, since a plain tick/skip step never
    /// coalesces patches.
    ///
    /// Mirrors `AbstractStep.coalescePatches(Language, List<Step>)`.
    pub fn coalesce_patches(_language: &dyn Language, _steps: &mut Vec<Box<dyn Step>>) -> i64 {
        0
    }

    /// Mirrors `AbstractStep.hashCode()`, replicating Java's `Long.hashCode` bit-mixing exactly
    /// (rather than deriving a Rust-native hash) so it stays comparable to the ported class's
    /// documented behavior.
    pub fn hash_code(&self) -> i32 {
        long_hash_code(self.thread_key)
            .wrapping_mul(31)
            .wrapping_add(long_hash_code(self.tick_count))
    }
}

/// Mirrors `Long.compare(long, long)`.
fn long_compare(a: i64, b: i64) -> i32 {
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// Mirrors `Long.hashCode(long)`, i.e. `(int) (value ^ (value >>> 32))`.
fn long_hash_code(value: i64) -> i32 {
    (value ^ (((value as u64) >> 32) as i64)) as i32
}

/// The one method a concrete [`Step`] built atop [`AbstractStepBase`] must still supply, plus the
/// accessors that expose its embedded [`AbstractStepBase`] to the helpers above.
///
/// Port of the effectively-abstract part of `ghidra.trace.model.time.schedule.AbstractStep`.
pub trait AbstractStep: Step {
    /// Access the shared step state.
    fn base(&self) -> &AbstractStepBase;

    /// Mutably access the shared step state.
    fn base_mut(&mut self) -> &mut AbstractStepBase;

    /// Return the step portion of [`AbstractStepBase::to_string_radix`].
    ///
    /// Mirrors the abstract method `AbstractStep.toStringStepPart(TimeRadix)`.
    fn to_string_step_part(&self, radix: &dyn TimeRadix) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::trace::model::time::schedule::step::StepType;
    use crate::trace::model::time::schedule::stepper::Stepper;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    #[derive(Debug, Clone)]
    struct MockStep {
        base: AbstractStepBase,
        step_type: StepType,
    }

    impl MockStep {
        fn tick(thread_key: i64, tick_count: i64) -> Self {
            MockStep { base: AbstractStepBase::new(thread_key, tick_count), step_type: StepType::Tick }
        }
    }

    impl AbstractStep for MockStep {
        fn base(&self) -> &AbstractStepBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut AbstractStepBase {
            &mut self.base
        }

        fn to_string_step_part(&self, _radix: &dyn TimeRadix) -> String {
            format!("{}", self.base.tick_count)
        }
    }

    impl Step for MockStep {
        fn to_string_radix(&self, radix: &dyn TimeRadix) -> String {
            AbstractStepBase::to_string_radix(self, radix)
        }

        fn get_type(&self) -> StepType {
            self.step_type
        }

        fn is_nop(&self) -> bool {
            self.base.is_nop()
        }

        fn get_thread_key(&self) -> i64 {
            self.base.thread_key
        }

        fn get_tick_count(&self) -> i64 {
            self.base.tick_count
        }

        fn get_skip_count(&self) -> i64 {
            0
        }

        fn get_patch_count(&self) -> i64 {
            self.base.get_patch_count()
        }

        fn is_compatible(&self, step: &dyn Step) -> bool {
            AbstractStepBase::is_compatible(self, step)
        }

        fn add_to(&mut self, step: &dyn Step) {
            AbstractStepBase::add_to(self, step);
        }

        fn subtract(&self, step: &dyn Step) -> Box<dyn Step> {
            Box::new(MockStep {
                base: AbstractStepBase::new(self.base.thread_key, self.base.tick_count - step.get_tick_count()),
                step_type: self.step_type,
            })
        }

        fn clone_box(&self) -> Box<dyn Step> {
            Box::new(self.clone())
        }

        fn rewind(&mut self, count: i64) -> i64 {
            self.base.rewind(count)
        }

        fn compare_step(&self, that: &dyn Step) -> CompareResult {
            AbstractStepBase::compare_step(self, that)
        }

        fn execute(
            &self,
            _emu_thread: &dyn ErasedPcodeThread,
            _stepper: &dyn Stepper,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn coalesce_patches(&self, language: &dyn Language, steps: &mut Vec<Box<dyn Step>>) -> i64 {
            AbstractStepBase::coalesce_patches(language, steps)
        }
    }

    struct DummyRadix;
    impl TimeRadix for DummyRadix {
        fn radix(&self) -> i32 {
            10
        }
    }

    #[test]
    #[should_panic(expected = "Cannot step a negative number")]
    fn new_rejects_negative_tick_count() {
        AbstractStepBase::new(0, -1);
    }

    #[test]
    fn is_nop_matches_java() {
        assert!(MockStep::tick(0, 0).is_nop());
        assert!(!MockStep::tick(0, 1).is_nop());
    }

    #[test]
    fn get_patch_count_is_always_zero() {
        assert_eq!(MockStep::tick(0, 5).get_patch_count(), 0);
    }

    #[test]
    #[should_panic(expected = "Cannot advance a negative number")]
    fn advance_rejects_negative() {
        let mut base = AbstractStepBase::new(0, 5);
        base.advance(-1);
    }

    #[test]
    #[should_panic(expected = "Total step count exceeds LONG_MAX")]
    fn advance_rejects_overflow() {
        let mut base = AbstractStepBase::new(0, i64::MAX);
        base.advance(1);
    }

    #[test]
    fn advance_sums_counts() {
        let mut base = AbstractStepBase::new(0, 5);
        base.advance(3);
        assert_eq!(base.tick_count, 8);
    }

    #[test]
    fn rewind_matches_java_semantics() {
        // Exceeds available count: clamps to 0 and returns the positive remainder.
        let mut base = AbstractStepBase::new(0, 5);
        assert_eq!(base.rewind(8), 3);
        assert_eq!(base.tick_count, 0);

        // Exact count: sets to 0 and returns 0.
        let mut base = AbstractStepBase::new(0, 5);
        assert_eq!(base.rewind(5), 0);
        assert_eq!(base.tick_count, 0);

        // Less than available: subtracts and returns the negative difference.
        let mut base = AbstractStepBase::new(0, 5);
        assert_eq!(base.rewind(2), -3);
        assert_eq!(base.tick_count, 3);
    }

    #[test]
    #[should_panic(expected = "Cannot rewind a negative number")]
    fn rewind_rejects_negative() {
        let mut base = AbstractStepBase::new(0, 5);
        base.rewind(-1);
    }

    #[test]
    fn is_compatible_requires_same_type_and_thread() {
        let a = MockStep::tick(3, 1);
        let same_thread = MockStep::tick(3, 9);
        let event_thread = MockStep::tick(-1, 9);
        let other_thread = MockStep::tick(4, 9);
        let mut other_type = MockStep::tick(3, 9);
        other_type.step_type = StepType::Skip;

        assert!(a.is_compatible(&same_thread));
        assert!(a.is_compatible(&event_thread));
        assert!(!a.is_compatible(&other_thread));
        assert!(!a.is_compatible(&other_type));
    }

    #[test]
    fn add_to_advances_by_other_tick_count() {
        let mut a = MockStep::tick(3, 5);
        let b = MockStep::tick(3, 4);
        a.add_to(&b);
        assert_eq!(a.base.tick_count, 9);
    }

    #[test]
    fn compare_step_orders_type_then_thread_then_ticks() {
        let tick = MockStep::tick(0, 1);
        let mut skip = MockStep::tick(0, 1);
        skip.step_type = StepType::Skip;
        // Different types: unrelated, ordered by StepType discriminant (Tick < Skip).
        let result = tick.compare_step(&skip);
        assert_eq!(result.compare_to(), -1);
        assert!(!result.related());

        // Same type, different thread: unrelated.
        let a = MockStep::tick(1, 5);
        let b = MockStep::tick(2, 5);
        let result = a.compare_step(&b);
        assert_eq!(result.compare_to(), -1);
        assert!(!result.related());

        // Same type and thread, different tick count: related.
        let a = MockStep::tick(1, 3);
        let b = MockStep::tick(1, 5);
        let result = a.compare_step(&b);
        assert_eq!(result.compare_to(), -1);
        assert!(result.related());

        // Fully equal.
        let a = MockStep::tick(1, 5);
        let b = MockStep::tick(1, 5);
        assert_eq!(a.compare_step(&b), CompareResult::Equals);
    }

    #[test]
    fn to_string_radix_prefixes_thread_key_unless_event_thread() {
        let event = MockStep::tick(-1, 7);
        assert_eq!(event.to_string_radix(&DummyRadix), "7");

        let named = MockStep::tick(2, 7);
        assert_eq!(named.to_string_radix(&DummyRadix), "t2-7");
    }

    #[test]
    fn hash_code_matches_java_long_hash_formula() {
        // Long.hashCode(3) == 3, Long.hashCode(5) == 5 for small non-negative values, so
        // AbstractStep.hashCode() == 3 * 31 + 5 == 98.
        let base = AbstractStepBase::new(3, 5);
        assert_eq!(base.hash_code(), 98);
    }

    #[test]
    fn base_struct_equality_is_structural() {
        assert_eq!(AbstractStepBase::new(1, 2), AbstractStepBase::new(1, 2));
        assert_ne!(AbstractStepBase::new(1, 2), AbstractStepBase::new(1, 3));
    }
}
