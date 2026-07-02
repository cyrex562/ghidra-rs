use std::cell::RefCell;
use std::rc::{Rc, Weak};

use crate::util::exception::AssertException;
use crate::util::task::BusyListener;

/// Minimal surface of `org.jdesktop.animation.timing.Animator` used by [`AbstractAnimator`].
///
/// This is a third-party Swing timing library that Ghidra's Java code depends on directly;
/// there is no Ghidra-authored interface wrapping it to reuse. This trait captures only the
/// operations `AbstractAnimator` calls on it, so a concrete implementation (a future port of
/// one of `AbstractAnimator`'s subclasses) can back it with whatever timing mechanism Rust
/// uses in place of the jdesktop library.
pub trait Animator {
    /// Registers a target to be notified of this animation's begin/end lifecycle.
    fn add_target(&mut self, target: Box<dyn TimingTarget>);

    fn start(&mut self);

    fn stop(&mut self);

    fn is_running(&self) -> bool;
}

/// Mirrors `org.jdesktop.animation.timing.TimingTarget`.
///
/// `AbstractAnimator` only ever overrides `begin`/`end`, exactly as its Java counterpart
/// does via `TimingTargetAdapter`, so both default to no-ops here.
pub trait TimingTarget {
    fn begin(&mut self) {}

    fn end(&mut self) {}
}

/// Behavior a concrete animator subclass must supply.
///
/// Mirrors the two abstract methods of `ghidra.graph.job.AbstractAnimator`. Java subclasses
/// (`TwinkleVertexAnimator`, `EdgeHoverAnimator`, ...) override these along with adding their
/// own fields; Rust has no inheritance, so those subclasses instead implement this trait and
/// are held by an [`AbstractAnimator`] via composition.
pub trait AnimatorBehavior {
    /// Creates the underlying animator, or `None` to finish immediately without animating.
    fn create_animator(&mut self) -> Option<Box<dyn Animator>>;

    /// Called exactly once when this animator has run to completion, whether it was
    /// stopped prematurely or ended naturally.
    fn finished(&mut self);
}

/// Port of `ghidra.graph.job.AbstractAnimator`.
///
/// Java subclasses inherit this class's state and control flow. Rust has no inheritance, so
/// this struct instead owns the shared state and drives the shared control flow, delegating
/// to a boxed [`AnimatorBehavior`] for the two methods Java subclasses used to override.
///
/// `start()` hands the created [`Animator`] a lifecycle target that must call back into this
/// animator once the animation ends; Java achieves that with an inner class capturing
/// `this`. Rust has no equivalent aliasing, so an `AbstractAnimator` is only usable behind
/// the `Rc<RefCell<_>>` handle returned by [`AbstractAnimator::new`]; the lifecycle target
/// holds only a [`Weak`] reference back to it.
pub struct AbstractAnimator {
    behavior: Box<dyn AnimatorBehavior>,
    animator: Option<Box<dyn Animator>>,
    has_finished: bool,
    busy_listener: Option<Box<dyn BusyListener>>,
}

impl AbstractAnimator {
    pub fn new(behavior: Box<dyn AnimatorBehavior>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            behavior,
            animator: None,
            has_finished: false,
            busy_listener: None,
        }))
    }

    pub fn set_busy_listener(&mut self, listener: Box<dyn BusyListener>) {
        self.busy_listener = Some(listener);
    }

    /// Stops this animator **and all scheduled animators!**, matching the Java doc's warning
    /// on `stopMe()`.
    pub fn follow_on_animator_scheduled(this: &Rc<RefCell<Self>>) {
        tracing::trace!("followOnAnimatorScheduled");
        Self::stop_me(this);
    }

    /// # Panics
    /// Panics with an [`AssertException`] if `start()` is called on an animator that has
    /// already finished.
    pub fn start(this: &Rc<RefCell<Self>>) {
        tracing::trace!("start()");

        Self::validate_not_finished(this);

        let created = this.borrow_mut().behavior.create_animator();
        tracing::trace!("created animator");

        let mut animator = match created {
            Some(animator) => animator,
            None => {
                Self::call_finish(this);
                return;
            }
        };

        if this.borrow().busy_listener.is_some() {
            animator.add_target(Box::new(BusyTarget { owner: Rc::downgrade(this) }));
        }

        animator.add_target(Box::new(FinishTarget { owner: Rc::downgrade(this) }));

        // this can happen if some external force calls stop() on this animator while it
        // is building itself
        Self::validate_not_finished(this);

        animator.start();
        this.borrow_mut().animator = Some(animator);
    }

    fn validate_not_finished(this: &Rc<RefCell<Self>>) {
        tracing::trace!("validateNotFinished()");

        if this.borrow().has_finished {
            panic!(
                "{}",
                AssertException::with_message(
                    "Called start() on an animator that has already finished!"
                )
            );
        }
    }

    fn call_finish(this: &Rc<RefCell<Self>>) {
        tracing::trace!("callFinish()");

        {
            let mut state = this.borrow_mut();
            if state.has_finished {
                return; // already called
            }
            state.has_finished = true;
        }

        this.borrow_mut().behavior.finished();
    }

    /// Stops this animator **and all scheduled animators!**
    pub fn stop(this: &Rc<RefCell<Self>>) {
        tracing::trace!("stop()");
        Self::stop_me(this);
    }

    pub fn stop_me(this: &Rc<RefCell<Self>>) {
        tracing::trace!("stopMe()");

        if this.borrow().animator.is_none() {
            this.borrow_mut().has_finished = true;
            return;
        }

        if let Some(animator) = this.borrow_mut().animator.as_mut() {
            animator.stop();
        }
    }

    pub fn is_running(this: &Rc<RefCell<Self>>) -> bool {
        tracing::trace!("isRunning()");
        Self::am_i_running(this)
    }

    pub fn has_finished(&self) -> bool {
        self.has_finished
    }

    fn am_i_running(this: &Rc<RefCell<Self>>) -> bool {
        tracing::trace!("amIRunning()");
        match &this.borrow().animator {
            None => false,
            Some(animator) => animator.is_running(),
        }
    }
}

struct BusyTarget {
    owner: Weak<RefCell<AbstractAnimator>>,
}

impl TimingTarget for BusyTarget {
    fn begin(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            if let Some(listener) = owner.borrow().busy_listener.as_ref() {
                listener.set_busy(true);
            }
        }
    }

    fn end(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            if let Some(listener) = owner.borrow().busy_listener.as_ref() {
                listener.set_busy(false);
            }
        }
    }
}

struct FinishTarget {
    owner: Weak<RefCell<AbstractAnimator>>,
}

impl TimingTarget for FinishTarget {
    fn end(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            AbstractAnimator::call_finish(&owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Default)]
    struct MockAnimatorState {
        running: bool,
        targets: Vec<Box<dyn TimingTarget>>,
    }

    struct MockAnimatorHandle(Rc<RefCell<MockAnimatorState>>);

    impl Animator for MockAnimatorHandle {
        fn add_target(&mut self, target: Box<dyn TimingTarget>) {
            self.0.borrow_mut().targets.push(target);
        }

        fn start(&mut self) {
            self.0.borrow_mut().running = true;
        }

        fn stop(&mut self) {
            self.0.borrow_mut().running = false;
        }

        fn is_running(&self) -> bool {
            self.0.borrow().running
        }
    }

    fn fire_begin(state: &Rc<RefCell<MockAnimatorState>>) {
        let mut state = state.borrow_mut();
        for target in state.targets.iter_mut() {
            target.begin();
        }
    }

    fn fire_end(state: &Rc<RefCell<MockAnimatorState>>) {
        let mut state = state.borrow_mut();
        for target in state.targets.iter_mut() {
            target.end();
        }
    }

    struct TestBehavior {
        to_create: RefCell<Option<Box<dyn Animator>>>,
        finished_calls: Rc<Cell<usize>>,
    }

    impl AnimatorBehavior for TestBehavior {
        fn create_animator(&mut self) -> Option<Box<dyn Animator>> {
            self.to_create.borrow_mut().take()
        }

        fn finished(&mut self) {
            self.finished_calls.set(self.finished_calls.get() + 1);
        }
    }

    struct TrackingBusyListener {
        last: std::sync::Mutex<Option<bool>>,
    }

    impl BusyListener for TrackingBusyListener {
        fn set_busy(&self, busy: bool) {
            *self.last.lock().unwrap() = Some(busy);
        }
    }

    fn new_mock_animator() -> (Rc<RefCell<MockAnimatorState>>, MockAnimatorHandle) {
        let state = Rc::new(RefCell::new(MockAnimatorState::default()));
        let handle = MockAnimatorHandle(Rc::clone(&state));
        (state, handle)
    }

    #[test]
    fn start_with_no_animator_finishes_immediately() {
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior { to_create: RefCell::new(None), finished_calls: Rc::clone(&finished_calls) };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);

        assert_eq!(finished_calls.get(), 1);
        assert!(animator.borrow().has_finished());
    }

    #[test]
    fn start_with_animator_defers_finish_until_it_ends() {
        let (mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls: Rc::clone(&finished_calls),
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);

        assert_eq!(finished_calls.get(), 0);
        assert!(!animator.borrow().has_finished());
        assert!(AbstractAnimator::is_running(&animator));

        fire_end(&mock_state);

        assert_eq!(finished_calls.get(), 1);
        assert!(animator.borrow().has_finished());
    }

    #[test]
    fn finish_is_only_called_once() {
        let (mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls: Rc::clone(&finished_calls),
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);
        fire_end(&mock_state);
        fire_end(&mock_state);

        assert_eq!(finished_calls.get(), 1);
    }

    #[test]
    #[should_panic(expected = "Called start() on an animator that has already finished!")]
    fn start_after_finished_panics() {
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior { to_create: RefCell::new(None), finished_calls };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);
        AbstractAnimator::start(&animator);
    }

    #[test]
    fn busy_listener_toggled_on_begin_and_end() {
        let (mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls,
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        let listener = std::sync::Arc::new(TrackingBusyListener { last: std::sync::Mutex::new(None) });
        struct SharedListener(std::sync::Arc<TrackingBusyListener>);
        impl BusyListener for SharedListener {
            fn set_busy(&self, busy: bool) {
                self.0.set_busy(busy);
            }
        }
        animator.borrow_mut().set_busy_listener(Box::new(SharedListener(std::sync::Arc::clone(&listener))));

        AbstractAnimator::start(&animator);

        fire_begin(&mock_state);
        assert_eq!(*listener.last.lock().unwrap(), Some(true));

        fire_end(&mock_state);
        assert_eq!(*listener.last.lock().unwrap(), Some(false));
    }

    #[test]
    fn stop_without_animator_marks_finished() {
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior { to_create: RefCell::new(None), finished_calls: Rc::clone(&finished_calls) };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::stop(&animator);

        assert!(animator.borrow().has_finished());
        // stop_me() sets the flag directly, bypassing the behavior's finished() callback
        assert_eq!(finished_calls.get(), 0);
    }

    #[test]
    fn stop_with_animator_delegates_to_it() {
        let (mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls,
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);
        assert!(mock_state.borrow().running);

        AbstractAnimator::stop(&animator);
        assert!(!mock_state.borrow().running);
        assert!(!animator.borrow().has_finished());
    }

    #[test]
    fn is_running_reflects_inner_animator() {
        let (_mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls,
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        assert!(!AbstractAnimator::is_running(&animator));

        AbstractAnimator::start(&animator);

        assert!(AbstractAnimator::is_running(&animator));
    }

    #[test]
    fn follow_on_animator_scheduled_stops_running_animator() {
        let (mock_state, mock_handle) = new_mock_animator();
        let finished_calls = Rc::new(Cell::new(0));
        let behavior = TestBehavior {
            to_create: RefCell::new(Some(Box::new(mock_handle))),
            finished_calls,
        };
        let animator = AbstractAnimator::new(Box::new(behavior));

        AbstractAnimator::start(&animator);
        AbstractAnimator::follow_on_animator_scheduled(&animator);

        assert!(!mock_state.borrow().running);
    }
}
