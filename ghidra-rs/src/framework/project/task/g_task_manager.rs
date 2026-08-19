//! Port of `ghidra.framework.task.GTaskManager`.

use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use crate::framework::model::{DomainObject, DomainObjectClosedListener};
use crate::framework::project::task::{GTask, GTaskListener};
use crate::framework::seam_stubs::{
    Exception, GScheduledTask, GTaskGroup, GTaskGroupStub, GTaskResult, GTaskResultStub,
};
use crate::generic::concurrent::GThreadPool;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;

/// The most recent task results kept by a manager (`GTaskManager.MAX_RESULTS`).
const MAX_RESULTS: usize = 100;

/// The domain object a task manager runs its tasks against. Tasks run on thread pool threads and
/// open transactions on the object, so it is shared and internally mutable.
pub type SharedDomainObject = Arc<Mutex<dyn DomainObject + Send>>;

/// Manages a queue of tasks to be executed, one at a time, in priority order. All the tasks
/// pertain to a [`DomainObject`] and transactions are created on the domain object so that tasks
/// can operate on it.
///
/// Tasks are organized into groups such that all tasks in a group will be completed before the
/// tasks in the next group, regardless of priority. Within a group, tasks are ordered first by
/// priority and then by the order in which they were added to the group. Groups are executed in
/// the order they were scheduled.
///
/// All tasks within the same group are executed within the same transaction on the domain object.
/// When all the tasks within a group are completed, the transaction is closed unless there is
/// another group scheduled that does not want its own transaction.
///
/// # Suspending
/// A manager can be suspended. When suspended, any currently running task will continue to run,
/// but no new or currently scheduled tasks will be executed until the manager is resumed.
/// [`GTaskManager::run_next_task_even_when_suspended`] runs the next scheduled task anyway.
///
/// # Yielding to other tasks
/// While running, a task can call [`GTaskManager::wait_for_higher_priority_tasks`], which runs
/// scheduled tasks (within the same group) that are a higher priority than the running task,
/// letting the running task yield until all higher priority tasks are executed.
///
/// # Locking
/// Java guards every public method with a single re-entrant lock. Rust's [`Mutex`] is not
/// re-entrant, so the state is locked exactly once per public method and the private helpers take
/// the already-held guard. As in Java, listeners are notified while the lock is held, so a
/// listener must not call back into its own manager.
pub struct GTaskManager {
    inner: Arc<Inner>,
}

/// The shared half of a manager: everything a task running on a pool thread needs to get back to
/// the manager that scheduled it.
struct Inner {
    thread_pool: Arc<GThreadPool>,
    state: Mutex<State>,
    /// Signalled when the manager runs out of work (Java's `notBusy`).
    not_busy: Condvar,
    /// Signalled when work is queued or started (Java's `isBusy`).
    is_busy: Condvar,
    /// Generation counter behind Java's `wait()`/`notify()` pair used by a yielding task.
    wake: Mutex<u64>,
    wake_cv: Condvar,
}

struct State {
    /// `None` once the domain object has been closed.
    domain_object: Option<SharedDomainObject>,
    /// Java's `SortedSet<GScheduledTask>`: kept sorted by priority, ties in insertion order.
    priority_q: Vec<Arc<dyn GScheduledTask>>,
    task_group_list: VecDeque<Arc<dyn GTaskGroup>>,
    running_task: Option<Arc<dyn GScheduledTask>>,
    running_group: Option<Arc<dyn GTaskGroup>>,
    suspended: bool,
    current_group_transaction_id: Option<i32>,
    /// Java chains listeners through `MulticastTaskListener`; a list is the same thing.
    listeners: Vec<Arc<dyn GTaskListener>>,
    delayed_task_stack: Vec<Arc<dyn GScheduledTask>>,
    results: VecDeque<Arc<dyn GTaskResult>>,
}

impl GTaskManager {
    /// Creates a new manager for `domain_object`, running its tasks on `thread_pool`.
    pub fn new(domain_object: SharedDomainObject, thread_pool: Arc<GThreadPool>) -> Self {
        let inner = Arc::new(Inner {
            thread_pool,
            state: Mutex::new(State {
                domain_object: Some(Arc::clone(&domain_object)),
                priority_q: Vec::new(),
                task_group_list: VecDeque::new(),
                running_task: None,
                running_group: None,
                suspended: false,
                current_group_transaction_id: None,
                listeners: Vec::new(),
                delayed_task_stack: Vec::new(),
                results: VecDeque::new(),
            }),
            not_busy: Condvar::new(),
            is_busy: Condvar::new(),
            wake: Mutex::new(0),
            wake_cv: Condvar::new(),
        });

        // Java also notifies GTaskManagerFactory here; that class is not ported yet, so the
        // manager only forgets its domain object.
        domain_object
            .lock()
            .unwrap()
            .add_close_listener(Box::new(CloseListener {
                manager: Arc::downgrade(&inner),
            }));

        Self { inner }
    }

    /// Forgets the domain object; called when it is closed. Tasks scheduled after this point
    /// complete immediately as cancelled.
    pub fn domain_object_closed(&self) {
        self.inner.state.lock().unwrap().domain_object = None;
    }

    /// Schedules a task to be run by this manager. Tasks are run one at a time, lower priority
    /// numbers first.
    ///
    /// If `use_current_group` is true the task is rolled into the current transaction group when
    /// one exists; otherwise any open transaction is closed and a new one opened before the task
    /// runs.
    pub fn schedule_task(
        &self,
        task: Arc<dyn GTask>,
        priority: i32,
        use_current_group: bool,
    ) -> Arc<dyn GScheduledTask> {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        let new_task = inner.schedule_task_locked(&mut state, task, priority, use_current_group);
        inner.is_busy.notify_all();
        inner.run_next_task_if_not_busy_or_suspended(&mut state);
        new_task
    }

    /// Schedules a task within the group with the given name. If a group with that name already
    /// exists (running or waiting) the task joins it; otherwise a new group is created.
    pub fn schedule_task_in_group(&self, task: Arc<dyn GTask>, priority: i32, group_name: &str) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();

        let running_matches = state
            .running_group
            .as_ref()
            .is_some_and(|g| g.get_description() == group_name);
        if running_matches {
            inner.schedule_task_locked(&mut state, task, priority, true);
            inner.is_busy.notify_all();
            inner.run_next_task_if_not_busy_or_suspended(&mut state);
            return;
        }

        let existing = state
            .task_group_list
            .iter()
            .find(|g| g.get_description() == group_name)
            .cloned();
        if let Some(group) = existing {
            let new_task = group.add_task(task, priority);
            inner.notify_task_scheduled(&state, &new_task);
            inner.run_next_task_if_not_busy_or_suspended(&mut state);
            return;
        }

        let group: Arc<dyn GTaskGroup> = GTaskGroupStub::new(group_name, true);
        group.add_task(task, priority);
        state.task_group_list.push_back(Arc::clone(&group));
        inner.notify_task_group_scheduled(&state, &group);
        inner.is_busy.notify_all();
        inner.run_next_task_if_not_busy_or_suspended(&mut state);
    }

    /// Schedules a task group to run. Groups run in the order they are scheduled.
    pub fn schedule_task_group(&self, group: Arc<dyn GTaskGroup>) {
        group.set_scheduled();
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        state.task_group_list.push_back(Arc::clone(&group));
        inner.notify_task_group_scheduled(&state, &group);
        inner.is_busy.notify_all();
        inner.run_next_task_if_not_busy_or_suspended(&mut state);
    }

    /// Sets the suspended state of this manager. While suspended no new tasks are started; any
    /// currently running task continues to run.
    pub fn set_suspended(&self, suspended: bool) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        state.suspended = suspended;
        inner.run_next_task_if_not_busy_or_suspended(&mut state);
        if !state.suspended {
            inner.wake_up_waiting_thread();
        }
        inner.notify_suspended_state_changed(&state);
    }

    /// Runs the next scheduled task even though this manager is suspended. Calling this while not
    /// suspended has no effect, since the manager is then either busy or has nothing to do.
    pub fn run_next_task_even_when_suspended(&self) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        inner.run_next_task_if_not_busy(&mut state);
        inner.wake_up_waiting_thread();
    }

    /// Adds a listener to be notified as tasks are scheduled and completed.
    pub fn add_task_listener(&self, listener: Arc<dyn GTaskListener>) {
        let mut state = self.inner.state.lock().unwrap();
        state.listeners.push(Arc::clone(&listener));
        listener.initialize();
    }

    /// Removes a previously added listener.
    pub fn remove_task_listener(&self, listener: &Arc<dyn GTaskListener>) {
        let mut state = self.inner.state.lock().unwrap();
        let target = Arc::as_ptr(listener) as *const ();
        state
            .listeners
            .retain(|l| Arc::as_ptr(l) as *const () != target);
    }

    /// True if this manager is running a task, or, if suspended, has tasks queued.
    pub fn is_busy(&self) -> bool {
        Inner::is_busy_locked(&self.inner.state.lock().unwrap())
    }

    /// Waits until this manager is no longer busy. Returns false if it was still busy when
    /// `timeout_millis` elapsed.
    pub fn wait_while_busy(&self, timeout_millis: u64) -> bool {
        let inner = &self.inner;
        let deadline = Instant::now() + Duration::from_millis(timeout_millis);
        let mut state = inner.state.lock().unwrap();
        while Inner::is_busy_locked(&state) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, timeout) = inner.not_busy.wait_timeout(state, deadline - now).unwrap();
            state = guard;
            if timeout.timed_out() && Inner::is_busy_locked(&state) {
                return false;
            }
        }
        true
    }

    /// Waits until this manager becomes busy. Returns false if it was still idle when
    /// `timeout_millis` elapsed.
    pub fn wait_until_busy(&self, timeout_millis: u64) -> bool {
        let inner = &self.inner;
        let deadline = Instant::now() + Duration::from_millis(timeout_millis);
        let mut state = inner.state.lock().unwrap();
        while !Inner::is_busy_locked(&state) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, timeout) = inner.is_busy.wait_timeout(state, deadline - now).unwrap();
            state = guard;
            if timeout.timed_out() && !Inner::is_busy_locked(&state) {
                return false;
            }
        }
        true
    }

    /// True if this manager is currently running a task.
    pub fn is_running(&self) -> bool {
        self.inner.state.lock().unwrap().running_task.is_some()
    }

    /// Lets the currently running task yield so that higher priority tasks within the same group
    /// complete before it continues.
    ///
    /// # Panics
    /// Panics (Java throws `IllegalStateException`) if called from any thread other than the one
    /// currently executing a task for this manager.
    pub fn wait_for_higher_priority_tasks(&self) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        let running = match state.running_task.clone() {
            Some(task) => task,
            None => return,
        };
        assert!(
            running.is_running_in_current_thread(),
            "Can only call this method from a currently running task"
        );
        let current_priority = running.get_priority();

        while let Some(next) = state.priority_q.first().cloned() {
            if next.get_priority() >= current_priority {
                break;
            }
            state.delayed_task_stack.push(Arc::clone(&running));
            running
                .get_task_monitor()
                .set_message("WAITING FOR HIGHER PRIORITY TASKS!");
            if state.suspended {
                state = inner.do_wait(state);
            }
            state.priority_q.remove(0);
            state.running_task = Some(Arc::clone(&next));
            drop(state);
            inner.run_task(next);
            state = inner.state.lock().unwrap();
            state.running_task = state.delayed_task_stack.pop();
        }
    }

    /// Returns the most recent task results, oldest first. Only the last
    /// [`MAX_RESULTS`](MAX_RESULTS) results are kept.
    pub fn get_task_results(&self) -> Vec<Arc<dyn GTaskResult>> {
        self.inner
            .state
            .lock()
            .unwrap()
            .results
            .iter()
            .cloned()
            .collect()
    }

    /// Returns the scheduled tasks of the currently running group, in the order they will run.
    pub fn get_scheduled_tasks(&self) -> Vec<Arc<dyn GScheduledTask>> {
        self.inner.state.lock().unwrap().priority_q.clone()
    }

    /// Returns the tasks that are currently waiting for higher priority tasks.
    pub fn get_delayed_tasks(&self) -> Vec<Arc<dyn GScheduledTask>> {
        self.inner.state.lock().unwrap().delayed_task_stack.clone()
    }

    /// Returns the currently running task, or `None` if no task is running.
    pub fn get_running_task(&self) -> Option<Arc<dyn GScheduledTask>> {
        self.inner.state.lock().unwrap().running_task.clone()
    }

    /// Returns the currently running group, or `None` if no group is running.
    pub fn get_current_group(&self) -> Option<Arc<dyn GTaskGroup>> {
        self.inner.state.lock().unwrap().running_group.clone()
    }

    /// Returns the groups that are waiting to run.
    pub fn get_scheduled_groups(&self) -> Vec<Arc<dyn GTaskGroup>> {
        self.inner
            .state
            .lock()
            .unwrap()
            .task_group_list
            .iter()
            .cloned()
            .collect()
    }

    /// True if this manager is currently suspended.
    pub fn is_suspended(&self) -> bool {
        self.inner.state.lock().unwrap().suspended
    }

    /// Cancels all tasks in the currently running group. Tasks in the group that have not started
    /// will never run and are immediately put into the results list. The task monitor of the
    /// running task is cancelled, but that task keeps running until it checks the monitor.
    ///
    /// Nothing happens unless `group` is the currently running group.
    pub fn cancel_running_group(&self, group: &Arc<dyn GTaskGroup>) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        let is_running_group = state
            .running_group
            .as_ref()
            .is_some_and(|running| Arc::ptr_eq(running, group));
        if !is_running_group {
            return;
        }
        group.set_cancelled();
        if let Some(task) = state.running_task.clone() {
            task.get_task_monitor().cancel();
        }
        if state.suspended {
            inner.process_cancelled_jobs_in_priority_q(&mut state);
        }
    }

    /// Cancels all scheduled groups and tasks. The task monitor of the running task is cancelled,
    /// but that task keeps running until it checks the monitor.
    pub fn cancel_all(&self) {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        if let Some(group) = state.running_group.clone() {
            group.set_cancelled();
            if let Some(task) = state.running_task.clone() {
                task.get_task_monitor().cancel();
            }
        }
        for group in state.task_group_list.iter() {
            group.set_cancelled();
        }
        if state.suspended {
            inner.process_cancelled_jobs_in_priority_q(&mut state);
            inner.process_cancelled_groups(&mut state);
        }
    }
}

/// Clears the manager's domain object when that object is closed.
struct CloseListener {
    manager: Weak<Inner>,
}

impl DomainObjectClosedListener for CloseListener {
    fn domain_object_closed(&mut self, _domain_object: &dyn DomainObject) {
        if let Some(inner) = self.manager.upgrade() {
            inner.state.lock().unwrap().domain_object = None;
        }
    }
}

impl Inner {
    fn is_busy_locked(state: &State) -> bool {
        state.running_task.is_some()
            || !state.priority_q.is_empty()
            || !state.task_group_list.is_empty()
    }

    fn schedule_task_locked(
        self: &Arc<Self>,
        state: &mut State,
        task: Arc<dyn GTask>,
        priority: i32,
        use_current_group: bool,
    ) -> Arc<dyn GScheduledTask> {
        // If a group is running and this task can use it, add the task to that group.
        if use_current_group && state.running_group.is_some() {
            let group = state.running_group.clone().unwrap();
            let new_task = group.add_task(task, priority);
            insert_by_priority(&mut state.priority_q, Arc::clone(&new_task));
            self.notify_task_scheduled(state, &new_task);
            new_task
        }
        // Otherwise, if the current group can't be used or there are no groups, start a new one.
        else if state.task_group_list.is_empty() || !use_current_group {
            let group: Arc<dyn GTaskGroup> = GTaskGroupStub::new(&task.get_name(), true);
            let new_task = group.add_task(task, priority);
            state.task_group_list.push_back(Arc::clone(&group));
            self.notify_task_group_scheduled(state, &group);
            new_task
        }
        // Otherwise add it to the first waiting group (only reachable while suspended).
        else {
            let group = Arc::clone(state.task_group_list.front().unwrap());
            let new_task = group.add_task(task, priority);
            self.notify_task_scheduled(state, &new_task);
            new_task
        }
    }

    fn run_next_task_if_not_busy_or_suspended(self: &Arc<Self>, state: &mut State) {
        if !state.suspended {
            self.run_next_task_if_not_busy(state);
        }
    }

    fn run_next_task_if_not_busy(self: &Arc<Self>, state: &mut State) {
        if state.running_task.is_some() {
            return;
        }
        if self.process_next_task_in_priority_q(state) {
            return;
        }
        self.process_next_task_group(state);
        self.process_next_task_in_priority_q(state);
    }

    fn process_next_task_group(self: &Arc<Self>, state: &mut State) {
        if let Some(group) = state.running_group.take() {
            self.notify_group_completed(state, &group);
        }
        if state.task_group_list.is_empty() {
            self.close_transaction(state);
            self.not_busy.notify_all();
            return;
        }
        let next_group = state.task_group_list.pop_front().unwrap();
        self.prepare_group(state, next_group);
    }

    fn prepare_group(self: &Arc<Self>, state: &mut State, task_group: Arc<dyn GTaskGroup>) {
        for task in task_group.get_tasks() {
            insert_by_priority(&mut state.priority_q, task);
        }
        if task_group.wants_new_transaction() {
            self.close_transaction(state);
        }
        self.open_transaction(state, &task_group.get_description());
        state.running_group = Some(Arc::clone(&task_group));
        self.notify_group_started(state, &task_group);
    }

    fn open_transaction(&self, state: &mut State, description: &str) {
        if state.current_group_transaction_id.is_some() {
            return;
        }
        if let Some(domain_object) = state.domain_object.clone() {
            let id = domain_object.lock().unwrap().start_transaction(description);
            state.current_group_transaction_id = Some(id);
        }
    }

    fn close_transaction(&self, state: &mut State) {
        if let (Some(domain_object), Some(id)) = (
            state.domain_object.clone(),
            state.current_group_transaction_id,
        ) {
            domain_object.lock().unwrap().end_transaction(id, true);
            state.current_group_transaction_id = None;
        }
    }

    fn process_next_task_in_priority_q(self: &Arc<Self>, state: &mut State) -> bool {
        if state.priority_q.is_empty() {
            return false;
        }
        let next_task = state.priority_q.remove(0);
        state.running_task = Some(Arc::clone(&next_task));
        self.is_busy.notify_all();

        let inner = Arc::clone(self);
        self.thread_pool.execute(move || inner.run_task(next_task));
        true
    }

    /// The body of Java's inner `GTaskRunnable`.
    fn run_task(self: &Arc<Self>, scheduled_task: Arc<dyn GScheduledTask>) {
        scheduled_task.set_thread();
        {
            let state = self.state.lock().unwrap();
            self.notify_task_started(&state, &scheduled_task);
        }

        let domain_object = self.state.lock().unwrap().domain_object.clone();
        let domain_object = match domain_object {
            Some(d) if !scheduled_task.get_group().was_cancelled() => d,
            _ => {
                self.task_completed(
                    &scheduled_task,
                    Some(Arc::new(CancelledException::default())),
                    true,
                );
                return;
            }
        };

        let task = scheduled_task.get_task();
        let monitor = scheduled_task.get_task_monitor();
        // The domain object lock is released before completing the task: a pool thread must never
        // hold it while asking for the manager state that the scheduling thread holds.
        let outcome = {
            let guard = domain_object.lock().unwrap();
            task.run(&*guard, monitor.as_ref())
        };
        match outcome {
            Ok(()) => self.task_completed(&scheduled_task, None, false),
            Err(e) => {
                let exception: Arc<dyn Exception> = Arc::new(e);
                self.task_completed(&scheduled_task, Some(exception), false)
            }
        }
    }

    fn task_completed(
        self: &Arc<Self>,
        task: &Arc<dyn GScheduledTask>,
        exception: Option<Arc<dyn Exception>>,
        cancelled: bool,
    ) {
        let mut state = self.state.lock().unwrap();
        self.task_completed_locked(&mut state, task, exception, cancelled);
    }

    fn task_completed_locked(
        self: &Arc<Self>,
        state: &mut State,
        task: &Arc<dyn GScheduledTask>,
        exception: Option<Arc<dyn Exception>>,
        cancelled: bool,
    ) {
        let result: Arc<dyn GTaskResult> = Arc::new(GTaskResultStub::new(
            state.running_group.as_ref(),
            task.as_ref(),
            exception,
            cancelled,
            state.current_group_transaction_id,
        ));
        task.get_group().task_completed();
        self.notify_task_completed(state, task, result.as_ref());
        state.results.push_back(result);
        if state.results.len() > MAX_RESULTS {
            state.results.pop_front();
        }
        state.running_task = None;
        if state.delayed_task_stack.is_empty() {
            self.run_next_task_if_not_busy_or_suspended(state);
        }
    }

    fn process_cancelled_groups(self: &Arc<Self>, state: &mut State) {
        let groups: Vec<Arc<dyn GTaskGroup>> = state.task_group_list.drain(..).collect();
        for group in groups {
            for task in group.get_tasks() {
                self.task_completed_locked(
                    state,
                    &task,
                    Some(Arc::new(CancelledException::default())),
                    true,
                );
            }
            self.notify_group_completed(state, &group);
        }
    }

    fn process_cancelled_jobs_in_priority_q(self: &Arc<Self>, state: &mut State) {
        let tasks: Vec<Arc<dyn GScheduledTask>> = state.priority_q.drain(..).collect();
        for task in tasks {
            self.task_completed_locked(
                state,
                &task,
                Some(Arc::new(CancelledException::default())),
                true,
            );
        }
        if let Some(group) = state.running_group.take() {
            self.notify_group_completed(state, &group);
        }
    }

    /// Java's `notify()` on the manager monitor: releases a task that is waiting for higher
    /// priority tasks while suspended.
    fn wake_up_waiting_thread(&self) {
        let mut generation = self.wake.lock().unwrap();
        *generation += 1;
        self.wake_cv.notify_all();
    }

    /// Java's `wait()`: releases the state lock, waits for [`Self::wake_up_waiting_thread`], then
    /// reacquires the state lock.
    fn do_wait<'a>(&'a self, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        let generation = *self.wake.lock().unwrap();
        drop(state);
        let mut current = self.wake.lock().unwrap();
        while *current == generation {
            current = self.wake_cv.wait(current).unwrap();
        }
        drop(current);
        self.state.lock().unwrap()
    }

    fn notify_listeners<F>(&self, state: &State, what: &str, notify: F)
    where
        F: Fn(&dyn GTaskListener),
    {
        for listener in &state.listeners {
            // Java logs and keeps going when a listener throws.
            if std::panic::catch_unwind(AssertUnwindSafe(|| notify(listener.as_ref()))).is_err() {
                Msg::error(
                    "GTaskManager",
                    &format!("Unexpected exception notifying listener of {what}"),
                );
            }
        }
    }

    fn notify_task_started(&self, state: &State, task: &Arc<dyn GScheduledTask>) {
        self.notify_listeners(state, "task started", |l| l.task_started(task.as_ref()));
    }

    fn notify_task_completed(
        &self,
        state: &State,
        task: &Arc<dyn GScheduledTask>,
        result: &dyn GTaskResult,
    ) {
        self.notify_listeners(state, "task completed", |l| {
            l.task_completed(task.as_ref(), result)
        });
    }

    fn notify_task_group_scheduled(&self, state: &State, group: &Arc<dyn GTaskGroup>) {
        self.notify_listeners(state, "group scheduled", |l| {
            l.task_group_scheduled(group.as_ref())
        });
    }

    fn notify_task_scheduled(&self, state: &State, scheduled_task: &Arc<dyn GScheduledTask>) {
        self.notify_listeners(state, "task scheduled", |l| {
            l.task_scheduled(scheduled_task.as_ref())
        });
    }

    fn notify_group_started(&self, state: &State, task_group: &Arc<dyn GTaskGroup>) {
        self.notify_listeners(state, "group started", |l| {
            l.task_group_started(task_group.as_ref())
        });
    }

    fn notify_group_completed(&self, state: &State, task_group: &Arc<dyn GTaskGroup>) {
        self.notify_listeners(state, "group completed", |l| {
            l.task_group_completed(task_group.as_ref())
        });
    }

    fn notify_suspended_state_changed(&self, state: &State) {
        let suspended = state.suspended;
        self.notify_listeners(state, "suspended state changed", |l| {
            l.suspended_state_changed(suspended)
        });
    }
}

/// Inserts `task` into the priority ordered queue, after any task of equal priority, which is how
/// Java's `TreeSet<GScheduledTask>` orders tasks scheduled with the same priority.
fn insert_by_priority(queue: &mut Vec<Arc<dyn GScheduledTask>>, task: Arc<dyn GScheduledTask>) {
    let position = queue
        .iter()
        .position(|queued| queued.compare_to(task.as_ref()) > 0)
        .unwrap_or(queue.len());
    queue.insert(position, task);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::TaskMonitor;
    use std::sync::atomic::{AtomicI32, Ordering};

    /// Records the transactions the manager opens and closes on it.
    #[derive(Default)]
    struct RecordingDomainObject {
        next_transaction_id: AtomicI32,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl DomainObject for RecordingDomainObject {
        fn get_name(&self) -> String {
            "test domain object".to_string()
        }

        fn start_transaction(&mut self, description: &str) -> i32 {
            let id = self.next_transaction_id.fetch_add(1, Ordering::SeqCst);
            self.log
                .lock()
                .unwrap()
                .push(format!("start[{id}] {description}"));
            id
        }

        fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
            self.log
                .lock()
                .unwrap()
                .push(format!("end[{transaction_id}] commit={commit}"));
            true
        }
    }

    /// Appends its name to a shared log when it runs.
    struct RecordingTask {
        name: String,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingTask {
        fn new(name: &str, log: &Arc<Mutex<Vec<String>>>) -> Arc<dyn GTask> {
            Arc::new(Self {
                name: name.to_string(),
                log: Arc::clone(log),
            })
        }
    }

    impl GTask for RecordingTask {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn run(
            &self,
            _domain_object: &dyn DomainObject,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.log.lock().unwrap().push(self.name.clone());
            Ok(())
        }
    }

    /// A task that always fails, to check the failure is captured in the result.
    struct FailingTask;

    impl GTask for FailingTask {
        fn get_name(&self) -> String {
            "failing task".to_string()
        }

        fn run(
            &self,
            _domain_object: &dyn DomainObject,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Err(CancelledException::new("task blew up"))
        }
    }

    #[derive(Default)]
    struct CountingListener {
        events: Mutex<Vec<String>>,
    }

    impl CountingListener {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        fn record(&self, event: String) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl GTaskListener for CountingListener {
        fn initialize(&self) {
            self.record("initialize".to_string());
        }
        fn task_started(&self, task: &dyn GScheduledTask) {
            self.record(format!("started:{}", task.get_description()));
        }
        fn task_completed(&self, task: &dyn GScheduledTask, _result: &dyn GTaskResult) {
            self.record(format!("completed:{}", task.get_description()));
        }
        fn task_group_scheduled(&self, group: &dyn GTaskGroup) {
            self.record(format!("group scheduled:{}", group.get_description()));
        }
        fn task_scheduled(&self, scheduled_task: &dyn GScheduledTask) {
            self.record(format!("scheduled:{}", scheduled_task.get_description()));
        }
        fn task_group_started(&self, group: &dyn GTaskGroup) {
            self.record(format!("group started:{}", group.get_description()));
        }
        fn task_group_completed(&self, group: &dyn GTaskGroup) {
            self.record(format!("group completed:{}", group.get_description()));
        }
        fn suspended_state_changed(&self, suspended: bool) {
            self.record(format!("suspended:{suspended}"));
        }
    }

    fn manager_with_log() -> (GTaskManager, Arc<Mutex<Vec<String>>>) {
        let transaction_log = Arc::new(Mutex::new(Vec::new()));
        let domain_object = RecordingDomainObject {
            next_transaction_id: AtomicI32::new(1),
            log: Arc::clone(&transaction_log),
        };
        let manager = GTaskManager::new(
            Arc::new(Mutex::new(domain_object)),
            GThreadPool::get_shared_thread_pool("g_task_manager_test"),
        );
        (manager, transaction_log)
    }

    #[test]
    fn tasks_in_a_group_run_in_priority_order() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        // While suspended, tasks scheduled with use_current_group all join the first waiting
        // group, so they compete on priority alone.
        manager.set_suspended(true);
        manager.schedule_task(RecordingTask::new("low", &run_log), 30, true);
        manager.schedule_task(RecordingTask::new("high", &run_log), 10, true);
        manager.schedule_task(RecordingTask::new("medium", &run_log), 20, true);

        assert_eq!(manager.get_scheduled_groups().len(), 1);
        assert!(run_log.lock().unwrap().is_empty(), "nothing runs while suspended");

        manager.set_suspended(false);
        assert!(manager.wait_while_busy(5_000), "tasks did not finish");

        assert_eq!(*run_log.lock().unwrap(), vec!["high", "medium", "low"]);
        let results = manager.get_task_results();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].get_description(), "high");
        assert_eq!(results[0].get_priority(), 10);
        assert!(!results[0].was_cancelled());
        assert!(results[0].get_exception().is_none());
    }

    #[test]
    fn equal_priorities_keep_scheduling_order() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        manager.schedule_task(RecordingTask::new("first", &run_log), 5, true);
        manager.schedule_task(RecordingTask::new("second", &run_log), 5, true);
        manager.schedule_task(RecordingTask::new("third", &run_log), 5, true);
        manager.set_suspended(false);

        assert!(manager.wait_while_busy(5_000));
        assert_eq!(*run_log.lock().unwrap(), vec!["first", "second", "third"]);
    }

    #[test]
    fn a_group_runs_inside_a_single_transaction() {
        let (manager, transaction_log) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        manager.schedule_task_in_group(RecordingTask::new("a", &run_log), 1, "analysis");
        manager.schedule_task_in_group(RecordingTask::new("b", &run_log), 2, "analysis");
        assert_eq!(manager.get_scheduled_groups().len(), 1);

        manager.set_suspended(false);
        assert!(manager.wait_while_busy(5_000));

        assert_eq!(*run_log.lock().unwrap(), vec!["a", "b"]);
        assert_eq!(
            *transaction_log.lock().unwrap(),
            vec!["start[1] analysis", "end[1] commit=true"]
        );
        assert!(manager.get_current_group().is_none());
        assert!(!manager.is_busy());
    }

    #[test]
    fn failed_task_result_carries_the_error() {
        let (manager, _) = manager_with_log();
        manager.schedule_task(Arc::new(FailingTask), 1, true);
        assert!(manager.wait_while_busy(5_000));

        let results = manager.get_task_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_description(), "failing task");
        assert!(!results[0].was_cancelled());
        assert_eq!(
            results[0].get_exception().map(|e| e.get_message()),
            Some("task blew up".to_string())
        );
    }

    #[test]
    fn cancel_all_while_suspended_completes_tasks_as_cancelled() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        manager.schedule_task(RecordingTask::new("one", &run_log), 1, true);
        manager.schedule_task(RecordingTask::new("two", &run_log), 2, true);
        manager.cancel_all();

        let results = manager.get_task_results();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.was_cancelled()));
        assert!(run_log.lock().unwrap().is_empty(), "cancelled tasks must not run");
        assert!(manager.get_scheduled_groups().is_empty());
        assert!(!manager.is_busy());
    }

    #[test]
    fn only_the_last_hundred_results_are_kept() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        for i in 0..MAX_RESULTS + 5 {
            manager.schedule_task(RecordingTask::new(&format!("task {i}"), &run_log), 1, true);
        }
        manager.cancel_all();

        let results = manager.get_task_results();
        assert_eq!(results.len(), MAX_RESULTS);
        // The oldest five results were dropped, so the list starts at task 5.
        assert_eq!(results[0].get_description(), "task 5");
        assert_eq!(results[MAX_RESULTS - 1].get_description(), "task 104");
    }

    #[test]
    fn listeners_are_notified_and_can_be_removed() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));
        let listener = Arc::new(CountingListener::default());
        let listener_handle: Arc<dyn GTaskListener> = listener.clone();

        manager.add_task_listener(Arc::clone(&listener_handle));
        manager.set_suspended(true);
        manager.schedule_task(RecordingTask::new("only", &run_log), 1, true);
        manager.set_suspended(false);
        assert!(manager.wait_while_busy(5_000));

        let events = listener.events();
        assert_eq!(events[0], "initialize");
        assert!(events.contains(&"suspended:true".to_string()));
        assert!(events.contains(&"group scheduled:only".to_string()));
        assert!(events.contains(&"group started:only".to_string()));
        assert!(events.contains(&"started:only".to_string()));
        assert!(events.contains(&"completed:only".to_string()));
        assert!(events.contains(&"group completed:only".to_string()));

        manager.remove_task_listener(&listener_handle);
        let before = listener.events().len();
        manager.set_suspended(true);
        assert_eq!(listener.events().len(), before, "removed listener still notified");
    }

    #[test]
    fn scheduling_without_the_current_group_creates_a_new_group() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        manager.schedule_task(RecordingTask::new("first", &run_log), 1, true);
        manager.schedule_task(RecordingTask::new("second", &run_log), 1, false);

        let groups = manager.get_scheduled_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].get_description(), "first");
        assert_eq!(groups[1].get_description(), "second");
    }

    #[test]
    fn a_scheduled_group_reports_itself_as_scheduled() {
        let (manager, _) = manager_with_log();
        let run_log = Arc::new(Mutex::new(Vec::new()));

        manager.set_suspended(true);
        let group = GTaskGroupStub::new("bulk", true);
        let handle: Arc<dyn GTaskGroup> = Arc::clone(&group) as Arc<dyn GTaskGroup>;
        handle.add_task(RecordingTask::new("x", &run_log), 1);
        handle.add_task(RecordingTask::new("y", &run_log), 1);
        manager.schedule_task_group(Arc::clone(&handle));

        assert!(group.is_scheduled());
        assert_eq!(manager.get_scheduled_groups().len(), 1);

        manager.set_suspended(false);
        assert!(manager.wait_while_busy(5_000));
        assert_eq!(*run_log.lock().unwrap(), vec!["x", "y"]);
        assert_eq!(group.completed_task_count(), 2);
    }
}
