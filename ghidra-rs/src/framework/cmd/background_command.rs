//! Port of `ghidra.framework.cmd.BackgroundCommand`: a command that runs in the background,
//! reporting to a task monitor.
//!
//! Java's abstract class carries both state (name, progress/cancel/modal flags, status message)
//! and behaviour, so it is split per the shape rules: [`BackgroundCommandBase`] holds the state
//! and concrete accessors, and [`BackgroundCommand`] declares the abstract `applyTo(T,
//! TaskMonitor)` plus the overridable hooks, reaching the state through
//! [`BackgroundCommand::base`].
use crate::util::task::{DummyMonitor, TaskMonitor};

/// The state shared by every background command. Mirrors the fields of `BackgroundCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundCommandBase {
    name: String,
    has_progress: bool,
    can_cancel: bool,
    is_modal: bool,
    status_msg: Option<String>,
}

impl BackgroundCommandBase {
    /// Mirrors `BackgroundCommand(String, boolean, boolean, boolean)`.
    pub fn new(name: impl Into<String>, has_progress: bool, can_cancel: bool, is_modal: bool) -> Self {
        BackgroundCommandBase {
            name: name.into(),
            has_progress,
            can_cancel,
            is_modal,
            status_msg: None,
        }
    }

    /// The command's name. Mirrors `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Mirrors `hasProgress()`.
    pub fn has_progress(&self) -> bool {
        self.has_progress
    }

    /// Mirrors `canCancel()`.
    pub fn can_cancel(&self) -> bool {
        self.can_cancel
    }

    /// Mirrors `isModal()`.
    pub fn is_modal(&self) -> bool {
        self.is_modal
    }

    /// The status message, if one was set. Mirrors `getStatusMsg()`.
    pub fn get_status_msg(&self) -> Option<&str> {
        self.status_msg.as_deref()
    }

    /// Mirrors the protected `setStatusMsg(String)`.
    pub fn set_status_msg(&mut self, status_msg: impl Into<String>) {
        self.status_msg = Some(status_msg.into());
    }
}

impl Default for BackgroundCommandBase {
    /// Mirrors the no-arg constructor: `"no-name"`, no progress, not cancellable, not modal.
    fn default() -> Self {
        Self::new("no-name", false, false, false)
    }
}

/// A command applied to a domain object of type `T` in the background. Mirrors
/// `ghidra.framework.cmd.BackgroundCommand<T>`.
///
/// `run(PluginTool, T)` (hand the command to a tool's background executor) is not declared: the
/// tool's background executor is not ported.
pub trait BackgroundCommand<T: ?Sized> {
    /// The shared command state.
    fn base(&self) -> &BackgroundCommandBase;

    /// The shared command state, mutably.
    fn base_mut(&mut self) -> &mut BackgroundCommandBase;

    /// Apply the command to `obj`. Mirrors the abstract `applyTo(T, TaskMonitor)`.
    fn apply_to(&mut self, obj: &mut T, monitor: &dyn TaskMonitor) -> bool;

    /// Apply the command without a monitor. Mirrors the final `applyTo(T)`, which passes
    /// `TaskMonitor.DUMMY`.
    fn apply_to_unmonitored(&mut self, obj: &mut T) -> bool {
        self.apply_to(obj, &DummyMonitor)
    }

    /// Mirrors `getName()`.
    fn get_name(&self) -> String {
        self.base().get_name().to_string()
    }

    /// Mirrors `hasProgress()`.
    fn has_progress(&self) -> bool {
        self.base().has_progress()
    }

    /// Mirrors `canCancel()`.
    fn can_cancel(&self) -> bool {
        self.base().can_cancel()
    }

    /// Mirrors `isModal()`.
    fn is_modal(&self) -> bool {
        self.base().is_modal()
    }

    /// Called when the command is discarded without running (e.g. cancelled while queued).
    /// Mirrors `dispose()`, which does nothing by default.
    fn dispose(&mut self) {}

    /// Called when the command's task completes. Mirrors `taskCompleted()`, which does nothing
    /// by default.
    fn task_completed(&mut self) {}

    /// Mirrors `getStatusMsg()`.
    fn get_status_msg(&self) -> Option<String> {
        self.base().get_status_msg().map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter {
        base: BackgroundCommandBase,
        seen_monitor_cancel: Option<bool>,
    }

    impl BackgroundCommand<i32> for Counter {
        fn base(&self) -> &BackgroundCommandBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut BackgroundCommandBase {
            &mut self.base
        }
        fn apply_to(&mut self, obj: &mut i32, monitor: &dyn TaskMonitor) -> bool {
            self.seen_monitor_cancel = Some(monitor.is_cancelled());
            *obj += 1;
            if *obj > 1 {
                self.base.set_status_msg("too big");
                return false;
            }
            true
        }
    }

    #[test]
    fn defaults_match_java_no_arg_constructor() {
        let base = BackgroundCommandBase::default();
        assert_eq!(base.get_name(), "no-name");
        assert!(!base.has_progress() && !base.can_cancel() && !base.is_modal());
        assert_eq!(base.get_status_msg(), None);
    }

    #[test]
    fn unmonitored_apply_uses_the_dummy_monitor() {
        let mut cmd = Counter {
            base: BackgroundCommandBase::new("count", true, true, false),
            seen_monitor_cancel: None,
        };
        let mut n = 0;
        assert!(cmd.apply_to_unmonitored(&mut n));
        assert_eq!(cmd.seen_monitor_cancel, Some(false));
        assert!(!cmd.apply_to_unmonitored(&mut n));
        assert_eq!(cmd.get_status_msg().as_deref(), Some("too big"));
        assert_eq!(cmd.get_name(), "count");
        assert!(cmd.has_progress() && cmd.can_cancel() && !cmd.is_modal());
    }
}
