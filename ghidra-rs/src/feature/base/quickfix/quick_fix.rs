//! Port of `ghidra.features.base.quickfix.QuickFix`.
//!
//! A generic base for executable items displayed in a table that can be executed individually or
//! in bulk (renaming a symbol, updating a comment, ...). Per this crate's composition-over-
//! inheritance convention, the abstract Java class becomes a [`QuickFix`] trait (its abstract
//! methods become required trait methods; its concrete methods become default trait methods)
//! plus a [`QuickFixState`] struct holding the private fields Java declares directly on the
//! class. A concrete quick fix (`RenameQuickFix`, `UpdateCommentQuickFix`, ...; none ported yet)
//! is expected to embed a [`QuickFixState`] and implement [`QuickFix`] by delegating the shared
//! accessors to it.
//!
//! # The sticky ERROR status
//!
//! [`QuickFix::refresh`] mirrors a deliberate (commented, not accidental) Java quirk: once a
//! quick fix's status is [`QuickFixStatus::Error`], `refresh()` still updates its bookkeeping of
//! the program's modification number, but returns *before* recomputing `current`/status from
//! [`QuickFix::do_get_current`] -- so an errored quick fix's status (and stale `current` value)
//! never changes again, even if the underlying program element goes on to change in a way that
//! would otherwise clear the error. Java's own comment: "once in an error status, it must stay
//! that way (to distinguish it from the \"not done\" state, otherwise we would clear it when we
//! refresh the status)".

use std::collections::HashMap;
use std::sync::Arc;

use crate::feature::base::quickfix::QuickFixStatus;
use crate::framework::model::DomainObject;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// Shared mutable state for a [`QuickFix`], mirroring the private fields Java declares directly
/// on the abstract `QuickFix` class (`modificationNumber`, `status`, `statusMessage`) plus the
/// `protected final`/`protected` fields (`program`, `original`, `replacement`, `current`).
pub struct QuickFixState {
    program: Arc<dyn Program>,
    original: String,
    replacement: String,
    current: Option<String>,
    modification_number: i64,
    status: QuickFixStatus,
    status_message: Option<String>,
}

impl QuickFixState {
    /// `QuickFix(Program, String, String)`.
    pub fn new(program: Arc<dyn Program>, original: impl Into<String>, replacement: impl Into<String>) -> Self {
        let original = original.into();
        let modification_number = program.get_modification_number();
        Self {
            program,
            replacement: replacement.into(),
            current: Some(original.clone()),
            original,
            modification_number,
            status: QuickFixStatus::None,
            status_message: None,
        }
    }

    pub fn program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn replacement(&self) -> &str {
        &self.replacement
    }

    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    pub fn status(&self) -> QuickFixStatus {
        self.status
    }

    pub fn status_message_override(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Sets the status and optional override message directly, bypassing [`QuickFix::refresh`]'s
    /// sticky-`ERROR` bookkeeping. Exposed so a second-layer "abstract subclass" state holder
    /// (e.g. `RenameQuickFixState`, ported at
    /// [`crate::feature::base::replace::rename_quick_fix`]) can call Java's `QuickFix.setStatus(
    /// QuickFixStatus, String)` from its own constructor, before a concrete [`QuickFix`] trait
    /// object exists to call it through.
    pub fn set_status_and_message(&mut self, status: QuickFixStatus, message: Option<String>) {
        self.status = status;
        self.status_message = message;
    }
}

/// Port of the abstract `ghidra.features.base.quickfix.QuickFix`.
pub trait QuickFix {
    /// Accessor for the embedded [`QuickFixState`]; every default method below is built on top of
    /// this pair, exactly the way Java's concrete methods read/write the base class's private
    /// fields directly.
    fn state(&self) -> &QuickFixState;
    /// Mutable accessor for the embedded [`QuickFixState`].
    fn state_mut(&mut self) -> &mut QuickFixState;

    // ---- Abstract in Java ----

    /// `QuickFix.getActionName()`.
    fn action_name(&self) -> String;

    /// `QuickFix.getItemType()`.
    fn item_type(&self) -> String;

    /// `QuickFix.getAddress()`.
    fn address(&self) -> Option<Address>;

    /// `QuickFix.getPath()`.
    fn path(&self) -> Option<String>;

    /// `QuickFix.getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>>;

    /// `QuickFix.doGetCurrent()`.
    fn do_get_current(&self) -> Option<String>;

    /// `QuickFix.execute()`.
    fn execute(&mut self);

    // ---- Concrete in Java ----

    /// `QuickFix.getOriginal()`.
    fn original(&self) -> String {
        self.state().original().to_string()
    }

    /// `QuickFix.getCurrent()`.
    fn current(&mut self) -> Option<String> {
        self.refresh();
        self.state().current().map(str::to_string)
    }

    /// `QuickFix.getPreview()`.
    fn preview(&self) -> String {
        self.state().replacement().to_string()
    }

    /// `QuickFix.performAction()`.
    fn perform_action(&mut self) {
        let status = self.state().status();
        if status == QuickFixStatus::Error || status == QuickFixStatus::Done {
            return;
        }
        self.execute();
    }

    /// `QuickFix.getStatus()`.
    fn status(&mut self) -> QuickFixStatus {
        self.refresh();
        self.state().status()
    }

    /// `QuickFix.getStatusMessage()`.
    fn status_message(&mut self) -> String {
        if let Some(msg) = self.state().status_message_override() {
            return msg.to_string();
        }
        match self.state().status() {
            QuickFixStatus::Done => "Applied".to_string(),
            QuickFixStatus::Error => "Error".to_string(),
            QuickFixStatus::None => "Not Applied".to_string(),
            QuickFixStatus::Warning => "Warning".to_string(),
            QuickFixStatus::Changed => "Target changed externally".to_string(),
            QuickFixStatus::Deleted => "Target no longer exists".to_string(),
        }
    }

    /// `QuickFix.setStatus(QuickFixStatus)`.
    fn set_status(&mut self, status: QuickFixStatus) {
        self.set_status_with_message(status, None);
    }

    /// `QuickFix.setStatus(QuickFixStatus, String)`.
    fn set_status_with_message(&mut self, status: QuickFixStatus, message: Option<String>) {
        self.state_mut().set_status_and_message(status, message);
    }

    /// `QuickFix.getCustomToolTipData()`.
    fn custom_tool_tip_data(&self) -> Option<HashMap<String, String>> {
        None
    }

    /// `QuickFix.navigateSpecial(ServiceProvider, boolean)`.
    ///
    /// The Java `ServiceProvider` parameter is dropped: no implementor in this crate needs it yet,
    /// and [`crate::framework::plugintool::ServiceProvider`] would otherwise need to be threaded
    /// through every call site just for this always-`false`-by-default hook. A concrete quick fix
    /// whose own override *does* need a service lookup (e.g.
    /// [`CompositeFieldQuickFixState::navigate_special`](crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState::navigate_special))
    /// keeps that logic as a plain inherent method taking the already-resolved service directly,
    /// then wires its `bool` result into its own [`QuickFix::navigate_special`] override.
    fn navigate_special(&mut self, _from_selection_change: bool) -> bool {
        false
    }

    /// `QuickFix.refresh()`. See the [module docs](self) for the sticky-ERROR quirk this
    /// reproduces faithfully.
    fn refresh(&mut self) {
        let program_modification_number = self.state().program().get_modification_number();
        if program_modification_number == self.state().modification_number {
            return;
        }
        self.state_mut().modification_number = program_modification_number;

        // Once in an error status, it must stay that way (to distinguish it from the "not done"
        // state, otherwise we would clear it when we refresh the status). See the module docs.
        if self.state().status() == QuickFixStatus::Error {
            return;
        }

        let current = self.do_get_current();
        self.state_mut().current = current;
        self.update_status();
    }

    /// `QuickFix.statusChanged(QuickFixStatus)`. No-op by default; overridable by concrete quick
    /// fixes that need to react to a status transition.
    fn status_changed(&mut self, _new_status: QuickFixStatus) {}

    /// `QuickFix.updateStatus()`.
    fn update_status(&mut self) {
        let new_status = self.compute_status();
        if new_status != self.state().status() {
            self.set_status(new_status);
            self.status_changed(new_status);
        }
    }

    /// `QuickFix.computeStatus()`.
    fn compute_status(&self) -> QuickFixStatus {
        match self.state().current() {
            None => QuickFixStatus::Deleted,
            Some(current) => {
                if current == self.state().original() {
                    QuickFixStatus::None
                } else if current == self.state().replacement() {
                    QuickFixStatus::Done
                } else {
                    QuickFixStatus::Changed
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct MockProgram {
        modification_number: Arc<AtomicI64>,
    }

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }

        fn get_modification_number(&self) -> i64 {
            self.modification_number.load(Ordering::SeqCst)
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    /// A minimal concrete quick fix simulating a rename: `execute()` writes the replacement into
    /// a fake "resource" (standing in for whatever database element a real quick fix would
    /// mutate) and bumps the program's modification number, mirroring the DB transaction a real
    /// `execute()` would perform.
    struct MockQuickFix {
        state: QuickFixState,
        resource: RefCell<String>,
        modification_number: Arc<AtomicI64>,
        execute_calls: usize,
    }

    impl MockQuickFix {
        fn new(original: &str, replacement: &str) -> Self {
            let modification_number = Arc::new(AtomicI64::new(0));
            let program: Arc<dyn Program> = Arc::new(MockProgram { modification_number: modification_number.clone() });
            Self {
                state: QuickFixState::new(program, original, replacement),
                resource: RefCell::new(original.to_string()),
                modification_number,
                execute_calls: 0,
            }
        }

        fn delete_resource(&self) {
            self.modification_number.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl QuickFix for MockQuickFix {
        fn state(&self) -> &QuickFixState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut QuickFixState {
            &mut self.state
        }
        fn action_name(&self) -> String {
            "Rename".to_string()
        }
        fn item_type(&self) -> String {
            "Symbol".to_string()
        }
        fn address(&self) -> Option<Address> {
            None
        }
        fn path(&self) -> Option<String> {
            None
        }
        fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            None
        }
        fn do_get_current(&self) -> Option<String> {
            if *self.resource.borrow() == "<deleted>" {
                None
            } else {
                Some(self.resource.borrow().clone())
            }
        }
        fn execute(&mut self) {
            *self.resource.borrow_mut() = self.state().replacement().to_string();
            self.modification_number.fetch_add(1, Ordering::SeqCst);
            self.execute_calls += 1;
        }
    }

    #[test]
    fn new_initializes_current_to_original_and_status_to_none() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        assert_eq!(qf.original(), "oldName");
        assert_eq!(qf.preview(), "newName");
        assert_eq!(qf.current(), Some("oldName".to_string()));
        assert_eq!(qf.status(), QuickFixStatus::None);
        assert_eq!(qf.status_message(), "Not Applied");
    }

    #[test]
    fn perform_action_executes_and_a_later_refresh_reports_done() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        qf.perform_action();
        assert_eq!(qf.execute_calls, 1);
        // execute() bumped the program's modification number, so the next status()/current()
        // call triggers a real refresh against the (now-updated) resource.
        assert_eq!(qf.current(), Some("newName".to_string()));
        assert_eq!(qf.status(), QuickFixStatus::Done);
        assert_eq!(qf.status_message(), "Applied");
    }

    #[test]
    fn perform_action_is_a_no_op_once_done() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        qf.perform_action();
        qf.status(); // force refresh so status is actually Done before the second attempt
        qf.perform_action();
        assert_eq!(qf.execute_calls, 1, "execute() must not run again once status is Done");
    }

    #[test]
    fn perform_action_is_a_no_op_when_status_is_error() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        qf.set_status(QuickFixStatus::Error);
        qf.perform_action();
        assert_eq!(qf.execute_calls, 0);
    }

    #[test]
    fn deleted_resource_reports_deleted_status_and_message() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        *qf.resource.borrow_mut() = "<deleted>".to_string();
        qf.delete_resource();
        assert_eq!(qf.current(), None);
        assert_eq!(qf.status(), QuickFixStatus::Deleted);
        assert_eq!(qf.status_message(), "Target no longer exists");
    }

    #[test]
    fn changed_externally_reports_changed_status() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        *qf.resource.borrow_mut() = "somethingElse".to_string();
        qf.delete_resource(); // bump modification number so refresh() actually re-reads it
        assert_eq!(qf.current(), Some("somethingElse".to_string()));
        assert_eq!(qf.status(), QuickFixStatus::Changed);
        assert_eq!(qf.status_message(), "Target changed externally");
    }

    #[test]
    fn error_status_is_sticky_across_refresh() {
        // Faithful reproduction of QuickFix.java's refresh(): once ERROR, later program changes
        // no longer update `current` or `status`, even though doGetCurrent() would now report
        // something different. See the module docs.
        let mut qf = MockQuickFix::new("oldName", "newName");
        qf.set_status(QuickFixStatus::Error);
        *qf.resource.borrow_mut() = "newName".to_string();
        qf.delete_resource(); // bump modification number so refresh() takes the ERROR-guard branch

        assert_eq!(qf.status(), QuickFixStatus::Error, "status must remain ERROR");
        assert_eq!(
            qf.current(),
            Some("oldName".to_string()),
            "current must remain stale -- refresh() returns before re-reading it"
        );
    }

    #[test]
    fn refresh_is_a_no_op_when_the_program_has_not_changed() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        // Mutate the resource directly without bumping the program's modification number.
        *qf.resource.borrow_mut() = "newName".to_string();
        // refresh() should see no modification-number change and skip re-reading doGetCurrent().
        assert_eq!(qf.current(), Some("oldName".to_string()));
    }

    #[test]
    fn set_status_with_message_overrides_the_default_message() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        qf.set_status_with_message(QuickFixStatus::Warning, Some("custom warning".to_string()));
        assert_eq!(qf.status_message(), "custom warning");
    }

    #[test]
    fn custom_tool_tip_data_and_navigate_special_default_to_none_and_false() {
        let mut qf = MockQuickFix::new("oldName", "newName");
        assert!(qf.custom_tool_tip_data().is_none());
        assert!(!qf.navigate_special(false));
        assert!(!qf.navigate_special(true));
    }

    #[test]
    fn address_path_and_program_location_default_mock_implementations() {
        let qf = MockQuickFix::new("oldName", "newName");
        assert!(qf.address().is_none());
        assert!(qf.path().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.action_name(), "Rename");
        assert_eq!(qf.item_type(), "Symbol");
    }

    #[test]
    fn compute_status_matches_each_branch() {
        let qf = MockQuickFix::new("oldName", "newName");
        assert_eq!(qf.compute_status(), QuickFixStatus::None);

        *qf.resource.borrow_mut() = "newName".to_string();
        // compute_status reads state().current(), not do_get_current() directly, so drive it
        // through a real refresh first.
        let mut qf = qf;
        qf.delete_resource();
        qf.status();
        assert_eq!(qf.compute_status(), QuickFixStatus::Done);
    }
}
