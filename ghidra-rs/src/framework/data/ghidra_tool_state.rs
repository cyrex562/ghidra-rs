use crate::app::nav::navigatable_removal_listener::NavigatableRemovalListener;
use crate::framework::model::DomainObject;

/// Captures a tool's navigation state (the active [`Navigatable`](crate::app::seam_stubs::Navigatable)'s
/// before/after location mementos) around an undoable change to a [`DomainObject`], so the tool's
/// position can be restored when that change is undone or redone.
///
/// Port of `ghidra.framework.data.GhidraToolState`, selected as a dependency-cycle cut-point:
/// `GhidraToolState` sits in `ghidra.framework.data` but reaches into `ghidra.app.nav`/
/// `ghidra.app.services` (`Navigatable`, `LocationMemento`, `GoToService`) and `docking`
/// (`ComponentProvider`), which in turn depend back on `ghidra.framework.*` types. Mapping the
/// concrete class to an object-safe trait lets those call sites depend on `Box<dyn
/// GhidraToolState>`/`&dyn GhidraToolState` instead of the concrete class, breaking the cycle.
///
/// This trait extends [`NavigatableRemovalListener`] (the interface the Java class `implements`)
/// and redeclares the three `ToolState` methods `GhidraToolState` overrides
/// (`getAfterState`/`restoreAfterRedo`/`restoreAfterUndo`); `ToolState` itself (the Java
/// superclass, not yet ported) is not otherwise modeled since every one of its public methods is
/// overridden here.
///
/// Not ported here:
/// - The constructor (`GhidraToolState(PluginTool, DomainObject)`): construction is
///   implementation-specific and not part of a trait's contract (mirroring how
///   [`DefaultProjectData`](crate::framework::data::DefaultProjectData)'s constructors are
///   likewise left to implementors). In Java it resolves the tool's active `Navigatable` (via the
///   active `ComponentProvider` if unconnected, else `GoToService.getDefaultNavigatable()`),
///   captures its current [`LocationMemento`] as `beforeMemento` if valid, and registers itself as
///   a [`NavigatableRemovalListener`] on that navigatable; implementors of this trait are expected
///   to reproduce that same initialization.
/// - The private helpers `getNavigatable()` and `updateFocus()`: implementation detail with no
///   cross-class API surface (`getNavigatable` backs the constructor's navigatable resolution;
///   `updateFocus` re-focuses the captured `ComponentProvider` after a restore).
pub trait GhidraToolState: NavigatableRemovalListener {
    /// Captures the tool's current navigation state as the "after" state, to be restored by a
    /// later [`restore_after_redo`](Self::restore_after_redo).
    ///
    /// Port of `GhidraToolState.getAfterState(DomainObject)`.
    fn get_after_state(&mut self, domain_object: &dyn DomainObject);

    /// Restores the tool's navigation state after a redo, moving to the captured "after" memento's
    /// location and re-focusing the active provider.
    ///
    /// Port of `GhidraToolState.restoreAfterRedo(DomainObject)`.
    fn restore_after_redo(&mut self, domain_object: &dyn DomainObject);

    /// Restores the tool's navigation state after an undo, moving to the captured "before"
    /// memento's location and re-focusing the active provider.
    ///
    /// Port of `GhidraToolState.restoreAfterUndo(DomainObject)`.
    fn restore_after_undo(&mut self, domain_object: &dyn DomainObject);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::Navigatable;

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    struct FakeNavigatable;
    impl Navigatable for FakeNavigatable {
        fn is_connected(&self) -> bool {
            false
        }
    }

    /// Minimal implementor tracking just enough state to prove the trait is usable through a
    /// `Box<dyn GhidraToolState>` and that its methods drive real (if simplified) before/after
    /// undo-redo location bookkeeping, mirroring the Java class's core responsibility.
    struct MockGhidraToolState {
        before_location: Option<&'static str>,
        after_location: Option<&'static str>,
        restored_to: Vec<&'static str>,
        removed: bool,
    }

    impl NavigatableRemovalListener for MockGhidraToolState {
        fn navigatable_removed(&mut self, _navigatable: &dyn Navigatable) {
            self.removed = true;
            self.before_location = None;
            self.after_location = None;
        }
    }

    impl GhidraToolState for MockGhidraToolState {
        fn get_after_state(&mut self, _domain_object: &dyn DomainObject) {
            self.after_location = Some("after");
        }

        fn restore_after_redo(&mut self, _domain_object: &dyn DomainObject) {
            if let Some(loc) = self.after_location {
                self.restored_to.push(loc);
            }
        }

        fn restore_after_undo(&mut self, _domain_object: &dyn DomainObject) {
            if let Some(loc) = self.before_location {
                self.restored_to.push(loc);
            }
        }
    }

    #[test]
    fn undo_redo_round_trip_restores_captured_locations() {
        let domain_object = MockDomainObject;
        let mut state = MockGhidraToolState {
            before_location: Some("before"),
            after_location: None,
            restored_to: Vec::new(),
            removed: false,
        };

        state.get_after_state(&domain_object);
        state.restore_after_undo(&domain_object);
        state.restore_after_redo(&domain_object);
        assert_eq!(state.restored_to, vec!["before", "after"]);
        assert!(!state.removed);

        state.navigatable_removed(&FakeNavigatable);
        assert!(state.removed);
        assert!(state.before_location.is_none());
        assert!(state.after_location.is_none());

        // Prove the trait is object-safe: usable behind `Box<dyn GhidraToolState>`.
        let mut boxed: Box<dyn GhidraToolState> = Box::new(MockGhidraToolState {
            before_location: Some("before2"),
            after_location: None,
            restored_to: Vec::new(),
            removed: false,
        });
        boxed.get_after_state(&domain_object);
        boxed.restore_after_redo(&domain_object);
    }
}
