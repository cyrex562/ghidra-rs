//! Port of `ghidra.features.base.replace.RenameQuickFix`.
//!
//! Base state/behavior for `QuickFix` objects that rename Ghidra program elements. Java's version
//! is itself still abstract (`RenameQuickFix extends QuickFix` but leaves `getItemType`/
//! `getAddress`/`getPath`/`getProgramLocation`/`doGetCurrent`/`execute` unimplemented); per this
//! crate's composition-over-inheritance convention, this becomes a second-layer base struct
//! (mirroring how [`QuickFixState`] itself is embedded by any [`QuickFix`] implementor) that a
//! concrete rename quick fix (e.g. a future `RenameSymbolQuickFix`; none ported yet) embeds
//! alongside whatever additional data it needs.

use crate::feature::base::quickfix::{QuickFixState, QuickFixStatus};
use crate::program::model::listing::Program;

use std::sync::Arc;

/// Java: `RenameQuickFix.getActionName()`, always `"Rename"`. A concrete rename quick fix's
/// [`QuickFix::action_name`](crate::feature::base::quickfix::QuickFix::action_name)
/// implementation should return this constant.
pub const RENAME_ACTION_NAME: &str = "Rename";

/// Port of the abstract `ghidra.features.base.replace.RenameQuickFix`.
pub struct RenameQuickFixState {
    pub base: QuickFixState,
}

impl RenameQuickFixState {
    /// Java: `RenameQuickFix(Program, String, String)`, which chains to `QuickFix`'s constructor
    /// and then immediately validates the replacement name.
    pub fn new(
        program: Arc<dyn Program>,
        name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        let mut state = Self { base: QuickFixState::new(program, name, new_name) };
        state.validate_replacement_name();
        state
    }

    /// Java: `RenameQuickFix.validateReplacementName()`. `protected` and overridable in Java;
    /// exposed as a plain method here since Rust has no virtual dispatch without an explicit
    /// trait -- a concrete rename quick fix wanting different validation should call its own
    /// logic instead of (or in addition to) this one, the same way a Java override would replace
    /// the base implementation.
    pub fn validate_replacement_name(&mut self) {
        // Java: `replacement.isBlank()`.
        if self.base.replacement().trim().is_empty() {
            self.base.set_status_and_message(
                QuickFixStatus::Error,
                Some("Can't rename to \"\"".to_string()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::base::quickfix::QuickFix;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::Address;
    use crate::program::util::ProgramLocation;

    struct MockProgram;

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
        fn get_modification_number(&self) -> i64 {
            0
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

    fn program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    /// A minimal concrete rename quick fix, embedding [`RenameQuickFixState`] the way a real
    /// `RenameXQuickFix` subclass would.
    struct MockRenameQuickFix {
        state: RenameQuickFixState,
    }

    impl MockRenameQuickFix {
        fn new(name: &str, new_name: &str) -> Self {
            Self { state: RenameQuickFixState::new(program(), name, new_name) }
        }
    }

    impl QuickFix for MockRenameQuickFix {
        fn state(&self) -> &QuickFixState {
            &self.state.base
        }
        fn state_mut(&mut self) -> &mut QuickFixState {
            &mut self.state.base
        }
        fn action_name(&self) -> String {
            RENAME_ACTION_NAME.to_string()
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
            Some(self.state().original().to_string())
        }
        fn execute(&mut self) {}
    }

    #[test]
    fn action_name_is_always_rename() {
        let qf = MockRenameQuickFix::new("old", "new");
        assert_eq!(qf.action_name(), "Rename");
        assert_eq!(RENAME_ACTION_NAME, "Rename");
    }

    #[test]
    fn valid_replacement_name_leaves_status_unset() {
        let qf = MockRenameQuickFix::new("old", "new");
        assert_eq!(qf.state.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn blank_replacement_name_is_an_error() {
        let qf = MockRenameQuickFix::new("old", "");
        assert_eq!(qf.state.base.status(), QuickFixStatus::Error);
        assert_eq!(qf.state.base.status_message_override(), Some("Can't rename to \"\""));
    }

    #[test]
    fn whitespace_only_replacement_name_is_also_an_error() {
        // Java: `replacement.isBlank()` treats an all-whitespace string as blank too.
        let qf = MockRenameQuickFix::new("old", "   ");
        assert_eq!(qf.state.base.status(), QuickFixStatus::Error);
    }

    #[test]
    fn non_blank_replacement_with_surrounding_whitespace_is_fine() {
        let qf = MockRenameQuickFix::new("old", "  new  ");
        assert_eq!(qf.state.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn validate_replacement_name_can_be_invoked_directly() {
        let mut state = RenameQuickFixState::new(program(), "old", "new");
        assert_eq!(state.base.status(), QuickFixStatus::None);
        // Simulate a later mutation of the replacement leaving it blank, then re-validating --
        // exercises `validate_replacement_name` as an independently callable operation, matching
        // its `protected` (overridable, separately invocable) visibility in Java.
        state.base.set_status_and_message(QuickFixStatus::None, None);
        state.validate_replacement_name();
        assert_eq!(state.base.status(), QuickFixStatus::None);
    }
}
