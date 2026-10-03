//! Port of `ghidra.features.base.replace.items.UpdateFieldCommentQuickFix`.
//!
//! QuickFix for updating structure or union field comments.
//!
//! # Faithfully reproduced quirk: `execute()` NPEs (as "failed: null") when the field is gone
//!
//! Java's `execute()`:
//! ```java
//! DataTypeComponent component = findComponent(fieldName);
//! try {
//!     component.setComment(replacement);
//! }
//! catch (Exception e) {
//!     setStatus(QuickFixStatus.ERROR, "Update field comment failed: " + e.getMessage());
//! }
//! ```
//! has no null check on `component` before dereferencing it (unlike
//! [`RenameFieldQuickFix`](crate::feature::base::replace::items::rename_field_quick_fix::RenameFieldQuickFix)'s
//! `execute()`, which does guard). When the field can no longer be found, `component` is `null`
//! and `component.setComment(replacement)` throws a `NullPointerException`; since
//! `NullPointerException` is an unchecked `RuntimeException` (itself an `Exception`), it *is*
//! caught by the surrounding `catch (Exception e)` -- and a bare `new NullPointerException()`'s
//! `getMessage()` is `null`, so string concatenation yields the literal text `"null"`. This port
//! reproduces that exact status/message pairing (rather than silently treating a missing field
//! as a no-op).

use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState;
use crate::program::model::address::Address;
use crate::program::model::data::composite::Composite;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

use std::sync::Arc;

/// QuickFix for updating structure or union field comments.
///
/// Port of `ghidra.features.base.replace.items.UpdateFieldCommentQuickFix`, which `extends
/// CompositeFieldQuickFix`.
pub struct UpdateFieldCommentQuickFix {
    /// Port of the inherited `CompositeFieldQuickFix` state.
    pub base: CompositeFieldQuickFixState,
    field_name: String,
}

impl UpdateFieldCommentQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the field whose comment is to be updated.
    /// * `composite` - the structure or union whose field comment is to be changed.
    /// * `field_name` - the field name whose comment is to be changed.
    /// * `ordinal` - the ordinal of the field being renamed within its containing composite.
    /// * `original` - the original comment of the field.
    /// * `new_comment` - the new comment for the field.
    ///
    /// Port of `UpdateFieldCommentQuickFix(Program, Composite, String, int, String, String)`.
    pub fn new(
        program: Arc<dyn Program>,
        composite: Arc<dyn Composite>,
        field_name: impl Into<String>,
        ordinal: i32,
        original: impl Into<String>,
        new_comment: impl Into<String>,
    ) -> Self {
        UpdateFieldCommentQuickFix {
            base: CompositeFieldQuickFixState::new(program, composite, ordinal, original, new_comment),
            field_name: field_name.into(),
        }
    }
}

impl QuickFix for UpdateFieldCommentQuickFix {
    fn state(&self) -> &QuickFixState {
        &self.base.base
    }

    fn state_mut(&mut self) -> &mut QuickFixState {
        &mut self.base.base
    }

    /// Port of `getActionName()`.
    fn action_name(&self) -> String {
        "Update".to_string()
    }

    /// Port of `getItemType()`.
    fn item_type(&self) -> String {
        "Field Comment".to_string()
    }

    /// Port of `CompositeFieldQuickFix.getAddress()`.
    fn address(&self) -> Option<Address> {
        self.base.address()
    }

    /// Port of `CompositeFieldQuickFix.getPath()`.
    fn path(&self) -> Option<String> {
        Some(self.base.path())
    }

    /// Port of `getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
        None
    }

    /// Port of `doGetCurrent()`.
    fn do_get_current(&self) -> Option<String> {
        self.base.find_component(&self.field_name).and_then(|component| component.get_comment())
    }

    /// Port of `execute()`. See the module docs for the faithfully-preserved NPE-as-"failed:
    /// null" quirk when the field can no longer be found.
    fn execute(&mut self) {
        match self.base.find_component(&self.field_name) {
            Some(component) => {
                let replacement = self.base.base.replacement().to_string();
                component.set_comment(Some(replacement));
            }
            None => {
                self.set_status_with_message(QuickFixStatus::Error, Some("Update field comment failed: null".to_string()));
            }
        }
    }

    /// `CompositeFieldQuickFix.getCustomToolTipData()` is inherited unchanged.
    fn custom_tool_tip_data(&self) -> Option<std::collections::HashMap<String, String>> {
        Some(self.base.custom_tool_tip_data())
    }
}

impl UpdateFieldCommentQuickFix {
    /// Select this quick fix's composite in the data type manager, and (unless triggered by a
    /// selection change) open its editor to this quick fix's field.
    ///
    /// Port of the inherited `CompositeFieldQuickFix.navigateSpecial(ServiceProvider, boolean)`,
    /// which `UpdateFieldCommentQuickFix` does not override; its `getFieldName()` override
    /// returns the stored `fieldName` field directly. Same `ServiceProvider`-dropping precedent
    /// as
    /// [`CompositeFieldQuickFixState::navigate_special`](crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState::navigate_special).
    pub fn navigate_special(
        &self,
        dtm_service: Option<&mut dyn crate::app::services::DataTypeManagerService>,
        from_selection_change: bool,
    ) -> bool {
        self.base.navigate_special(dtm_service, from_selection_change, &self.field_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
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

    fn program() -> Arc<dyn Program> {
        Arc::new(MockProgram { modification_number: Arc::new(AtomicI64::new(0)) })
    }

    /// The mutable backing state for a mock component, shared (via `Arc`) across every handle
    /// returned for the same ordinal -- mirroring how a real `DataTypeComponentDB` mutation is
    /// visible to every later lookup of that same ordinal, not just the handle it was called
    /// through.
    struct MockComponentData {
        ordinal: i32,
        field_name: Option<String>,
        comment: std::sync::Mutex<Option<String>>,
    }

    #[derive(Clone)]
    struct MockComponent(Arc<MockComponentData>);

    impl DataTypeComponent for MockComponent {
        fn get_ordinal(&self) -> i32 {
            self.0.ordinal
        }
        fn get_field_name(&self) -> Option<String> {
            self.0.field_name.clone()
        }
        fn get_comment(&self) -> Option<String> {
            self.0.comment.lock().unwrap().clone()
        }
        fn set_comment(&self, comment: Option<String>) -> Box<dyn DataTypeComponent> {
            *self.0.comment.lock().unwrap() = comment;
            Box::new(self.clone())
        }
    }

    struct MockComposite {
        path_name: String,
        components: Vec<MockComponent>,
        deleted: std::sync::atomic::AtomicBool,
    }
    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            "MockComposite".to_string()
        }
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn is_deleted(&self) -> bool {
            self.deleted.load(std::sync::atomic::Ordering::Relaxed)
        }
    }
    impl Composite for MockComposite {
        fn get_num_components(&self) -> i32 {
            self.components.len() as i32
        }
        fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
            self.components
                .iter()
                .find(|c| c.0.ordinal == ordinal)
                .cloned()
                .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
                .ok_or_else(|| format!("no component at ordinal {ordinal}"))
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components.iter().cloned().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
        }
    }

    fn composite() -> Arc<MockComposite> {
        Arc::new(MockComposite {
            path_name: "/MyStruct".to_string(),
            components: vec![MockComponent(Arc::new(MockComponentData {
                ordinal: 0,
                field_name: Some("alpha".to_string()),
                comment: std::sync::Mutex::new(Some("old comment".to_string())),
            }))],
            deleted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn quick_fix() -> UpdateFieldCommentQuickFix {
        UpdateFieldCommentQuickFix::new(program(), composite(), "alpha", 0, "old comment", "new comment")
    }

    #[test]
    fn constructor_and_basic_accessors() {
        let qf = quick_fix();
        assert_eq!(qf.action_name(), "Update");
        assert_eq!(qf.item_type(), "Field Comment");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.path(), Some("/MyStruct".to_string()));
        assert_eq!(qf.do_get_current(), Some("old comment".to_string()));
    }

    #[test]
    fn execute_updates_the_comment() {
        let mut qf = quick_fix();
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("new comment".to_string()));
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_reports_npe_as_failed_null_when_field_is_missing() {
        // See the module docs: findComponent("missing") finds nothing, and Java's execute()
        // dereferences the null component directly -- reproduced here as an ERROR status with
        // the literal message "Update field comment failed: null".
        let mut qf = UpdateFieldCommentQuickFix::new(program(), composite(), "missing", 0, "old", "new");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.base.base.status(), QuickFixStatus::Error);
        assert_eq!(qf.base.base.status_message_override(), Some("Update field comment failed: null"));
    }

    #[test]
    fn custom_tool_tip_data_reports_composite_path() {
        let qf = quick_fix();
        let tips = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(tips.get("DataType"), Some(&"/MyStruct".to_string()));
    }

    #[test]
    fn navigate_special_uses_the_stored_field_name() {
        let qf = quick_fix();
        assert!(!qf.navigate_special(None, false));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let mut boxed: Box<dyn QuickFix> = Box::new(quick_fix());
        assert_eq!(boxed.item_type(), "Field Comment");
        assert_eq!(boxed.original(), "old comment");
        assert_eq!(boxed.preview(), "new comment");
    }
}
