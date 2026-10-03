//! Port of `ghidra.features.base.replace.items.RenameFieldQuickFix`.
//!
//! QuickFix for renaming structure or union fields.

use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState;
use crate::program::model::address::Address;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

use std::sync::Arc;

/// QuickFix for renaming structure or union fields.
///
/// Port of `ghidra.features.base.replace.items.RenameFieldQuickFix`, which `extends
/// CompositeFieldQuickFix`.
pub struct RenameFieldQuickFix {
    /// Port of the inherited `CompositeFieldQuickFix` state.
    pub base: CompositeFieldQuickFixState,
}

impl RenameFieldQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the structure or union field to be renamed.
    /// * `composite` - the composite whose field is being renamed.
    /// * `ordinal` - the ordinal of the field being renamed within its containing composite.
    /// * `original` - the original name of the field.
    /// * `new_name` - the new name for the field.
    ///
    /// Port of `RenameFieldQuickFix(Program, Composite, int, String, String)`.
    pub fn new(
        program: Arc<dyn Program>,
        composite: Arc<dyn Composite>,
        ordinal: i32,
        original: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        RenameFieldQuickFix { base: CompositeFieldQuickFixState::new(program, composite, ordinal, original, new_name) }
    }

    /// Port of the private `getComponent()`: finds the component by its original name, falling
    /// back to the replacement name (in case a refresh already renamed it).
    fn get_component(&self) -> Option<Box<dyn DataTypeComponent>> {
        if let Some(component) = self.base.find_component(self.base.base.original()) {
            return Some(component);
        }
        self.base.find_component(self.base.base.replacement())
    }

    /// Select this quick fix's composite in the data type manager, and (unless triggered by a
    /// selection change) open its editor to the field's current name.
    ///
    /// Port of the inherited `CompositeFieldQuickFix.navigateSpecial(ServiceProvider, boolean)`,
    /// which `RenameFieldQuickFix` does not override; its `getFieldName()` override returns the
    /// base `QuickFix.current` field, ported here as
    /// [`QuickFixState::current`](crate::feature::base::quickfix::QuickFixState::current). Same
    /// `ServiceProvider`-dropping precedent as
    /// [`CompositeFieldQuickFixState::navigate_special`](crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState::navigate_special) --
    /// see that method's and [`QuickFix::navigate_special`]'s own docs.
    pub fn navigate_special(
        &self,
        dtm_service: Option<&mut dyn crate::app::services::DataTypeManagerService>,
        from_selection_change: bool,
    ) -> bool {
        let field_name = self.base.base.current().unwrap_or("");
        self.base.navigate_special(dtm_service, from_selection_change, field_name)
    }
}

impl QuickFix for RenameFieldQuickFix {
    fn state(&self) -> &QuickFixState {
        &self.base.base
    }

    fn state_mut(&mut self) -> &mut QuickFixState {
        &mut self.base.base
    }

    /// Port of `getActionName()`.
    fn action_name(&self) -> String {
        "Rename".to_string()
    }

    /// Port of `getItemType()`.
    fn item_type(&self) -> String {
        "Field Name".to_string()
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
        self.get_component().and_then(|component| component.get_field_name())
    }

    /// Port of `execute()`. Java's `component.setFieldName(replacement)` mutates the underlying
    /// component in place and returns nothing; this port's
    /// [`DataTypeComponent::set_field_name`](crate::program::model::data::data_type_component::DataTypeComponent::set_field_name)
    /// is immutable-style (returns a new component reflecting the change) per that trait's own
    /// convention, so the new instance is simply discarded once the call (and its side effect on
    /// a real backing store) has happened.
    fn execute(&mut self) {
        if let Some(component) = self.get_component() {
            let replacement = self.base.base.replacement().to_string();
            component.set_field_name(Some(replacement));
        }
    }

    /// Port of `getProgramLocation()` is above; `CompositeFieldQuickFix.getCustomToolTipData()`
    /// is inherited unchanged.
    fn custom_tool_tip_data(&self) -> Option<std::collections::HashMap<String, String>> {
        Some(self.base.custom_tool_tip_data())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type::DataType;
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
        field_name: std::sync::Mutex<Option<String>>,
    }

    #[derive(Clone)]
    struct MockComponent(Arc<MockComponentData>);

    impl DataTypeComponent for MockComponent {
        fn get_ordinal(&self) -> i32 {
            self.0.ordinal
        }
        fn get_field_name(&self) -> Option<String> {
            self.0.field_name.lock().unwrap().clone()
        }
        fn set_field_name(&self, field_name: Option<String>) -> Box<dyn DataTypeComponent> {
            *self.0.field_name.lock().unwrap() = field_name;
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
            components: vec![
                MockComponent(Arc::new(MockComponentData { ordinal: 0, field_name: std::sync::Mutex::new(Some("alpha".to_string())) })),
                MockComponent(Arc::new(MockComponentData { ordinal: 1, field_name: std::sync::Mutex::new(Some("beta".to_string())) })),
            ],
            deleted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn quick_fix() -> RenameFieldQuickFix {
        RenameFieldQuickFix::new(program(), composite(), 0, "alpha", "renamed")
    }

    #[test]
    fn constructor_and_basic_accessors() {
        let qf = quick_fix();
        assert_eq!(qf.action_name(), "Rename");
        assert_eq!(qf.item_type(), "Field Name");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.path(), Some("/MyStruct".to_string()));
    }

    #[test]
    fn do_get_current_finds_the_field_by_original_name() {
        let qf = quick_fix();
        assert_eq!(qf.do_get_current(), Some("alpha".to_string()));
    }

    #[test]
    fn execute_renames_the_field() {
        let mut qf = quick_fix();
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("renamed".to_string()));
    }

    #[test]
    fn do_get_current_falls_back_to_replacement_name_after_a_rename() {
        // Once execute() has run, findComponent(original) no longer matches, so getComponent()
        // falls back to findComponent(replacement).
        let mut qf = quick_fix();
        QuickFix::execute(&mut qf);
        assert_eq!(qf.get_component().and_then(|c| c.get_field_name()), Some("renamed".to_string()));
    }

    #[test]
    fn execute_is_a_no_op_when_the_field_cannot_be_found() {
        let mut qf = RenameFieldQuickFix::new(program(), composite(), 0, "does-not-exist", "renamed");
        QuickFix::execute(&mut qf);
        // Neither "does-not-exist" nor "renamed" is present, so getComponent() (and hence
        // do_get_current) reports None both before and after.
        assert_eq!(qf.do_get_current(), None);
    }

    #[test]
    fn custom_tool_tip_data_reports_composite_path() {
        let qf = quick_fix();
        let tips = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(tips.get("DataType"), Some(&"/MyStruct".to_string()));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let mut boxed: Box<dyn QuickFix> = Box::new(quick_fix());
        assert_eq!(boxed.item_type(), "Field Name");
        assert_eq!(boxed.original(), "alpha");
        assert_eq!(boxed.preview(), "renamed");
    }
}
