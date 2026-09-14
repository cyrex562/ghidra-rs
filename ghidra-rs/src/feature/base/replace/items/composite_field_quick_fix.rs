//! Port of `ghidra.features.base.replace.items.CompositeFieldQuickFix`.
//!
//! Base state/behavior for `QuickFix` objects that rename Composite (Structure/Union) fields.
//! Primarily exists to host the logic for finding components in a composite even as it is
//! changing. Java's class is itself still abstract (`getItemType()`/`getFieldName()` remain
//! unimplemented); per this crate's composition-over-inheritance convention (and mirroring how
//! [`RenameQuickFixState`](crate::feature::base::replace::RenameQuickFixState) embeds
//! [`QuickFixState`]), this becomes a second-layer base struct that a concrete field quick fix
//! (e.g. a future `RenameCompositeFieldQuickFix`; none ported yet) embeds alongside whatever
//! additional data it needs, and calls into from its own [`QuickFix`] trait implementation.
//!
//! # `navigateSpecial`'s `ServiceProvider` parameter
//!
//! [`QuickFix::navigate_special`] already dropped its Java `ServiceProvider` parameter entirely
//! (see that trait's own docs: "no implementor in this crate needs it yet"). This class's own
//! override *does* need to look up a `DataTypeManagerService`
//! (`services.getService(DataTypeManagerService.class)`), so
//! [`CompositeFieldQuickFixState::navigate_special`] is kept as a plain inherent method (matching
//! the same "no virtual dispatch without an explicit trait" precedent
//! [`RenameQuickFixState::validate_replacement_name`](crate::feature::base::replace::RenameQuickFixState::validate_replacement_name)
//! already established) taking the already-resolved service directly as `Option<&mut dyn
//! DataTypeManagerService>`, standing in for the generic `ServiceProvider.getService(Class)`
//! lookup -- a concrete quick fix wanting the full lookup semantics resolves the service itself
//! (however it obtains a `ServiceProvider`) and passes the result in, then wires this method's
//! `bool` result into its own [`QuickFix::navigate_special`] implementation.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::services::DataTypeManagerService;
use crate::feature::base::quickfix::QuickFixState;
use crate::program::model::address::Address;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::listing::Program;

/// Port of the abstract `ghidra.features.base.replace.items.CompositeFieldQuickFix`.
pub struct CompositeFieldQuickFixState {
    pub base: QuickFixState,
    /// The composite being changed.
    pub composite: Arc<dyn Composite>,
    /// The tracked ordinal of the field within [`Self::composite`].
    ///
    /// `Cell`-wrapped (rather than a plain `i32`, mutated through `&mut self`) so that
    /// [`Self::find_component`] -- which updates this when the field has moved to a different
    /// ordinal -- can be called from [`QuickFix::do_get_current`](crate::feature::base::quickfix::QuickFix::do_get_current)
    /// and `QuickFix::execute`'s read-only counterparts, both of which only ever have `&self`
    /// access to a concrete quick fix (mirroring how Java's `this.ordinal = i;` inside the
    /// nominally side-effect-only `findComponent` is unremarkable under Java's lack of
    /// const-correctness, but needs an explicit interior-mutability cell in Rust).
    ordinal: Cell<i32>,
}

impl CompositeFieldQuickFixState {
    /// Construct a composite field quick fix state.
    ///
    /// * `program` - the program containing the composite.
    /// * `composite` - the composite being changed.
    /// * `ordinal` - the ordinal of the field within the composite.
    /// * `original` - the original name of the field.
    /// * `new_name` - the new name for the field.
    ///
    /// Port of `CompositeFieldQuickFix(Program, Composite, int, String, String)`, which chains to
    /// `QuickFix`'s constructor and stores `composite`/`ordinal` directly.
    pub fn new(
        program: Arc<dyn Program>,
        composite: Arc<dyn Composite>,
        ordinal: i32,
        original: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        CompositeFieldQuickFixState {
            base: QuickFixState::new(program, original, new_name),
            composite,
            ordinal: Cell::new(ordinal),
        }
    }

    /// Port of `CompositeFieldQuickFix.getAddress()`, which always returns `null`.
    pub fn address(&self) -> Option<Address> {
        None
    }

    /// Port of `CompositeFieldQuickFix.getPath()`.
    pub fn path(&self) -> String {
        self.composite.get_path_name()
    }

    /// Find the component with the given field name, tolerating the component's ordinal having
    /// moved.
    ///
    /// Port of the protected `findComponent(String)`.
    pub fn find_component(&self, name: &str) -> Option<Box<dyn DataTypeComponent>> {
        if let Some(component) = self.component_by_ordinal() {
            if component.get_field_name().as_deref() == Some(name) {
                return Some(component);
            }
        }

        // perhaps it moved (has a different ordinal now)?
        let components = self.composite.get_defined_components();
        for (i, component) in components.into_iter().enumerate() {
            if component.get_field_name().as_deref() == Some(name) {
                self.ordinal.set(i as i32);
                return Some(component);
            }
        }
        None
    }

    /// Fetch the component currently at this quick fix's tracked ordinal, or `None` if the
    /// composite was deleted or the ordinal is now out of range.
    ///
    /// Port of the protected `getComponentByOrdinal()`.
    pub fn component_by_ordinal(&self) -> Option<Box<dyn DataTypeComponent>> {
        if self.composite.is_deleted() {
            return None;
        }
        let ordinal = self.ordinal.get();
        if ordinal >= self.composite.get_num_components() {
            return None;
        }
        self.composite.get_component(ordinal).ok()
    }

    /// Port of `CompositeFieldQuickFix.getCustomToolTipData()`: `Map.of("DataType",
    /// composite.getPathName())`.
    pub fn custom_tool_tip_data(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("DataType".to_string(), self.composite.get_path_name());
        map
    }

    /// Select this quick fix's composite in the data type manager, and (unless triggered by a
    /// selection change) open its editor to `field_name`.
    ///
    /// * `dtm_service` - the resolved `DataTypeManagerService`, or `None` if unavailable. Stands
    ///   in for `services.getService(DataTypeManagerService.class)` returning `null`; see the
    ///   module docs for why this is a parameter rather than a `ServiceProvider` lookup.
    /// * `from_selection_change` - `true` if this navigation was triggered by a selection change.
    /// * `field_name` - the field name to select in the editor, when opened. Stands in for the
    ///   abstract `getFieldName()` a concrete subclass would supply.
    ///
    /// Port of the protected `navigateSpecial(ServiceProvider, boolean)`.
    pub fn navigate_special(
        &self,
        dtm_service: Option<&mut dyn DataTypeManagerService>,
        from_selection_change: bool,
        field_name: &str,
    ) -> bool {
        let Some(service) = dtm_service else {
            return false;
        };

        service.set_data_type_selected(Some(self.composite.as_ref() as &dyn DataType));

        if !from_selection_change {
            service.edit_composite(self.composite.as_ref(), Some(field_name));
        }
        true
    }

    /// Open the editor for this quick fix's composite (without selecting a specific field).
    ///
    /// Port of the protected `editComposite(DataTypeManagerService)`.
    pub fn edit_composite(&self, dtm_service: &mut dyn DataTypeManagerService) {
        dtm_service.edit_composite(self.composite.as_ref(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;

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

    #[derive(Clone)]
    struct MockComponent {
        ordinal: i32,
        field_name: Option<String>,
    }

    impl DataTypeComponent for MockComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
    }

    /// A minimal `Composite` double: a fixed-size list of named components, with `deleted`
    /// toggleable so tests can exercise `component_by_ordinal`'s guard.
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
                .find(|c| c.ordinal == ordinal)
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
                MockComponent { ordinal: 0, field_name: Some("alpha".to_string()) },
                MockComponent { ordinal: 1, field_name: Some("beta".to_string()) },
            ],
            deleted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn state(ordinal: i32) -> CompositeFieldQuickFixState {
        CompositeFieldQuickFixState::new(program(), composite(), ordinal, "alpha", "renamed")
    }

    #[test]
    fn address_is_always_none() {
        let s = state(0);
        assert!(s.address().is_none());
    }

    #[test]
    fn path_delegates_to_composite_path_name() {
        let s = state(0);
        assert_eq!(s.path(), "/MyStruct");
    }

    #[test]
    fn find_component_matches_by_current_ordinal_first() {
        let mut s = state(0);
        let found = s.find_component("alpha").expect("alpha should be found");
        assert_eq!(found.get_ordinal(), 0);
    }

    #[test]
    fn find_component_falls_back_to_scanning_when_ordinal_moved() {
        // The tracked ordinal (0) now points at "alpha", but we search for "beta" (ordinal 1) --
        // find_component must fall back to scanning get_defined_components and update `ordinal`.
        let mut s = state(0);
        let found = s.find_component("beta").expect("beta should be found via scan");
        assert_eq!(found.get_ordinal(), 1);
        // The internal ordinal should now track beta's position.
        let by_ordinal = s.component_by_ordinal().expect("component now at tracked ordinal");
        assert_eq!(by_ordinal.get_field_name().as_deref(), Some("beta"));
    }

    #[test]
    fn find_component_returns_none_for_unknown_name() {
        let mut s = state(0);
        assert!(s.find_component("does-not-exist").is_none());
    }

    #[test]
    fn component_by_ordinal_returns_none_when_composite_deleted() {
        let comp = composite();
        comp.deleted.store(true, std::sync::atomic::Ordering::Relaxed);
        let s = CompositeFieldQuickFixState::new(program(), comp, 0, "alpha", "renamed");
        assert!(s.component_by_ordinal().is_none());
    }

    #[test]
    fn component_by_ordinal_returns_none_when_ordinal_out_of_range() {
        let s = state(5);
        assert!(s.component_by_ordinal().is_none());
    }

    #[test]
    fn custom_tool_tip_data_reports_composite_path() {
        let s = state(0);
        let tips = s.custom_tool_tip_data();
        assert_eq!(tips.get("DataType"), Some(&"/MyStruct".to_string()));
    }

    #[test]
    fn navigate_special_returns_false_when_service_unavailable() {
        let s = state(0);
        assert!(!s.navigate_special(None, false, "alpha"));
    }
}
