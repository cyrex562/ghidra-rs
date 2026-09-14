//! Port of `ghidra.features.base.replace.items.UpdateDataTypeDescriptionQuickFix`.
//!
//! QuickFix for updating a datatype's description (only supported on structures, unions, or
//! enums).

use crate::app::services::DataTypeManagerService;
use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

use std::sync::Arc;

/// QuickFix for updating a datatype's description (only supported on structures, unions, or
/// enums).
///
/// Port of `ghidra.features.base.replace.items.UpdateDataTypeDescriptionQuickFix`.
pub struct UpdateDataTypeDescriptionQuickFix {
    /// Port of the inherited `QuickFix` state.
    pub base: QuickFixState,
    data_type: Box<dyn DataType>,
}

impl UpdateDataTypeDescriptionQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the datatype description to be updated.
    /// * `data_type` - the datatype being renamed.
    /// * `new_description` - the new description for the datatype.
    ///
    /// Port of `UpdateDataTypeDescriptionQuickFix(Program, DataType, String)`.
    pub fn new(program: Arc<dyn Program>, data_type: Box<dyn DataType>, new_description: impl Into<String>) -> Self {
        let description = Self::get_description(data_type.as_ref()).unwrap_or_default();
        UpdateDataTypeDescriptionQuickFix { base: QuickFixState::new(program, description, new_description), data_type }
    }

    /// Port of the private static `getDescription(DataType)`.
    fn get_description(dt: &dyn DataType) -> Option<String> {
        if let Some(composite) = dt.as_composite() {
            return Some(composite.get_description());
        }
        if let Some(enumm) = dt.as_enum() {
            return Some(enumm.get_description());
        }
        None
    }

    /// Select this quick fix's datatype in the data type manager.
    ///
    /// * `dtm_service` - the resolved `DataTypeManagerService`, or `None` if unavailable. Stands
    ///   in for `services.getService(DataTypeManagerService.class)` returning `null`; see
    ///   [`QuickFix::navigate_special`]'s docs for why this is a parameter rather than a
    ///   `ServiceProvider` lookup.
    /// * `from_selection_change` - `true` if this navigation was triggered by a selection change.
    ///
    /// Port of `navigateSpecial(ServiceProvider, boolean)`.
    pub fn navigate_special(&self, dtm_service: Option<&mut dyn DataTypeManagerService>, from_selection_change: bool) -> bool {
        let Some(service) = dtm_service else {
            return false;
        };
        service.set_data_type_selected(Some(self.data_type.as_ref()));
        if !from_selection_change {
            service.edit(self.data_type.as_ref());
        }
        true
    }
}

impl QuickFix for UpdateDataTypeDescriptionQuickFix {
    fn state(&self) -> &QuickFixState {
        &self.base
    }

    fn state_mut(&mut self) -> &mut QuickFixState {
        &mut self.base
    }

    /// Port of `getActionName()`.
    fn action_name(&self) -> String {
        "Update".to_string()
    }

    /// Port of `getItemType()`.
    fn item_type(&self) -> String {
        "Datatype Description".to_string()
    }

    /// Port of `getAddress()`.
    fn address(&self) -> Option<Address> {
        None
    }

    /// Port of `getPath()`.
    fn path(&self) -> Option<String> {
        Some(self.data_type.get_category_path().get_path())
    }

    /// Port of `getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
        None
    }

    /// Port of `doGetCurrent()`.
    fn do_get_current(&self) -> Option<String> {
        if self.data_type.is_deleted() {
            return None;
        }
        Self::get_description(self.data_type.as_ref())
    }

    /// Port of `execute()`.
    fn execute(&mut self) {
        let replacement = self.base.replacement().to_string();
        let result: Result<(), String> = if let Some(composite) = self.data_type.as_composite_mut() {
            composite.set_description(&replacement).map_err(|e| e.to_string())
        }
        else if let Some(enumm) = self.data_type.as_enum_mut() {
            crate::program::model::data::enum_::Enum::set_description(enumm, &replacement);
            Ok(())
        }
        else {
            Ok(())
        };
        if let Err(e) = result {
            self.set_status_with_message(QuickFixStatus::Error, Some(format!("Rename datatype failed: {e}")));
        }
    }

    /// Port of `getCustomToolTipData()`.
    fn custom_tool_tip_data(&self) -> Option<std::collections::HashMap<String, String>> {
        let mut map = std::collections::HashMap::new();
        map.insert("Category".to_string(), self.data_type.get_category_path().to_string());
        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{Archive, TreePath};
    use crate::app::services::{DataTypeArchiveService, DataTypeQueryService, OpenArchiveError, OpenProjectArchiveError};
    use crate::framework::model::{DomainFile, DomainObject};
    use crate::framework::seam_stubs::HelpLocation;
    use crate::generic::jar::ResourceFile;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
    use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
    use crate::program::model::data::data_type_path::DataTypePath;
    use crate::program::model::data::enum_::Enum;
    use crate::program::database::data::EnumSignedState;
    use crate::program::model::listing::DataTypeArchive;
    use crate::util::exception::{DuplicateNameException, InvalidNameException};
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::collections::HashSet;
    use std::path::Path;
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

    /// A `Composite`-shaped `DataType` double.
    struct MockComposite {
        path_name: String,
        category_path: String,
        description: Mutex<String>,
        fail_set_description: bool,
    }
    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            "MockComposite".to_string()
        }
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse(&self.category_path).expect("valid test category path")
        }
        fn get_description(&self) -> String {
            self.description.lock().unwrap().clone()
        }
        fn set_description(&mut self, description: &str) -> Result<(), crate::program::model::data::data_type::UnsupportedOperationError> {
            if self.fail_set_description {
                return Err(crate::program::model::data::data_type::UnsupportedOperationError("cannot set description".to_string()));
            }
            *self.description.lock().unwrap() = description.to_string();
            Ok(())
        }
        fn as_composite(&self) -> Option<&dyn Composite> {
            Some(self)
        }
        fn as_composite_mut(&mut self) -> Option<&mut dyn Composite> {
            Some(self)
        }
    }
    impl Composite for MockComposite {
        fn get_num_components(&self) -> i32 {
            0
        }
        fn get_component(&self, _ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("no components".to_string())
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            Vec::new()
        }
    }

    fn composite_data_type(description: &str) -> Box<dyn DataType> {
        Box::new(MockComposite {
            path_name: "/MyStruct".to_string(),
            category_path: "/Category".to_string(),
            description: Mutex::new(description.to_string()),
            fail_set_description: false,
        })
    }

    fn failing_composite_data_type() -> Box<dyn DataType> {
        Box::new(MockComposite {
            path_name: "/MyStruct".to_string(),
            category_path: "/Category".to_string(),
            description: Mutex::new("old".to_string()),
            fail_set_description: true,
        })
    }

    /// An `Enum`-shaped `DataType` double.
    struct MockEnum {
        path_name: String,
        category_path: String,
        description: Mutex<String>,
    }
    impl Clone for MockEnum {
        fn clone(&self) -> Self {
            MockEnum {
                path_name: self.path_name.clone(),
                category_path: self.category_path.clone(),
                description: Mutex::new(self.description.lock().unwrap().clone()),
            }
        }
    }
    impl DataType for MockEnum {
        fn get_name(&self) -> String {
            "MockEnum".to_string()
        }
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse(&self.category_path).expect("valid test category path")
        }
        fn get_description(&self) -> String {
            self.description.lock().unwrap().clone()
        }
        fn as_enum(&self) -> Option<&dyn Enum> {
            Some(self)
        }
        fn as_enum_mut(&mut self) -> Option<&mut dyn Enum> {
            Some(self)
        }
    }
    impl Enum for MockEnum {
        fn get_value_for_name(&self, _name: &str) -> Option<i64> {
            None
        }
        fn get_name_for_value(&self, _value: i64) -> Option<String> {
            None
        }
        fn get_names_for_value(&self, _value: i64) -> Option<Vec<String>> {
            None
        }
        fn get_comment(&self, _name: &str) -> String {
            String::new()
        }
        fn get_values(&self) -> Vec<i64> {
            Vec::new()
        }
        fn get_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_count(&self) -> i32 {
            0
        }
        fn add(&mut self, _name: &str, _value: i64) {}
        fn add_with_comment(&mut self, _name: &str, _value: i64, _comment: &str) {}
        fn remove(&mut self, _name: &str) {}
        fn set_description(&mut self, description: &str) {
            *self.description.lock().unwrap() = description.to_string();
        }
        fn get_enum_representation(&self, big_int: i128, _settings: &dyn crate::docking::settings::settings::Settings, _bit_length: i32) -> String {
            big_int.to_string()
        }
        fn contains_name(&self, _name: &str) -> bool {
            false
        }
        fn contains_value(&self, _value: i64) -> bool {
            false
        }
        fn is_signed(&self) -> bool {
            false
        }
        fn get_signed_state(&self) -> EnumSignedState {
            EnumSignedState::None
        }
        fn get_max_possible_value(&self) -> i64 {
            i64::MAX
        }
        fn get_min_possible_value(&self) -> i64 {
            i64::MIN
        }
        fn get_minimum_possible_length(&self) -> i32 {
            1
        }
        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
            Box::new(self.clone())
        }
    }

    fn enum_data_type(description: &str) -> Box<dyn DataType> {
        Box::new(MockEnum {
            path_name: "/Category/MyEnum".to_string(),
            category_path: "/Category".to_string(),
            description: Mutex::new(description.to_string()),
        })
    }

    #[test]
    fn constructor_captures_the_composites_current_description() {
        let qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old desc"), "new desc");
        assert_eq!(qf.action_name(), "Update");
        assert_eq!(qf.item_type(), "Datatype Description");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.do_get_current(), Some("old desc".to_string()));
        assert_eq!(qf.path(), Some("/Category".to_string()));
    }

    #[test]
    fn execute_updates_a_composites_description() {
        let mut qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old desc"), "new desc");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("new desc".to_string()));
        assert_eq!(qf.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_updates_an_enums_description() {
        let mut qf = UpdateDataTypeDescriptionQuickFix::new(program(), enum_data_type("old desc"), "new desc");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("new desc".to_string()));
        assert_eq!(qf.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_reports_an_error_status_on_composite_failure() {
        let mut qf = UpdateDataTypeDescriptionQuickFix::new(program(), failing_composite_data_type(), "new desc");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.base.status(), QuickFixStatus::Error);
        let msg = qf.base.status_message_override().expect("error message present");
        assert!(msg.starts_with("Rename datatype failed: "), "unexpected message: {msg}");
    }

    #[test]
    fn custom_tool_tip_data_reports_the_category_path() {
        let qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old desc"), "new desc");
        let map = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(map.get("Category"), Some(&"/Category".to_string()));
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockArchive;
    impl Archive for MockArchive {}

    struct MockDtmService {
        selected: RefCell<Vec<Option<String>>>,
        edited: RefCell<Vec<String>>,
    }
    impl MockDtmService {
        fn new() -> Self {
            Self { selected: RefCell::new(Vec::new()), edited: RefCell::new(Vec::new()) }
        }
    }

    #[allow(deprecated)]
    impl DataTypeQueryService for MockDtmService {
        fn get_sorted_data_type_list(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_sorted_category_path_list(&self) -> Vec<CategoryPath> {
            Vec::new()
        }
        fn get_data_type(&self, _filter_text: Option<&str>) -> Option<Box<dyn DataType>> {
            None
        }
        fn prompt_for_data_type(&self, _filter_text: Option<&str>) -> Option<Box<dyn DataType>> {
            None
        }
        fn find_data_types(&self, _name: &str, _monitor: &dyn TaskMonitor) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_data_types_by_path(&self, _path: &DataTypePath) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_program_data_type_by_path(&self, _path: &DataTypePath) -> Option<Box<dyn DataType>> {
            None
        }
    }

    impl DataTypeArchiveService for MockDtmService {
        fn get_built_in_data_types_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
        fn get_data_type_managers(&self) -> Vec<Box<dyn DataTypeManager>> {
            Vec::new()
        }
        fn close_archive(&self, _dtm: &dyn DataTypeManager) {}
        fn open_data_type_archive(&self, _archive_name: &str) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_archive(&self, _file: &ResourceFile, _acquire_write_lock: bool) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_project_archive(
            &self,
            _domain_file: &dyn DomainFile,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DataTypeManager>, OpenProjectArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_archive_for_data_type_archive(&self, _data_type_archive: &dyn DataTypeArchive) -> Box<dyn Archive> {
            Box::new(MockArchive)
        }
        fn open_archive_file(&self, _file: &Path, _acquire_write_lock: bool) -> Result<Box<dyn Archive>, OpenArchiveError> {
            Ok(Box::new(MockArchive))
        }
    }

    impl DataTypeManagerService for MockDtmService {
        fn get_favorites(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn add_data_type_manager_change_listener(&mut self, _listener: Box<dyn DataTypeManagerChangeListener>) {}
        fn remove_data_type_manager_change_listener(&mut self, _listener: &dyn DataTypeManagerChangeListener) {}
        fn set_recently_used(&mut self, _dt: &dyn DataType) {}
        fn get_recently_used(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn get_editor_help_location(&self, _data_type: &dyn DataType) -> Option<Box<dyn HelpLocation>> {
            None
        }
        fn is_editable(&self, _dt: &dyn DataType) -> bool {
            true
        }
        fn edit(&mut self, dt: &dyn DataType) {
            self.edited.borrow_mut().push(dt.get_path_name());
        }
        fn edit_composite(&mut self, _composite: &dyn Composite, _field_name: Option<&str>) {}
        fn set_data_type_selected(&mut self, data_type: Option<&dyn DataType>) {
            self.selected.borrow_mut().push(data_type.map(|d| d.get_path_name()));
        }
        fn set_category_selected(&mut self, _category: Option<&dyn crate::program::model::data::category::Category>) {}
        fn get_selected_data_types(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn choose_data_type_from_tree(&self, _selected_path: Option<&dyn TreePath>) -> Option<Box<dyn DataType>> {
            None
        }
        fn get_category_path(&self, _selected_path: Option<&dyn TreePath>) -> Option<CategoryPath> {
            None
        }
        fn get_possible_equate_names(&self, _value: i64) -> HashSet<String> {
            HashSet::new()
        }
    }

    #[test]
    fn navigate_special_without_a_service_returns_false() {
        let qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old"), "new");
        assert!(!qf.navigate_special(None, false));
    }

    #[test]
    fn navigate_special_with_a_service_selects_and_edits_the_datatype() {
        let qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old"), "new");
        let mut service = MockDtmService::new();
        let result = qf.navigate_special(Some(&mut service), false);
        assert!(result);
        assert_eq!(service.selected.borrow().as_slice(), &[Some("/MyStruct".to_string())]);
        assert_eq!(service.edited.borrow().as_slice(), &["/MyStruct".to_string()]);
    }

    #[test]
    fn navigate_special_from_a_selection_change_does_not_edit() {
        let qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old"), "new");
        let mut service = MockDtmService::new();
        let result = qf.navigate_special(Some(&mut service), true);
        assert!(result);
        assert!(service.edited.borrow().is_empty());
    }

    #[test]
    fn quick_fix_trait_default_navigate_special_is_false() {
        let mut qf = UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old"), "new");
        assert!(!QuickFix::navigate_special(&mut qf, false));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let mut boxed: Box<dyn QuickFix> =
            Box::new(UpdateDataTypeDescriptionQuickFix::new(program(), composite_data_type("old"), "new"));
        assert_eq!(boxed.item_type(), "Datatype Description");
        assert_eq!(boxed.preview(), "new");
    }
}
