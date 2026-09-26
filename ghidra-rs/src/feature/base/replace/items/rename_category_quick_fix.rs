//! Port of `ghidra.features.base.replace.items.RenameCategoryQuickFix`.
//!
//! QuickFix for renaming datatype categories.
//!
//! # `navigateSpecial`'s `ServiceProvider` parameter
//!
//! Same situation as
//! [`CompositeFieldQuickFixState::navigate_special`](crate::feature::base::replace::items::composite_field_quick_fix::CompositeFieldQuickFixState::navigate_special)
//! (see that method's and [`QuickFix::navigate_special`]'s own docs): the Java override needs a
//! `DataTypeManagerService` (`services.getService(DataTypeManagerService.class)`), but
//! `QuickFix::navigate_special` already dropped its `ServiceProvider` parameter entirely. Per that
//! same precedent, [`RenameCategoryQuickFix::navigate_special`] is a plain inherent method taking
//! the already-resolved service directly; `impl QuickFix for RenameCategoryQuickFix` does not
//! override the trait method (so it falls back to the trait's always-`false` default) since there
//! is no service to pass through that signature -- a caller wanting the real behavior calls the
//! inherent method directly once it has resolved a `DataTypeManagerService` itself.
//!
//! # Faithfully reproduced quirk: `getPath()`/`getCustomToolTipData()` can NPE on a root category
//!
//! Java's `getPath()` and `getCustomToolTipData()` both call `category.getParent().<method>()`
//! *without* the `null`-parent guard that [`RenameCategoryQuickFix::check_for_duplicates`] uses --
//! so constructing a `RenameCategoryQuickFix` for the root category (which has no parent) and then
//! calling either of those methods throws an unchecked `NullPointerException` in Java. This port
//! preserves that as a panic (via `.expect(..)`) rather than silently returning `None`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::app::services::DataTypeManagerService;
use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::feature::base::replace::{RenameQuickFixState, RENAME_ACTION_NAME};
use crate::program::model::address::Address;
use crate::program::model::data::category::Category;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// QuickFix for renaming datatype categories.
///
/// Port of `ghidra.features.base.replace.items.RenameCategoryQuickFix`.
pub struct RenameCategoryQuickFix {
    /// Port of the inherited `RenameQuickFix` state.
    pub base: RenameQuickFixState,
    category: Box<dyn Category>,
}

impl RenameCategoryQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the category to be renamed.
    /// * `category` - the category to be renamed.
    /// * `new_name` - the new name for the category.
    ///
    /// Port of `RenameCategoryQuickFix(Program, Category, String)`.
    pub fn new(program: Arc<dyn Program>, category: Box<dyn Category>, new_name: impl Into<String>) -> Self {
        let name = category.get_name();
        let mut quick_fix = RenameCategoryQuickFix {
            base: RenameQuickFixState::new(program, name, new_name),
            category,
        };
        quick_fix.check_for_duplicates();
        quick_fix
    }

    /// Port of the private `checkForDuplicates()`.
    fn check_for_duplicates(&mut self) {
        let Some(parent) = self.category.get_parent() else {
            return;
        };
        if parent.get_category(self.base.base.replacement()).is_some() {
            let message = format!(
                "The name \"{}\" already exists in category \"{}\"",
                self.base.base.replacement(),
                parent.get_category_path_name()
            );
            // Bypasses the `QuickFix` trait's `set_status`/`set_status_with_message` (see
            // `RenameQuickFixState::validate_replacement_name`'s doc comment for why): this
            // method is called both from `Self::new` (before a `dyn QuickFix` exists) and from
            // `QuickFix::status_changed` (through the trait), so it talks to the shared state
            // directly either way.
            self.base.base.set_status_and_message(QuickFixStatus::Warning, Some(message));
        }
    }

    /// Select this quick fix's category in the data type manager.
    ///
    /// * `dtm_service` - the resolved `DataTypeManagerService`, or `None` if unavailable. Stands
    ///   in for `services.getService(DataTypeManagerService.class)` returning `null`; see the
    ///   module docs for why this is a parameter rather than a `ServiceProvider` lookup.
    /// * `from_selection_change` - unused; Java's override also ignores this parameter (it's part
    ///   of the shared `navigateSpecial` signature, but `RenameCategoryQuickFix`'s body never
    ///   reads it).
    ///
    /// Port of `navigateSpecial(ServiceProvider, boolean)`.
    pub fn navigate_special(
        &self,
        dtm_service: Option<&mut dyn DataTypeManagerService>,
        from_selection_change: bool,
    ) -> bool {
        let _ = from_selection_change;
        let Some(service) = dtm_service else {
            return false;
        };
        service.set_category_selected(Some(self.category.as_ref()));
        true
    }
}

impl QuickFix for RenameCategoryQuickFix {
    fn state(&self) -> &QuickFixState {
        &self.base.base
    }

    fn state_mut(&mut self) -> &mut QuickFixState {
        &mut self.base.base
    }

    fn action_name(&self) -> String {
        RENAME_ACTION_NAME.to_string()
    }

    /// Port of `getItemType()`.
    fn item_type(&self) -> String {
        "datatype category".to_string()
    }

    /// Port of `getAddress()`.
    fn address(&self) -> Option<Address> {
        None
    }

    /// Port of `getPath()`. See the module docs for the faithfully reproduced root-category NPE
    /// quirk.
    fn path(&self) -> Option<String> {
        let parent = self.category.get_parent().expect(
            "RenameCategoryQuickFix.getPath(): category has no parent (mirrors a Java \
             NullPointerException from getParent().getCategoryPathName() on the root category)",
        );
        Some(parent.get_category_path_name())
    }

    /// Port of `getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
        None
    }

    /// Port of `doGetCurrent()`.
    fn do_get_current(&self) -> Option<String> {
        Some(self.category.get_name())
    }

    /// Port of `execute()`.
    fn execute(&mut self) {
        let replacement = self.base.base.replacement().to_string();
        if let Err(e) = self.category.set_name(&replacement) {
            self.set_status_with_message(QuickFixStatus::Error, Some(format!("Rename Failed! {}", e)));
        }
    }

    /// Port of `statusChanged(QuickFixStatus)`.
    fn status_changed(&mut self, new_status: QuickFixStatus) {
        if new_status == QuickFixStatus::None {
            self.check_for_duplicates();
        }
    }

    /// Port of `getCustomToolTipData()`. See the module docs for the faithfully reproduced
    /// root-category NPE quirk.
    fn custom_tool_tip_data(&self) -> Option<HashMap<String, String>> {
        let parent = self.category.get_parent().expect(
            "RenameCategoryQuickFix.getCustomToolTipData(): category has no parent (mirrors a \
             Java NullPointerException from getParent().getCategoryPathName() on the root \
             category)",
        );
        let mut map = HashMap::new();
        map.insert("Parent Path".to_string(), parent.get_category_path_name());
        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::TreePath;
    use crate::framework::seam_stubs::Archive;
    use crate::app::services::{
        DataTypeArchiveService, DataTypeQueryService, OpenArchiveError, OpenProjectArchiveError,
    };
    use crate::framework::model::{DomainFile, DomainObject};
    use crate::framework::seam_stubs::HelpLocation;
    use crate::generic::jar::ResourceFile;
    use crate::program::model::data::category::SetCategoryNameError;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
    use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
    use crate::program::model::data::data_type_path::DataTypePath;
    use crate::program::model::listing::DataTypeArchive;
    use crate::util::exception::{DuplicateNameException, InvalidNameException};
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;
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

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    /// A configurable `Category` double.
    ///
    /// * `name` -- current name, mutated by `set_name`.
    /// * `parent` -- `None` for the root category (exercises the NPE-mirroring quirk).
    /// * `sibling_names` -- names `get_category` reports as already existing under this
    ///   category's parent (used to drive the duplicate-name warning).
    /// * `path_name` -- the fully-qualified path name this category reports.
    #[derive(Clone)]
    struct MockCategory {
        name: RefCell<String>,
        parent: Option<Box<MockCategoryHandle>>,
        sibling_names: Vec<String>,
        path_name: String,
    }

    /// `Category` is object-safe (`dyn Category`), but `MockCategory`'s `parent` needs to be
    /// `Clone`-able to support `#[derive(Clone)]`; `Box<dyn Category>` isn't `Clone`, so the
    /// parent is stored as a boxed concrete handle instead and converted to `Box<dyn Category>`
    /// on demand in `get_parent`.
    #[derive(Clone)]
    struct MockCategoryHandle(MockCategory);

    impl MockCategory {
        fn root() -> Self {
            MockCategory {
                name: RefCell::new("root".to_string()),
                parent: None,
                sibling_names: Vec::new(),
                path_name: "/".to_string(),
            }
        }

        fn child(name: &str, parent_path_name: &str, sibling_names: Vec<&str>) -> Self {
            let sibling_names: Vec<String> = sibling_names.into_iter().map(str::to_string).collect();
            // The parent needs to know the same sibling names so `parent.get_category(name)`
            // (used by `check_for_duplicates`) agrees with what `set_name` (used by `execute`)
            // treats as already taken -- both describe "a category with this name already
            // exists among these siblings" from two different vantage points.
            let parent = MockCategory {
                name: RefCell::new("parent".to_string()),
                parent: None,
                sibling_names: sibling_names.clone(),
                path_name: parent_path_name.to_string(),
            };
            MockCategory {
                name: RefCell::new(name.to_string()),
                parent: Some(Box::new(MockCategoryHandle(parent))),
                sibling_names,
                path_name: format!("{parent_path_name}/{name}"),
            }
        }
    }

    impl Category for MockCategory {
        fn get_name(&self) -> String {
            self.name.borrow().clone()
        }
        fn set_name(&mut self, name: &str) -> Result<(), SetCategoryNameError> {
            if name.is_empty() {
                return Err(SetCategoryNameError::InvalidName(InvalidNameException::with_message(
                    "name must not be empty",
                )));
            }
            if self.sibling_names.contains(&name.to_string()) {
                return Err(SetCategoryNameError::Duplicate(DuplicateNameException::with_message(
                    format!("category named \"{name}\" already exists"),
                )));
            }
            *self.name.borrow_mut() = name.to_string();
            Ok(())
        }
        fn get_categories(&self) -> Vec<Box<dyn Category>> {
            Vec::new()
        }
        fn get_data_types(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_data_types_by_base_name(&self, _name: &str) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn add_data_type(
            &mut self,
            dt: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            dt
        }
        fn get_category(&self, name: &str) -> Option<Box<dyn Category>> {
            if self.sibling_names.iter().any(|n| n == name) {
                Some(Box::new(MockCategory {
                    name: RefCell::new(name.to_string()),
                    parent: None,
                    sibling_names: Vec::new(),
                    path_name: format!("{}/{}", self.path_name, name),
                }))
            } else {
                None
            }
        }
        fn get_category_path(&self) -> CategoryPath {
            unimplemented!("not exercised by these tests")
        }
        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }
        fn create_category(&mut self, _name: &str) -> Result<Box<dyn Category>, InvalidNameException> {
            Err(InvalidNameException::new())
        }
        fn remove_category(&mut self, _name: &str, _monitor: &dyn TaskMonitor) -> bool {
            false
        }
        fn remove_empty_category(&mut self, _name: &str, _monitor: &dyn TaskMonitor) -> bool {
            false
        }
        fn move_category(
            &mut self,
            _category: Box<dyn Category>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn DataTypeConflictHandler,
            _monitor: &dyn TaskMonitor,
        ) -> Box<dyn Category> {
            Box::new(MockCategory::root())
        }
        fn get_parent(&self) -> Option<Box<dyn Category>> {
            self.parent.as_ref().map(|p| Box::new(p.0.clone()) as Box<dyn Category>)
        }
        fn is_root(&self) -> bool {
            self.parent.is_none()
        }
        fn get_category_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn get_root(&self) -> Box<dyn Category> {
            Box::new(MockCategory::root())
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Result<(), DataTypeDependencyException> {
            Ok(())
        }
        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn TaskMonitor) -> bool {
            false
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn compare_to(&self, other: &dyn Category) -> std::cmp::Ordering {
            Category::get_name(self).cmp(&other.get_name())
        }
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockArchive;
    impl Archive for MockArchive {
        fn get_name(&self) -> String {
            "MockArchive".to_string()
        }

        fn close(&self) {}

        fn is_modifiable(&self) -> bool {
            false
        }

        fn is_savable(&self) -> bool {
            false
        }

        fn is_changed(&self) -> bool {
            false
        }

        fn save(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A `DataTypeManagerService` double recording every `set_category_selected` call (by the
    /// category's reported path name) so tests can assert on `navigate_special`'s effect.
    struct MockDtmService {
        selected: RefCell<Vec<Option<String>>>,
    }
    impl MockDtmService {
        fn new() -> Self {
            Self { selected: RefCell::new(Vec::new()) }
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
        fn open_data_type_archive(
            &self,
            _archive_name: &str,
        ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_archive(
            &self,
            _file: &ResourceFile,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_project_archive(
            &self,
            _domain_file: &dyn DomainFile,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DataTypeManager>, OpenProjectArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }
        fn open_archive_for_data_type_archive(
            &self,
            _data_type_archive: &dyn DataTypeArchive,
        ) -> Box<dyn Archive> {
            Box::new(MockArchive)
        }
        fn open_archive_file(
            &self,
            _file: &Path,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn Archive>, OpenArchiveError> {
            Ok(Box::new(MockArchive))
        }
    }

    impl DataTypeManagerService for MockDtmService {
        fn get_favorites(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn add_data_type_manager_change_listener(
            &mut self,
            _listener: Box<dyn DataTypeManagerChangeListener>,
        ) {
        }
        fn remove_data_type_manager_change_listener(
            &mut self,
            _listener: &dyn DataTypeManagerChangeListener,
        ) {
        }
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
        fn edit(&mut self, _dt: &dyn DataType) {}
        fn edit_composite(&mut self, _composite: &dyn Composite, _field_name: Option<&str>) {}
        fn set_data_type_selected(&mut self, _data_type: Option<&dyn DataType>) {}
        fn set_category_selected(&mut self, category: Option<&dyn Category>) {
            self.selected.borrow_mut().push(category.map(|c| c.get_category_path_name()));
        }
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

    fn category(name: &str, parent_path_name: &str, sibling_names: Vec<&str>) -> Box<dyn Category> {
        Box::new(MockCategory::child(name, parent_path_name, sibling_names))
    }

    #[test]
    fn constructor_and_basic_accessors() {
        let cat = category("OldName", "/Path", vec![]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert_eq!(qf.action_name(), "Rename");
        assert_eq!(qf.item_type(), "datatype category");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.do_get_current(), Some("OldName".to_string()));
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn path_returns_the_parents_category_path_name() {
        let cat = category("OldName", "/Path", vec![]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert_eq!(qf.path(), Some("/Path".to_string()));
    }

    #[test]
    #[should_panic(expected = "category has no parent")]
    fn path_panics_for_the_root_category_mirroring_a_java_npe() {
        let qf = RenameCategoryQuickFix::new(program(), Box::new(MockCategory::root()), "NewName");
        let _ = qf.path();
    }

    #[test]
    #[should_panic(expected = "category has no parent")]
    fn custom_tool_tip_data_panics_for_the_root_category_mirroring_a_java_npe() {
        let qf = RenameCategoryQuickFix::new(program(), Box::new(MockCategory::root()), "NewName");
        let _ = qf.custom_tool_tip_data();
    }

    #[test]
    fn custom_tool_tip_data_reports_the_parent_path() {
        let cat = category("OldName", "/Path", vec![]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        let map = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(map.get("Parent Path"), Some(&"/Path".to_string()));
    }

    #[test]
    fn constructor_warns_when_replacement_name_already_exists_in_parent() {
        let cat = category("OldName", "/Path", vec!["NewName"]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert_eq!(qf.base.base.status(), QuickFixStatus::Warning);
        assert_eq!(
            qf.base.base.status_message_override(),
            Some("The name \"NewName\" already exists in category \"/Path\"")
        );
    }

    #[test]
    fn constructor_does_not_warn_when_replacement_name_is_unique() {
        let cat = category("OldName", "/Path", vec!["SomethingElse"]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn status_changed_to_none_re_checks_for_duplicates() {
        let cat = category("OldName", "/Path", vec!["NewName"]);
        let mut qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        // Clear the warning the constructor set, then simulate the framework transitioning the
        // status back to NONE; check_for_duplicates should reassert the warning.
        qf.base.base.set_status_and_message(QuickFixStatus::None, None);
        QuickFix::status_changed(&mut qf, QuickFixStatus::None);
        assert_eq!(qf.base.base.status(), QuickFixStatus::Warning);
    }

    #[test]
    fn status_changed_to_other_statuses_does_not_re_check() {
        let cat = category("OldName", "/Path", vec!["NewName"]);
        let mut qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        qf.base.base.set_status_and_message(QuickFixStatus::None, None);
        QuickFix::status_changed(&mut qf, QuickFixStatus::Done);
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_renames_the_category() {
        let cat = category("OldName", "/Path", vec![]);
        let mut qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("NewName".to_string()));
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_reports_an_error_status_on_failure() {
        // MockCategory::set_name fails for names already present in `sibling_names`, mirroring a
        // DuplicateNameException from the real Category.setName.
        let cat = category("OldName", "/Path", vec!["Taken"]);
        let mut qf = RenameCategoryQuickFix::new(program(), cat, "Taken");
        // Constructor already warned (duplicate replacement name); executing still attempts the
        // rename and now surfaces the underlying failure as an ERROR status with a message
        // prefixed "Rename Failed! ", exactly as Java's execute() does.
        QuickFix::execute(&mut qf);
        assert_eq!(qf.base.base.status(), QuickFixStatus::Error);
        let msg = qf.base.base.status_message_override().expect("error message present");
        assert!(msg.starts_with("Rename Failed! "), "unexpected message: {msg}");
    }

    #[test]
    fn navigate_special_without_a_service_returns_false() {
        let cat = category("OldName", "/Path", vec![]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert!(!qf.navigate_special(None, false));
    }

    #[test]
    fn navigate_special_with_a_service_selects_the_category_and_returns_true() {
        let cat = category("OldName", "/Path", vec![]);
        let qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        let mut service = MockDtmService::new();
        let result = qf.navigate_special(Some(&mut service), false);
        assert!(result);
        assert_eq!(service.selected.borrow().as_slice(), &[Some("/Path/OldName".to_string())]);
    }

    #[test]
    fn quick_fix_trait_default_navigate_special_is_false() {
        // impl QuickFix for RenameCategoryQuickFix intentionally does not override
        // navigate_special (see the module docs), so it falls back to the trait default.
        let cat = category("OldName", "/Path", vec![]);
        let mut qf = RenameCategoryQuickFix::new(program(), cat, "NewName");
        assert!(!QuickFix::navigate_special(&mut qf, false));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let cat = category("OldName", "/Path", vec![]);
        let mut boxed: Box<dyn QuickFix> = Box::new(RenameCategoryQuickFix::new(program(), cat, "NewName"));
        assert_eq!(boxed.item_type(), "datatype category");
        assert_eq!(boxed.original(), "OldName");
        assert_eq!(boxed.preview(), "NewName");
    }
}
