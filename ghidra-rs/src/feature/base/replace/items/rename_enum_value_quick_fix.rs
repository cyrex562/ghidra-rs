//! Port of `ghidra.features.base.replace.items.RenameEnumValueQuickFix`.
//!
//! QuickFix for renaming enum values.
//!
//! # `navigateSpecial`'s `ServiceProvider` parameter
//!
//! Same situation as
//! [`RenameCategoryQuickFix::navigate_special`](crate::feature::base::replace::items::rename_category_quick_fix::RenameCategoryQuickFix::navigate_special)
//! (see that method's and [`QuickFix::navigate_special`]'s own docs): the Java override needs a
//! `DataTypeManagerService`, but `QuickFix::navigate_special` already dropped its `ServiceProvider`
//! parameter entirely. [`RenameEnumValueQuickFix::navigate_special`] is a plain inherent method
//! taking the already-resolved service directly; `impl QuickFix for RenameEnumValueQuickFix` does
//! not override the trait method, so it falls back to the trait's always-`false` default.
//!
//! # Faithfully reproduced quirk: constructing on a missing value name panics
//!
//! Java's constructor does `this.enumValue = enumDt.getValue(valueName);` with no surrounding
//! `try`/`catch` -- `Enum.getValue` throws an uncaught `NoSuchElementException("No value for " +
//! valueName)` when `valueName` isn't in the enum, so *constructing* a `RenameEnumValueQuickFix`
//! for a value that doesn't exist throws straight out of the constructor. This port preserves
//! that as a panic (mirroring the same precedent as
//! [`RenameCategoryQuickFix`](crate::feature::base::replace::items::rename_category_quick_fix)'s
//! root-category NPE) rather than returning `Result` or silently defaulting the value.
//!
//! # Faithfully reproduced quirk: renaming an enum value drops its comment
//!
//! `execute()` re-adds the entry via the two-argument `enumm.add(replacement, enumValue)`
//! (dropping any comment previously on `original`) rather than the three-argument
//! `add(name, value, comment)` overload [`UpdateEnumCommentQuickFix`](crate::feature::base::replace::items::update_enum_comment_quick_fix::UpdateEnumCommentQuickFix)
//! uses. A per-value comment set before a rename is therefore silently lost by this quick fix,
//! exactly as in Java.
//!
//! # `Enum::add`/`Enum::remove` are infallible in this port
//!
//! Java's `execute()` wraps `enumm.add`/`enumm.remove` in a `try`/`catch (Exception e)`, reporting
//! any failure (e.g. a duplicate value/name) as an `QuickFixStatus.ERROR`. This crate's
//! [`Enum::add`](crate::program::model::data::enum_::Enum::add)/[`Enum::remove`](crate::program::model::data::enum_::Enum::remove)
//! are infallible (`()`-returning), so there is nothing for this port's `execute()` to catch --
//! the `ERROR`-status branch of the Java method is consequently unreachable here.

use std::collections::HashMap;
use std::sync::Arc;

use crate::app::services::DataTypeManagerService;
use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::feature::base::replace::{RenameQuickFixState, RENAME_ACTION_NAME};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// QuickFix for renaming enum values.
///
/// Port of `ghidra.features.base.replace.items.RenameEnumValueQuickFix`.
pub struct RenameEnumValueQuickFix {
    /// Port of the inherited `RenameQuickFix` state.
    pub base: RenameQuickFixState,
    enumm: Box<dyn Enum>,
    enum_value: i64,
}

impl RenameEnumValueQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the enum to be renamed.
    /// * `enum_dt` - the enum whose value is being renamed.
    /// * `value_name` - the enum value name being changed.
    /// * `new_name` - the new name for the enum value.
    ///
    /// Port of `RenameEnumValueQuickFix(Program, Enum, String, String)`. See the module docs for
    /// the faithfully-preserved panic when `value_name` is not present in `enum_dt`.
    pub fn new(
        program: Arc<dyn Program>,
        enum_dt: Box<dyn Enum>,
        value_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        let value_name = value_name.into();
        let enum_value = enum_dt.get_value_for_name(&value_name).unwrap_or_else(|| {
            panic!(
                "RenameEnumValueQuickFix::new: No value for {value_name} (mirrors an uncaught \
                 Java NoSuchElementException thrown from the constructor)"
            )
        });
        let mut quick_fix = RenameEnumValueQuickFix {
            base: RenameQuickFixState::new(program, value_name, new_name),
            enumm: enum_dt,
            enum_value,
        };
        quick_fix.validate();
        quick_fix
    }

    /// Port of the private `validate()`.
    fn validate(&mut self) {
        if Enum::contains_name(self.enumm.as_ref(), self.base.base.replacement()) {
            self.base.base.set_status_and_message(
                QuickFixStatus::Warning,
                Some("New name not allowed because it duplicates an existing value name".to_string()),
            );
        }
    }

    /// Select this quick fix's enum in the data type manager.
    ///
    /// * `dtm_service` - the resolved `DataTypeManagerService`, or `None` if unavailable. See the
    ///   module docs for why this is a parameter rather than a `ServiceProvider` lookup.
    /// * `from_selection_change` - `true` if this navigation was triggered by a selection change.
    ///
    /// Port of `navigateSpecial(ServiceProvider, boolean)`.
    pub fn navigate_special(
        &self,
        dtm_service: Option<&mut dyn DataTypeManagerService>,
        from_selection_change: bool,
    ) -> bool {
        let Some(service) = dtm_service else {
            return false;
        };
        service.set_data_type_selected(Some(self.enumm.as_ref() as &dyn DataType));
        if !from_selection_change {
            service.edit(self.enumm.as_ref() as &dyn DataType);
        }
        true
    }
}

impl QuickFix for RenameEnumValueQuickFix {
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
        "Enum Value".to_string()
    }

    /// Port of `getAddress()`.
    fn address(&self) -> Option<Address> {
        None
    }

    /// Port of `getPath()`.
    fn path(&self) -> Option<String> {
        Some(self.enumm.get_path_name())
    }

    /// Port of `getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
        None
    }

    /// Port of `doGetCurrent()`.
    fn do_get_current(&self) -> Option<String> {
        if self.enumm.contains_name(self.base.base.original()) {
            Some(self.base.base.original().to_string())
        } else if self.enumm.contains_name(self.base.base.replacement()) {
            Some(self.base.base.replacement().to_string())
        } else {
            None
        }
    }

    /// Port of `execute()`. See the module docs for why the `ERROR`-status catch path is
    /// unreachable in this port, and for the faithfully-preserved comment-loss quirk.
    fn execute(&mut self) {
        self.enumm.add(self.base.base.replacement(), self.enum_value);
        self.enumm.remove(self.base.base.original());
    }

    /// Port of `statusChanged(QuickFixStatus)`.
    fn status_changed(&mut self, new_status: QuickFixStatus) {
        if new_status == QuickFixStatus::None {
            self.validate();
        }
    }

    /// Port of `getCustomToolTipData()`.
    fn custom_tool_tip_data(&self) -> Option<HashMap<String, String>> {
        let mut map = HashMap::new();
        map.insert("Enum".to_string(), self.enumm.get_path_name());
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
    use crate::program::database::data::EnumSignedState;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
    use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
    use crate::program::model::data::data_type_path::DataTypePath;
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

    /// A configurable `Enum` double, storing entries as `(name, value, comment)` tuples.
    struct MockEnum {
        path_name: String,
        entries: Mutex<Vec<(String, i64, String)>>,
    }

    impl Clone for MockEnum {
        fn clone(&self) -> Self {
            MockEnum { path_name: self.path_name.clone(), entries: Mutex::new(self.entries.lock().unwrap().clone()) }
        }
    }

    impl MockEnum {
        fn new(path_name: &str, entries: Vec<(&str, i64, &str)>) -> Self {
            MockEnum {
                path_name: path_name.to_string(),
                entries: Mutex::new(
                    entries.into_iter().map(|(n, v, c)| (n.to_string(), v, c.to_string())).collect(),
                ),
            }
        }
    }

    impl DataType for MockEnum {
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
    }

    impl Enum for MockEnum {
        fn get_value_for_name(&self, name: &str) -> Option<i64> {
            self.entries.lock().unwrap().iter().find(|(n, _, _)| n == name).map(|(_, v, _)| *v)
        }
        fn get_name_for_value(&self, value: i64) -> Option<String> {
            self.entries.lock().unwrap().iter().find(|(_, v, _)| *v == value).map(|(n, _, _)| n.clone())
        }
        fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
            let names: Vec<String> =
                self.entries.lock().unwrap().iter().filter(|(_, v, _)| *v == value).map(|(n, _, _)| n.clone()).collect();
            if names.is_empty() { None } else { Some(names) }
        }
        fn get_comment(&self, name: &str) -> String {
            self.entries.lock().unwrap().iter().find(|(n, _, _)| n == name).map(|(_, _, c)| c.clone()).unwrap_or_default()
        }
        fn get_values(&self) -> Vec<i64> {
            let mut v: Vec<i64> = self.entries.lock().unwrap().iter().map(|(_, v, _)| *v).collect();
            v.sort_unstable();
            v
        }
        fn get_names(&self) -> Vec<String> {
            let mut v: Vec<(i64, String)> = self.entries.lock().unwrap().iter().map(|(n, v, _)| (*v, n.clone())).collect();
            v.sort();
            v.into_iter().map(|(_, n)| n).collect()
        }
        fn get_count(&self) -> i32 {
            self.entries.lock().unwrap().len() as i32
        }
        fn add(&mut self, name: &str, value: i64) {
            self.add_with_comment(name, value, "");
        }
        fn add_with_comment(&mut self, name: &str, value: i64, comment: &str) {
            self.entries.lock().unwrap().push((name.to_string(), value, comment.to_string()));
        }
        fn remove(&mut self, name: &str) {
            self.entries.lock().unwrap().retain(|(n, _, _)| n != name);
        }
        fn set_description(&mut self, _description: &str) {}
        fn get_enum_representation(&self, big_int: i128, _settings: &dyn crate::docking::settings::settings::Settings, _bit_length: i32) -> String {
            big_int.to_string()
        }
        fn contains_name(&self, name: &str) -> bool {
            self.entries.lock().unwrap().iter().any(|(n, _, _)| n == name)
        }
        fn contains_value(&self, value: i64) -> bool {
            self.entries.lock().unwrap().iter().any(|(_, v, _)| *v == value)
        }
        fn is_signed(&self) -> bool {
            self.entries.lock().unwrap().iter().any(|(_, v, _)| *v < 0)
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

    fn enum_dt() -> Box<dyn Enum> {
        Box::new(MockEnum::new("/Category/Colors", vec![("RED", 0, "the red one"), ("GREEN", 1, "")]))
    }

    #[test]
    fn constructor_and_basic_accessors() {
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        assert_eq!(qf.action_name(), "Rename");
        assert_eq!(qf.item_type(), "Enum Value");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.path(), Some("/Category/Colors".to_string()));
        assert_eq!(qf.do_get_current(), Some("RED".to_string()));
        assert_eq!(qf.base.base.status(), QuickFixStatus::None);
    }

    #[test]
    #[should_panic(expected = "No value for MISSING")]
    fn constructor_panics_when_value_name_is_missing_mirroring_a_java_no_such_element_exception() {
        let _ = RenameEnumValueQuickFix::new(program(), enum_dt(), "MISSING", "NEW");
    }

    #[test]
    fn constructor_warns_when_replacement_name_already_exists() {
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "GREEN");
        assert_eq!(qf.base.base.status(), QuickFixStatus::Warning);
        assert_eq!(
            qf.base.base.status_message_override(),
            Some("New name not allowed because it duplicates an existing value name")
        );
    }

    #[test]
    fn execute_renames_the_value_preserving_the_original_numeric_value() {
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("SCARLET".to_string()));
        assert_eq!(qf.enumm.get_value_for_name("SCARLET"), Some(0));
        assert!(!qf.enumm.contains_name("RED"));
    }

    #[test]
    fn execute_drops_the_original_comment_mirroring_the_java_quirk() {
        // RED starts with the comment "the red one" (see enum_dt()); execute() re-adds via the
        // two-argument add(name, value) overload, which has no comment parameter, so the comment
        // is lost -- see the module docs.
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.enumm.get_comment("SCARLET"), "");
    }

    #[test]
    fn status_changed_to_none_re_validates() {
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "GREEN");
        qf.base.base.set_status_and_message(QuickFixStatus::None, None);
        QuickFix::status_changed(&mut qf, QuickFixStatus::None);
        assert_eq!(qf.base.base.status(), QuickFixStatus::Warning);
    }

    #[test]
    fn custom_tool_tip_data_reports_the_enum_path() {
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        let map = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(map.get("Enum"), Some(&"/Category/Colors".to_string()));
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

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
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        assert!(!qf.navigate_special(None, false));
    }

    #[test]
    fn navigate_special_with_a_service_selects_and_edits_the_enum() {
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        let mut service = MockDtmService::new();
        let result = qf.navigate_special(Some(&mut service), false);
        assert!(result);
        assert_eq!(service.selected.borrow().as_slice(), &[Some("/Category/Colors".to_string())]);
        assert_eq!(service.edited.borrow().as_slice(), &["/Category/Colors".to_string()]);
    }

    #[test]
    fn navigate_special_from_a_selection_change_does_not_edit() {
        let qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        let mut service = MockDtmService::new();
        let result = qf.navigate_special(Some(&mut service), true);
        assert!(result);
        assert!(service.edited.borrow().is_empty());
    }

    #[test]
    fn quick_fix_trait_default_navigate_special_is_false() {
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        assert!(!QuickFix::navigate_special(&mut qf, false));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let mut boxed: Box<dyn QuickFix> = Box::new(RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET"));
        assert_eq!(boxed.item_type(), "Enum Value");
        assert_eq!(boxed.original(), "RED");
        assert_eq!(boxed.preview(), "SCARLET");
    }

    #[test]
    fn do_get_current_reports_replacement_after_execute() {
        // Faithful to Java's doGetCurrent(): once renamed, `original` ("RED") is no longer
        // present, so the second `else if` branch reports the replacement instead.
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("SCARLET".to_string()));
    }

    #[test]
    fn do_get_current_none_when_neither_name_present() {
        let mut qf = RenameEnumValueQuickFix::new(program(), enum_dt(), "RED", "SCARLET");
        // Manually drop both names to simulate external deletion.
        qf.enumm.remove("RED");
        assert_eq!(qf.do_get_current(), None);
    }
}
