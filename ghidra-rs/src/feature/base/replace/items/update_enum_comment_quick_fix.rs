//! Port of `ghidra.features.base.replace.items.UpdateEnumCommentQuickFix`.
//!
//! QuickFix for updating enum value comments.
//!
//! # Faithfully reproduced quirk: `execute()` errors with `"No value for <name>"` when the value
//! is gone
//!
//! Java's `execute()` starts with `long value = enumm.getValue(valueName);`, which throws an
//! uncaught (within the method -- it *is* caught by the surrounding `try`/`catch (Exception e)`)
//! `NoSuchElementException("No value for " + valueName)` when `valueName` no longer exists (see
//! `EnumDataType.getValue`). This port's
//! [`Enum::get_value_for_name`](crate::program::model::data::enum_::Enum::get_value_for_name)
//! returns `None` in that situation instead of throwing (per that method's own doc comment), so
//! `execute()` reproduces the same observable status/message by treating `None` as the caught
//! exception would be: `QuickFixStatus::Error` with message `"Update enum comment failed: No
//! value for <valueName>"`.

use crate::feature::base::quickfix::{QuickFix, QuickFixState, QuickFixStatus};
use crate::program::model::address::Address;
use crate::program::model::data::enum_::Enum;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

use std::sync::Arc;

/// QuickFix for updating enum value comments.
///
/// Port of `ghidra.features.base.replace.items.UpdateEnumCommentQuickFix`.
pub struct UpdateEnumCommentQuickFix {
    /// Port of the inherited `QuickFix` state.
    pub base: QuickFixState,
    enumm: Box<dyn Enum>,
    value_name: String,
}

impl UpdateEnumCommentQuickFix {
    /// Constructor.
    ///
    /// * `program` - the program containing the enum value whose comment is to be updated.
    /// * `enum_dt` - the enum whose field value comment is to be changed.
    /// * `value_name` - the enum value name whose comment is to be changed.
    /// * `new_comment` - the new comment for the enum value.
    ///
    /// Port of `UpdateEnumCommentQuickFix(Program, Enum, String, String)`.
    pub fn new(
        program: Arc<dyn Program>,
        enum_dt: Box<dyn Enum>,
        value_name: impl Into<String>,
        new_comment: impl Into<String>,
    ) -> Self {
        let value_name = value_name.into();
        let current_comment = enum_dt.get_comment(&value_name);
        UpdateEnumCommentQuickFix {
            base: QuickFixState::new(program, current_comment, new_comment),
            enumm: enum_dt,
            value_name,
        }
    }
}

impl QuickFix for UpdateEnumCommentQuickFix {
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
        "Enum Comment".to_string()
    }

    /// Port of `getAddress()`.
    fn address(&self) -> Option<Address> {
        None
    }

    /// Port of `getPath()`.
    fn path(&self) -> Option<String> {
        Some(self.enumm.get_category_path().get_path())
    }

    /// Port of `getProgramLocation()`.
    fn program_location(&self) -> Option<Box<dyn ProgramLocation>> {
        None
    }

    /// Port of `doGetCurrent()`.
    fn do_get_current(&self) -> Option<String> {
        Some(self.enumm.get_comment(&self.value_name))
    }

    /// Port of `execute()`. See the module docs for the faithfully-preserved
    /// `NoSuchElementException`-mirroring error path.
    fn execute(&mut self) {
        let Some(value) = self.enumm.get_value_for_name(&self.value_name) else {
            self.set_status_with_message(
                QuickFixStatus::Error,
                Some(format!("Update enum comment failed: No value for {}", self.value_name)),
            );
            return;
        };
        let replacement = self.base.replacement().to_string();
        self.enumm.remove(&self.value_name);
        self.enumm.add_with_comment(&self.value_name, value, &replacement);
    }

    /// Port of `getCustomToolTipData()`.
    fn custom_tool_tip_data(&self) -> Option<std::collections::HashMap<String, String>> {
        let mut map = std::collections::HashMap::new();
        map.insert("Datatype".to_string(), self.enumm.get_path_name());
        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::database::data::EnumSignedState;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use std::sync::Mutex;
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

    struct MockEnum {
        path_name: String,
        category_path: String,
        entries: Mutex<Vec<(String, i64, String)>>,
    }
    impl Clone for MockEnum {
        fn clone(&self) -> Self {
            MockEnum {
                path_name: self.path_name.clone(),
                category_path: self.category_path.clone(),
                entries: Mutex::new(self.entries.lock().unwrap().clone()),
            }
        }
    }
    impl MockEnum {
        fn new(path_name: &str, category_path: &str, entries: Vec<(&str, i64, &str)>) -> Self {
            MockEnum {
                path_name: path_name.to_string(),
                category_path: category_path.to_string(),
                entries: Mutex::new(entries.into_iter().map(|(n, v, c)| (n.to_string(), v, c.to_string())).collect()),
            }
        }
    }
    impl DataType for MockEnum {
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            crate::program::model::data::category_path::CategoryPath::parse(&self.category_path)
                .expect("valid test category path")
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

    fn enum_dt() -> Box<dyn Enum> {
        Box::new(MockEnum::new("/Category/Colors", "/Category", vec![("RED", 0, "the red one"), ("GREEN", 1, "")]))
    }

    #[test]
    fn constructor_captures_the_current_comment() {
        let qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "a redder comment");
        assert_eq!(qf.action_name(), "Update");
        assert_eq!(qf.item_type(), "Enum Comment");
        assert!(qf.address().is_none());
        assert!(qf.program_location().is_none());
        assert_eq!(qf.do_get_current(), Some("the red one".to_string()));
        assert_eq!(qf.base.original(), "the red one");
    }

    #[test]
    fn path_uses_the_category_path() {
        let qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "new");
        assert_eq!(qf.path(), Some("/Category".to_string()));
    }

    #[test]
    fn execute_updates_the_comment_preserving_the_value() {
        let mut qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "a redder comment");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.do_get_current(), Some("a redder comment".to_string()));
        assert_eq!(qf.enumm.get_value_for_name("RED"), Some(0));
        assert_eq!(qf.base.status(), QuickFixStatus::None);
    }

    #[test]
    fn execute_reports_no_value_for_error_when_the_value_name_is_gone() {
        let mut qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "a redder comment");
        qf.enumm.remove("RED");
        QuickFix::execute(&mut qf);
        assert_eq!(qf.base.status(), QuickFixStatus::Error);
        assert_eq!(qf.base.status_message_override(), Some("Update enum comment failed: No value for RED"));
    }

    #[test]
    fn custom_tool_tip_data_reports_the_enum_path() {
        let qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "new");
        let map = qf.custom_tool_tip_data().expect("some tooltip data");
        assert_eq!(map.get("Datatype"), Some(&"/Category/Colors".to_string()));
    }

    #[test]
    fn object_safe_as_boxed_quick_fix_trait() {
        let mut boxed: Box<dyn QuickFix> = Box::new(UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "new"));
        assert_eq!(boxed.item_type(), "Enum Comment");
        assert_eq!(boxed.preview(), "new");
    }

    #[test]
    fn quick_fix_trait_default_navigate_special_is_false() {
        // UpdateEnumCommentQuickFix does not override navigateSpecial in Java.
        let mut qf = UpdateEnumCommentQuickFix::new(program(), enum_dt(), "RED", "new");
        assert!(!QuickFix::navigate_special(&mut qf, false));
    }
}
