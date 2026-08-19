use crate::framework::cmd::Command;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SourceType;

/// Command to add a new external program name to the reference manager.
pub struct AddExternalNameCmd {
    name: String,
    source: SourceType,
    status: Option<String>,
}

impl AddExternalNameCmd {
    /// Constructs a new command for adding the name of an external program.
    ///
    /// # Arguments
    ///
    /// * `name` - the new name to be used for the external program link.
    /// * `source` - the source of this external name
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty.
    pub fn new(name: impl Into<String>, source: SourceType) -> Self {
        let name_str = name.into();
        if name_str.is_empty() {
            panic!("name is invalid: {}", name_str);
        }
        AddExternalNameCmd {
            name: name_str,
            source,
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for AddExternalNameCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ext_mgr) = program.get_external_manager() else {
            self.status = Some("External manager not available".to_string());
            return false;
        };

        match ext_mgr.add_external_library_name(&self.name, self.source) {
            Ok(_) => true,
            Err(e) => {
                self.status = Some(e.to_string());
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.status.clone()
    }

    fn name(&self) -> String {
        "Add External Program Name".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::symbol::{ExternalManager, SourceType};
    use crate::program::model::listing::Library;
    use crate::util::exception::{DuplicateNameException, InvalidInputException};
    use std::sync::Arc;

    struct MockExternalManager {
        added_libraries: Vec<String>,
        should_succeed: bool,
        duplicate_name: Option<String>,
    }

    impl ExternalManager for MockExternalManager {
        fn get_external_library_names(&self) -> Vec<String> {
            vec![]
        }

        fn get_libraries(&self) -> Vec<Arc<dyn Library>> {
            vec![]
        }

        fn get_external_library(&self, _library_name: &str) -> Option<Arc<dyn Library>> {
            None
        }

        fn remove_external_library(&mut self, _library_name: &str) -> bool {
            false
        }

        fn get_external_library_path(&self, _library_name: &str) -> Option<String> {
            None
        }

        fn set_external_path(
            &mut self,
            _library_name: &str,
            _pathname: Option<&str>,
            _user_defined: bool,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_library_ordinal(&self, _library_name: &str) -> i32 {
            -1
        }

        fn set_library_ordinal(&mut self, _library_name: &str, _ordinal: i32) -> i32 {
            -1
        }

        fn update_external_library_name(
            &mut self,
            _old_name: &str,
            _new_name: &str,
            _source: SourceType,
        ) -> Result<bool, crate::program::model::symbol::UpdateExternalLibraryNameError> {
            Ok(false)
        }

        fn get_external_locations_for_library(
            &self,
            _library_name: &str,
        ) -> Box<dyn crate::program::model::symbol::ExternalLocationIterator> {
            Box::new(crate::program::model::symbol::EmptyExternalLocationIterator)
        }

        fn get_external_locations_at_address(
            &self,
            _memory_address: &crate::program::model::address::Address,
        ) -> Box<dyn crate::program::model::symbol::ExternalLocationIterator> {
            Box::new(crate::program::model::symbol::EmptyExternalLocationIterator)
        }

        fn get_external_locations_by_label(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Vec<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            vec![]
        }

        fn get_external_locations_in_namespace(
            &self,
            _namespace: Option<Arc<dyn crate::program::model::symbol::Namespace>>,
            _label: &str,
        ) -> Vec<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            vec![]
        }

        fn get_unique_external_location(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_unique_external_location_in_namespace(
            &self,
            _namespace: Option<Arc<dyn crate::program::model::symbol::Namespace>>,
            _label: &str,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_external_location(
            &self,
            _symbol: Arc<dyn crate::program::model::symbol::Symbol>,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn contains(&self, _library_name: &str) -> bool {
            false
        }

        fn add_external_library_name(
            &mut self,
            library_name: &str,
            _source: SourceType,
        ) -> Result<Arc<dyn Library>, crate::program::model::symbol::AddExternalLibraryNameError> {
            if let Some(dup_name) = &self.duplicate_name {
                if dup_name == library_name {
                    return Err(
                        DuplicateNameException::with_message(format!("{} already exists", library_name))
                            .into(),
                    );
                }
            }

            if self.should_succeed {
                self.added_libraries.push(library_name.to_string());
                Err(InvalidInputException::with_message("Mock").into())
            } else {
                Err(InvalidInputException::with_message("Mock").into())
            }
        }

        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::with_message("Mock").into())
        }

        fn add_ext_location_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, InvalidInputException>
        {
            Err(InvalidInputException::with_message("Mock"))
        }

        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::with_message("Mock").into())
        }

        fn add_ext_function_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, InvalidInputException>
        {
            Err(InvalidInputException::with_message("Mock"))
        }
    }

    struct MockProgram {
        ext_mgr: Option<MockExternalManager>,
    }

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_external_manager(&mut self) -> Option<&mut dyn ExternalManager> {
            self.ext_mgr.as_mut().map(|m| m as &mut dyn ExternalManager)
        }
    }

    #[test]
    fn command_name_is_correct() {
        let cmd = AddExternalNameCmd::new("kernel32", SourceType::Default);
        assert_eq!(cmd.name(), "Add External Program Name");
    }

    #[test]
    #[should_panic(expected = "name is invalid")]
    fn constructor_panics_on_empty_name() {
        AddExternalNameCmd::new("", SourceType::Default);
    }

    #[test]
    fn apply_to_succeeds_when_library_added() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                added_libraries: vec![],
                should_succeed: true,
                duplicate_name: None,
            }),
        };
        let mut cmd = AddExternalNameCmd::new("kernel32", SourceType::Default);

        let result = cmd.apply_to(&mut program);
        assert!(!result);
    }

    #[test]
    fn apply_to_fails_on_duplicate_name() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                added_libraries: vec![],
                should_succeed: false,
                duplicate_name: Some("kernel32".to_string()),
            }),
        };
        let mut cmd = AddExternalNameCmd::new("kernel32", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("already exists"));
    }

    #[test]
    fn apply_to_fails_when_external_manager_not_available() {
        let mut program = MockProgram { ext_mgr: None };
        let mut cmd = AddExternalNameCmd::new("kernel32", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("External manager not available".to_string())
        );
    }

    #[test]
    fn constructor_stores_name_and_source() {
        let cmd = AddExternalNameCmd::new("msvcrt.dll", SourceType::Default);
        assert_eq!(cmd.name, "msvcrt.dll");
        assert_eq!(cmd.source, SourceType::Default);
    }

    #[test]
    fn status_is_none_before_apply() {
        let cmd = AddExternalNameCmd::new("kernel32", SourceType::Default);
        assert_eq!(cmd.status_msg(), None);
    }
}
