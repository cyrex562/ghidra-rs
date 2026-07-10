use crate::framework::cmd::Command;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SourceType;

/// Command to update the name for an external program.
pub struct UpdateExternalNameCmd {
    old_name: String,
    new_name: String,
    source: SourceType,
    status: Option<String>,
}

impl UpdateExternalNameCmd {
    /// Constructs a new command for updating the name of an external program.
    ///
    /// # Arguments
    ///
    /// * `old_name` - the current name of the external program link.
    /// * `new_name` - the new name to be used for the external program link.
    /// * `source` - the source of this external name
    ///
    /// # Panics
    ///
    /// Panics if `new_name` is empty.
    pub fn new(old_name: impl Into<String>, new_name: impl Into<String>, source: SourceType) -> Self {
        let new_name_str = new_name.into();
        if new_name_str.is_empty() {
            panic!("newName is invalid");
        }
        UpdateExternalNameCmd {
            old_name: old_name.into(),
            new_name: new_name_str,
            source,
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for UpdateExternalNameCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ext_mgr) = program.get_external_manager() else {
            self.status = Some("External manager not available".to_string());
            return false;
        };

        match ext_mgr.update_external_library_name(&self.old_name, &self.new_name, self.source) {
            Ok(true) => true,
            Ok(false) => {
                self.status = Some(format!("{} not found", self.old_name));
                false
            }
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
        "Update External Program Name".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::symbol::{ExternalManager, SourceType, UpdateExternalLibraryNameError};
    use crate::program::model::listing::Library;
    use crate::util::exception::{DuplicateNameException, InvalidInputException};
    use std::sync::Arc;

    struct MockExternalManager {
        updated_names: Vec<(String, String)>,
        should_succeed: bool,
        return_duplicate: bool,
        return_invalid: bool,
    }

    impl ExternalManager for MockExternalManager {
        fn get_external_library_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_libraries(&self) -> Vec<Arc<dyn crate::program::model::listing::Library>> {
            Vec::new()
        }

        fn get_external_library(&self, _library_name: &str) -> Option<Arc<dyn crate::program::model::listing::Library>> {
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
        ) -> Result<(), crate::util::exception::InvalidInputException> {
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
            old_name: &str,
            new_name: &str,
            _source: SourceType,
        ) -> Result<bool, UpdateExternalLibraryNameError> {
            if self.return_duplicate {
                return Err(DuplicateNameException::with_message(format!("{} already exists", new_name)).into());
            }
            if self.return_invalid {
                return Err(InvalidInputException::with_message("Invalid name").into());
            }
            if self.should_succeed {
                self.updated_names.push((old_name.to_string(), new_name.to_string()));
                Ok(true)
            } else {
                Ok(false)
            }
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
            Vec::new()
        }

        fn get_external_locations_in_namespace(
            &self,
            _namespace: Option<Arc<dyn crate::program::model::symbol::Namespace>>,
            _label: &str,
        ) -> Vec<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            Vec::new()
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
            _library_name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::listing::Library>, crate::program::model::symbol::AddExternalLibraryNameError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, crate::program::model::symbol::AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_location_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, crate::util::exception::InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, crate::program::model::symbol::AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_function_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, crate::util::exception::InvalidInputException> {
            unimplemented!("not needed for this smoke test")
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
        let cmd = UpdateExternalNameCmd::new("kernel32", "kernel64", SourceType::Default);
        assert_eq!(cmd.name(), "Update External Program Name");
    }

    #[test]
    fn apply_to_succeeds_when_library_renamed() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                updated_names: vec![],
                should_succeed: true,
                return_duplicate: false,
                return_invalid: false,
            }),
        };
        let mut cmd = UpdateExternalNameCmd::new("kernel32", "kernel64", SourceType::Default);

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        assert_eq!(
            program.ext_mgr.as_ref().unwrap().updated_names,
            vec![("kernel32".to_string(), "kernel64".to_string())]
        );
    }

    #[test]
    fn apply_to_fails_when_old_name_not_found() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                updated_names: vec![],
                should_succeed: false,
                return_duplicate: false,
                return_invalid: false,
            }),
        };
        let mut cmd = UpdateExternalNameCmd::new("nonexistent", "newname", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("nonexistent not found".to_string()));
    }

    #[test]
    fn apply_to_fails_when_duplicate_name() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                updated_names: vec![],
                should_succeed: false,
                return_duplicate: true,
                return_invalid: false,
            }),
        };
        let mut cmd = UpdateExternalNameCmd::new("kernel32", "existing_lib", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("already exists"));
    }

    #[test]
    fn apply_to_fails_with_invalid_input() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                updated_names: vec![],
                should_succeed: false,
                return_duplicate: false,
                return_invalid: true,
            }),
        };
        let mut cmd = UpdateExternalNameCmd::new("kernel32", "new64", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("Invalid name".to_string()));
    }

    #[test]
    fn apply_to_fails_when_external_manager_not_available() {
        let mut program = MockProgram { ext_mgr: None };
        let mut cmd = UpdateExternalNameCmd::new("kernel32", "kernel64", SourceType::Default);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("External manager not available".to_string())
        );
    }

    #[test]
    fn constructor_stores_names() {
        let cmd = UpdateExternalNameCmd::new("old_name", "new_name", SourceType::Default);
        assert_eq!(cmd.old_name, "old_name");
        assert_eq!(cmd.new_name, "new_name");
    }

    #[test]
    #[should_panic(expected = "newName is invalid")]
    fn constructor_panics_on_empty_new_name() {
        UpdateExternalNameCmd::new("kernel32", "", SourceType::Default);
    }
}
