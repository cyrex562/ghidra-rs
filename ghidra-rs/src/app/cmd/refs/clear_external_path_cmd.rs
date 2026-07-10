use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Command to clear the external program path associated with an external Library.
pub struct ClearExternalPathCmd {
    external_name: String,
    status: Option<String>,
    user_defined: bool,
}

impl ClearExternalPathCmd {
    /// Constructs a new command for clearing the external program path associated with a
    /// specified external Library.
    ///
    /// # Arguments
    ///
    /// * `external_name` - external Library name
    pub fn new(external_name: impl Into<String>) -> Self {
        ClearExternalPathCmd {
            external_name: external_name.into(),
            status: None,
            user_defined: true,
        }
    }
}

impl Command<dyn Program + 'static> for ClearExternalPathCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ext_mgr) = program.get_external_manager() else {
            self.status = Some("External manager not available".to_string());
            return false;
        };

        if ext_mgr.get_external_library(&self.external_name).is_none() {
            self.status = Some(format!("Library not found: {}", self.external_name));
            return false;
        }

        match ext_mgr.set_external_path(&self.external_name, None, self.user_defined) {
            Ok(()) => true,
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
        "Clear External Library Path".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::symbol::ExternalManager;
    use crate::program::model::listing::Library;
    use crate::util::exception::InvalidInputException;
    use std::sync::Arc;

    struct MockLibrary;

    impl crate::program::model::symbol::Namespace for MockLibrary {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    impl Library for MockLibrary {
        fn get_associated_program_path(&self) -> Option<String> {
            None
        }

        fn set_associated_program_path(
            &mut self,
            _program_path: Option<&str>,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
    }

    struct MockExternalManager {
        library_exists: bool,
        should_succeed: bool,
    }

    impl ExternalManager for MockExternalManager {
        fn get_external_library_names(&self) -> Vec<String> {
            vec![]
        }

        fn get_libraries(&self) -> Vec<Arc<dyn Library>> {
            vec![]
        }

        fn get_external_library(&self, library_name: &str) -> Option<Arc<dyn Library>> {
            if self.library_exists && library_name == "test_lib" {
                Some(Arc::new(MockLibrary))
            } else {
                None
            }
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
            if self.should_succeed {
                Ok(())
            } else {
                Err(InvalidInputException::new("Mock error"))
            }
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
            _source: crate::program::model::symbol::SourceType,
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
            _library_name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Library>, crate::program::model::symbol::AddExternalLibraryNameError>
        {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_location_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, InvalidInputException>
        {
            Err(InvalidInputException::new("Mock"))
        }

        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_function_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<crate::program::model::address::Address>,
            _source_type: crate::program::model::symbol::SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn crate::program::model::symbol::ExternalLocation>, InvalidInputException>
        {
            Err(InvalidInputException::new("Mock"))
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
        let cmd = ClearExternalPathCmd::new("kernel32");
        assert_eq!(cmd.name(), "Clear External Library Path");
    }

    #[test]
    fn apply_to_succeeds_when_library_exists() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: true,
                should_succeed: true,
            }),
        };
        let mut cmd = ClearExternalPathCmd::new("test_lib");

        let result = cmd.apply_to(&mut program);
        assert!(result);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_fails_when_library_not_found() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: false,
                should_succeed: true,
            }),
        };
        let mut cmd = ClearExternalPathCmd::new("missing_lib");

        let result = cmd.apply_to(&mut program);
        assert!(!result);
        assert_eq!(
            cmd.status_msg(),
            Some("Library not found: missing_lib".to_string())
        );
    }

    #[test]
    fn apply_to_fails_when_set_external_path_fails() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: true,
                should_succeed: false,
            }),
        };
        let mut cmd = ClearExternalPathCmd::new("test_lib");

        let result = cmd.apply_to(&mut program);
        assert!(!result);
        assert!(cmd.status_msg().is_some());
    }

    #[test]
    fn apply_to_fails_when_external_manager_not_available() {
        let mut program = MockProgram { ext_mgr: None };
        let mut cmd = ClearExternalPathCmd::new("kernel32");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("External manager not available".to_string())
        );
    }

    #[test]
    fn status_is_none_before_apply() {
        let cmd = ClearExternalPathCmd::new("kernel32");
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn constructor_stores_name_with_user_defined_true() {
        let cmd = ClearExternalPathCmd::new("test_lib");
        assert_eq!(cmd.external_name, "test_lib");
        assert!(cmd.user_defined);
    }
}
