use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Command to remove an external program name from the reference manager.
pub struct RemoveExternalNameCmd {
    external_name: String,
    status: Option<String>,
}

impl RemoveExternalNameCmd {
    /// Constructs a new command removing an external program name.
    ///
    /// # Arguments
    ///
    /// * `external_name` - the name of the external program name to be removed.
    pub fn new(external_name: impl Into<String>) -> Self {
        RemoveExternalNameCmd {
            external_name: external_name.into(),
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for RemoveExternalNameCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ext_mgr) = program.get_external_manager() else {
            self.status = Some("External manager not available".to_string());
            return false;
        };

        if !ext_mgr.remove_external_library(&self.external_name) {
            self.status = Some(format!("{} can not be removed", self.external_name));
            return false;
        }

        true
    }

    fn status_msg(&self) -> Option<String> {
        self.status.clone()
    }

    fn name(&self) -> String {
        "Remove External Program Name".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::symbol::{ExternalManager, SourceType};
    use crate::program::model::listing::Library;
    use std::sync::Arc;

    struct MockExternalManager {
        removed_libraries: Vec<String>,
        should_succeed: bool,
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

        fn remove_external_library(&mut self, library_name: &str) -> bool {
            if self.should_succeed {
                self.removed_libraries.push(library_name.to_string());
                true
            } else {
                false
            }
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
        let cmd = RemoveExternalNameCmd::new("kernel32");
        assert_eq!(cmd.name(), "Remove External Program Name");
    }

    #[test]
    fn apply_to_succeeds_when_library_removed() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                removed_libraries: vec![],
                should_succeed: true,
            }),
        };
        let mut cmd = RemoveExternalNameCmd::new("kernel32");

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        assert_eq!(
            program.ext_mgr.as_ref().unwrap().removed_libraries,
            vec!["kernel32"]
        );
    }

    #[test]
    fn apply_to_fails_when_library_cannot_be_removed() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                removed_libraries: vec![],
                should_succeed: false,
            }),
        };
        let mut cmd = RemoveExternalNameCmd::new("kernel32");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("kernel32 can not be removed".to_string())
        );
    }

    #[test]
    fn apply_to_fails_when_external_manager_not_available() {
        let mut program = MockProgram { ext_mgr: None };
        let mut cmd = RemoveExternalNameCmd::new("kernel32");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("External manager not available".to_string())
        );
    }

    #[test]
    fn constructor_stores_library_name() {
        let cmd = RemoveExternalNameCmd::new("msvcrt.dll");
        assert_eq!(cmd.external_name, "msvcrt.dll");
    }
}
