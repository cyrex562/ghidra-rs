use crate::framework::cmd::Command;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SourceType;

/// Command for setting the external program name and path.
///
/// If the named external Library does not already exist it is created first, using the
/// configured `source`.
pub struct SetExternalNameCmd {
    external_name: String,
    external_path: String,
    source: SourceType,
    status: Option<String>,
}

impl SetExternalNameCmd {
    /// Constructs a new command for creating a Library, if it does not exist, and setting the
    /// associated external program path. If created, a [`SourceType::UserDefined`] source will
    /// be specified.
    ///
    /// # Arguments
    ///
    /// * `external_name` - the Library name.
    /// * `external_path` - the project file path of the program file to associate with the
    ///   Library.
    pub fn new(external_name: impl Into<String>, external_path: impl Into<String>) -> Self {
        Self::with_source(external_name, external_path, SourceType::UserDefined)
    }

    /// Constructs a new command for creating a Library, if it does not exist, and setting the
    /// associated external program path.
    ///
    /// # Arguments
    ///
    /// * `external_name` - the Library name.
    /// * `external_path` - the project file path of the program file to associate with the
    ///   Library.
    /// * `source` - the symbol source type to be applied if the library must be created.
    pub fn with_source(
        external_name: impl Into<String>,
        external_path: impl Into<String>,
        source: SourceType,
    ) -> Self {
        SetExternalNameCmd {
            external_name: external_name.into(),
            external_path: external_path.into(),
            source,
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for SetExternalNameCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ext_mgr) = program.get_external_manager() else {
            self.status = Some("External manager not available".to_string());
            return false;
        };

        if ext_mgr.get_external_library(&self.external_name).is_none() {
            if let Err(e) = ext_mgr.add_external_library_name(&self.external_name, self.source) {
                self.status = Some(e.to_string());
                return false;
            }
        }

        match ext_mgr.set_external_path(
            &self.external_name,
            Some(&self.external_path),
            self.source == SourceType::UserDefined,
        ) {
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
        "Set External Library Name and Path".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::Library;
    use crate::program::model::symbol::ExternalManager;
    use crate::util::exception::InvalidInputException;
    use std::sync::Arc;

    struct MockLibrary;

    impl Library for MockLibrary {
        fn get_name(&self) -> String {
            "test_lib".to_string()
        }
    }

    struct MockExternalManager {
        library_exists: bool,
        added_libraries: Vec<(String, SourceType)>,
        set_paths: Vec<(String, Option<String>, bool)>,
        add_should_fail: bool,
        set_path_should_fail: bool,
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
            library_name: &str,
            pathname: Option<&str>,
            user_defined: bool,
        ) -> Result<(), InvalidInputException> {
            if self.set_path_should_fail {
                return Err(InvalidInputException::new("bad path"));
            }
            self.set_paths.push((
                library_name.to_string(),
                pathname.map(|p| p.to_string()),
                user_defined,
            ));
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

        fn get_external_location_for_label_in_library(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_external_location_at_address(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn add_external_library_name(
            &mut self,
            library_name: &str,
            source: SourceType,
        ) -> Result<Arc<dyn Library>, crate::program::model::symbol::AddExternalLibraryNameError>
        {
            if self.add_should_fail {
                return Err(InvalidInputException::new("cannot add").into());
            }
            self.added_libraries
                .push((library_name.to_string(), source));
            self.library_exists = true;
            Ok(Arc::new(MockLibrary))
        }

        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _label: Option<&str>,
            _address: Option<&crate::program::model::address::Address>,
            _source: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_location_in_library_reuse(
            &mut self,
            _library_name: &str,
            _label: Option<&str>,
            _address: Option<&crate::program::model::address::Address>,
            _source: SourceType,
            _reuse_existing: bool,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _label: Option<&str>,
            _address: Option<&crate::program::model::address::Address>,
            _source: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn add_ext_function_in_library_reuse(
            &mut self,
            _library_name: &str,
            _label: Option<&str>,
            _address: Option<&crate::program::model::address::Address>,
            _source: SourceType,
            _reuse_existing: bool,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::ExternalLocation>,
            crate::program::model::symbol::AddExternalLocationInLibraryError,
        > {
            Err(InvalidInputException::new("Mock").into())
        }

        fn remove_external_location(
            &mut self,
            _location: Arc<dyn crate::program::model::symbol::ExternalLocation>,
        ) {
        }

        fn contains_external_location(
            &self,
            _location: &dyn crate::program::model::symbol::ExternalLocation,
        ) -> bool {
            false
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
        let cmd = SetExternalNameCmd::new("kernel32", "/External/kernel32.dll");
        assert_eq!(cmd.name(), "Set External Library Name and Path");
    }

    #[test]
    fn default_constructor_uses_user_defined_source() {
        let cmd = SetExternalNameCmd::new("kernel32", "/External/kernel32.dll");
        assert_eq!(cmd.source, SourceType::UserDefined);
    }

    #[test]
    fn apply_to_creates_library_when_missing_and_sets_path() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: false,
                added_libraries: vec![],
                set_paths: vec![],
                add_should_fail: false,
                set_path_should_fail: false,
            }),
        };
        let mut cmd = SetExternalNameCmd::with_source(
            "test_lib",
            "/External/test_lib.dll",
            SourceType::UserDefined,
        );

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        let ext_mgr = program.ext_mgr.as_ref().unwrap();
        assert_eq!(
            ext_mgr.added_libraries,
            vec![("test_lib".to_string(), SourceType::UserDefined)]
        );
        assert_eq!(
            ext_mgr.set_paths,
            vec![(
                "test_lib".to_string(),
                Some("/External/test_lib.dll".to_string()),
                true
            )]
        );
    }

    #[test]
    fn apply_to_skips_add_when_library_already_exists() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: true,
                added_libraries: vec![],
                set_paths: vec![],
                add_should_fail: false,
                set_path_should_fail: false,
            }),
        };
        let mut cmd =
            SetExternalNameCmd::new("test_lib", "/External/test_lib.dll");

        assert!(cmd.apply_to(&mut program));
        let ext_mgr = program.ext_mgr.as_ref().unwrap();
        assert!(ext_mgr.added_libraries.is_empty());
        assert_eq!(ext_mgr.set_paths.len(), 1);
    }

    #[test]
    fn apply_to_fails_when_add_fails() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: false,
                added_libraries: vec![],
                set_paths: vec![],
                add_should_fail: true,
                set_path_should_fail: false,
            }),
        };
        let mut cmd = SetExternalNameCmd::new("test_lib", "/External/test_lib.dll");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("cannot add".to_string()));
        assert!(program.ext_mgr.as_ref().unwrap().set_paths.is_empty());
    }

    #[test]
    fn apply_to_fails_when_set_path_fails() {
        let mut program = MockProgram {
            ext_mgr: Some(MockExternalManager {
                library_exists: true,
                added_libraries: vec![],
                set_paths: vec![],
                add_should_fail: false,
                set_path_should_fail: true,
            }),
        };
        let mut cmd = SetExternalNameCmd::new("test_lib", "/External/test_lib.dll");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("bad path".to_string()));
    }

    #[test]
    fn apply_to_fails_when_external_manager_not_available() {
        let mut program = MockProgram { ext_mgr: None };
        let mut cmd = SetExternalNameCmd::new("kernel32", "/External/kernel32.dll");

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("External manager not available".to_string())
        );
    }

    #[test]
    fn constructor_stores_name_and_path() {
        let cmd = SetExternalNameCmd::new("msvcrt.dll", "/External/msvcrt.dll");
        assert_eq!(cmd.external_name, "msvcrt.dll");
        assert_eq!(cmd.external_path, "/External/msvcrt.dll");
    }
}
