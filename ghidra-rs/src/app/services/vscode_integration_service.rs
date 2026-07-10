//! Service that provides Visual Studio Code-related functionality.
//!
//! Mirrors `ghidra.app.services.VSCodeIntegrationService`.

use std::io;
use std::path::{Path, PathBuf};

use crate::app::seam_stubs::ToolOptions;

/// Service that provides Visual Studio Code-related functionality.
pub trait VSCodeIntegrationService {
    /// Gets the Visual Studio Code Integration options.
    fn get_vscode_integration_options(&self) -> Box<dyn ToolOptions>;

    /// Gets the Visual Studio Code executable file.
    ///
    /// Fails if the executable file does not exist.
    fn get_vscode_executable_file(&self) -> io::Result<PathBuf>;

    /// Launches Visual Studio Code with `file` as the initial file to open.
    fn launch_vscode(&self, file: &Path);

    /// Displays the given Visual Studio Code related error message in an error dialog.
    ///
    /// `ask_about_options` indicates whether the user should be asked if they want to be taken
    /// to the Visual Studio Code options. `cause` is an optional error tied to the message.
    fn handle_vscode_error(
        &self,
        error: &str,
        ask_about_options: bool,
        cause: Option<&dyn std::error::Error>,
    );

    /// Creates a new Visual Studio Code module project at `project_dir`.
    ///
    /// Fails if the directory failed to be created.
    fn create_vscode_module_project(&self, project_dir: &Path) -> io::Result<()>;

    /// Adds `project_dir` to the Visual Studio Code workspace file at `workspace_file`. A new
    /// workspace will be created if it doesn't already exist.
    ///
    /// Fails if the directory failed to be created.
    fn add_to_vscode_workspace(&self, workspace_file: &Path, project_dir: &Path) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    struct MockVSCodeIntegrationService {
        last_error: RefCell<Option<String>>,
    }

    impl VSCodeIntegrationService for MockVSCodeIntegrationService {
        fn get_vscode_integration_options(&self) -> Box<dyn ToolOptions> {
            Box::new(StubToolOptions)
        }

        fn get_vscode_executable_file(&self) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/usr/bin/code"))
        }

        fn launch_vscode(&self, _file: &Path) {}

        fn handle_vscode_error(
            &self,
            error: &str,
            _ask_about_options: bool,
            _cause: Option<&dyn std::error::Error>,
        ) {
            *self.last_error.borrow_mut() = Some(error.to_string());
        }

        fn create_vscode_module_project(&self, _project_dir: &Path) -> io::Result<()> {
            Ok(())
        }

        fn add_to_vscode_workspace(
            &self,
            _workspace_file: &Path,
            _project_dir: &Path,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn VSCodeIntegrationService> =
            Box::new(MockVSCodeIntegrationService {
                last_error: RefCell::new(None),
            });

        assert!(service.get_vscode_executable_file().is_ok());
        service.launch_vscode(Path::new("/tmp/foo.rs"));
        service.handle_vscode_error("boom", true, None);
        assert!(service
            .create_vscode_module_project(Path::new("/tmp/proj"))
            .is_ok());
        assert!(service
            .add_to_vscode_workspace(Path::new("/tmp/ws.code-workspace"), Path::new("/tmp/proj"))
            .is_ok());
    }
}
