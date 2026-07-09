//! Service that provides Eclipse-related functionality.
//!
//! Mirrors `ghidra.app.services.EclipseIntegrationService`.

use std::io;
use std::path::{Path, PathBuf};

use crate::app::plugin::core::eclipse::EclipseConnection;
use crate::app::seam_stubs::ToolOptions;
use crate::util::task::TaskMonitor;

/// Service that provides Eclipse-related functionality.
pub trait EclipseIntegrationService {
    /// Gets the Eclipse Integration options.
    fn get_eclipse_integration_options(&self) -> Box<dyn ToolOptions>;

    /// Gets the Eclipse executable file.
    ///
    /// Fails if the executable file does not exist.
    fn get_eclipse_executable_file(&self) -> io::Result<PathBuf>;

    /// Gets the Eclipse dropins directory, creating it if it doesn't exist.
    ///
    /// Fails if the dropins directory was not found and could not be created.
    fn get_eclipse_dropins_dir(&self) -> io::Result<PathBuf>;

    /// Gets the Eclipse workspace directory. The directory may or may not exist. Returns
    /// `None` if the workspace directory is undefined, in which case Eclipse is in control of
    /// selecting a workspace directory to use.
    fn get_eclipse_workspace_dir(&self) -> Option<PathBuf>;

    /// Checks whether a feature is installed in Eclipse, using `filter` (given a directory and
    /// file name) to match the feature file.
    ///
    /// Fails if Eclipse is not installed.
    fn is_eclipse_feature_installed(
        &self,
        filter: &dyn Fn(&Path, &str) -> bool,
    ) -> io::Result<bool>;

    /// Attempts to connect to Eclipse on the given port. This may result in Eclipse being
    /// launched. If the launch and/or connection fails, an error message will be displayed.
    /// Check the status of the returned [`EclipseConnection`] for details on the connection.
    fn connect_to_eclipse(&self, port: i32) -> EclipseConnection;

    /// Offers to install GhidraDev into Eclipse's dropins directory. `monitor` can be used to
    /// cancel the installation.
    fn offer_ghidra_dev_installation(&self, monitor: &dyn TaskMonitor);

    /// Displays the given Eclipse related error message in an error dialog.
    ///
    /// `ask_about_options` indicates whether the user should be asked if they want to be taken
    /// to the Eclipse options. `cause` is an optional error tied to the message.
    fn handle_eclipse_error(
        &self,
        error: &str,
        ask_about_options: bool,
        cause: Option<&dyn std::error::Error>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    struct MockEclipseIntegrationService {
        last_error: RefCell<Option<String>>,
    }

    impl EclipseIntegrationService for MockEclipseIntegrationService {
        fn get_eclipse_integration_options(&self) -> Box<dyn ToolOptions> {
            Box::new(StubToolOptions)
        }

        fn get_eclipse_executable_file(&self) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/opt/eclipse/eclipse"))
        }

        fn get_eclipse_dropins_dir(&self) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/opt/eclipse/dropins"))
        }

        fn get_eclipse_workspace_dir(&self) -> Option<PathBuf> {
            None
        }

        fn is_eclipse_feature_installed(
            &self,
            filter: &dyn Fn(&Path, &str) -> bool,
        ) -> io::Result<bool> {
            Ok(filter(Path::new("/opt/eclipse/features"), "GhidraDev.feature"))
        }

        fn connect_to_eclipse(&self, _port: i32) -> EclipseConnection {
            EclipseConnection::new()
        }

        fn offer_ghidra_dev_installation(&self, monitor: &dyn TaskMonitor) {
            monitor.set_message("installing GhidraDev");
        }

        fn handle_eclipse_error(
            &self,
            error: &str,
            _ask_about_options: bool,
            _cause: Option<&dyn std::error::Error>,
        ) {
            *self.last_error.borrow_mut() = Some(error.to_string());
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn EclipseIntegrationService> =
            Box::new(MockEclipseIntegrationService {
                last_error: RefCell::new(None),
            });

        assert!(service.get_eclipse_executable_file().is_ok());
        assert!(service.get_eclipse_dropins_dir().is_ok());
        assert!(service.get_eclipse_workspace_dir().is_none());
        assert!(service
            .is_eclipse_feature_installed(&|_dir, name| name == "GhidraDev.feature")
            .unwrap());

        let monitor = DummyMonitor;
        service.offer_ghidra_dev_installation(&monitor);

        service.handle_eclipse_error("boom", true, None);
    }
}
