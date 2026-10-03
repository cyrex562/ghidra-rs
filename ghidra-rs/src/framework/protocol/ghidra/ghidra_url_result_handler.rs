use std::io;

use crate::framework::model::{DomainFile, DomainFolder};
use crate::util::task::TaskMonitor;

/// Handler for processing Ghidra URL query results.
///
/// Port of `ghidra.framework.protocol.ghidra.GhidraURLResultHandler`.
pub trait GhidraURLResultHandler {
    /// Process the specified domain file query result.
    ///
    /// Dissemination of the `domain_file` instance should be restricted and any use of it
    /// completed before the call to this method returns. Upon return from this method call
    /// the underlying connection will be closed and at which time the `domain_file` instance
    /// will become invalid.
    ///
    /// # Arguments
    ///
    /// * `domain_file` - The domain file to which the URL refers
    /// * `url` - URL which was used to retrieve the specified `domain_file`
    /// * `monitor` - Task monitor for progress tracking
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if an IO error occurs, or `CancelledException` if task is cancelled.
    fn process_result_file(
        &mut self,
        domain_file: &dyn DomainFile,
        url: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Process the specified domain folder query result.
    ///
    /// Dissemination of the `domain_folder` instance should be restricted and any use of it
    /// completed before the call to this method returns. Upon return from this method call
    /// the underlying connection will be closed and at which time the `domain_folder` instance
    /// will become invalid.
    ///
    /// # Arguments
    ///
    /// * `domain_folder` - The domain folder to which the URL refers
    /// * `url` - URL which was used to retrieve the specified `domain_folder`
    /// * `monitor` - Task monitor for progress tracking
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if an IO error occurs, or `CancelledException` if task is cancelled.
    fn process_result_folder(
        &mut self,
        domain_folder: &dyn DomainFolder,
        url: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Handle error which occurs during query operation.
    ///
    /// # Arguments
    ///
    /// * `title` - Error title
    /// * `message` - Error detail
    /// * `url` - URL which was used for query
    /// * `cause` - Cause of error (may be None)
    ///
    /// # Errors
    ///
    /// May throw `io::Error` if handler decides to propagate error.
    fn handle_error(
        &mut self,
        title: &str,
        message: &str,
        url: &str,
        cause: Option<io::Error>,
    ) -> Result<(), io::Error>;

    /// Handle authorization error.
    ///
    /// This condition is generally logged and user notified via GUI during connection processing.
    /// This method does not do anything by default but is provided to flag failure if needed
    /// since `handle_error()` will not be invoked.
    ///
    /// # Arguments
    ///
    /// * `url` - Connection URL
    ///
    /// # Errors
    ///
    /// May throw `io::Error` if handler decides to propagate error.
    fn handle_unauthorized_access(&mut self, _url: &str) -> Result<(), io::Error> {
        Ok(())
    }

    /// Handle an external link URL which is not followed.
    ///
    /// # Arguments
    ///
    /// * `url` - Connection URL
    ///
    /// # Errors
    ///
    /// May throw `io::Error` if handler decides to propagate error.
    fn external_link_ignored(&mut self, _url: &str) -> Result<(), io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainFile {
        name: String,
    }

    impl DomainFile for MockDomainFile {}

    struct MockDomainFolder {
        path: String,
    }

    impl DomainFolder for MockDomainFolder {}

    struct TestHandler {
        file_processed: bool,
        folder_processed: bool,
        error_handled: bool,
        unauthorized_handled: bool,
        external_link_handled: bool,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                file_processed: false,
                folder_processed: false,
                error_handled: false,
                unauthorized_handled: false,
                external_link_handled: false,
            }
        }
    }

    impl GhidraURLResultHandler for TestHandler {
        fn process_result_file(
            &mut self,
            _domain_file: &dyn DomainFile,
            _url: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.file_processed = true;
            Ok(())
        }

        fn process_result_folder(
            &mut self,
            _domain_folder: &dyn DomainFolder,
            _url: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.folder_processed = true;
            Ok(())
        }

        fn handle_error(
            &mut self,
            _title: &str,
            _message: &str,
            _url: &str,
            _cause: Option<io::Error>,
        ) -> Result<(), io::Error> {
            self.error_handled = true;
            Ok(())
        }

        fn handle_unauthorized_access(&mut self, _url: &str) -> Result<(), io::Error> {
            self.unauthorized_handled = true;
            Ok(())
        }

        fn external_link_ignored(&mut self, _url: &str) -> Result<(), io::Error> {
            self.external_link_handled = true;
            Ok(())
        }
    }

    #[test]
    fn process_result_file_called() {
        let mut handler = TestHandler::new();
        let file = MockDomainFile {
            name: "test.bin".to_string(),
        };
        let monitor = crate::util::task::DummyMonitor;

        let result = handler.process_result_file(&file, "ghidra://localhost/file", &monitor);
        assert!(result.is_ok());
        assert!(handler.file_processed);
    }

    #[test]
    fn process_result_folder_called() {
        let mut handler = TestHandler::new();
        let folder = MockDomainFolder {
            path: "/projects".to_string(),
        };
        let monitor = crate::util::task::DummyMonitor;

        let result = handler.process_result_folder(&folder, "ghidra://localhost/folder", &monitor);
        assert!(result.is_ok());
        assert!(handler.folder_processed);
    }

    #[test]
    fn handle_error_called() {
        let mut handler = TestHandler::new();
        let result = handler.handle_error(
            "Connection Error",
            "Failed to connect to server",
            "ghidra://localhost/project",
            None,
        );
        assert!(result.is_ok());
        assert!(handler.error_handled);
    }

    #[test]
    fn handle_error_with_cause() {
        let mut handler = TestHandler::new();
        let cause = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let result = handler.handle_error(
            "Network Error",
            "Connection failed",
            "ghidra://host/repo",
            Some(cause),
        );
        assert!(result.is_ok());
        assert!(handler.error_handled);
    }

    #[test]
    fn handle_unauthorized_access_default_implementation() {
        let mut handler = TestHandler::new();
        let result = handler.handle_unauthorized_access("ghidra://localhost/private");
        assert!(result.is_ok());
        assert!(handler.unauthorized_handled);
    }

    #[test]
    fn external_link_ignored_default_implementation() {
        let mut handler = TestHandler::new();
        let result = handler.external_link_ignored("https://external.com");
        assert!(result.is_ok());
        assert!(handler.external_link_handled);
    }

    #[test]
    fn multiple_calls_in_sequence() {
        let mut handler = TestHandler::new();
        let file = MockDomainFile {
            name: "file.bin".to_string(),
        };
        let folder = MockDomainFolder {
            path: "/path".to_string(),
        };
        let monitor = crate::util::task::DummyMonitor;

        handler
            .process_result_file(&file, "ghidra://host/file", &monitor)
            .unwrap();
        assert!(handler.file_processed);

        handler
            .process_result_folder(&folder, "ghidra://host/folder", &monitor)
            .unwrap();
        assert!(handler.folder_processed);

        handler
            .handle_unauthorized_access("ghidra://host/private")
            .unwrap();
        assert!(handler.unauthorized_handled);

        handler
            .external_link_ignored("https://external.com")
            .unwrap();
        assert!(handler.external_link_handled);
    }
}
