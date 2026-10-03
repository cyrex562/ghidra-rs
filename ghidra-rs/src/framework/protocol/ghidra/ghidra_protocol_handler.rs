use std::io;

use crate::framework::protocol::ghidra::GhidraProtocolConnector;
use crate::util::classfinder::ExtensionPoint;

/// Provides the extension point for Ghidra protocol extensions. A Ghidra protocol extension will
/// be identified within by the optional `extProtocolName` appearing within a Ghidra URL:
/// `ghidra:[<extProtocolName>:]/...` In the absence of a protocol extension the default protocol
/// handler will be used (see
/// [`DefaultGhidraProtocolHandler`](crate::framework::protocol::ghidra::DefaultGhidraProtocolHandler),
/// which -- being the sole concrete subclass and itself a separate cycle cut-point -- is ported as
/// its own flattened trait rather than as an implementor of this one).
///
/// Port of `ghidra.framework.protocol.ghidra.GhidraProtocolHandler`, an abstract class
/// implementing the marker interface `ExtensionPoint`.
///
/// Selected as a dependency-cycle cut-point, so every method here takes `&self` and returns
/// owned/boxed values, matching the convention used elsewhere in this crate for cut-point traits
/// (e.g. [`GhidraProtocolConnector`], [`DefaultGhidraProtocolHandler`](crate::framework::protocol::ghidra::DefaultGhidraProtocolHandler)).
pub trait GhidraProtocolHandler: ExtensionPoint {
    /// Determine if this protocol handler is responsible for handling the specified named
    /// protocol extension. One handler may support multiple protocol extension names (e.g. http
    /// and https). Mirrors `isExtensionSupported(String)`.
    fn is_extension_supported(&self, ext_protocol_name: &str) -> bool;

    /// Get the Ghidra protocol connector for a Ghidra URL which requires this extension. Mirrors
    /// `getConnector(URL)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` is invalid,
    /// mirroring `MalformedURLException`.
    fn get_connector(&self, ghidra_url: &str) -> io::Result<Box<dyn GhidraProtocolConnector>>;
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::framework::client::{NotConnectedException, RepositoryAdapter, RepositoryServerAdapter};
    use crate::framework::protocol::ghidra::{GhidraProtocolConnector, StatusCode};
    use crate::util::classfinder::ExtensionPoint;

    use super::*;

    struct MockHttpConnector(String);

    impl GhidraProtocolConnector for MockHttpConnector {
        fn get_repository_root_ghidra_url(&self) -> Option<String> {
            None
        }
        fn get_repository_name(&self) -> Option<String> {
            None
        }
        fn get_folder_path(&self) -> Option<String> {
            Some(self.0.clone())
        }
        fn get_folder_item_name(&self) -> Option<String> {
            None
        }
        fn get_status_code(&self) -> Option<StatusCode> {
            None
        }
        fn get_repository_adapter(&self) -> Option<Box<dyn RepositoryAdapter>> {
            None
        }
        fn get_repository_server_adapter(&self) -> Option<Box<dyn RepositoryServerAdapter>> {
            None
        }
        fn connect(&self, _read_only: bool) -> io::Result<StatusCode> {
            Ok(StatusCode::Ok)
        }
        fn connect_to_repository(&self, _repository: Box<dyn RepositoryAdapter>) -> io::Result<()> {
            Ok(())
        }
        fn is_read_only(&self) -> Result<bool, NotConnectedException> {
            Ok(true)
        }
    }

    /// Mock extension supporting `http` and `https`, mirroring the doc comment's example of one
    /// handler supporting multiple protocol extension names.
    struct MockHttpProtocolHandler;

    impl ExtensionPoint for MockHttpProtocolHandler {}

    impl GhidraProtocolHandler for MockHttpProtocolHandler {
        fn is_extension_supported(&self, ext_protocol_name: &str) -> bool {
            matches!(ext_protocol_name, "http" | "https")
        }

        fn get_connector(&self, ghidra_url: &str) -> io::Result<Box<dyn GhidraProtocolConnector>> {
            let rest = ghidra_url.strip_prefix("ghidra:http:").or_else(|| {
                ghidra_url.strip_prefix("ghidra:https:")
            }).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported URL form for ghidra protocol: {ghidra_url}"),
                )
            })?;
            Ok(Box::new(MockHttpConnector(rest.to_string())))
        }
    }

    #[test]
    fn is_extension_supported_matches_registered_names_only() {
        let handler = MockHttpProtocolHandler;
        let dyn_handler: &dyn GhidraProtocolHandler = &handler;

        assert!(dyn_handler.is_extension_supported("http"));
        assert!(dyn_handler.is_extension_supported("https"));
        assert!(!dyn_handler.is_extension_supported("ftp"));
    }

    #[test]
    fn get_connector_parses_supported_url_and_rejects_others() {
        let handler = MockHttpProtocolHandler;
        let dyn_handler: &dyn GhidraProtocolHandler = &handler;

        let connector = dyn_handler.get_connector("ghidra:http://example.com/repo").unwrap();
        assert_eq!(connector.get_folder_path().as_deref(), Some("//example.com/repo"));

        match dyn_handler.get_connector("ghidra:/local/path") {
            Ok(_) => panic!("expected malformed URL error for unsupported extension"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }
}
