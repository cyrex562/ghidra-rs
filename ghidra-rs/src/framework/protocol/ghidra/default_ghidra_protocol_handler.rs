use std::io;

use crate::framework::protocol::ghidra::GhidraProtocolConnector;

/// Provides the default protocol handler which corresponds to the original RMI-based Ghidra
/// Server and local file-based Ghidra projects: `ghidra://host/repo/...` or
/// `ghidra:/path/projectName/...`.
///
/// Port of `ghidra.framework.protocol.ghidra.DefaultGhidraProtocolHandler`, a concrete subclass
/// of the abstract extension point `ghidra.framework.protocol.ghidra.GhidraProtocolHandler`
/// (not yet ported). Selected as a dependency-cycle cut-point, so this concrete class is
/// represented as a trait matching its own flattened public API (its two `@Override`s of
/// `GhidraProtocolHandler`'s abstract methods) rather than as a struct implementing a separately
/// ported `GhidraProtocolHandler` trait; every method here takes `&self`, matching the convention
/// used elsewhere in this crate for cut-point traits (e.g.
/// [`GhidraProtocolConnector`](crate::framework::protocol::ghidra::GhidraProtocolConnector),
/// [`GhidraURLConnection`](crate::framework::protocol::ghidra::GhidraURLConnection)).
///
/// See also `DefaultGhidraProtocolConnector` and `DefaultLocalGhidraProtocolConnector` (neither
/// yet ported), the two concrete [`GhidraProtocolConnector`] implementations
/// [`get_connector`](Self::get_connector) chooses between based on whether the URL's authority
/// (host) component is blank.
pub trait DefaultGhidraProtocolHandler {
    /// Determine if this protocol handler is responsible for handling the specified named
    /// protocol extension. Mirrors `isExtensionSupported(String)`, which this default handler
    /// implements to only ever support the *absence* of a protocol extension (`None`, mirroring
    /// Java's `extProtocolName == null`) -- one handler may support multiple protocol extension
    /// names (e.g. http and https), but this is the fallback used in the absence of any.
    fn is_extension_supported(&self, ext_protocol_name: Option<&str>) -> bool {
        ext_protocol_name.is_none()
    }

    /// Get the Ghidra protocol connector for a Ghidra URL which requires this extension, mirrors
    /// `getConnector(URL)`. Real implementations are expected to return a
    /// `DefaultLocalGhidraProtocolConnector` when `ghidra_url`'s authority (host) component is
    /// blank, and a `DefaultGhidraProtocolConnector` otherwise, mirroring the Java method's
    /// `StringUtils.isBlank(ghidraUrl.getAuthority())` branch (neither concrete connector is
    /// ported yet, so this is left as a required method rather than a default body).
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` is not a
    /// supported URL form for the ghidra protocol, mirroring `MalformedURLException`.
    fn get_connector(&self, ghidra_url: &str) -> io::Result<Box<dyn GhidraProtocolConnector>>;
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::framework::client::{NotConnectedException, RepositoryAdapter, RepositoryServerAdapter};
    use crate::framework::protocol::ghidra::{GhidraProtocolConnector, StatusCode};

    use super::*;

    struct MockLocalConnector(String);

    impl GhidraProtocolConnector for MockLocalConnector {
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

    struct MockRemoteConnector(String);

    impl GhidraProtocolConnector for MockRemoteConnector {
        fn get_repository_root_ghidra_url(&self) -> Option<String> {
            Some(self.0.clone())
        }
        fn get_repository_name(&self) -> Option<String> {
            Some(self.0.clone())
        }
        fn get_folder_path(&self) -> Option<String> {
            None
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

    /// Mirrors `DefaultGhidraProtocolHandler.getConnector(URL)`'s branch on a blank authority,
    /// choosing between the (unported) local and repository connector implementations.
    struct MockDefaultGhidraProtocolHandler;

    impl DefaultGhidraProtocolHandler for MockDefaultGhidraProtocolHandler {
        fn get_connector(&self, ghidra_url: &str) -> io::Result<Box<dyn GhidraProtocolConnector>> {
            let after_scheme = ghidra_url.strip_prefix("ghidra:").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported URL form for ghidra protocol: {ghidra_url}"),
                )
            })?;
            if let Some(rest) = after_scheme.strip_prefix("//") {
                let authority = rest.split('/').next().unwrap_or("");
                if authority.trim().is_empty() {
                    return Ok(Box::new(MockLocalConnector(rest.to_string())));
                }
                return Ok(Box::new(MockRemoteConnector(authority.to_string())));
            }
            Ok(Box::new(MockLocalConnector(after_scheme.to_string())))
        }
    }

    #[test]
    fn is_extension_supported_only_accepts_absent_extension() {
        let handler = MockDefaultGhidraProtocolHandler;
        let dyn_handler: &dyn DefaultGhidraProtocolHandler = &handler;

        assert!(dyn_handler.is_extension_supported(None));
        assert!(!dyn_handler.is_extension_supported(Some("http")));
    }

    #[test]
    fn get_connector_chooses_local_or_remote_by_authority() {
        let handler = MockDefaultGhidraProtocolHandler;
        let dyn_handler: &dyn DefaultGhidraProtocolHandler = &handler;

        let local = dyn_handler.get_connector("ghidra:/path/projectName").unwrap();
        assert!(local.get_repository_name().is_none());

        let remote = dyn_handler.get_connector("ghidra://host/repo/path").unwrap();
        assert_eq!(remote.get_repository_name().as_deref(), Some("host"));
    }

    #[test]
    fn get_connector_rejects_url_missing_ghidra_scheme() {
        let handler = MockDefaultGhidraProtocolHandler;
        match handler.get_connector("http://host/repo") {
            Ok(_) => panic!("expected malformed URL error"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }
}
