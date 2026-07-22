use std::io;

use crate::framework::client::{NotConnectedException, RepositoryAdapter, RepositoryServerAdapter};
use crate::framework::protocol::ghidra::StatusCode;

/// Provides an abstract implementation to access Ghidra repositories using various underlying
/// communication protocols. The common requirement for all implementations is the ability to
/// derive a repository URL from any folder or file URL.
///
/// Port of `ghidra.framework.protocol.ghidra.GhidraProtocolConnector`, an abstract class whose
/// concrete construction logic (`checkProtocol`/`checkUserInfo`/`checkHostInfo`/
/// `parseRepositoryName`/`initFolderItemPath`/`parseItemPath`) parses a `ghidra://` URL (mirrored
/// elsewhere in this crate as a plain `&str`/`String`, per the convention documented on
/// [`Project`](crate::framework::model::Project)) into the `repositoryName`/`itemPath`/
/// `folderPath`/`folderItemName` fields this trait exposes as getters. That construction logic is
/// only ever invoked from within a concrete connector's own constructor and is overridden by at
/// most one subclass each (`DefaultLocalGhidraProtocolConnector`), so it is not part of this
/// trait's dyn-dispatched capability surface -- concrete implementations (not yet ported) are
/// expected to reproduce it as private/inherent construction helpers instead, mirroring how
/// [`RepositoryAdapter`]'s own package-private wiring helpers are excluded from its trait surface.
///
/// Selected as a dependency-cycle cut-point, so every method here takes `&self` and returns
/// owned/boxed values, matching the convention used elsewhere in this crate for cut-point traits
/// (e.g. [`GhidraURLConnection`](crate::framework::protocol::ghidra::GhidraURLConnection),
/// [`RepositoryAdapter`]). Implementations are expected to back the connection/status-code/
/// folder-path state this trait's methods observe and mutate with interior mutability, mirroring
/// the underlying Java class's own mutable instance fields (`statusCode`, `folderPath`,
/// `folderItemName`, `repositoryAdapter`, `repositoryServerAdapter`).
///
/// The package-private `connect(RepositoryAdapter)` overload becomes
/// [`connect_to_repository`](Self::connect_to_repository) since Rust has no method overloading,
/// distinguishing it from the public abstract `connect(boolean)` overload
/// ([`connect`](Self::connect)); both are retained since `TransientProjectManager` (unported)
/// calls each of them directly.
pub trait GhidraProtocolConnector {
    /// Get the URL associated with the repository/project root folder. This will be used as a key
    /// to its corresponding transient project data. Mirrors the protected abstract
    /// `getRepositoryRootGhidraURL()`.
    ///
    /// Returns `None` if the connection is a server-only URL.
    fn get_repository_root_ghidra_url(&self) -> Option<String>;

    /// Gets the repository name associated with the URL. If a local URL is used this will
    /// correspond to the project name. Mirrors `getRepositoryName()`.
    ///
    /// Returns `None` if the URL does not identify a specific repository.
    fn get_repository_name(&self) -> Option<String>;

    /// Gets the repository folder path associated with the URL. Mirrors `getFolderPath()`.
    ///
    /// If an ambiguous path has been specified, the folder path may change after a connection is
    /// established (e.g. folder item name will be appended to folder path and item name will
    /// become `None` if the item turns out to be a folder).
    fn get_folder_path(&self) -> Option<String>;

    /// Gets the repository folder item name associated with the URL. Mirrors
    /// `getFolderItemName()`.
    ///
    /// If an ambiguous path has been specified, the folder item name may become `None` after a
    /// connection is established (e.g. folder item name will be appended to folder path and item
    /// name will become `None` if the item turns out to be a folder).
    fn get_folder_item_name(&self) -> Option<String>;

    /// Gets the status code from a Ghidra URL connect attempt. Mirrors `getStatusCode()`.
    ///
    /// Returns `None` if not yet connected.
    fn get_status_code(&self) -> Option<StatusCode>;

    /// Get the [`RepositoryAdapter`] associated with a URL which specifies a repository. Mirrors
    /// `getRepositoryAdapter()`.
    ///
    /// Returns `None` if a project locator is supplied instead.
    fn get_repository_adapter(&self) -> Option<Box<dyn RepositoryAdapter>>;

    /// Get the [`RepositoryServerAdapter`] associated with a URL which specifies a repository or
    /// repository server. Mirrors `getRepositoryServerAdapter()`.
    ///
    /// Returns `None` if a project locator is supplied instead.
    fn get_repository_server_adapter(&self) -> Option<Box<dyn RepositoryServerAdapter>>;

    /// Connect to the resource specified by the associated URL. Mirrors the public abstract
    /// `connect(boolean readOnly)`. This method should only be invoked once; a second attempt may
    /// result in an error.
    ///
    /// `read_only` indicates whether the resource should be requested for write access when
    /// `false`.
    ///
    /// # Errors
    /// Returns `io::Error` if a connection error occurs.
    fn connect(&self, read_only: bool) -> io::Result<StatusCode>;

    /// Utilize a cached connection via the specified repository adapter. Mirrors the
    /// package-private `connect(RepositoryAdapter repository)`.
    ///
    /// This method may only be invoked if not yet connected and the associated URL corresponds to
    /// a repository ([`get_repository_name`](Self::get_repository_name) returns `Some`). The
    /// connection status code should be established based upon the availability of the URL
    /// referenced repository resource (i.e. folder or file).
    ///
    /// # Errors
    /// Returns `io::Error` if already connected, if `repository` does not correspond to this
    /// connector's repository name, if `repository` is not itself connected, or if an IO error
    /// occurs.
    fn connect_to_repository(&self, repository: Box<dyn RepositoryAdapter>) -> io::Result<()>;

    /// Determines the read-only nature of a connected resource. Mirrors the public abstract
    /// `isReadOnly()`.
    ///
    /// # Errors
    /// Returns [`NotConnectedException`] if connect has not yet been performed.
    fn is_read_only(&self) -> Result<bool, NotConnectedException>;
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[derive(Clone)]
    struct SharedRepoState {
        name: String,
        connected: Rc<Cell<bool>>,
    }

    struct MockRepositoryAdapter(SharedRepoState);

    impl RepositoryAdapter for MockRepositoryAdapter {
        fn get_name(&self) -> String {
            self.0.name.clone()
        }

        fn is_connected(&self) -> bool {
            self.0.connected.get()
        }

        fn connect(&self) -> io::Result<()> {
            self.0.connected.set(true);
            Ok(())
        }
    }

    struct MockGhidraProtocolConnector {
        root_url: String,
        repository_name: Option<String>,
        folder_path: RefCell<Option<String>>,
        folder_item_name: RefCell<Option<String>>,
        status: Cell<Option<StatusCode>>,
        read_only: Cell<bool>,
        repository: RefCell<Option<SharedRepoState>>,
    }

    impl MockGhidraProtocolConnector {
        fn new(root_url: &str, repository_name: &str) -> Self {
            Self {
                root_url: root_url.to_string(),
                repository_name: Some(repository_name.to_string()),
                folder_path: RefCell::new(Some("/".to_string())),
                folder_item_name: RefCell::new(None),
                status: Cell::new(None),
                read_only: Cell::new(true),
                repository: RefCell::new(None),
            }
        }
    }

    impl GhidraProtocolConnector for MockGhidraProtocolConnector {
        fn get_repository_root_ghidra_url(&self) -> Option<String> {
            Some(self.root_url.clone())
        }

        fn get_repository_name(&self) -> Option<String> {
            self.repository_name.clone()
        }

        fn get_folder_path(&self) -> Option<String> {
            self.folder_path.borrow().clone()
        }

        fn get_folder_item_name(&self) -> Option<String> {
            self.folder_item_name.borrow().clone()
        }

        fn get_status_code(&self) -> Option<StatusCode> {
            self.status.get()
        }

        fn get_repository_adapter(&self) -> Option<Box<dyn RepositoryAdapter>> {
            self.repository
                .borrow()
                .clone()
                .map(|state| Box::new(MockRepositoryAdapter(state)) as Box<dyn RepositoryAdapter>)
        }

        fn get_repository_server_adapter(&self) -> Option<Box<dyn RepositoryServerAdapter>> {
            None
        }

        fn connect(&self, read_only: bool) -> io::Result<StatusCode> {
            if self.status.get().is_some() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "already connected"));
            }
            let Some(name) = self.repository_name.clone() else {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "no repository for URL"));
            };
            self.read_only.set(read_only);
            *self.repository.borrow_mut() =
                Some(SharedRepoState { name, connected: Rc::new(Cell::new(true)) });
            self.status.set(Some(StatusCode::Ok));
            Ok(StatusCode::Ok)
        }

        fn connect_to_repository(&self, repository: Box<dyn RepositoryAdapter>) -> io::Result<()> {
            if self.status.get().is_some() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "already connected"));
            }
            let expected = self.repository_name.as_deref().unwrap_or("");
            if repository.get_name() != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid repository connection",
                ));
            }
            if !repository.is_connected() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "expected connected repository",
                ));
            }
            self.status.set(Some(StatusCode::Ok));
            *self.repository.borrow_mut() = Some(SharedRepoState {
                name: repository.get_name(),
                connected: Rc::new(Cell::new(true)),
            });
            Ok(())
        }

        fn is_read_only(&self) -> Result<bool, NotConnectedException> {
            if self.status.get().is_none() {
                return Err(NotConnectedException::new("not connected"));
            }
            Ok(self.read_only.get())
        }
    }

    #[test]
    fn connect_establishes_status_and_repository_adapter() {
        let connector = MockGhidraProtocolConnector::new("ghidra://host/MyRepo", "MyRepo");
        let dyn_connector: &dyn GhidraProtocolConnector = &connector;

        assert!(dyn_connector.get_status_code().is_none());
        assert!(dyn_connector.is_read_only().is_err());

        let status = dyn_connector.connect(true).unwrap();
        assert_eq!(status, StatusCode::Ok);
        assert_eq!(dyn_connector.get_status_code(), Some(StatusCode::Ok));
        assert_eq!(dyn_connector.is_read_only().unwrap(), true);

        let adapter = dyn_connector.get_repository_adapter().unwrap();
        assert_eq!(adapter.get_name(), "MyRepo");
        assert!(adapter.is_connected());

        // A second connect attempt is rejected, mirroring the Java "already connected" check.
        assert!(dyn_connector.connect(false).is_err());
    }

    #[test]
    fn connect_to_repository_rejects_mismatched_or_disconnected_adapter() {
        let connector = MockGhidraProtocolConnector::new("ghidra://host/MyRepo", "MyRepo");

        let mismatched = MockRepositoryAdapter(SharedRepoState {
            name: "OtherRepo".to_string(),
            connected: Rc::new(Cell::new(true)),
        });
        assert!(connector.connect_to_repository(Box::new(mismatched)).is_err());
        assert!(connector.get_status_code().is_none());

        let disconnected = MockRepositoryAdapter(SharedRepoState {
            name: "MyRepo".to_string(),
            connected: Rc::new(Cell::new(false)),
        });
        assert!(connector.connect_to_repository(Box::new(disconnected)).is_err());
        assert!(connector.get_status_code().is_none());
    }

    #[test]
    fn connect_to_repository_reuses_cached_connection() {
        let connector = MockGhidraProtocolConnector::new("ghidra://host/MyRepo", "MyRepo");
        let cached = MockRepositoryAdapter(SharedRepoState {
            name: "MyRepo".to_string(),
            connected: Rc::new(Cell::new(true)),
        });

        connector.connect_to_repository(Box::new(cached)).unwrap();

        assert_eq!(connector.get_status_code(), Some(StatusCode::Ok));
        let adapter = connector.get_repository_adapter().unwrap();
        assert_eq!(adapter.get_name(), "MyRepo");
        assert!(adapter.is_connected());
    }
}
