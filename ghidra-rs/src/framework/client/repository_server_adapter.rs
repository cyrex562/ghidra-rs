use std::io;

use thiserror::Error;

use crate::framework::client::remote_adapter_listener::RemoteAdapterListener;
use crate::framework::client::RepositoryAdapter;
use crate::framework::model::server_info::ServerInfo;
use crate::util::exception::{DuplicateNameException, UserAccessException};

/// Builds the `io::Error` returned by every default method below.
///
/// Mirrors `RepositoryServerAdapter`'s `checkServerHandle()`, which throws `NotConnectedException`
/// (itself an `IOException` subclass) whenever the wrapped `RepositoryServerHandle` is unset. Every
/// default trait method below models a `RepositoryServerAdapter` that has never successfully
/// connected, so this is the error each of them naturally returns; see the identical helper in
/// [`RepositoryAdapter`](crate::framework::client::repository_adapter).
fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Not connected to the server")
}

/// Combines the checked exceptions declared on `RepositoryServerAdapter.createRepository`, which is
/// declared `throws DuplicateNameException, UserAccessException, IOException,
/// NotConnectedException` (`NotConnectedException` is itself an `IOException` subclass, folded into
/// the `Io` variant here).
#[derive(Error, Debug)]
pub enum CreateRepositoryError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    UserAccess(#[from] UserAccessException),
}

/// Combines the checked exceptions declared on `RepositoryServerAdapter.deleteRepository`, which is
/// declared `throws UserAccessException, IOException, NotConnectedException`
/// (`NotConnectedException` is itself an `IOException` subclass, folded into the `Io` variant here).
#[derive(Error, Debug)]
pub enum RepositoryAccessError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    UserAccess(#[from] UserAccessException),
}

/// Provides a persistent wrapper for a `RepositoryServerHandle` which may become invalid if the
/// remote connection were to fail.
///
/// Mirrors `ghidra.framework.client.RepositoryServerAdapter`.
///
/// Ported to a trait (rather than a concrete class) at a dependency-cycle cut-point identified in
/// the Java package graph, so that other core types (e.g.
/// [`ProjectManager`](crate::framework::model::ProjectManager)) can depend on repository-server
/// behavior without depending on a single concrete implementation. Every method takes `&self` and
/// returns owned/boxed values, matching the same object-safety rationale used by
/// [`RepositoryAdapter`](crate::framework::client::RepositoryAdapter): a resilient/remote
/// implementation needs interior mutability (e.g. a `Mutex`) even for what look like read-only
/// calls, since `connect`/`disconnect`/user-caching all mutate shared state under the hood in the
/// original Java (`synchronized` methods throughout).
///
/// Every method is given a default describing a `RepositoryServerAdapter` that has never
/// successfully connected (see [`not_connected`]), so existing bare
/// `impl RepositoryServerAdapter for MockX {}` blocks (written against the placeholder trait this
/// promotes) keep compiling.
///
/// The package-private `verifyConnection`, `checkServerHandle`, `hadUnexpectedDisconnect`,
/// `getRepositoryHandle`, and `checkPasswordExpiration` members, along with the two `protected`/
/// package-private constructors, are internal wiring not part of this trait's public capability
/// surface (analogous to the internal members `RepositoryAdapter` also excludes).
pub trait RepositoryServerAdapter {
    /// Add a listener to this remote adapter.
    fn add_listener(&self, listener: Box<dyn RemoteAdapterListener>) {
        let _ = listener;
    }

    /// Remove a listener from this remote adapter.
    fn remove_listener(&self, listener: &dyn RemoteAdapterListener) {
        let _ = listener;
    }

    /// Returns true if the connection attempt was cancelled by the user.
    fn is_cancelled(&self) -> bool {
        false
    }

    /// Returns a description of the last error associated with a failed connection attempt, or
    /// `None` if there was none.
    fn get_last_connect_error(&self) -> Option<String> {
        None
    }

    /// Returns true if connected.
    fn is_connected(&self) -> bool {
        false
    }

    /// Attempt to connect or re-connect to the server.
    ///
    /// Returns `Ok(true)` if the connect was successful, `Ok(false)` if cancelled by the user.
    ///
    /// # Errors
    /// Returns `Err` if the connect attempt failed (the user has already been informed of the
    /// error).
    fn connect(&self) -> io::Result<bool> {
        Err(not_connected())
    }

    /// Create a new repository on the server.
    fn create_repository(&self, name: &str) -> Result<Box<dyn RepositoryAdapter>, CreateRepositoryError> {
        let _ = name;
        Err(CreateRepositoryError::Io(not_connected()))
    }

    /// Get a handle to an existing repository. The returned repository adapter is initially
    /// disconnected; the returned adapter's own `connect()` (or another repository action method)
    /// must be invoked to establish a repository connection.
    fn get_repository(&self, name: &str) -> Box<dyn RepositoryAdapter> {
        Box::new(DisconnectedRepositoryAdapter { name: name.to_string() })
    }

    /// Delete a repository.
    fn delete_repository(&self, name: &str) -> Result<(), RepositoryAccessError> {
        let _ = name;
        Err(RepositoryAccessError::Io(not_connected()))
    }

    /// Returns a list of all repository names defined to the server.
    fn get_repository_names(&self) -> io::Result<Vec<String>> {
        Err(not_connected())
    }

    /// Returns true if server allows anonymous access. Individual repositories must grant
    /// anonymous access separately.
    fn anonymous_access_allowed(&self) -> io::Result<bool> {
        Err(not_connected())
    }

    /// Returns true if user has restricted read-only access to server (e.g., anonymous user).
    fn is_read_only(&self) -> io::Result<bool> {
        Err(not_connected())
    }

    /// Returns user's server login identity.
    fn get_user(&self) -> String {
        String::new()
    }

    /// Returns a list of all known users.
    fn get_all_users(&self) -> io::Result<Vec<String>> {
        Err(not_connected())
    }

    /// Set the simple password for the user. `salted_sha256_password_hash` is a hex character
    /// representation of a salted SHA256 hash of the password. Returns true if the password
    /// changed.
    fn set_password(&self, salted_sha256_password_hash: &[u8]) -> io::Result<bool> {
        let _ = salted_sha256_password_hash;
        Err(not_connected())
    }

    /// Returns true if this server allows the user to change their password.
    fn can_set_password(&self) -> bool {
        false
    }

    /// Returns server information. May be `None` if using a fixed `RepositoryServerHandle`.
    fn get_server_info(&self) -> Option<ServerInfo> {
        None
    }

    /// Returns a display string describing the server this adapter connects to.
    ///
    /// Mirrors `RepositoryServerAdapter.toString()`, which returns the cached `serverInfoStr`
    /// field (derived from `server.toString()`, or a directly supplied string when constructed
    /// from a fixed `RepositoryServerHandle`) even when [`get_server_info`](Self::get_server_info)
    /// returns `None`.
    fn server_info_str(&self) -> String {
        self.get_server_info().map(|info| info.to_string()).unwrap_or_default()
    }

    /// Force disconnect with server.
    fn disconnect(&self) {}
}

/// Trivial fallback used by [`RepositoryServerAdapter::get_repository`]'s default implementation
/// before a real, connectable `RepositoryServerAdapter` is available. Mirrors the disconnected
/// `RepositoryAdapter` that `RepositoryServerAdapter.getRepository(String)` unconditionally
/// constructs in Java, preserving only the requested repository name.
struct DisconnectedRepositoryAdapter {
    name: String,
}

impl RepositoryAdapter for DisconnectedRepositoryAdapter {
    fn get_name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A mock that behaves like a real resilient repository server adapter: `connect`/
    /// `disconnect` flip connection state, and repository operations only succeed while
    /// "connected", proving the trait captures meaningful behavior rather than being a
    /// pass-through shell.
    #[derive(Default)]
    struct MockRepositoryServerAdapter {
        connected: Cell<bool>,
        repositories: RefCell<Vec<String>>,
    }

    impl RepositoryServerAdapter for MockRepositoryServerAdapter {
        fn is_connected(&self) -> bool {
            self.connected.get()
        }

        fn connect(&self) -> io::Result<bool> {
            self.connected.set(true);
            Ok(true)
        }

        fn disconnect(&self) {
            self.connected.set(false);
        }

        fn create_repository(
            &self,
            name: &str,
        ) -> Result<Box<dyn RepositoryAdapter>, CreateRepositoryError> {
            if !self.is_connected() {
                return Err(CreateRepositoryError::Io(not_connected()));
            }
            let mut repos = self.repositories.borrow_mut();
            if repos.iter().any(|r| r == name) {
                return Err(CreateRepositoryError::Duplicate(DuplicateNameException::with_message(
                    format!("Repository '{name}' already exists"),
                )));
            }
            repos.push(name.to_string());
            Ok(Box::new(DisconnectedRepositoryAdapter { name: name.to_string() }))
        }

        fn get_repository_names(&self) -> io::Result<Vec<String>> {
            if !self.is_connected() {
                return Err(not_connected());
            }
            Ok(self.repositories.borrow().clone())
        }

        fn delete_repository(&self, name: &str) -> Result<(), RepositoryAccessError> {
            if !self.is_connected() {
                return Err(RepositoryAccessError::Io(not_connected()));
            }
            let mut repos = self.repositories.borrow_mut();
            let before = repos.len();
            repos.retain(|r| r != name);
            if repos.len() == before {
                return Err(RepositoryAccessError::Io(io::Error::other(format!(
                    "no such repository: {name}"
                ))));
            }
            Ok(())
        }

        fn get_user(&self) -> String {
            "alice".to_string()
        }
    }

    #[test]
    fn test_object_safety_and_connection_lifecycle() {
        let server: Box<dyn RepositoryServerAdapter> =
            Box::new(MockRepositoryServerAdapter::default());

        assert!(!server.is_connected());
        assert!(server.create_repository("Repo1").is_err());

        assert!(server.connect().unwrap());
        assert!(server.is_connected());
        assert_eq!(server.get_user(), "alice");

        server.create_repository("Repo1").unwrap();
        assert_eq!(server.get_repository_names().unwrap(), vec!["Repo1".to_string()]);

        let err = server.create_repository("Repo1").unwrap_err();
        assert!(matches!(err, CreateRepositoryError::Duplicate(_)));

        server.delete_repository("Repo1").unwrap();
        assert!(server.get_repository_names().unwrap().is_empty());

        server.disconnect();
        assert!(!server.is_connected());
        assert!(server.get_repository_names().is_err());
    }

    #[test]
    fn test_get_repository_returns_disconnected_adapter_with_name() {
        struct BareRepositoryServerAdapter;
        impl RepositoryServerAdapter for BareRepositoryServerAdapter {}

        let server = BareRepositoryServerAdapter;
        let repo = server.get_repository("MyRepo");
        assert_eq!(repo.get_name(), "MyRepo");
        assert!(!repo.is_connected());
    }

    #[test]
    fn test_bare_default_impl_reports_not_connected() {
        struct BareRepositoryServerAdapter;
        impl RepositoryServerAdapter for BareRepositoryServerAdapter {}

        let server = BareRepositoryServerAdapter;
        assert!(!server.is_connected());
        assert!(!server.is_cancelled());
        assert!(server.get_last_connect_error().is_none());
        assert!(!server.can_set_password());
        assert!(server.get_server_info().is_none());
        assert_eq!(server.server_info_str(), "");
        assert!(server.connect().is_err());
        assert!(server.get_repository_names().is_err());
        assert!(server.anonymous_access_allowed().is_err());
        assert!(server.delete_repository("x").is_err());
    }
}
