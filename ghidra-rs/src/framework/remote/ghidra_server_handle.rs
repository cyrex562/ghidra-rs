use std::io;

use thiserror::Error;

use crate::framework::remote::{GhidraPrincipal, RemoteRepositoryServerHandle};
use crate::framework::seam_stubs::AuthCallback;

/// The collective interface version for all Ghidra Server remote interfaces. If any remote
/// interface is modified, this value should be incremented.
pub const SERVER_INTERFACE_VERSION: i32 = 13;

/// The minimum server interface version that the client can operate with.
pub const MIN_CLIENT_INTERFACE_VERSION: i32 = 13;

/// The minimum interface version that the server will support for older client versions. When
/// this version is less than [`MIN_CLIENT_INTERFACE_VERSION`] it allows older Ghidra clients to
/// continue using the current server version, while current Ghidra clients cannot use an older
/// server version.
pub const SERVER_MIN_CLIENT_INTERFACE_VERSION: i32 = 11;

/// The server BIND version which the Ghidra client can communicate with. This corresponds to
/// [`MIN_CLIENT_INTERFACE_VERSION`].
pub const GHIDRA_BIND_VERSION: &str = "12.0.5";

/// Minimum version of a Ghidra client release which can communicate with the current Ghidra
/// Server. This corresponds to [`SERVER_MIN_CLIENT_INTERFACE_VERSION`] and [`ALT_BIND_NAME`].
pub const ALT_GHIDRA_BIND_VERSION: &str = "9.0";

/// Default RMI base port for Ghidra Server.
pub const DEFAULT_PORT: u16 = 13100;

/// RMI registry binding name prefix for all versions of the remote `GhidraServerHandle` object.
pub const BIND_NAME_PREFIX: &str = "GhidraServer";

/// Primary RMI registry binding name for the remote `GhidraServerHandle` object. This BIND name
/// is used by both the server and client. Equal to `BIND_NAME_PREFIX` + `GHIDRA_BIND_VERSION`.
pub const BIND_NAME: &str = "GhidraServer12.0.5";

/// Alternate RMI registry binding name for the remote `GhidraServerHandle` object. This alternate
/// BIND name is used only by the server in support of older Ghidra clients and corresponds to
/// [`SERVER_MIN_CLIENT_INTERFACE_VERSION`]. Equal to `BIND_NAME_PREFIX` + `ALT_GHIDRA_BIND_VERSION`.
pub const ALT_BIND_NAME: &str = "GhidraServer9.0";

/// Combines the checked exceptions declared on `GhidraServerHandle.getRepositoryServer`, which is
/// declared `throws FailedLoginException, RemoteException`.
#[derive(Error, Debug)]
pub enum GhidraServerHandleError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("login failed: {0}")]
    FailedLogin(String),
}

/// Provides access to a remote server.
///
/// Mirrors `ghidra.framework.remote.GhidraServerHandle`. This remote interface facilitates user
/// login/authentication, providing a more useful handle to the associated repository server.
///
/// In Java, `getRepositoryServer` takes a `javax.security.auth.Subject` carrying the
/// authenticated user's principals; consistent with
/// [`GhidraPrincipal::get_ghidra_principal`](crate::framework::remote::GhidraPrincipal::get_ghidra_principal),
/// which already takes the extracted principal slice rather than modeling `Subject` itself, this
/// trait accepts `Option<&[GhidraPrincipal]>` directly. `javax.security.auth.callback.Callback`
/// is a marker interface with no members, so it is represented by the
/// [`AuthCallback`](crate::framework::seam_stubs::AuthCallback) placeholder marker trait.
pub trait GhidraServerHandle {
    /// Returns user authentication proxy object: authentication callbacks which must be satisfied
    /// or `None` if authentication is not required.
    fn get_authentication_callbacks(&self) -> io::Result<Option<Vec<Box<dyn AuthCallback>>>>;

    /// Get a handle to the repository server.
    ///
    /// `user` is the user's authenticated principals (extracted from the Java `Subject`).
    /// `auth_callbacks` are valid authentication callback objects which have been satisfied, or
    /// `None` if the server does not require authentication.
    fn get_repository_server(
        &self,
        user: Option<&[GhidraPrincipal]>,
        auth_callbacks: Option<&[Box<dyn AuthCallback>]>,
    ) -> Result<Box<dyn RemoteRepositoryServerHandle>, GhidraServerHandleError>;

    /// Check server interface compatibility with the specified client interface version.
    fn check_compatibility(&self, client_interface_version: i32) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::RepositoryHandle;
    use crate::framework::remote::RepositoryServerHandle;
    use std::cell::RefCell;

    struct MockCallback;

    impl AuthCallback for MockCallback {}

    struct MockRepositoryServerHandle {
        repositories: RefCell<Vec<String>>,
    }

    impl RepositoryServerHandle for MockRepositoryServerHandle {
        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn is_read_only(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn create_repository(&self, _name: &str) -> io::Result<Box<dyn RepositoryHandle>> {
            Err(io::Error::other("not supported by mock"))
        }

        fn get_repository(&self, _name: &str) -> io::Result<Option<Box<dyn RepositoryHandle>>> {
            Ok(None)
        }

        fn delete_repository(&self, _name: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_repository_names(&self) -> io::Result<Vec<String>> {
            Ok(self.repositories.borrow().clone())
        }

        fn get_user(&self) -> io::Result<String> {
            Ok("alice".to_string())
        }

        fn get_all_users(&self) -> io::Result<Vec<String>> {
            Ok(vec!["alice".to_string()])
        }

        fn can_set_password(&self) -> io::Result<bool> {
            Ok(true)
        }

        fn get_password_expiration(&self) -> io::Result<i64> {
            Ok(-1)
        }

        fn set_password(&self, _salted_sha256_password_hash: &[u8]) -> io::Result<bool> {
            Ok(true)
        }

        fn connected(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Mock server handle whose login/compatibility logic mirrors the real Java server: login
    /// fails without a `GhidraPrincipal`, and `checkCompatibility` rejects client interface
    /// versions below `SERVER_MIN_CLIENT_INTERFACE_VERSION`.
    struct MockGhidraServerHandle;

    impl GhidraServerHandle for MockGhidraServerHandle {
        fn get_authentication_callbacks(&self) -> io::Result<Option<Vec<Box<dyn AuthCallback>>>> {
            Ok(Some(vec![Box::new(MockCallback)]))
        }

        fn get_repository_server(
            &self,
            user: Option<&[GhidraPrincipal]>,
            auth_callbacks: Option<&[Box<dyn AuthCallback>]>,
        ) -> Result<Box<dyn RemoteRepositoryServerHandle>, GhidraServerHandleError> {
            let principals = user.unwrap_or(&[]);
            if principals.is_empty() {
                return Err(GhidraServerHandleError::FailedLogin(
                    "no GhidraPrincipal present on subject".to_string(),
                ));
            }
            if auth_callbacks.is_none() {
                return Err(GhidraServerHandleError::FailedLogin(
                    "authentication callbacks not satisfied".to_string(),
                ));
            }
            Ok(Box::new(MockRepositoryServerHandle {
                repositories: RefCell::new(vec![format!(
                    "repo-for-{}",
                    principals[0].name()
                )]),
            }))
        }

        fn check_compatibility(&self, client_interface_version: i32) -> io::Result<()> {
            if client_interface_version < SERVER_MIN_CLIENT_INTERFACE_VERSION {
                return Err(io::Error::other(format!(
                    "client interface version {client_interface_version} is not supported"
                )));
            }
            Ok(())
        }
    }

    #[test]
    fn test_object_safety_and_login_flow() {
        let server: Box<dyn GhidraServerHandle> = Box::new(MockGhidraServerHandle);

        let callbacks = server.get_authentication_callbacks().unwrap();
        assert!(callbacks.is_some());
        let callbacks = callbacks.unwrap();

        let err = server.get_repository_server(None, Some(&callbacks)).unwrap_err();
        assert!(matches!(err, GhidraServerHandleError::FailedLogin(_)));

        let principals = vec![GhidraPrincipal::new("alice")];
        let handle = server
            .get_repository_server(Some(&principals), Some(&callbacks))
            .unwrap();
        assert_eq!(
            handle.get_repository_names().unwrap(),
            vec!["repo-for-alice".to_string()]
        );
    }

    #[test]
    fn test_check_compatibility() {
        let server: Box<dyn GhidraServerHandle> = Box::new(MockGhidraServerHandle);

        assert!(server
            .check_compatibility(SERVER_MIN_CLIENT_INTERFACE_VERSION)
            .is_ok());
        assert!(server.check_compatibility(SERVER_INTERFACE_VERSION).is_ok());
        assert!(server
            .check_compatibility(SERVER_MIN_CLIENT_INTERFACE_VERSION - 1)
            .is_err());
    }

    #[test]
    fn test_bind_name_constants() {
        assert_eq!(
            BIND_NAME,
            format!("{BIND_NAME_PREFIX}{GHIDRA_BIND_VERSION}")
        );
        assert_eq!(
            ALT_BIND_NAME,
            format!("{BIND_NAME_PREFIX}{ALT_GHIDRA_BIND_VERSION}")
        );
    }
}
